//! `--detach` (issue 70): a command that goes into the background by
//! itself, so that an agent starts it one time and does other work.
//!
//! The parent runs this binary again (`/proc/self/exe`) with
//! [`CHILD_FLAG`] first. No fork happens after the async runtime starts.
//! The child:
//!
//! 1. closes each inherited file descriptor from 3, resets the signal mask
//!    and takes the lock of its instance ([`crate::instances`]);
//! 2. runs the command with the stdin, the stderr and the terminal of the
//!    caller (a prompt and Ctrl-C work until it is ready);
//! 3. at ready ([`ready`]): stdin to `/dev/null`, stderr to the log,
//!    `setsid()`, SIGHUP ignored; one ready line to the parent on the pipe
//!    that is its stdout; then stdout to the log.
//!
//! The parent prints the lines of the child until the ready line, then the
//! ready document (one JSON line), and exits 0. A child that ends first
//! gives the parent its exit code. After `--ready-timeout`, the parent
//! stops the child and exits 75.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};

use crate::instances::{self, Held, Record};

/// The first argument of a detached child. Only cfrs writes it.
pub const CHILD_FLAG: &str = "--detach-child";
/// The name of the instance, for the child.
pub const NAME_VARIABLE: &str = "CFRS_DETACH_NAME";
/// The hash of the arguments, for the child.
pub const HASH_VARIABLE: &str = "CFRS_DETACH_HASH";
/// The command (`tunnel`, `warp proxy`), for the child.
pub const COMMAND_VARIABLE: &str = "CFRS_DETACH_COMMAND";
/// The start of the ready line on the pipe.
const READY: &str = "cfrs-detached-ready ";
/// The log is cut at this size; the part before goes to `.log.1`.
pub const LOG_CAP: u64 = 1 << 20;
/// Exit code: no ready in time, or the pipe to the parent closed.
pub const TEMPFAIL: i32 = crate::exit::TEMPFAIL;

static CHILD: AtomicBool = AtomicBool::new(false);
static SENT: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<Option<ChildState>> = Mutex::new(None);

struct ChildState {
    dir: PathBuf,
    record: Record,
    _lock: Held,
}

/// The options of `--detach`.
#[derive(Clone, Debug)]
pub struct Options {
    pub name: Option<String>,
    pub ready_timeout: Duration,
    pub replace: bool,
}

/// At the start of `main`, before any thread: with [`CHILD_FLAG`] after
/// the binary, remove it, close each inherited descriptor from 3, and reset
/// the signals. Gives the arguments with no flag.
pub fn prepare(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.get(1).is_some_and(|a| a == CHILD_FLAG) {
        args.remove(1);
        CHILD.store(true, Ordering::SeqCst);
        unix::prepare();
    }
    args
}

/// Whether this process is a detached child (before or after its ready).
pub fn is_child() -> bool {
    CHILD.load(Ordering::SeqCst)
}

/// In a detached child, after the command line parses: take the lock of the
/// instance and write its record (state `starting`). When another process
/// holds the lock, the error says so.
pub fn child_begin() -> Result<()> {
    let name = std::env::var(NAME_VARIABLE).context("a detached child with no instance name")?;
    instances::check_name(&name)?;
    let hash = std::env::var(HASH_VARIABLE).unwrap_or_default();
    let command = std::env::var(COMMAND_VARIABLE).unwrap_or_default();
    let dir = instances::run_dir()?;
    let paths = instances::paths(&dir, &name);
    let lock = instances::try_lock(&paths.lock)?
        .with_context(|| format!("the instance {name} runs already"))?;
    let record = Record {
        name: name.clone(),
        pid: std::process::id(),
        supervisor: None,
        started: instances::now(),
        command,
        args: std::env::args()
            .skip(1)
            .filter(|a| a != CHILD_FLAG)
            .collect(),
        hash,
        cwd: std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_default(),
        state: "starting".into(),
        ready: None,
        log: paths.log.display().to_string(),
        restarts: 0,
    };
    instances::write(&dir, &record)?;
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(ChildState {
        dir,
        record,
        _lock: lock,
    });
    Ok(())
}

/// The command is ready, with `doc` (a JSON object: `url`, or `listen`, and
/// more). In a detached child, the first call leaves the terminal of the
/// caller and sends the ready line; each other call, and a call in a
/// process that is not a detached child, does nothing.
pub fn ready(mut doc: serde_json::Value) {
    if !is_child() || SENT.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = guard.as_mut() else {
        return;
    };
    let log_path = PathBuf::from(&state.record.log);
    let log = open_private(&log_path).ok();
    if let Some(object) = doc.as_object_mut() {
        object.insert("event".into(), "detached".into());
        object.insert("name".into(), state.record.name.clone().into());
        object.insert("pid".into(), state.record.pid.into());
        object.insert("command".into(), state.record.command.clone().into());
        object.insert("log".into(), state.record.log.clone().into());
    }
    state.record.state = "ready".into();
    state.record.ready = Some(doc.clone());
    let _ = instances::write(&state.dir, &state.record);
    let line = format!("{READY}{doc}\n");
    let _ = std::io::stdout().flush();
    if !unix::leave(log.as_ref(), line.as_bytes()) {
        std::process::exit(TEMPFAIL);
    }
    if let Some(file) = log {
        cap(log_path, file);
    }
}

fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

/// Past [`LOG_CAP`], copy the log to `.log.1` and cut it (checked each
/// minute).
fn cap(path: PathBuf, file: std::fs::File) {
    let _ = std::thread::Builder::new()
        .name("detach-log".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            let Ok(meta) = file.metadata() else { return };
            if meta.len() > LOG_CAP {
                let mut aside = path.clone().into_os_string();
                aside.push(".1");
                let _ = std::fs::copy(&path, &aside);
                if file.set_len(0).is_ok() {
                    let _ = (&file)
                        .write_all(b"cfrs: the log passed 1 MiB; its part before is in .log.1\n");
                }
            }
        });
}

/// The ways to run this binary again: `/proc/self/exe` (this image, also
/// after `cfrs update` replaced the file), then the path of the system.
fn binaries() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if Path::new("/proc/self/exe").exists() {
        out.push(PathBuf::from("/proc/self/exe"));
    }
    if let Ok(path) = std::env::current_exe() {
        if path.exists() && !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// Why `--detach` cannot work here, if it cannot.
fn refusal() -> Option<&'static str> {
    (std::process::id() == 1).then_some(
        "cfrs is process 1 (a container entry point): a detached child would end with the container; run it in the foreground",
    )
}

/// The default name: the command and 6 characters of the hash.
pub fn default_name(command: &str, hash: &str) -> String {
    let command: String = command
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let mut name = format!("{command}-{}", &hash[..hash.len().min(6)]);
    name.truncate(32);
    name
}

/// The parent part of `--detach` for `command`. Gives the exit code.
pub fn start(command: &str, options: &Options) -> i32 {
    match start_inner(command, options) {
        Ok(code) => code,
        Err(err) => {
            let code = crate::exit::code_of(&err);
            eprintln!("cfrs: --detach: {err:#}");
            if code == crate::exit::FAILURE {
                crate::exit::UNAVAILABLE
            } else {
                code
            }
        }
    }
}

fn start_inner(command: &str, options: &Options) -> Result<i32> {
    use crate::exit::{fault, Fault};
    if let Some(why) = refusal() {
        return Err(fault(Fault::Unavailable, anyhow::anyhow!(why)));
    }
    let dir = instances::run_dir().map_err(|e| fault(Fault::Config, e))?;
    let typed: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let (args, vars) = crate::autostart::split_secrets(&typed, &|k| std::env::var(k).ok());
    let secrets: Vec<(String, String)> = vars
        .iter()
        .filter(|(k, _)| k == "TUNNEL_TOKEN" || k == "CFRS_PROXY")
        .cloned()
        .collect();
    // The hash leaves out the options of --detach itself: a second start
    // with another --ready-timeout is the same instance.
    let hashed = without_detach_options(&args);
    let hash = instances::hash_of(&hashed, &secrets);
    let name = match &options.name {
        Some(name) => name.clone(),
        None => default_name(command, &hash),
    };
    instances::check_name(&name).map_err(|e| fault(Fault::Usage, e))?;
    let paths = instances::paths(&dir, &name);
    // One start at a time for each name.
    let _start = instances::lock(&paths.start)?;
    if instances::is_alive(&dir, &name) {
        let record = instances::read(&dir, &name);
        let same = record.as_ref().is_some_and(|r| r.hash == hash);
        if same {
            let doc = wait_ready_record(&dir, &name, options.ready_timeout)?;
            println!("{doc}");
            return Ok(0);
        }
        if !options.replace {
            return Err(fault(
                Fault::Unavailable,
                anyhow::anyhow!(
                    "the instance {name} runs with other arguments; use --replace, or another --name"
                ),
            ));
        }
        stop(&dir, &name, Duration::from_secs(10))?;
    } else {
        instances::remove(&dir, &name);
    }
    let mut tried = Vec::new();
    for program in binaries() {
        let mut cmd = Command::new(&program);
        {
            use std::os::unix::process::CommandExt;
            cmd.arg0("cfrs");
        }
        cmd.arg(CHILD_FLAG)
            .args(&args)
            .envs(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .env(NAME_VARIABLE, &name)
            .env(HASH_VARIABLE, &hash)
            .env(COMMAND_VARIABLE, command)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        match cmd.spawn() {
            Ok(child) => return Ok(wait_ready_child(child, &dir, &name, options.ready_timeout)),
            Err(err) => tried.push(format!("{}: {err}", program.display())),
        }
    }
    bail!("cfrs could not run itself again: {}", tried.join("; "))
}

/// The arguments with no `--detach`, `--name`, `--ready-timeout`,
/// `--replace` or `--no-restart` (and their values).
pub fn without_detach_options(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        let flag = arg.split('=').next().unwrap_or("");
        match flag {
            "--detach" | "--replace" | "--no-restart" => {}
            "--name" | "--ready-timeout" => skip = !arg.contains('='),
            _ => out.push(arg.clone()),
        }
    }
    out
}

/// Wait for the ready line of a child that this process started.
fn wait_ready_child(
    mut child: std::process::Child,
    dir: &Path,
    name: &str,
    timeout: Duration,
) -> i32 {
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(Some(line)).is_err() {
                    return;
                }
            }
            let _ = tx.send(None);
        });
    }
    let deadline = Instant::now() + timeout;
    let mut out = std::io::stdout();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Some(line)) => {
                if let Some(doc) = line.strip_prefix(READY) {
                    let _ = writeln!(out, "{doc}");
                    let _ = out.flush();
                    return 0;
                }
                let _ = writeln!(out, "{line}");
            }
            Ok(None) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                eprintln!(
                    "cfrs: --detach: {name} was not ready in {} s; it is stopped",
                    timeout.as_secs()
                );
                terminate(child.id(), &mut child);
                instances::remove(dir, name);
                return TEMPFAIL;
            }
        }
    }
    let code = match child.wait() {
        Ok(status) => code_of(status),
        Err(_) => crate::exit::FAILURE,
    };
    instances::remove(dir, name);
    if code == 0 {
        // A command that ends with no ready (for example --run-for 0).
        eprintln!("cfrs: --detach: {name} ended before it was ready");
    }
    code
}

/// SIGTERM, then SIGKILL after 5 s.
fn terminate(pid: u32, child: &mut std::process::Child) {
    // SAFETY: a signal to a child of this process.
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(crate::exit::FAILURE)
}

/// Wait until the record of the live instance `name` is ready, and give
/// its ready document.
pub fn wait_ready_record(dir: &Path, name: &str, timeout: Duration) -> Result<serde_json::Value> {
    use crate::exit::{fault, Fault};
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(record) = instances::read(dir, name) {
            if let Some(doc) = record.ready.filter(|_| record.state == "ready") {
                return Ok(doc);
            }
        }
        if !instances::is_alive(dir, name) {
            return Err(fault(
                Fault::Unavailable,
                anyhow::anyhow!("the instance {name} ended before it was ready; see its log"),
            ));
        }
        if Instant::now() >= deadline {
            return Err(fault(
                Fault::Unavailable,
                anyhow::anyhow!(
                    "the instance {name} was not ready in {} s",
                    timeout.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stop the instance `name`: SIGTERM to its supervisor (or to it), wait
/// until its lock is free for `timeout`, then SIGKILL. Remove its record.
pub fn stop(dir: &Path, name: &str, timeout: Duration) -> Result<()> {
    let Some(record) = instances::read(dir, name) else {
        bail!("no instance {name}");
    };
    if !instances::is_alive(dir, name) {
        instances::remove(dir, name);
        return Ok(());
    }
    let pids: Vec<u32> = record.supervisor.into_iter().chain([record.pid]).collect();
    for pid in &pids {
        // SAFETY: a signal to the process that holds the lock of the
        // instance (the lock proves that the record is not stale).
        unsafe { libc::kill(*pid as i32, libc::SIGTERM) };
    }
    let deadline = Instant::now() + timeout;
    while instances::is_alive(dir, name) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if instances::is_alive(dir, name) {
        for pid in &pids {
            // SAFETY: as above.
            unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while instances::is_alive(dir, name) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    instances::remove(dir, name);
    Ok(())
}

mod unix {
    use std::os::fd::AsRawFd;

    /// Close each descriptor from 3; reset the signal mask and the actions
    /// of INT, TERM and QUIT; name the process `cfrs`.
    pub(super) fn prepare() {
        // SAFETY: the system call closes descriptors of this process; no
        // thread runs yet, so no descriptor is in use.
        let closed = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } == 0;
        if !closed {
            let fds: Vec<i32> = std::fs::read_dir("/proc/self/fd")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .filter(|fd| *fd >= 3)
                .collect();
            for fd in fds {
                // SAFETY: as above.
                unsafe { libc::close(fd) };
            }
        }
        // SAFETY: a name of 4 bytes and its NUL; an empty signal set and
        // the default action of three signals, before any thread.
        unsafe {
            libc::prctl(libc::PR_SET_NAME, c"cfrs".as_ptr());
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
                libc::signal(signal, libc::SIG_DFL);
            }
        }
    }

    /// Stdin to `/dev/null`, stderr to the log; `setsid()`, SIGHUP
    /// ignored; `line` to the parent; stdout to the log. Whether the line
    /// went.
    pub(super) fn leave(log: Option<&std::fs::File>, line: &[u8]) -> bool {
        let Ok(null) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
        else {
            return false;
        };
        let sink = log.map_or(null.as_raw_fd(), |f| f.as_raw_fd());
        // SAFETY: dup2 of open files onto the standard descriptors of this
        // process; setsid has no precondition (a child is not the leader
        // of a group); the action of SIGHUP.
        unsafe {
            libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO);
            libc::dup2(sink, libc::STDERR_FILENO);
            libc::setsid();
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
        let said = write_all(libc::STDOUT_FILENO, line);
        // SAFETY: as above.
        unsafe { libc::dup2(sink, libc::STDOUT_FILENO) };
        said
    }

    fn write_all(fd: i32, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            // SAFETY: a write of a live slice to a descriptor of this process.
            let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if n <= 0 {
                return false;
            }
            bytes = &bytes[n as usize..];
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_detach_options_are_not_in_the_hash() {
        let args: Vec<String> = [
            "tunnel",
            "--detach",
            "--name",
            "web",
            "--ready-timeout=30",
            "--port",
            "3000",
            "--replace",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            without_detach_options(&args),
            vec!["tunnel", "--port", "3000"]
        );
    }

    #[test]
    fn default_names() {
        assert_eq!(default_name("tunnel", "0123456789abcdef"), "tunnel-012345");
        assert_eq!(
            default_name("warp proxy", "abcdef0123"),
            "warp-proxy-abcdef"
        );
        instances::check_name(&default_name("net switch", "ffffffffffffffff")).unwrap();
    }
}
