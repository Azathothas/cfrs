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
/// The first argument of the supervisor of a detached child (issue 73).
pub const SUPERVISE_FLAG: &str = "--detach-supervise";
/// Set for the child of a supervisor.
pub const SUPERVISED_VARIABLE: &str = "CFRS_DETACH_SUPERVISED";
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
    /// Run a supervisor that starts the instance again after it ends.
    pub restart: bool,
}

/// At the start of `main`, before any thread: with [`CHILD_FLAG`] after
/// the binary, remove it, close each inherited descriptor from 3, and reset
/// the signals. Gives the arguments with no flag.
pub fn prepare(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.get(1).is_some_and(|a| a == SUPERVISE_FLAG) {
        args.remove(1);
        unix::prepare();
        std::process::exit(supervise::run(&args));
    }
    if args.get(1).is_some_and(|a| a == CHILD_FLAG) {
        args.remove(1);
        CHILD.store(true, Ordering::SeqCst);
        unix::prepare();
    }
    args
}

/// Set when a command is ready, or when it first waits for a stop signal:
/// from then on SIGINT, SIGTERM and SIGHUP start its clean shutdown. Before
/// it, each has its default action.
static STOP_ARMED: AtomicBool = AtomicBool::new(false);

/// From now on, a stop signal starts the clean shutdown.
pub fn arm_stop() {
    STOP_ARMED.store(true, Ordering::SeqCst);
}

/// Whether a stop signal starts the clean shutdown ([`arm_stop`]).
pub fn stop_armed() -> bool {
    STOP_ARMED.load(Ordering::SeqCst)
}

/// Whether this process is a detached child (before or after its ready).
pub fn is_child() -> bool {
    CHILD.load(Ordering::SeqCst)
}

/// Change the record of this child (a no-op for another process). The
/// record on disk goes first: the supervisor writes it too.
fn update_record(change: impl FnOnce(&mut Record)) {
    if !is_child() {
        return;
    }
    let guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(state) = guard.as_ref() else {
        return;
    };
    let mut record =
        instances::read(&state.dir, &state.record.name).unwrap_or_else(|| state.record.clone());
    change(&mut record);
    let _ = instances::write(&state.dir, &record);
}

/// The end of a detached child is planned (issue 195: `--stop-after`,
/// `--idle-secs`, `--run-for`): the record says `done`, and the supervisor
/// does not start it again. A no-op for another process.
pub fn planned_end() {
    update_record(|r| r.state = "done".into());
}

/// The child asks to wait `secs` before its next start (issues 182 and
/// 210: the Retry-After of a refused provision). A no-op for another
/// process.
pub fn retry_after(secs: u64) {
    update_record(|r| r.retry_after_s = Some(secs));
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
    let supervised = std::env::var_os(SUPERVISED_VARIABLE).is_some();
    let lock_path = if supervised {
        &paths.child_lock
    } else {
        &paths.lock
    };
    let lock = instances::try_lock(lock_path)?
        .with_context(|| format!("the instance {name} runs already"))?;
    if supervised {
        // The supervisor wrote the record: keep its pid, its start and the
        // count of restarts.
        if let Some(mut record) = instances::read(&dir, &name) {
            record.pid = std::process::id();
            record.state = "starting".into();
            instances::write(&dir, &record)?;
            begin_log(&paths.log, &name);
            *STATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(ChildState {
                dir,
                record,
                _lock: lock,
            });
            return Ok(());
        }
    }
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
        retry_after_s: None,
    };
    instances::write(&dir, &record)?;
    begin_log(&paths.log, &name);
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(ChildState {
        dir,
        record,
        _lock: lock,
    });
    Ok(())
}

/// The start of an instance in its log (issue 103): a separator line with
/// the time and the pid, and from now on each log line goes to the log too
/// (before, the lines before the ready went only to the starter, and the log
/// showed the lines of an earlier run).
fn begin_log(path: &Path, name: &str) {
    use std::io::Write as _;
    let Ok(mut file) = open_private(path) else {
        return;
    };
    let _ = writeln!(
        file,
        "cfrs: ---- start {} pid {} name {name} ----",
        crate::trust::imf_fixdate(std::time::SystemTime::now()),
        std::process::id()
    );
    crate::report::set_log_tee(file);
}

/// The command is ready, with `doc` (a JSON object: `url`, or `listen`, and
/// more). In a detached child, the first call leaves the terminal of the
/// caller and sends the ready line; each other call, and a call in a
/// process that is not a detached child, does nothing.
pub fn ready(mut doc: serde_json::Value) {
    arm_stop();
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
    // From the leave on, stderr is the log itself.
    crate::report::clear_log_tee();
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
        cmd.arg(if options.restart {
            SUPERVISE_FLAG
        } else {
            CHILD_FLAG
        })
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
                // Issue 210: 124, as timeout(1); 75 is a refusal for now.
                return crate::exit::TIMEOUT;
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
    // A pid gets a signal only while its process holds its lock: a pid of
    // the record can belong to another process after a crash.
    let p = instances::paths(dir, name);
    let held = |lock: &Path| matches!(instances::try_lock(lock), Ok(None));
    let targets = || -> Vec<u32> {
        match record.supervisor {
            Some(sup) if held(&p.lock) => vec![sup],
            Some(_) if held(&p.child_lock) && record.pid != 0 => vec![record.pid],
            None if held(&p.lock) && record.pid != 0 => vec![record.pid],
            _ => Vec::new(),
        }
    };
    // With a supervisor, only the supervisor gets SIGTERM: it stops its
    // child, and does not start it again.
    for pid in targets() {
        // SAFETY: a signal to a process that holds a lock of the instance.
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }
    let deadline = Instant::now() + timeout;
    while instances::is_alive(dir, name) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if instances::is_alive(dir, name) {
        // The record now has the pid of a child that the supervisor
        // started again, if it did.
        let record = instances::read(dir, name).unwrap_or(record.clone());
        let mut pids = Vec::new();
        if record.supervisor.is_some() && held(&p.lock) {
            pids.extend(record.supervisor);
        }
        if record.pid != 0
            && (held(&p.child_lock) || (record.supervisor.is_none() && held(&p.lock)))
        {
            pids.push(record.pid);
        }
        for pid in pids {
            // SAFETY: as above.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while instances::is_alive(dir, name) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    instances::remove(dir, name);
    Ok(())
}

/// The supervisor of a detached child (issue 73). It has no async runtime.
mod supervise {
    use super::*;
    use std::sync::atomic::AtomicBool;

    static STOP: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_stop(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }

    /// Exit codes after which the supervisor does not start the child
    /// again: a bad command line, a bad configuration.
    pub(super) const FINAL: [i32; 2] = [crate::exit::USAGE, crate::exit::CONFIG];
    /// A run this long resets the backoff.
    const STABLE: Duration = Duration::from_secs(30);
    /// A run shorter than this is a quick failure.
    const QUICK: Duration = Duration::from_secs(10);
    /// After this many quick failures in sequence, run the kept binary.
    const QUICK_LIMIT: u32 = 5;

    /// The wait before the next start: the backoff, or the Retry-After that
    /// the child asked for when it is longer (at most 1 h).
    pub(super) fn next_wait(backoff: Duration, asked: Option<u64>) -> Duration {
        match asked {
            Some(secs) => backoff.max(Duration::from_secs(secs.min(3600))),
            None => backoff,
        }
    }

    /// The next delay: twice the delay, at most 30 s.
    pub(super) fn next_backoff(delay: Duration) -> Duration {
        (delay * 2).min(Duration::from_secs(30))
    }

    /// A factor from 0.5 to 1.5, from the clock.
    fn jitter() -> f64 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        0.5 + (nanos % 1000) as f64 / 1000.0
    }

    fn note(text: &str) {
        eprintln!("cfrs: supervisor: {text}");
    }

    pub(super) fn run(args: &[OsString]) -> i32 {
        match run_inner(args) {
            Ok(code) => code,
            Err(err) => {
                note(&format!("{err:#}"));
                TEMPFAIL
            }
        }
    }

    fn run_inner(args: &[OsString]) -> Result<i32> {
        let name = std::env::var(NAME_VARIABLE).context("a supervisor with no instance name")?;
        instances::check_name(&name)?;
        let dir = instances::run_dir()?;
        let paths = instances::paths(&dir, &name);
        let _lock = instances::try_lock(&paths.lock)?
            .with_context(|| format!("the instance {name} runs already"))?;
        // SAFETY: a handler that only stores to an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_stop as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut action.sa_mask);
            for signal in [libc::SIGTERM, libc::SIGINT] {
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
        }
        let child_args: Vec<OsString> = args.iter().skip(1).cloned().collect();
        let mut record = Record {
            name: name.clone(),
            pid: 0,
            supervisor: Some(std::process::id()),
            started: instances::now(),
            command: std::env::var(COMMAND_VARIABLE).unwrap_or_default(),
            args: child_args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
            hash: std::env::var(HASH_VARIABLE).unwrap_or_default(),
            cwd: std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
            state: "starting".into(),
            ready: None,
            log: paths.log.display().to_string(),
            restarts: 0,
            retry_after_s: None,
        };
        instances::write(&dir, &record)?;
        let current = binaries()
            .into_iter()
            .next()
            .context("no path of this binary")?;
        let previous = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| crate::update::previous_of(&p))
            .filter(|p| p.exists());
        let mut program = current;
        let mut ready_seen = false;
        let mut delay = Duration::from_secs(1);
        let mut quick = 0u32;
        loop {
            let mut cmd = Command::new(&program);
            {
                use std::os::unix::process::CommandExt;
                cmd.arg0("cfrs");
            }
            cmd.arg(CHILD_FLAG)
                .args(&child_args)
                .env(SUPERVISED_VARIABLE, "1")
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            let mut child = cmd
                .spawn()
                .with_context(|| format!("starting {}", program.display()))?;
            let started = Instant::now();
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            if let Some(stdout) = child.stdout.take() {
                std::thread::spawn(move || {
                    for line in BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                });
            }
            let status = loop {
                if STOP.load(Ordering::SeqCst) {
                    stop_child(&mut child);
                    instances::remove(&dir, &name);
                    return Ok(0);
                }
                while let Ok(line) = rx.try_recv() {
                    if line.starts_with(READY) {
                        if !ready_seen {
                            ready_seen = true;
                            // The supervisor leaves the terminal too, and
                            // passes the ready line to the parent.
                            let log = open_private(&paths.log).ok();
                            if !unix::leave(log.as_ref(), format!("{line}\n").as_bytes()) {
                                stop_child(&mut child);
                                instances::remove(&dir, &name);
                                return Ok(TEMPFAIL);
                            }
                        } else {
                            note(&format!("ready again: {}", line.trim_start_matches(READY)));
                        }
                    } else {
                        println!("{line}");
                    }
                }
                if let Ok(Some(status)) = child.try_wait() {
                    break status;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            // The lines that came before the end.
            while let Ok(line) = rx.try_recv() {
                if !line.starts_with(READY) {
                    println!("{line}");
                }
            }
            let code = code_of(status);
            // Issues 195, 182 and 210: what the child said of its end.
            let said = instances::read(&dir, &name);
            if ready_seen && code == 0 && said.as_ref().is_some_and(|r| r.state == "done") {
                note("the instance ended on request (--stop-after, --idle-secs or --run-for); it is not started again");
                instances::remove(&dir, &name);
                return Ok(0);
            }
            let asked = said.as_ref().and_then(|r| r.retry_after_s);
            if !ready_seen {
                // The first run ended before it was ready: the parent gets
                // its code.
                instances::remove(&dir, &name);
                return Ok(code);
            }
            if FINAL.contains(&code) {
                note(&format!(
                    "the instance exited {code}; it is not started again"
                ));
                instances::remove(&dir, &name);
                return Ok(code);
            }
            if STOP.load(Ordering::SeqCst) {
                instances::remove(&dir, &name);
                return Ok(0);
            }
            let ran = started.elapsed();
            if ran >= STABLE {
                delay = Duration::from_secs(1);
                quick = 0;
            } else if ran < QUICK && asked.is_none() {
                // A refusal with a Retry-After is not a quick failure: it
                // must not swap to the kept binary (issue 182).
                quick += 1;
            }
            if quick >= QUICK_LIMIT {
                if let Some(prev) = previous.as_ref().filter(|p| **p != program) {
                    note(&format!(
                        "{quick} quick failures in sequence: the kept binary {} runs now",
                        prev.display()
                    ));
                    program = prev.clone();
                    quick = 0;
                }
            }
            record = instances::read(&dir, &name).unwrap_or(record);
            record.restarts += 1;
            record.pid = 0;
            record.state = "restarting".into();
            record.retry_after_s = None;
            instances::write(&dir, &record)?;
            let wait = next_wait(delay.mul_f64(jitter()), asked);
            note(&format!(
                "the instance exited {code} after {} s; start {} in {} ms",
                ran.as_secs(),
                record.restarts,
                wait.as_millis()
            ));
            let until = Instant::now() + wait;
            while Instant::now() < until {
                if STOP.load(Ordering::SeqCst) {
                    instances::remove(&dir, &name);
                    return Ok(0);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            delay = next_backoff(delay);
        }
    }

    /// SIGTERM to the child, SIGKILL after 10 s.
    fn stop_child(child: &mut std::process::Child) {
        // SAFETY: a signal to a child of this process.
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
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
    fn the_backoff_doubles_to_30_s() {
        let mut delay = Duration::from_secs(1);
        let mut seen = Vec::new();
        for _ in 0..7 {
            seen.push(delay.as_secs());
            delay = supervise::next_backoff(delay);
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(supervise::FINAL, [64, 78]);
    }

    /// Issues 182 and 210: a Retry-After of the child is the wait when it is
    /// longer than the backoff, at most 1 h.
    #[test]
    fn the_wait_honours_a_retry_after() {
        let backoff = Duration::from_secs(4);
        assert_eq!(supervise::next_wait(backoff, None), backoff);
        assert_eq!(supervise::next_wait(backoff, Some(1)), backoff);
        assert_eq!(
            supervise::next_wait(backoff, Some(1379)),
            Duration::from_secs(1379)
        );
        assert_eq!(
            supervise::next_wait(backoff, Some(99_999)),
            Duration::from_secs(3600)
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
