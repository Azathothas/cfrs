//! The registry of detached instances (`--detach`, issue 71).
//!
//! Each instance has three files in the run directory (mode 0700):
//!
//! * `NAME.json` (mode 0600): the [`Record`]: pids, the command, its
//!   arguments with no secret and their hash, the directory, the state, the
//!   ready document, the log, the restarts.
//! * `NAME.lock`: the instance holds an exclusive `flock` on it while it
//!   runs. An instance is alive when the lock is held; a pid alone is not a
//!   proof (a pid can come again after a reboot).
//! * `NAME.log`: for each start, a separator line (`---- start TIME pid PID
//!   name NAME ----`), the log lines of the instance from its start, and
//!   stdout and stderr after it is ready.
//!
//! `NAME.secrets` (mode 0600), when the instance has a secret (`--token`, a
//! `--proxy` with a user part, or `TUNNEL_TOKEN`): the secret variables, in
//! the text of an autostart env file. `autostart add --from NAME` copies
//! them (issue 265). The record and `ps` never show them (issue 262).
//!
//! `NAME.start` is a second lock: one start at a time for each name, so
//! two starts at the same time give one instance.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};

/// The run directory in place of the default (tests, and hosts with no
/// `XDG_RUNTIME_DIR` and no state directory).
pub const RUN_DIR_VARIABLE: &str = "CFRS_RUN_DIR";

/// The run directory: `CFRS_RUN_DIR`, else `$XDG_RUNTIME_DIR/cfrs/run`
/// (empty after a reboot), else `run` in the state directory. Mode 0700,
/// owned by this user.
pub fn run_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(RUN_DIR_VARIABLE).filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        crate::state::prepare(&dir)
            .with_context(|| format!("{RUN_DIR_VARIABLE}={}", dir.display()))?;
        return Ok(dir);
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(runtime).join("cfrs/run");
        if crate::state::prepare(&dir).is_ok() {
            return Ok(dir);
        }
    }
    let state = crate::state::state_dir()?.context(
        "detached instances need a run directory: set CFRS_RUN_DIR or a state directory",
    )?;
    let dir = state.join("run");
    crate::state::prepare(&dir)?;
    Ok(dir)
}

/// The run directory when it exists, with no directory made (issue 178:
/// `warp status` made it). The candidates of [`run_dir`], in its order.
pub fn existing_run_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::var_os(RUN_DIR_VARIABLE).filter(|v| !v.is_empty()) {
        candidates.push(PathBuf::from(dir));
    } else {
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            candidates.push(PathBuf::from(runtime).join("cfrs/run"));
        }
        if let Ok(Some(dir)) = crate::state::find_existing("run") {
            candidates.push(dir);
        }
    }
    candidates.into_iter().find(|d| d.is_dir())
}

/// The run directory to read (ps, stop, logs, wait, status): the one that
/// exists, or a path that does not exist. A read makes no directory
/// (podssh: status said "writes nothing" and made the run directory).
pub fn lookup_dir() -> PathBuf {
    existing_run_dir().unwrap_or_else(|| {
        std::env::var_os(RUN_DIR_VARIABLE)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nonexistent/cfrs-run"))
    })
}

/// A name is 1 to 32 characters from `A-Z a-z 0-9 _ -`.
pub fn check_name(name: &str) -> Result<()> {
    let good = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !good {
        bail!("the instance name {name:?} must be 1 to 32 characters from A-Z a-z 0-9 _ -");
    }
    Ok(())
}

/// The files of the instance `name` in `dir`.
#[derive(Clone, Debug)]
pub struct Paths {
    pub record: PathBuf,
    /// Held by the supervisor (issue 73), or by an instance with no
    /// supervisor.
    pub lock: PathBuf,
    /// Held by the child of a supervisor.
    pub child_lock: PathBuf,
    pub start: PathBuf,
    pub log: PathBuf,
    /// The secret variables (issue 265).
    pub secrets: PathBuf,
}

/// The files of `name` in `dir`. The name is checked first
/// ([`check_name`]): a name such as `../x` or `/x` must not give a path
/// outside `dir` (issue 260).
pub fn paths(dir: &Path, name: &str) -> Result<Paths> {
    check_name(name)?;
    Ok(Paths {
        record: dir.join(format!("{name}.json")),
        lock: dir.join(format!("{name}.lock")),
        child_lock: dir.join(format!("{name}.child.lock")),
        start: dir.join(format!("{name}.start")),
        log: dir.join(format!("{name}.log")),
        secrets: dir.join(format!("{name}.secrets")),
    })
}

/// The record of an instance.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    /// The process that serves (the child).
    pub pid: u32,
    /// The supervisor (issue 73), when one runs.
    #[serde(default)]
    pub supervisor: Option<u32>,
    /// Unix seconds of the start of this instance.
    pub started: u64,
    /// The command, for example `tunnel` or `warp proxy`.
    pub command: String,
    /// The arguments after the binary, with no secret.
    pub args: Vec<String>,
    /// A hash of the arguments and of the secrets (not the secrets).
    pub hash: String,
    pub cwd: String,
    /// `starting` or `ready`.
    pub state: String,
    /// The ready document, when the instance is ready.
    #[serde(default)]
    pub ready: Option<serde_json::Value>,
    pub log: String,
    #[serde(default)]
    pub restarts: u32,
    /// The wait that the child asks for before its next start (issues 182
    /// and 210: the Retry-After of a refused provision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// Read the record of `name`, if there is one that parses.
pub fn read(dir: &Path, name: &str) -> Option<Record> {
    let text = std::fs::read_to_string(paths(dir, name).ok()?.record).ok()?;
    serde_json::from_str(&text).ok()
}

/// Write the record (mode 0600) with a rename, so a reader never sees half.
pub fn write(dir: &Path, record: &Record) -> Result<()> {
    use std::io::Write as _;
    let path = paths(dir, &record.name)?.record;
    let tmp = dir.join(format!(".{}.json.{}", record.name, std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(serde_json::to_string_pretty(record)?.as_bytes())?;
    file.write_all(b"\n")?;
    drop(file);
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))
}

/// The variables that hold a secret of an instance.
pub const SECRET_VARIABLES: &[&str] = &["TUNNEL_TOKEN", "CFRS_PROXY"];

/// The secret variables of `vars` ([`SECRET_VARIABLES`]).
pub fn secrets_of(vars: &[(String, String)]) -> Vec<(String, String)> {
    vars.iter()
        .filter(|(k, _)| SECRET_VARIABLES.contains(&k.as_str()))
        .cloned()
        .collect()
}

/// The lock files that this process holds, as (device, inode). A lock of
/// this process is not a lock of another instance: [`remove`] can delete
/// it (the end of a registered process, the end of a supervisor).
static OWN: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());

fn id_of(file: &File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    file.metadata().ok().map(|m| (m.dev(), m.ino()))
}

fn own() -> std::sync::MutexGuard<'static, Vec<(u64, u64)>> {
    OWN.lock().unwrap_or_else(|e| e.into_inner())
}

/// Write the secret variables of `name` to `NAME.secrets` (mode 0600, with a
/// rename). With no secret, remove the file.
pub fn write_secrets(dir: &Path, name: &str, secrets: &[(String, String)]) -> Result<()> {
    use std::io::Write as _;
    let path = paths(dir, name)?.secrets;
    if secrets.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let text = crate::autostart::env_text(secrets)?;
    let tmp = dir.join(format!(".{name}.secrets.{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(text.as_bytes())?;
    drop(file);
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))
}

/// The secret variables of `name`; empty when it has none.
pub fn read_secrets(dir: &Path, name: &str) -> Vec<(String, String)> {
    paths(dir, name)
        .ok()
        .and_then(|p| std::fs::read_to_string(p.secrets).ok())
        .map(|text| secrets_of(&crate::autostart::parse_env(&text)))
        .unwrap_or_default()
}

/// An exclusive `flock` that this process holds until the value is dropped
/// (or the process ends).
#[derive(Debug)]
pub struct Held(File);

impl Held {
    fn new(file: File) -> Held {
        if let Some(id) = id_of(&file) {
            own().push(id);
        }
        Held(file)
    }

    /// The file descriptor, which must stay open (a detached child keeps it
    /// across its start).
    pub fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(id) = id_of(&self.0) {
            let mut own = own();
            if let Some(i) = own.iter().position(|x| *x == id) {
                own.swap_remove(i);
            }
        }
    }
}

fn open_lock(path: &Path) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Take the lock of `path` with no wait; `None` when another process holds
/// it.
pub fn try_lock(path: &Path) -> Result<Option<Held>> {
    let file = open_lock(path)?;
    // SAFETY: flock on a descriptor of this process.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(Some(Held::new(file)));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(None);
    }
    Err(err).with_context(|| format!("locking {}", path.display()))
}

/// Take the lock of `path`, and wait for it.
pub fn lock(path: &Path) -> Result<Held> {
    let file = open_lock(path)?;
    loop {
        // SAFETY: flock on a descriptor of this process.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(Held::new(file));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err).with_context(|| format!("locking {}", path.display()));
        }
    }
}

/// Whether a process holds a lock of the instance `name`: the lock of the
/// supervisor, or the lock of its child (a child goes on when its
/// supervisor is killed).
/// It makes no file (issue 266: `cfrs wait NAME` made `NAME.lock` and
/// `NAME.child.lock`).
pub fn is_alive(dir: &Path, name: &str) -> bool {
    let Ok(p) = paths(dir, name) else {
        return false;
    };
    [p.lock, p.child_lock].iter().any(|lock| is_held(lock))
}

/// Whether another process holds the lock of `path`. A missing file is not
/// held, and is not made.
pub fn is_held(path: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) else {
        return false;
    };
    // SAFETY: flock on a descriptor of this process.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        // Free: the lock ends when the file is closed.
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
}

/// The state of one lock file for [`remove`].
enum LockState {
    /// No file.
    Missing,
    /// Nobody else holds it: this process holds it now (`Some`), or held
    /// it before (`None`).
    Free(Option<Held>),
    /// Another process holds it (or it cannot be opened).
    Busy,
}

fn lock_state(path: &Path) -> LockState {
    let file = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return LockState::Missing,
        Err(_) => return LockState::Busy,
    };
    if id_of(&file).is_some_and(|id| own().contains(&id)) {
        return LockState::Free(None);
    }
    // SAFETY: flock on a descriptor of this process.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        LockState::Free(Some(Held::new(file)))
    } else {
        LockState::Busy
    }
}

/// Remove the files of `name` (not the log, which can tell why it ended).
/// A lock that another process holds is never removed (issue 264: `stop`
/// on an unreadable record removed the locks of a live instance, and a
/// second instance could start with the name). Then nothing is removed,
/// and the result is false.
pub fn remove(dir: &Path, name: &str) -> bool {
    let Ok(p) = paths(dir, name) else {
        return false;
    };
    let mut free = Vec::new();
    for lock in [&p.lock, &p.child_lock] {
        match lock_state(lock) {
            LockState::Missing => {}
            LockState::Free(held) => free.push((lock, held)),
            LockState::Busy => return false,
        }
    }
    let _ = std::fs::remove_file(&p.record);
    let _ = std::fs::remove_file(&p.secrets);
    // Each lock is removed while this process holds it.
    for (lock, _held) in &free {
        let _ = std::fs::remove_file(lock);
    }
    true
}

/// One instance of [`list`].
#[derive(Clone, Debug)]
pub struct Entry {
    pub record: Record,
    pub alive: bool,
}

/// The live instances of `dir`, by name. A record whose lock nobody holds
/// is stale: it is not in the list. The list writes nothing (issue 266:
/// `status` and `bug-report` removed files); [`prune`] removes the stale
/// records.
pub fn list(dir: &Path) -> Vec<Entry> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".json")?;
            (!stem.starts_with('.')).then(|| stem.to_string())
        })
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let Some(record) = read(dir, &name) else {
            // Issue 264: a live instance with a record that does not parse
            // is shown (state unknown), not hidden.
            if check_name(&name).is_ok() && is_alive(dir, &name) {
                out.push(Entry {
                    record: Record {
                        name: name.clone(),
                        state: "unknown".into(),
                        ..Record::default()
                    },
                    alive: true,
                });
            }
            continue;
        };
        if is_alive(dir, &name) {
            out.push(Entry {
                record,
                alive: true,
            });
        }
    }
    out
}

/// Remove the files of each stale instance of `dir` (`cfrs ps`).
pub fn prune(dir: &Path) {
    let names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            Some(name.strip_suffix(".json")?.to_string())
        })
        .filter(|name| check_name(name).is_ok())
        .collect();
    for name in names {
        if read(dir, &name).is_some() && !is_alive(dir, &name) {
            remove(dir, &name);
        }
    }
}

/// A short hash (16 hex) of the arguments and of the secret values.
pub fn hash_of(args: &[String], secrets: &[(String, String)]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for arg in args {
        ctx.update(arg.as_bytes());
        ctx.update(&[0]);
    }
    ctx.update(&[1]);
    for (k, v) in secrets {
        ctx.update(k.as_bytes());
        ctx.update(&[0]);
        ctx.update(v.as_bytes());
        ctx.update(&[0]);
    }
    ctx.finish().as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Unix seconds now.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for good in ["a", "tunnel-1", "A_b-9", &"x".repeat(32)] {
            check_name(good).unwrap();
        }
        for bad in ["", "a b", "../x", "x.y", &"x".repeat(33), "é"] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_name_that_leaves_the_directory_gives_no_path() {
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("run");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(dir.path().join("x.json"), "{}").unwrap();
        for bad in ["../x", "/abs/x", "a/b", ".hidden", ""] {
            assert!(paths(&inner, bad).is_err(), "{bad}");
            assert!(read(&inner, bad).is_none(), "{bad}");
            assert!(!is_alive(&inner, bad), "{bad}");
            remove(&inner, bad);
        }
        assert!(
            dir.path().join("x.json").exists(),
            "remove left the outer file"
        );
        assert!(!dir.path().join("x.lock").exists());
        assert!(std::fs::read_dir(&inner).unwrap().next().is_none());
    }

    #[test]
    fn remove_leaves_a_lock_that_another_process_holds() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path(), "h").unwrap();
        std::fs::write(&p.record, "").unwrap();
        std::fs::write(&p.lock, "").unwrap();
        // A lock of another process: a child that holds it.
        let mut child = std::process::Command::new("flock")
            .arg("-o")
            .arg(&p.lock)
            .args(["sleep", "30"])
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while try_lock(&p.lock).unwrap().is_some() {
            assert!(std::time::Instant::now() < until, "the child holds no lock");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!remove(dir.path(), "h"));
        assert!(p.lock.exists(), "a held lock stays");
        assert!(p.record.exists(), "the record of a live instance stays");
        let _ = child.kill();
        let _ = child.wait();
        assert!(remove(dir.path(), "h"));
        assert!(!p.lock.exists());
        assert!(!p.record.exists());
    }

    #[test]
    fn remove_deletes_a_lock_of_this_process() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path(), "o").unwrap();
        let held = try_lock(&p.lock).unwrap().unwrap();
        assert!(remove(dir.path(), "o"));
        assert!(!p.lock.exists());
        drop(held);
    }

    #[test]
    fn is_alive_makes_no_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_alive(dir.path(), "nosuch"));
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_held_lock_is_alive_and_a_free_lock_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let record = Record {
            name: "t".into(),
            pid: std::process::id(),
            state: "ready".into(),
            ..Record::default()
        };
        write(dir.path(), &record).unwrap();
        let held = try_lock(&paths(dir.path(), "t").unwrap().lock)
            .unwrap()
            .unwrap();
        assert!(is_alive(dir.path(), "t"));
        assert!(try_lock(&paths(dir.path(), "t").unwrap().lock)
            .unwrap()
            .is_none());
        let listed = list(dir.path());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].record, record);
        drop(held);
        assert!(!is_alive(dir.path(), "t"));
        assert!(list(dir.path()).is_empty(), "a stale record is not listed");
        assert!(read(dir.path(), "t").is_some(), "list writes nothing");
        prune(dir.path());
        assert!(read(dir.path(), "t").is_none(), "prune removes it");
    }

    #[test]
    fn the_hash_changes_with_the_arguments_and_the_secrets() {
        let a = hash_of(&["tunnel".into(), "--port".into(), "3000".into()], &[]);
        assert_eq!(a.len(), 16);
        assert_eq!(
            a,
            hash_of(&["tunnel".into(), "--port".into(), "3000".into()], &[])
        );
        assert_ne!(
            a,
            hash_of(&["tunnel".into(), "--port".into(), "3001".into()], &[])
        );
        assert_ne!(
            a,
            hash_of(
                &["tunnel".into(), "--port".into(), "3000".into()],
                &[("TUNNEL_TOKEN".into(), "x".into())]
            )
        );
    }

    #[test]
    fn the_record_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            &Record {
                name: "p".into(),
                ..Record::default()
            },
        )
        .unwrap();
        let mode = std::fs::metadata(paths(dir.path(), "p").unwrap().record)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
