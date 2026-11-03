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
}

pub fn paths(dir: &Path, name: &str) -> Paths {
    Paths {
        record: dir.join(format!("{name}.json")),
        lock: dir.join(format!("{name}.lock")),
        child_lock: dir.join(format!("{name}.child.lock")),
        start: dir.join(format!("{name}.start")),
        log: dir.join(format!("{name}.log")),
    }
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
}

/// Read the record of `name`, if there is one that parses.
pub fn read(dir: &Path, name: &str) -> Option<Record> {
    let text = std::fs::read_to_string(paths(dir, name).record).ok()?;
    serde_json::from_str(&text).ok()
}

/// Write the record (mode 0600) with a rename, so a reader never sees half.
pub fn write(dir: &Path, record: &Record) -> Result<()> {
    use std::io::Write as _;
    let path = paths(dir, &record.name).record;
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

/// An exclusive `flock` that this process holds until the value is dropped
/// (or the process ends).
#[derive(Debug)]
pub struct Held(File);

impl Held {
    /// The file descriptor, which must stay open (a detached child keeps it
    /// across its start).
    pub fn fd(&self) -> i32 {
        self.0.as_raw_fd()
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
        return Ok(Some(Held(file)));
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
            return Ok(Held(file));
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
pub fn is_alive(dir: &Path, name: &str) -> bool {
    let p = paths(dir, name);
    [p.lock, p.child_lock]
        .iter()
        .any(|lock| matches!(try_lock(lock), Ok(None)))
}

/// Remove the files of `name` (not the log, which can tell why it ended).
pub fn remove(dir: &Path, name: &str) {
    let p = paths(dir, name);
    let _ = std::fs::remove_file(p.record);
    let _ = std::fs::remove_file(p.lock);
    let _ = std::fs::remove_file(p.child_lock);
}

/// One instance of [`list`].
#[derive(Clone, Debug)]
pub struct Entry {
    pub record: Record,
    pub alive: bool,
}

/// The instances of `dir`, by name. A record whose lock nobody holds is
/// stale: it is removed, and it is not in the list.
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
            continue;
        };
        if is_alive(dir, &name) {
            out.push(Entry {
                record,
                alive: true,
            });
        } else {
            remove(dir, &name);
        }
    }
    out
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
    fn a_held_lock_is_alive_and_a_free_lock_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let record = Record {
            name: "t".into(),
            pid: std::process::id(),
            state: "ready".into(),
            ..Record::default()
        };
        write(dir.path(), &record).unwrap();
        let held = try_lock(&paths(dir.path(), "t").lock).unwrap().unwrap();
        assert!(is_alive(dir.path(), "t"));
        assert!(try_lock(&paths(dir.path(), "t").lock).unwrap().is_none());
        let listed = list(dir.path());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].record, record);
        drop(held);
        assert!(!is_alive(dir.path(), "t"));
        assert!(list(dir.path()).is_empty(), "a stale record is removed");
        assert!(read(dir.path(), "t").is_none());
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
        let mode = std::fs::metadata(paths(dir.path(), "p").record)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
