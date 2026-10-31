//! Where cfrs keeps its files: the WARP identity, and the shims that it
//! builds.
//!
//! The state directory is the first of these that cfrs can create and write:
//!
//! 1. `CFRS_STATE_DIR` (only this one when it is set; `none` keeps no file);
//! 2. `$XDG_STATE_HOME/cfrs`;
//! 3. `$HOME/.local/state/cfrs`;
//! 4. `$XDG_RUNTIME_DIR/cfrs`;
//! 5. `cfrs-<uid>` in the temporary directory.
//!
//! cfrs never takes the current directory unless the user names it. Each
//! directory is made with mode 0700. A directory of the temporary directory
//! that belongs to another user, or that other users can write, is refused.
//! cfrs reads the home only from `HOME`, never from the user database, so a
//! uid with no passwd entry works.

use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};

/// The variable that names the state directory.
pub const STATE_DIR_VARIABLE: &str = "CFRS_STATE_DIR";

/// The candidates, with the name of their source, from the variables of
/// `env`.
pub fn candidates(env: &dyn Fn(&str) -> Option<OsString>) -> Option<Vec<(String, PathBuf)>> {
    let var = |key: &str| env(key).filter(|v| !v.is_empty());
    if let Some(dir) = var(STATE_DIR_VARIABLE) {
        if dir == "none" {
            return None;
        }
        return Some(vec![(STATE_DIR_VARIABLE.to_string(), PathBuf::from(dir))]);
    }
    let mut out = Vec::new();
    if let Some(dir) = var("XDG_STATE_HOME") {
        out.push((
            "$XDG_STATE_HOME".to_string(),
            PathBuf::from(dir).join("cfrs"),
        ));
    }
    if let Some(home) = var("HOME") {
        out.push((
            "$HOME".to_string(),
            PathBuf::from(home).join(".local/state/cfrs"),
        ));
    }
    if let Some(dir) = var("XDG_RUNTIME_DIR") {
        out.push((
            "$XDG_RUNTIME_DIR".to_string(),
            PathBuf::from(dir).join("cfrs"),
        ));
    }
    let tmp = var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let uid = unsafe { libc::geteuid() };
    out.push((
        "the temporary directory".to_string(),
        tmp.join(format!("cfrs-{uid}")),
    ));
    Some(out)
}

/// The state directory of this process, or `None` with `CFRS_STATE_DIR=none`.
/// The error names each path that cfrs tried, and why it failed.
pub fn state_dir() -> Result<Option<PathBuf>> {
    choose(&|key| std::env::var_os(key))
}

/// [`state_dir`] with the variables of `env`.
pub fn choose(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Option<PathBuf>> {
    let Some(candidates) = candidates(env) else {
        return Ok(None);
    };
    let mut failures = Vec::new();
    for (source, dir) in candidates {
        match prepare(&dir) {
            Ok(()) => return Ok(Some(dir)),
            Err(err) => failures.push(format!("{} ({source}): {err:#}", dir.display())),
        }
    }
    bail!(
        "no state directory can be written; set {STATE_DIR_VARIABLE} to a directory, or to none to keep no file. Tried: {}",
        failures.join("; ")
    )
}

/// Make `dir` (mode 0700), check its owner and its mode, and write a file
/// in it.
pub fn prepare(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .context("making the directory")?;
    let meta = std::fs::metadata(dir).context("reading the directory")?;
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        bail!(
            "the directory belongs to user {}, not to this user ({uid})",
            meta.uid()
        );
    }
    if meta.mode() & 0o022 != 0 {
        bail!(
            "other users can write the directory (mode {:04o})",
            meta.mode() & 0o7777
        );
    }
    writable(dir)
}

/// Write and remove a file in `dir`.
pub fn writable(dir: &Path) -> Result<()> {
    let probe = dir.join(format!(".cfrs-probe-{}", std::process::id()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .context("writing a file")?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Check that cfrs can write the file `path` later: its directory can be
/// made and written. Call it before work that the file must keep (a WARP
/// registration), so that a failure costs nothing.
pub fn check_file_writable(path: &Path) -> Result<()> {
    let dir = match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir,
        None => Path::new("."),
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .and_then(|_| writable(dir).map_err(std::io::Error::other))
        .with_context(|| format!("{} cannot be written", dir.display()))
}

/// True when the file system of `dir` lets cfrs run or map code from it
/// (no `noexec` mount).
pub fn allows_exec(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return false;
    }
    st.f_flag & libc::ST_NOEXEC == 0
}

/// A directory for a file that must run or be loaded (a shim), named
/// `name`: the first of the temporary directory, the state directory and
/// `$XDG_RUNTIME_DIR` that is writable and not `noexec`.
pub fn exec_dir(name: &str) -> Result<PathBuf> {
    let mut tried = Vec::new();
    let mut candidates = vec![std::env::temp_dir().join(name)];
    if let Ok(Some(state)) = state_dir() {
        candidates.push(state.join(name));
    }
    if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        candidates.push(PathBuf::from(run).join(name));
    }
    for dir in candidates {
        if let Err(err) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
        {
            tried.push(format!("{}: {err}", dir.display()));
            continue;
        }
        if !allows_exec(&dir) {
            tried.push(format!("{}: the file system is noexec", dir.display()));
            continue;
        }
        if let Err(err) = writable(&dir) {
            tried.push(format!("{}: {err:#}", dir.display()));
            continue;
        }
        return Ok(dir);
    }
    bail!(
        "no directory can hold a shim: {}; use --out",
        tried.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn with_no_home_the_chain_uses_the_temporary_directory() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().to_str().unwrap();
        let chosen = choose(&env(&[("TMPDIR", tmp)])).unwrap().unwrap();
        assert!(chosen.starts_with(tmp), "{}", chosen.display());
        assert!(chosen
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("cfrs-"));
        let cwd = std::env::current_dir().unwrap();
        assert!(!chosen.starts_with(&cwd) || cwd.starts_with(tmp));
        let mode = std::fs::metadata(&chosen).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn the_order_of_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let state = format!("{base}/state");
        let home = format!("{base}/home");
        let chosen = choose(&env(&[("XDG_STATE_HOME", &state), ("HOME", &home)]))
            .unwrap()
            .unwrap();
        assert_eq!(chosen, PathBuf::from(&state).join("cfrs"));
        let chosen = choose(&env(&[("HOME", &home)])).unwrap().unwrap();
        assert_eq!(chosen, PathBuf::from(&home).join(".local/state/cfrs"));
        let own = format!("{base}/own");
        let chosen = choose(&env(&[(STATE_DIR_VARIABLE, &own), ("HOME", &home)]))
            .unwrap()
            .unwrap();
        assert_eq!(chosen, PathBuf::from(&own));
    }

    #[test]
    fn none_keeps_no_file() {
        assert_eq!(
            choose(&env(&[(STATE_DIR_VARIABLE, "none"), ("HOME", "/")])).unwrap(),
            None
        );
    }

    /// A path under a file cannot be a directory, also for root. The error
    /// names each path.
    #[test]
    fn with_no_writable_candidate_the_error_names_each_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"").unwrap();
        let f = file.to_str().unwrap();
        let err = choose(&env(&[
            ("XDG_STATE_HOME", f),
            ("HOME", f),
            ("XDG_RUNTIME_DIR", f),
            ("TMPDIR", f),
        ]))
        .unwrap_err()
        .to_string();
        for want in [
            "$XDG_STATE_HOME",
            "$HOME",
            "$XDG_RUNTIME_DIR",
            "the temporary directory",
            "CFRS_STATE_DIR",
        ] {
            assert!(err.contains(want), "{want} is not in: {err}");
        }
    }

    #[test]
    fn a_directory_that_others_can_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = prepare(&open).unwrap_err().to_string();
        assert!(err.contains("other users can write"), "{err}");
    }

    #[test]
    fn a_file_that_must_be_written_later_is_checked_first() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"").unwrap();
        assert!(check_file_writable(&file.join("warp.json")).is_err());
        assert!(check_file_writable(&dir.path().join("new/warp.json")).is_ok());
    }

    #[test]
    fn the_temporary_directory_allows_exec_here() {
        // The test only reads the flag; a noexec /tmp makes exec_dir go on.
        let _ = allows_exec(&std::env::temp_dir());
        assert!(!allows_exec(Path::new("/no/such/dir")));
    }
}
