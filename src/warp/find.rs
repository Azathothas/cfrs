//! Find the socket of a running `podnet warp up` (T-070).
//!
//! `warp exec`, `warp shell`, `warp nc` and the agent try these sockets, in
//! this order, and take the first that answers:
//!
//! 1. `--socket PATH` (when it is given, no other socket is tried);
//! 2. `PODNET_WARP_SOCKET`;
//! 3. `warp.sock` in the run directory of this process;
//! 4. the socket of the pointer file that `warp up` writes at a fixed place
//!    of the user: `$XDG_RUNTIME_DIR/podnet/warp-up.json`, else
//!    `podnet-<uid>/warp-up.json` in the temporary directory.
//!
//! The pointer file has mode 0600 in a directory of mode 0700, and podnet
//! reads it only when this user owns it. It names the socket and the state
//! directory of `warp up`, so that a `warp up` with another state directory
//! is found.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The variable that names the socket of the running `podnet warp up`.
pub const SOCKET_VARIABLE: &str = "PODNET_WARP_SOCKET";

/// The option `--socket` of `warp exec`, `warp shell` and `warp nc`.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct At {
    /// The socket of the running podnet warp up. Without it: PODNET_WARP_SOCKET,
    /// warp.sock in the run directory, then the pointer file that podnet warp up
    /// writes ($XDG_RUNTIME_DIR/podnet/warp-up.json, else podnet-<uid> in the
    /// temporary directory)
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

/// The pointer file of `podnet warp up`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pointer {
    /// The unix socket of the proxy.
    pub socket: PathBuf,
    /// The state directory of `warp up`, when it has one.
    pub state_dir: Option<PathBuf>,
}

/// The directory of the pointer file: `$XDG_RUNTIME_DIR/podnet`, else
/// `podnet-<uid>` in the temporary directory. It does not depend on the
/// state directory.
pub fn pointer_dir() -> PathBuf {
    pointer_dir_of(
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        std::env::temp_dir(),
    )
}

fn pointer_dir_of(runtime: Option<PathBuf>, temp: PathBuf) -> PathBuf {
    match runtime.filter(|r| !r.as_os_str().is_empty() && r.is_dir()) {
        Some(runtime) => runtime.join("podnet"),
        None => temp.join(format!("podnet-{}", unsafe { libc::geteuid() })),
    }
}

/// The path of the pointer file.
pub fn pointer_path() -> PathBuf {
    pointer_dir().join("warp-up.json")
}

/// Write the pointer file for `socket` (mode 0600, directory mode 0700).
pub fn write_pointer(socket: &Path) -> Result<()> {
    let dir = pointer_dir();
    crate::state::prepare(&dir)?;
    let pointer = Pointer {
        socket: socket.to_path_buf(),
        state_dir: crate::state::state_dir().ok().flatten(),
    };
    crate::warp::write_private(&dir.join("warp-up.json"), &serde_json::to_vec(&pointer)?)?;
    Ok(())
}

/// Read the pointer file: none when it is missing, when another user owns
/// it, or when other users can read or write it.
pub fn read_pointer() -> Option<Pointer> {
    read_pointer_at(&pointer_path())
}

fn read_pointer_at(path: &Path) -> Option<Pointer> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Remove the pointer file when it names `socket`.
pub fn remove_pointer(socket: &Path) {
    if read_pointer().is_some_and(|p| p.socket == socket) {
        let _ = std::fs::remove_file(pointer_path());
    }
}

/// The sockets to try, in order, each with where it came from.
pub fn candidates(at: &At) -> Vec<(&'static str, PathBuf)> {
    candidates_of(
        at,
        std::env::var_os(SOCKET_VARIABLE).map(PathBuf::from),
        crate::instances::run_dir().ok(),
        read_pointer(),
    )
}

fn candidates_of(
    at: &At,
    variable: Option<PathBuf>,
    run_dir: Option<PathBuf>,
    pointer: Option<Pointer>,
) -> Vec<(&'static str, PathBuf)> {
    if let Some(socket) = &at.socket {
        return vec![("--socket", socket.clone())];
    }
    let mut out: Vec<(&'static str, PathBuf)> = Vec::new();
    let mut add = |from, path: PathBuf| {
        if !path.as_os_str().is_empty() && !out.iter().any(|(_, p)| *p == path) {
            out.push((from, path));
        }
    };
    if let Some(path) = variable {
        add(SOCKET_VARIABLE, path);
    }
    if let Some(dir) = run_dir {
        add("the run directory", dir.join("warp.sock"));
    }
    if let Some(pointer) = pointer {
        add("the pointer file", pointer.socket);
    }
    out
}

fn answers(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// The socket of the running `podnet warp up`: the first candidate that
/// answers. Else an error (exit 69) that names each socket tried, and the
/// state directory of the pointer file.
pub fn running(at: &At) -> Result<PathBuf> {
    let tried = candidates(at);
    if let Some((_, socket)) = tried.iter().find(|(_, s)| answers(s)) {
        return Ok(socket.clone());
    }
    Err(crate::exit::fault(
        crate::exit::Fault::Unavailable,
        anyhow::anyhow!(not_running(&tried, read_pointer().as_ref())),
    ))
}

/// The text of the error when no socket answers.
fn not_running(tried: &[(&'static str, PathBuf)], pointer: Option<&Pointer>) -> String {
    let mut text = String::from("podnet warp up is not running (no answer on ");
    if tried.is_empty() {
        text.push_str("any socket: no run directory");
    }
    let list: Vec<String> = tried
        .iter()
        .map(|(from, p)| format!("{} ({from})", p.display()))
        .collect();
    text.push_str(&list.join(", "));
    text.push_str("); start it with: podnet warp up");
    if let Some(dir) = pointer.and_then(|p| p.state_dir.as_ref()) {
        text.push_str(&format!(
            "; the last podnet warp up had the state directory {} (PODNET_STATE_DIR)",
            dir.display()
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn the_lookup_order_of_the_warp_socket() {
        let pointer = Pointer {
            socket: p("/other/run/warp.sock"),
            state_dir: Some(p("/other")),
        };
        let all = candidates_of(
            &At::default(),
            Some(p("/v/warp.sock")),
            Some(p("/run")),
            Some(pointer.clone()),
        );
        assert_eq!(
            all,
            [
                (SOCKET_VARIABLE, p("/v/warp.sock")),
                ("the run directory", p("/run/warp.sock")),
                ("the pointer file", p("/other/run/warp.sock")),
            ]
        );
        // --socket alone.
        let at = At {
            socket: Some(p("/s.sock")),
        };
        let only = candidates_of(&at, Some(p("/v")), Some(p("/run")), Some(pointer));
        assert_eq!(only, [("--socket", p("/s.sock"))]);
        // A path is tried one time; an empty variable is no path.
        let same = Pointer {
            socket: p("/run/warp.sock"),
            state_dir: None,
        };
        let two = candidates_of(&At::default(), Some(p("")), Some(p("/run")), Some(same));
        assert_eq!(two, [("the run directory", p("/run/warp.sock"))]);
    }

    #[test]
    fn the_pointer_dir_does_not_depend_on_the_state_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        std::fs::create_dir(&rt).unwrap();
        assert_eq!(
            pointer_dir_of(Some(rt.clone()), p("/tmp")),
            rt.join("podnet")
        );
        let uid = unsafe { libc::geteuid() };
        let want = p("/tmp").join(format!("podnet-{uid}"));
        assert_eq!(pointer_dir_of(None, p("/tmp")), want);
        // A runtime directory that does not exist is not used.
        assert_eq!(pointer_dir_of(Some(tmp.path().join("no")), p("/tmp")), want);
    }

    #[test]
    fn a_pointer_file_that_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("warp-up.json");
        let pointer = Pointer {
            socket: p("/r/warp.sock"),
            state_dir: Some(p("/s")),
        };
        crate::warp::write_private(&path, &serde_json::to_vec(&pointer).unwrap()).unwrap();
        assert_eq!(read_pointer_at(&path), Some(pointer));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_pointer_at(&path), None);
    }

    #[test]
    fn warp_exec_finds_warp_up_of_another_state_directory() {
        // A listener stands in for the socket of a `warp up` with another
        // state directory: only the pointer file names it.
        let tmp = tempfile::tempdir().unwrap();
        let other = tmp.path().join("other-run/warp.sock");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&other).unwrap();
        let pointer = Pointer {
            socket: other.clone(),
            state_dir: Some(tmp.path().join("other")),
        };
        let tried = candidates_of(
            &At::default(),
            None,
            Some(tmp.path().join("own-run")),
            Some(pointer.clone()),
        );
        let found = tried.iter().find(|(_, s)| answers(s)).map(|(_, s)| s);
        assert_eq!(found, Some(&other));
        // With no answer, the error names each socket and the state
        // directory of the pointer file.
        drop(_listener);
        std::fs::remove_file(&other).unwrap();
        assert!(!tried.iter().any(|(_, s)| answers(s)));
        let text = not_running(&tried, Some(&pointer));
        assert!(
            text.contains("own-run/warp.sock (the run directory)"),
            "{text}"
        );
        assert!(
            text.contains("other-run/warp.sock (the pointer file)"),
            "{text}"
        );
        assert!(text.contains("other (PODNET_STATE_DIR)"), "{text}");
    }
}
