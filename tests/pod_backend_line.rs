//! T-071: `warp exec` and `warp shell` take `--backend` and give it to the
//! pod; the pod names the backend in one line on stderr; with `-v`, the
//! seccomp backend logs each socket and each `setsockopt` that it emulates.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn podnet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_podnet"))
}

/// The backends that `podnet pod doctor` finds on this host.
fn backends() -> (bool, bool) {
    let out = podnet().args(["pod", "doctor", "--json"]).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let yes = |key: &str| report[key] == serde_json::Value::Bool(true);
    (yes("backend_netns"), yes("backend_seccomp"))
}

/// A C compiler: `$CC`, then `cc`, `gcc` or `clang` on `PATH`.
fn compiler() -> Option<PathBuf> {
    let mut names: Vec<String> = std::env::var("CC").into_iter().collect();
    names.extend(["cc", "gcc", "clang"].map(String::from));
    let path = std::env::var_os("PATH")?;
    names.iter().find_map(|name| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// A program that makes a TCP socket, sets `TCP_NODELAY` on it, makes a
/// UDP socket of IPv6, and exits 0. It opens no connection.
const CLIENT: &str = r#"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int t = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (t < 0 || setsockopt(t, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) != 0) {
        perror("tcp");
        return 1;
    }
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    if (u < 0) { perror("udp"); return 1; }
    close(t);
    close(u);
    return 0;
}
"#;

fn build(dir: &Path, cc: &Path) -> PathBuf {
    let src = dir.join("client.c");
    std::fs::write(&src, CLIENT).unwrap();
    let out = dir.join("client");
    let status = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap();
    assert!(status.success(), "compiling the client failed");
    out
}

/// A temporary directory with a unix socket that answers (a stand-in of
/// the proxy of `warp up`: no program here opens a connection).
struct Host {
    dir: tempfile::TempDir,
    socket: PathBuf,
    _listener: UnixListener,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("warp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        Host {
            dir,
            socket,
            _listener: listener,
        }
    }

    /// `podnet GLOBAL warp exec --socket S --backend B -- PROGRAM`.
    fn warp_exec(&self, global: &[&str], backend: &str, program: &Path) -> Output {
        let home = self.dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let out = podnet()
            .args(global)
            .args(["warp", "exec", "--socket"])
            .arg(&self.socket)
            .args(["--backend", backend, "--"])
            .arg(program)
            .env("HOME", &home)
            .env("PODNET_STATE_DIR", self.dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", self.dir.path())
            .env_remove("PODNET_WARP_SOCKET")
            .env_remove("PODNET_NETNS_QUIET")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        out
    }

    /// `podnet pod OPTIONS -x unix:S -- PROGRAM`.
    fn pod(&self, options: &[&str], program: &Path) -> Output {
        let out = podnet()
            .arg("pod")
            .args(options)
            .arg("-x")
            .arg(format!("unix:{}", self.socket.display()))
            .arg("--")
            .arg(program)
            .env_remove("PODNET_NETNS_QUIET")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        out
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The lines of stderr that name a backend.
fn backend_lines(out: &Output) -> Vec<String> {
    stderr(out)
        .lines()
        .filter(|l| l.contains(" backend: "))
        .map(String::from)
        .collect()
}

#[test]
fn warp_exec_names_its_backend_once() {
    let (netns, seccomp) = backends();
    if !netns && !seccomp {
        eprintln!("skipping: no backend of the pod on this host");
        return;
    }
    let host = Host::new();
    let truth = Path::new("true");
    let out = host.warp_exec(&[], "auto", truth);
    let lines = backend_lines(&out);
    assert_eq!(lines.len(), 1, "{}", stderr(&out));
    assert!(
        lines[0].contains("seccomp backend: ") || lines[0].contains("netns backend: "),
        "{lines:?}"
    );
    assert!(lines[0].contains("use --backend"), "{lines:?}");
    // -q removes the line.
    let out = host.warp_exec(&["-q"], "auto", truth);
    assert!(backend_lines(&out).is_empty(), "{}", stderr(&out));
    // podnet pod names the backend only when it is asked to.
    let backend = if seccomp { "seccomp" } else { "netns" };
    let out = host.pod(&["--backend", backend], truth);
    assert!(backend_lines(&out).is_empty(), "{}", stderr(&out));
}

#[test]
fn warp_exec_passes_the_backend_to_the_pod() {
    let (netns, seccomp) = backends();
    let host = Host::new();
    let truth = Path::new("true");
    for (backend, available) in [("netns", netns), ("seccomp", seccomp)] {
        if !available {
            eprintln!("skipping {backend}: not available on this host");
            continue;
        }
        let out = host.warp_exec(&[], backend, truth);
        let lines = backend_lines(&out);
        assert_eq!(lines.len(), 1, "{}", stderr(&out));
        assert!(
            lines[0].contains(&format!("{backend} backend: ")),
            "{lines:?}"
        );
    }
    // podnet -v warp exec gives -v to the pod.
    let Some(cc) = compiler() else {
        eprintln!("skipping -v: no C compiler");
        return;
    };
    if !seccomp {
        eprintln!("skipping -v: no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let client = build(host.dir.path(), &cc);
    let out = host.warp_exec(&["-v"], "seccomp", &client);
    assert!(
        stderr(&out).contains("socket emulated as a socket pair"),
        "{}",
        stderr(&out)
    );
    let out = host.warp_exec(&[], "seccomp", &client);
    assert!(
        !stderr(&out).contains("socket emulated"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn seccomp_logs_its_emulation_at_info() {
    let Some(cc) = compiler() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    if !backends().1 {
        eprintln!("skipping: no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let host = Host::new();
    let client = build(host.dir.path(), &cc);
    let out = host.pod(&["--backend", "seccomp", "-v"], &client);
    let err = stderr(&out);
    for want in [
        "podnet-netns: socket emulated as a socket pair (IPv4 TCP)",
        "podnet-netns: socket emulated as a socket pair (IPv6 UDP)",
        "podnet-netns: setsockopt answered by the pod (fd ",
    ] {
        assert!(
            err.lines().any(|l| l.starts_with(want)),
            "{want:?} in:\n{err}"
        );
    }
    // Without -v: no line about the emulation.
    let out = host.pod(&["--backend", "seccomp"], &client);
    let err = stderr(&out);
    assert!(!err.contains("socket emulated"), "{err}");
    assert!(!err.contains("setsockopt answered"), "{err}");
}
