//! T-065: under the seccomp backend, the program holds the socket of a
//! plain Unix-socket upstream after the handshake, and no relay task
//! stays. A TCP upstream keeps the relay.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn pod() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_podnet"));
    command.arg("pod");
    command
}

fn seccomp_available() -> bool {
    let out = pod().args(["doctor", "--json"]).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    report["backend_seccomp"] == serde_json::Value::Bool(true)
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

/// One SOCKS5 CONNECT: do the handshake, echo each byte until the end of
/// the stream, then keep the connection open for 10 s. A relay that stays
/// waits for this end, so the pod exits only after its drain limit (3 s).
fn socks5_echo<S: Read + Write>(mut c: S) {
    let mut b = [0u8; 2];
    if c.read_exact(&mut b).is_err() {
        return;
    }
    let mut m = vec![0u8; b[1] as usize];
    let _ = c.read_exact(&mut m);
    let _ = c.write_all(&[5, 0]);
    let mut h = [0u8; 4];
    if c.read_exact(&mut h).is_err() {
        return;
    }
    let mut r = vec![0u8; if h[3] == 1 { 6 } else { 18 }];
    let _ = c.read_exact(&mut r);
    let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let mut buf = [0u8; 256];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 || c.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    std::thread::sleep(Duration::from_secs(10));
}

/// The program: the socket inode before and after the connect, the result
/// of `TCP_NODELAY`, and one echo through a blocking read.
const CLIENT: &str = r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void link_of(int fd, char *out, size_t len) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, out, len - 1);
    out[n > 0 ? n : 0] = 0;
}

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    char before[128], after[128];
    link_of(fd, before, sizeof before);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(8777);
    inet_pton(AF_INET, "93.184.216.34", &to.sin_addr);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); return 1; }
    link_of(fd, after, sizeof after);
    printf("same_socket %d\n", strcmp(before, after) == 0);
    int one = 1;
    printf("nodelay_set %d\n", setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one));
    struct sockaddr_in peer;
    socklen_t sl = sizeof peer;
    if (getpeername(fd, (struct sockaddr *)&peer, &sl) == 0) {
        printf("peer_port %d\n", ntohs(peer.sin_port));
    }
    if (write(fd, "ping\n", 5) != 5) { perror("write"); return 1; }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("got %s", buf); } else { perror("read"); }
    fflush(stdout);
    close(fd);
    return 0;
}
"#;

/// Run the program under the pod with the proxy `proxy`. Return stdout,
/// stderr, and the time until the pod exits.
fn run(proxy: &str) -> Option<(String, String, Duration)> {
    let Some(cc) = compiler() else {
        eprintln!("skipping: no C compiler");
        return None;
    };
    if !seccomp_available() {
        eprintln!("skipping: no SECCOMP_RET_USER_NOTIF");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let program = build(dir.path(), &cc);
    let start = Instant::now();
    let out = pod()
        .args(["--backend", "seccomp", "-v", "-x", proxy, "--"])
        .arg(&program)
        .output()
        .unwrap();
    let took = start.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{stdout}\n{stderr}");
    Some((stdout, stderr, took))
}

fn has(text: &str, want: &str) -> bool {
    text.lines().any(|l| l == want)
}

#[test]
fn seccomp_handoff_of_a_unix_upstream_leaves_no_relay() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for c in listener.incoming().flatten() {
            std::thread::spawn(move || socks5_echo(c));
        }
    });
    let Some((stdout, stderr, took)) = run(&format!("unix:{}", sock.display())) else {
        return;
    };
    let all = format!("{stdout}\n{stderr}");
    // The program holds another socket after the connect: the upstream.
    assert!(has(&stdout, "same_socket 0"), "{all}");
    assert!(has(&stdout, "nodelay_set 0"), "{all}");
    assert!(has(&stdout, "peer_port 8777"), "{all}");
    assert!(has(&stdout, "got ping"), "{all}");
    assert!(
        stderr.contains("the program holds the upstream socket"),
        "{all}"
    );
    // No relay stays: the pod does not wait for its drain limit (3 s).
    assert!(took < Duration::from_millis(2500), "{took:?}\n{all}");
}

#[test]
fn seccomp_tcp_upstream_keeps_the_relay() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in listener.incoming().flatten() {
            std::thread::spawn(move || socks5_echo(c));
        }
    });
    let Some((stdout, stderr, _)) = run(&format!("socks5://127.0.0.1:{port}")) else {
        return;
    };
    let all = format!("{stdout}\n{stderr}");
    assert!(has(&stdout, "same_socket 1"), "{all}");
    assert!(has(&stdout, "nodelay_set 0"), "{all}");
    assert!(has(&stdout, "got ping"), "{all}");
    assert!(
        !stderr.contains("the program holds the upstream socket"),
        "{all}"
    );
}
