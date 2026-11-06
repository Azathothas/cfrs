//! T-063: a TCP socket of the program under the seccomp backend keeps its
//! entry after the connect. Its options and its addresses come from the
//! entry, not from the `AF_UNIX` socketpair of the program.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn build(dir: &Path, cc: &Path, source: &str) -> PathBuf {
    let src = dir.join("client.c");
    std::fs::write(&src, source).unwrap();
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

/// A SOCKS5 CONNECT stand-in on a unix socket: it greets each connection
/// with one line and closes it.
fn socks5(listener: UnixListener) {
    for conn in listener.incoming() {
        let Ok(mut c) = conn else { break };
        std::thread::spawn(move || {
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
            let rest = match h[3] {
                1 => 4 + 2,
                4 => 16 + 2,
                _ => {
                    let mut n = [0u8; 1];
                    let _ = c.read_exact(&mut n);
                    n[0] as usize + 2
                }
            };
            let mut r = vec![0u8; rest];
            let _ = c.read_exact(&mut r);
            let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            let _ = c.write_all(b"HELLO\n");
        });
    }
}

const CLIENT: &str = r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(8776);
    inet_pton(AF_INET, "93.184.216.34", &to.sin_addr);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); return 1; }
    int one = 1;
    printf("nodelay_set %d\n", setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one));
    int idle = 42;
    printf("keepidle_set %d\n", setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle));
    int v = -1;
    socklen_t len = sizeof v;
    int r = getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, &len);
    printf("nodelay_get %d %d\n", r, v);
    v = -1;
    len = sizeof v;
    r = getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &v, &len);
    printf("keepidle_get %d %d\n", r, v);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    char ip[64];
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0) {
        struct sockaddr_in *in = (struct sockaddr_in *)&ss;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
        printf("peer %d %s %d\n", ss.ss_family, ip, ntohs(in->sin_port));
    } else {
        perror("getpeername");
    }
    sl = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) {
        printf("local %d\n", ss.ss_family);
    } else {
        perror("getsockname");
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("got %s", buf); }
    close(fd);
    return 0;
}
"#;

#[test]
fn seccomp_tcp_socket_keeps_its_options_and_addresses() {
    let Some(cc) = compiler() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    if !seccomp_available() {
        eprintln!("skipping: no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || socks5(listener));
    let program = build(dir.path(), &cc, CLIENT);
    let out = pod()
        .args(["--backend", "seccomp"])
        .arg("-x")
        .arg(format!("unix:{}", sock.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let inet = libc_af_inet();
    for want in [
        "nodelay_set 0".to_string(),
        "keepidle_set 0".to_string(),
        "nodelay_get 0 1".to_string(),
        "keepidle_get 0 42".to_string(),
        format!("peer {inet} 93.184.216.34 8776"),
        format!("local {inet}"),
        "got HELLO".to_string(),
    ] {
        assert!(
            stdout.lines().any(|l| l == want),
            "{want:?} in:\n{stdout}\n{stderr}"
        );
    }
    drop(UnixStream::connect(&sock));
}

/// `AF_INET` of Linux.
fn libc_af_inet() -> i32 {
    2
}
