//! T-064: under the seccomp backend, the entry of a socket follows the
//! socket, not the descriptor number. A copy (`fork`, `dup`, `dup2`, `dup3`,
//! `fcntl(F_DUPFD)`, `fcntl(F_DUPFD_CLOEXEC)`) finds the entry, and a close
//! of one copy keeps the entry for the other copies.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// Compile `source` and run it in the pod with the SOCKS5 stand-in. `None`
/// when the host has no C compiler or no seccomp user notification.
fn run_in_pod(source: &str) -> Option<Output> {
    let Some(cc) = compiler() else {
        eprintln!("skipping: no C compiler");
        return None;
    };
    if !seccomp_available() {
        eprintln!("skipping: no SECCOMP_RET_USER_NOTIF");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || socks5(listener));
    let program = build(dir.path(), &cc, source);
    let out = pod()
        .args(["--backend", "seccomp"])
        .arg("-x")
        .arg(format!("unix:{}", sock.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    Some(out)
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

fn expect_lines(out: &Output, want: &[String]) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    for want in want {
        assert!(
            stdout.lines().any(|l| l == want),
            "{want:?} in:\n{stdout}\n{stderr}"
        );
    }
}

/// The parent makes a TCP socket and forks. The child closes its copy and
/// exits. Then the parent connects through the proxy.
const FORK_CLOSE: &str = r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        close(fd);
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(8776);
    inet_pton(AF_INET, "93.184.216.34", &to.sin_addr);
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); return 1; }
    printf("connected\n");
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("got %s", buf); }
    close(fd);
    return 0;
}
"#;

#[test]
fn seccomp_close_in_a_child_keeps_the_parent_entry() {
    let Some(out) = run_in_pod(FORK_CLOSE) else {
        return;
    };
    expect_lines(&out, &["connected".to_string(), "got HELLO".to_string()]);
}

/// For each way to copy a descriptor: connect a UDP socket to port 53,
/// copy it, close the first descriptor, and send a DNS query on the copy.
/// The fake DNS of the pod answers when the copy has the destination.
const DUP_UDP: &str = r#"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int copy(int fd, int how) {
    switch (how) {
    case 0: return dup(fd);
    case 1: return dup2(fd, 40);
    case 2: return dup3(fd, 41, O_CLOEXEC);
    case 3: return fcntl(fd, F_DUPFD, 50);
    default: return fcntl(fd, F_DUPFD_CLOEXEC, 60);
    }
}

int main(void) {
    static const char *names[] = {"dup", "dup2", "dup3", "F_DUPFD", "F_DUPFD_CLOEXEC"};
    for (int how = 0; how < 5; how++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return 1; }
        struct sockaddr_in to;
        memset(&to, 0, sizeof to);
        to.sin_family = AF_INET;
        to.sin_port = htons(53);
        inet_pton(AF_INET, "192.0.2.1", &to.sin_addr);
        if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); return 1; }
        int c = copy(fd, how);
        if (c < 0) { perror("copy"); return 1; }
        close(fd);
        unsigned char q[64];
        int id = 0x1200 + how;
        memset(q, 0, sizeof q);
        q[0] = id >> 8; q[1] = id & 0xff; q[2] = 1; q[5] = 1;
        static const unsigned char name[] = "\7example\3com";
        memcpy(q + 12, name, sizeof name);
        int len = 12 + sizeof name;
        q[len + 1] = 1; q[len + 3] = 1;
        len += 4;
        if (send(c, q, len, 0) != len) { printf("%s send failed\n", names[how]); continue; }
        struct pollfd p = { .fd = c, .events = POLLIN };
        if (poll(&p, 1, 3000) != 1) { printf("%s timeout\n", names[how]); continue; }
        unsigned char r[512];
        ssize_t n = recv(c, r, sizeof r, 0);
        int got = n >= 12 ? (r[0] << 8 | r[1]) : -1;
        printf("%s %s\n", names[how], got == id ? "answered" : "wrong");
        close(c);
    }
    return 0;
}
"#;

#[test]
fn seccomp_dup_keeps_the_udp_destination() {
    let Some(out) = run_in_pod(DUP_UDP) else {
        return;
    };
    let want: Vec<String> = ["dup", "dup2", "dup3", "F_DUPFD", "F_DUPFD_CLOEXEC"]
        .iter()
        .map(|name| format!("{name} answered"))
        .collect();
    expect_lines(&out, &want);
}

/// The program makes more sockets than the supervisor tracks, and closes
/// each one with `close_range`, which the filter does not stop. The
/// supervisor must free the entries of the closed sockets.
const MANY_SOCKETS: &str = r#"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    for (int i = 0; i < 5000; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { printf("socket %d failed\n", i); perror("socket"); return 1; }
        syscall(436, fd, fd, 0);
    }
    printf("made 5000\n");
    return 0;
}
"#;

#[test]
fn seccomp_closed_sockets_free_their_entries() {
    let Some(out) = run_in_pod(MANY_SOCKETS) else {
        return;
    };
    expect_lines(&out, &["made 5000".to_string()]);
}
