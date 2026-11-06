//! T-067: under the seccomp backend, a slow upstream dial of one `connect`
//! does not stop the supervisor. The other calls of the program get their
//! answers while the dial runs.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
        .args(["-O2", "-pthread", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap();
    assert!(status.success(), "compiling the client failed");
    out
}

/// The port of the slow target. The stand-in answers its CONNECT after
/// [`SLOW`].
const SLOW_PORT: u16 = 8001;
const SLOW: Duration = Duration::from_secs(2);

/// A SOCKS5 CONNECT stand-in on a unix socket. It greets each connection
/// with the line `HELLO PORT` and closes it. It answers a CONNECT to
/// [`SLOW_PORT`] after [`SLOW`].
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
            let port = u16::from_be_bytes([r[rest - 2], r[rest - 1]]);
            if port == SLOW_PORT {
                std::thread::sleep(SLOW);
            }
            let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            let _ = c.write_all(format!("HELLO {port}\n").as_bytes());
        });
    }
}

/// Thread 2 connects to the slow target. Meanwhile, the main thread calls
/// `getsockname` on a second socket, then connects it to a fast target.
/// Each line gives the time of the call in milliseconds.
const CLIENT: &str = r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static struct sockaddr_in target(int port) {
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    inet_pton(AF_INET, "93.184.216.34", &to.sin_addr);
    return to;
}

static void greeting(int fd, const char *name) {
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("%s got %s", name, buf); }
    fflush(stdout);
}

static int slow_fd;

static void *slow(void *arg) {
    (void)arg;
    struct sockaddr_in to = target(8001);
    long t0 = now_ms();
    int r = connect(slow_fd, (struct sockaddr *)&to, sizeof to);
    printf("slow_connect %d %ld\n", r, now_ms() - t0);
    greeting(slow_fd, "slow");
    return NULL;
}

int main(void) {
    slow_fd = socket(AF_INET, SOCK_STREAM, 0);
    int fast_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (slow_fd < 0 || fast_fd < 0) { perror("socket"); return 1; }
    pthread_t th;
    pthread_create(&th, NULL, slow, NULL);
    /* Let the slow dial start. */
    usleep(300000);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    long t0 = now_ms();
    int r = getsockname(fast_fd, (struct sockaddr *)&ss, &sl);
    printf("getsockname %d %ld\n", r, now_ms() - t0);
    struct sockaddr_in to = target(8002);
    t0 = now_ms();
    r = connect(fast_fd, (struct sockaddr *)&to, sizeof to);
    printf("fast_connect %d %ld\n", r, now_ms() - t0);
    fflush(stdout);
    greeting(fast_fd, "fast");
    pthread_join(th, NULL);
    return 0;
}
"#;

/// The value of the line `NAME RESULT MS`: (result, milliseconds).
fn timed(stdout: &str, name: &str) -> (i64, u64) {
    let line = stdout
        .lines()
        .find(|l| l.starts_with(&format!("{name} ")))
        .unwrap_or_else(|| panic!("no line {name:?} in:\n{stdout}"));
    let words: Vec<&str> = line.split_whitespace().collect();
    (words[1].parse().unwrap(), words[2].parse().unwrap())
}

/// Run `source` in a pod with the stand-in. `None` when the host cannot.
fn run(source: &str) -> Option<(String, String)> {
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
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{stdout}\n{stderr}");
    Some((stdout, stderr))
}

#[test]
fn seccomp_a_slow_dial_does_not_stop_other_calls() {
    let Some((stdout, stderr)) = run(CLIENT) else {
        return;
    };
    let (r, ms) = timed(&stdout, "getsockname");
    assert_eq!(r, 0, "{stdout}\n{stderr}");
    assert!(ms < 100, "getsockname took {ms} ms:\n{stdout}\n{stderr}");
    let (r, ms) = timed(&stdout, "fast_connect");
    assert_eq!(r, 0, "{stdout}\n{stderr}");
    assert!(
        ms < 1000,
        "the fast connect took {ms} ms:\n{stdout}\n{stderr}"
    );
    let (r, ms) = timed(&stdout, "slow_connect");
    assert_eq!(r, 0, "{stdout}\n{stderr}");
    assert!(
        ms >= 1500,
        "the slow connect took {ms} ms:\n{stdout}\n{stderr}"
    );
    for want in ["slow got HELLO 8001", "fast got HELLO 8002"] {
        assert!(
            stdout.lines().any(|l| l == want),
            "{want:?} in:\n{stdout}\n{stderr}"
        );
    }
}

/// Thread 2 connects to the slow target. The main thread closes the socket
/// during the dial, then connects a new socket to a fast target.
const CLOSE_CLIENT: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in target(int port) {
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    inet_pton(AF_INET, "93.184.216.34", &to.sin_addr);
    return to;
}

static int slow_fd;

static void *slow(void *arg) {
    (void)arg;
    struct sockaddr_in to = target(8001);
    int r = connect(slow_fd, (struct sockaddr *)&to, sizeof to);
    printf("slow_connect %d %d\n", r, r == 0 ? 0 : errno);
    fflush(stdout);
    return NULL;
}

int main(void) {
    slow_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (slow_fd < 0) { perror("socket"); return 1; }
    pthread_t th;
    pthread_create(&th, NULL, slow, NULL);
    usleep(300000);
    printf("close %d\n", close(slow_fd));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to = target(8002);
    printf("fast_connect %d\n", connect(fd, (struct sockaddr *)&to, sizeof to));
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("fast got %s", buf); }
    fflush(stdout);
    pthread_join(th, NULL);
    return 0;
}
"#;

#[test]
fn seccomp_a_close_during_a_slow_dial_aborts_the_connect() {
    let Some((stdout, stderr)) = run(CLOSE_CLIENT) else {
        return;
    };
    // ECONNABORTED of Linux.
    for want in [
        "close 0",
        "fast_connect 0",
        "fast got HELLO 8002",
        "slow_connect -1 103",
    ] {
        assert!(
            stdout.lines().any(|l| l == want),
            "{want:?} in:\n{stdout}\n{stderr}"
        );
    }
}
