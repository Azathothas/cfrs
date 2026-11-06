//! T-066: three datagram calls under the seccomp backend. An ICMP datagram
//! socket gets an echo answer from the gateway of the pod, and `EACCES` for
//! another destination. `recvmmsg` gives the real source of each message.
//! A UDP name over 255 bytes gets `EINVAL`.

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

/// A SOCKS5 stand-in on a unix socket: it accepts each command and then
/// closes the connection after one line.
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

fn expect_lines(out: &Output, want: &[&str]) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    for want in want {
        assert!(
            stdout.lines().any(|l| l == *want),
            "{want:?} in:\n{stdout}\n{stderr}"
        );
    }
}

/// The ICMP part of the static guest of the vn kit: an echo to the gateway
/// of the pod (10.66.255.254) gets an answer; an echo to 192.0.2.1 gets
/// `EACCES`.
const ICMP_ECHO: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd < 0) { perror("socket"); return 1; }
    unsigned char req[16] = {8, 0, 0, 0, 0x12, 0x34, 0, 7,
                             'p', 'o', 'd', 'n', 'e', 't', '!', '!'};
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    inet_pton(AF_INET, "10.66.255.254", &to.sin_addr);
    if (sendto(fd, req, sizeof req, 0, (struct sockaddr *)&to, sizeof to) != sizeof req) {
        perror("sendto gateway");
        return 1;
    }
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, 5000) != 1) { printf("no answer\n"); return 1; }
    unsigned char rep[64];
    struct sockaddr_in from;
    memset(&from, 0, sizeof from);
    socklen_t fl = sizeof from;
    ssize_t n = recvfrom(fd, rep, sizeof rep, 0, (struct sockaddr *)&from, &fl);
    if (n < 8) { perror("recvfrom"); return 1; }
    char ip[32] = "?";
    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
    printf("reply type %d code %d seq %d len %zd from %s family %d\n",
           rep[0], rep[1], rep[6] << 8 | rep[7], n, ip, from.sin_family);
    printf("payload %s\n", n == 16 && memcmp(rep + 8, req + 8, 8) == 0 ? "same" : "differs");
    unsigned sum = 0;
    for (ssize_t i = 0; i < n; i += 2)
        sum += (unsigned)(rep[i] << 8) | (i + 1 < n ? rep[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    printf("checksum %s\n", sum == 0xffff ? "good" : "bad");
    inet_pton(AF_INET, "192.0.2.1", &to.sin_addr);
    if (sendto(fd, req, sizeof req, 0, (struct sockaddr *)&to, sizeof to) < 0)
        printf("other: %s\n", errno == EACCES ? "EACCES" : strerror(errno));
    else
        printf("other: sent\n");
    return 0;
}
"#;

#[test]
fn seccomp_icmp_echo_to_the_gateway() {
    let Some(out) = run_in_pod(ICMP_ECHO) else {
        return;
    };
    expect_lines(
        &out,
        &[
            "reply type 0 code 0 seq 7 len 16 from 10.66.255.254 family 2",
            "payload same",
            "checksum good",
            "other: EACCES",
        ],
    );
}

/// The common part of the C programs below: a DNS query for `name`.
const QUERY: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* A DNS query (type A) for the labels of `name` (dots separate them). */
static int query(unsigned char *q, int id, const char *name) {
    memset(q, 0, 12);
    q[0] = id >> 8; q[1] = id & 0xff; q[2] = 1; q[5] = 1;
    int len = 12;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        int l = dot ? (int)(dot - s) : (int)strlen(s);
        q[len++] = l;
        memcpy(q + len, s, l);
        len += l;
        s += l + (dot ? 1 : 0);
    }
    q[len++] = 0;
    q[len++] = 0; q[len++] = 1; q[len++] = 0; q[len++] = 1;
    return len;
}

static int send_query(int fd, const char *server, int id, const char *name) {
    unsigned char q[512];
    int len = query(q, id, name);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    inet_pton(AF_INET, server, &to.sin_addr);
    return sendto(fd, q, len, 0, (struct sockaddr *)&to, sizeof to) == len ? 0 : -1;
}
"#;

/// Two DNS answers from two resolver addresses, read with one `recvmmsg`.
/// Then a blocking `recvmmsg` waits for an answer that comes later.
const RECVMMSG: &str = r#"
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/wait.h>
@QUERY@

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    unsigned char bufs[4][512];
    struct sockaddr_in names[4];
    struct iovec iovs[4];
    struct mmsghdr msgs[4];
    memset(msgs, 0, sizeof msgs);
    for (int i = 0; i < 4; i++) {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_len = sizeof bufs[i];
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &names[i];
        msgs[i].msg_hdr.msg_namelen = sizeof names[i];
    }
    int r = recvmmsg(fd, msgs, 4, MSG_DONTWAIT, NULL);
    printf("empty: %s\n", r < 0 && errno == EAGAIN ? "EAGAIN" : "other");
    if (send_query(fd, "192.0.2.1", 0x101, "one.example") != 0) { perror("send"); return 1; }
    if (send_query(fd, "192.0.2.2", 0x102, "two.example") != 0) { perror("send"); return 1; }
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, 5000) != 1) { printf("no answer\n"); return 1; }
    r = recvmmsg(fd, msgs, 4, MSG_WAITFORONE, NULL);
    printf("count %d\n", r);
    for (int i = 0; i < r; i++) {
        char ip[32] = "?";
        inet_ntop(AF_INET, &names[i].sin_addr, ip, sizeof ip);
        int id = bufs[i][0] << 8 | bufs[i][1];
        printf("message %d id %x from %s:%d family %d namelen %u len %s\n", i, id, ip,
               ntohs(names[i].sin_port), names[i].sin_family, msgs[i].msg_hdr.msg_namelen,
               msgs[i].msg_len > 12 ? "ok" : "short");
    }
    /* A blocking call with no message waits; a child sends later. */
    pid_t child = fork();
    if (child == 0) {
        usleep(300000);
        send_query(fd, "192.0.2.3", 0x103, "three.example");
        _exit(0);
    }
    for (int i = 0; i < 4; i++) msgs[i].msg_hdr.msg_namelen = sizeof names[i];
    r = recvmmsg(fd, msgs, 4, 0, NULL);
    char ip[32] = "?";
    inet_ntop(AF_INET, &names[0].sin_addr, ip, sizeof ip);
    printf("blocking count %d from %s\n", r, ip);
    waitpid(child, NULL, 0);
    return 0;
}
"#;

#[test]
fn seccomp_recvmmsg_gets_the_real_source() {
    let Some(out) = run_in_pod(&RECVMMSG.replace("@QUERY@", QUERY)) else {
        return;
    };
    expect_lines(
        &out,
        &[
            "empty: EAGAIN",
            "count 2",
            "message 0 id 101 from 192.0.2.1:53 family 2 namelen 16 len ok",
            "message 1 id 102 from 192.0.2.2:53 family 2 namelen 16 len ok",
            "blocking count 1 from 192.0.2.3",
        ],
    );
}

/// A name of 304 bytes gets a fake address; a datagram to that address
/// gets `EINVAL`, because SOCKS5 carries a name of 255 bytes at most.
const LONG_NAME: &str = r#"
@QUERY@

int main(void) {
    char name[400] = "";
    for (int i = 0; i < 5; i++) {
        if (i) strcat(name, ".");
        strncat(name, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 60);
    }
    printf("name %zu\n", strlen(name));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    if (send_query(fd, "192.0.2.1", 0x201, name) != 0) { perror("send"); return 1; }
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, 5000) != 1) { printf("no answer\n"); return 1; }
    unsigned char r[1024];
    ssize_t n = recv(fd, r, sizeof r, 0);
    if (n < 16) { printf("short answer\n"); return 1; }
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(9999);
    memcpy(&to.sin_addr, r + n - 4, 4);
    char ip[32] = "?";
    inet_ntop(AF_INET, &to.sin_addr, ip, sizeof ip);
    printf("fake %s\n", strncmp(ip, "198.18.", 7) == 0 ? "yes" : ip);
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&to, sizeof to) < 0)
        printf("long: %s\n", errno == EINVAL ? "EINVAL" : strerror(errno));
    else
        printf("long: sent\n");
    return 0;
}
"#;

#[test]
fn seccomp_long_udp_name_is_refused() {
    let Some(out) = run_in_pod(&LONG_NAME.replace("@QUERY@", QUERY)) else {
        return;
    };
    expect_lines(&out, &["name 304", "fake yes", "long: EINVAL"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.lines().any(|l| l.contains("over 255 bytes")),
        "a log line in:\n{stderr}"
    );
}
