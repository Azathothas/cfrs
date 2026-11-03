//! End-to-end tests for `pod-netns`'s seccomp backend.
//!
//! A SOCKS5 proxy listens on a unix socket (the only bind a sealed host
//! permits). A compiled C program calls `socket(AF_INET)`/`connect(AF_INET)`
//! normally; the filter stops both and the supervisor hands it a socketpair
//! and dials the proxy. No `LD_PRELOAD` is involved, so a **static** build is
//! exercised too — that is the whole point of the backend.
//!
//! Three tests: a single proxy, two chained hops, and UDP relayed through
//! `UDP ASSOCIATE`. If the host does not offer `SECCOMP_RET_USER_NOTIF` they
//! report that and pass, as the other shim tests do without a compiler.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Find a C compiler: `$CC`, then `cc`, `gcc` or `clang` on `PATH`.
fn compiler() -> Option<PathBuf> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(cc) = std::env::var("CC") {
        names.push(cc);
    }
    names.extend(["cc", "gcc", "clang"].map(String::from));
    let path = std::env::var_os("PATH")?;
    for name in names {
        let candidate = PathBuf::from(&name);
        if candidate.is_absolute() && candidate.is_file() {
            return Some(candidate);
        }
        for dir in std::env::split_paths(&path) {
            let full = dir.join(&name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

fn have_compiler() -> bool {
    compiler().is_some()
}

fn build_program(dir: &std::path::Path, name: &str, source: &str, static_link: bool) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let output = dir.join(name);
    let cc = compiler().unwrap();
    let mut cmd = Command::new(cc);
    cmd.arg("-O2");
    if static_link {
        cmd.arg("-static");
    }
    let status = cmd
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    output
}

/// Read a SOCKS5 request after the method handshake; returns (cmd, host, port).
fn read_request(c: &mut UnixStream) -> Option<(u8, String, u16)> {
    let mut hdr = [0u8; 2];
    c.read_exact(&mut hdr).ok()?;
    let mut methods = vec![0u8; hdr[1] as usize];
    c.read_exact(&mut methods).ok()?;
    c.write_all(&[5, 0]).ok()?;
    let mut req = [0u8; 4];
    c.read_exact(&mut req).ok()?;
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).ok()?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).ok()?;
            let mut h = vec![0u8; l[0] as usize];
            c.read_exact(&mut h).ok()?;
            String::from_utf8_lossy(&h).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).ok()?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return None,
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).ok()?;
    Some((req[1], host, u16::from_be_bytes(p)))
}

/// A SOCKS5 CONNECT proxy on a unix socket. With `hop`, a target named
/// `unix:<path>` is forwarded to that socket; otherwise it greets and echoes.
fn socks5_proxy(listener: UnixListener, targets: mpsc::Sender<String>, hop: bool) {
    for conn in listener.incoming() {
        let mut c = match conn {
            Ok(c) => c,
            Err(_) => break,
        };
        let targets = targets.clone();
        let _ = std::thread::spawn(move || {
            let Some((cmd, host, port)) = read_request(&mut c) else {
                return;
            };
            if cmd != 1 {
                return;
            }
            let _ = targets.send(format!("{host}:{port}"));
            if hop && host.starts_with("unix:") {
                let Ok(mut up) = UnixStream::connect(&host[5..]) else {
                    return;
                };
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let mut up2 = up.try_clone().unwrap();
                let mut c2 = c.try_clone().unwrap();
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut up2, &mut c2);
                    let _ = c2.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut c, &mut up);
            } else {
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let _ = c.write_all(b"HELLO-FROM-TARGET\n");
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

fn seccomp_available() -> bool {
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["doctor", "--json"])
        .output()
        .expect("run pod-netns doctor");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints JSON");
    report["backend_seccomp"] == serde_json::Value::Bool(true)
}

fn netns_available() -> bool {
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["doctor", "--json"])
        .output()
        .expect("run pod-netns doctor");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints JSON");
    report["backend_netns"] == serde_json::Value::Bool(true)
}

#[test]
fn netns_backend_proxies_a_static_and_a_dynamic_binary() {
    if !have_compiler() || !netns_available() {
        eprintln!("skipping: no compiler or no netns backend");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-nsclient-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let dynamic = build_program(&dir, "client-dynamic", CLIENT, false);
    let statically = build_program(&dir, "client-static", CLIENT, true);
    for program in [&dynamic, &statically] {
        let stdout = run_on("netns", &[&sock], program);
        assert!(stdout.contains("HELLO-FROM-TARGET"), "{stdout:?}");
    }
    assert_eq!(rx.recv().unwrap(), "93.184.216.34:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn netns_backend_resolves_names_and_carries_parallel_flows() {
    if !have_compiler() || !netns_available() {
        eprintln!("skipping: no compiler or no netns backend");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-nsdns-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "parallel", PARALLEL_DNS_CLIENT, false);
    let stdout = run_on("netns", &[&sock], &program);
    assert_eq!(stdout.matches("HELLO-FROM-TARGET").count(), 3, "{stdout:?}");
    let mut targets: Vec<String> = (0..3).map(|_| rx.recv().unwrap()).collect();
    targets.sort();
    assert_eq!(targets, ["a.example:80", "b.example:80", "c.example:80"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Resolve three names, open three connections to port 80 at the same time,
/// then read from each.
const PARALLEL_DNS_CLIENT: &str = r#"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    const char *names[3] = {"a.example", "b.example", "c.example"};
    int fds[3];
    for (int i = 0; i < 3; i++) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(names[i], "80", &hints, &res) != 0) { printf("DNS-FAIL\n"); return 1; }
        fds[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(fds[i], res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 1; }
        freeaddrinfo(res);
    }
    for (int i = 0; i < 3; i++) {
        char b[64] = {0};
        int n = read(fds[i], b, sizeof b - 1);
        printf("%d:%s", n, n > 0 ? b : "");
    }
    return 0;
}
"#;

fn run(_dir: &std::path::Path, proxies: &[&std::path::Path], program: &std::path::Path) -> String {
    run_on("seccomp", proxies, program)
}

fn run_on(backend: &str, proxies: &[&std::path::Path], program: &std::path::Path) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pod-netns"));
    cmd.args(["--backend", backend, "-v"]);
    for p in proxies {
        cmd.arg("-x").arg(format!("unix:{}", p.display()));
    }
    let output = cmd.arg("--").arg(program).output().expect("run pod-netns");
    assert!(
        output.status.success(),
        "pod-netns failed: stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

const CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    write(s, "PING\n", 5);
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("READ:%d:%s", n, b);
    return 0;
}
"#;

const SERVER: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(8080);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    if (listen(s, 4) < 0) { perror("listen"); return 1; }
    int c = accept(s, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }
    char b[64] = {0};
    int n = read(c, b, sizeof b - 1);
    if (n <= 0) return 1;
    write(c, "PONG\n", 5);
    return 0;
}
"#;

const DNS_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    int r = getaddrinfo("example.com", "80", &hints, &res);
    if (r != 0) { printf("GAI:%d\n", r); return 1; }
    char ip[64] = {0};
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 1; }
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("DNS:%s:%d:%s", ip, n, b);
    return 0;
}
"#;

const IPV6_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_port = htons(80);
    inet_pton(AF_INET6, "2001:db8::1", &a.sin6_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    write(s, "PING\n", 5);
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("READ6:%d:%s", n, b);
    return 0;
}
"#;

const UDP_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in d; memset(&d, 0, sizeof d);
    d.sin_family = AF_INET; d.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &d.sin_addr);
    if (sendto(s, "PING", 4, 0, (struct sockaddr *)&d, sizeof d) < 0) { perror("sendto"); return 1; }
    char b[128] = {0};
    int n = recvfrom(s, b, sizeof b - 1, 0, NULL, NULL);
    printf("UDP:%d:%s", n, n > 0 ? b : "");
    return 0;
}
"#;

/// Issue 84: a proxy on a unix socket that knows only the UDP association
/// in the stream (0x83) and refuses UDP ASSOCIATE. The datagram of the
/// program goes as a frame on the control connection, and the answer comes
/// back the same way: the supervisor needs no kernel UDP socket.
#[test]
fn seccomp_backend_relays_udp_in_the_stream() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-udp-stream-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (commands, seen) = mpsc::channel::<u8>();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            let commands = commands.clone();
            std::thread::spawn(move || {
                let Some((cmd, _host, _port)) = read_request(&mut c) else {
                    return;
                };
                let _ = commands.send(cmd);
                if cmd != 0x83 {
                    let _ = c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return;
                }
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                loop {
                    let mut len = [0u8; 2];
                    if c.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut datagram = vec![0u8; u16::from_be_bytes(len) as usize];
                    if c.read_exact(&mut datagram).is_err() {
                        return;
                    }
                    // An IPv4 header: 10 bytes; the answer comes from the
                    // same address.
                    if datagram.len() < 10 || datagram[3] != 1 {
                        continue;
                    }
                    let mut answer = datagram[..10].to_vec();
                    answer.extend_from_slice(b"ECHO:");
                    answer.extend_from_slice(&datagram[10..]);
                    let mut frame = (answer.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&answer);
                    if c.write_all(&frame).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let program = build_program(&dir, "udp-stream-client", UDP_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("UDP:9:ECHO:PING"), "{stdout:?}");
    let commands: Vec<u8> = seen.try_iter().collect();
    assert_eq!(commands, vec![0x83], "no UDP ASSOCIATE: {commands:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

const UDP_NAME_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    int r = getaddrinfo("stun.example", "19302", &hints, &res);
    if (r != 0) { printf("GAI:%d\n", r); return 1; }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (sendto(s, "PING", 4, 0, res->ai_addr, res->ai_addrlen) < 0) { perror("sendto"); return 1; }
    char b[128] = {0};
    int n = recvfrom(s, b, sizeof b - 1, 0, NULL, NULL);
    printf("UDP:%d:%s", n, n > 0 ? b : "");
    return 0;
}
"#;

/// Issue 113: a datagram to a fake IP of the pod goes to the proxy with
/// the name (ATYP 3), as a TCP connect does. Before, the proxy got the fake
/// IP (198.18.x.x), which no host has.
#[test]
fn seccomp_backend_sends_udp_to_a_name_as_the_name() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-udp-name-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (dests, seen) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { break };
            let dests = dests.clone();
            std::thread::spawn(move || {
                let Some((cmd, _, _)) = read_request(&mut c) else {
                    return;
                };
                if cmd != 0x83 {
                    let _ = c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return;
                }
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                loop {
                    let mut len = [0u8; 2];
                    if c.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut d = vec![0u8; u16::from_be_bytes(len) as usize];
                    if c.read_exact(&mut d).is_err() {
                        return;
                    }
                    let header = match d[3] {
                        1 => 10,
                        3 => 7 + d[4] as usize,
                        4 => 22,
                        _ => continue,
                    };
                    let dest = match d[3] {
                        3 => String::from_utf8_lossy(&d[5..5 + d[4] as usize]).into_owned(),
                        _ => format!("atyp {}", d[3]),
                    };
                    let port = u16::from_be_bytes([d[header - 2], d[header - 1]]);
                    let _ = dests.send(format!("{dest}:{port}"));
                    let mut answer = d[..header].to_vec();
                    answer.extend_from_slice(b"ECHO:");
                    answer.extend_from_slice(&d[header..]);
                    let mut frame = (answer.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&answer);
                    if c.write_all(&frame).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let program = build_program(&dir, "udp-name-client", UDP_NAME_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("UDP:9:ECHO:PING"), "{stdout:?}");
    assert_eq!(seen.try_recv().unwrap(), "stun.example:19302");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_proxies_a_static_and_a_dynamic_binary() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let dynamic = build_program(&dir, "client-dynamic", CLIENT, false);
    let statically = build_program(&dir, "client-static", CLIENT, true);
    for program in [&dynamic, &statically] {
        let stdout = run(&dir, &[&sock], program);
        assert!(stdout.contains("HELLO-FROM-TARGET"), "{stdout:?}");
    }
    assert_eq!(rx.recv().unwrap(), "93.184.216.34:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_chains_two_proxies() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p1 = dir.join("p1.sock");
    let p2 = dir.join("p2.sock");
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();
    let l2 = UnixListener::bind(&p2).unwrap();
    let l1 = UnixListener::bind(&p1).unwrap();
    std::thread::spawn(move || socks5_proxy(l2, tx2, false));
    std::thread::spawn(move || socks5_proxy(l1, tx1, true));

    let program = build_program(&dir, "client-chain", CLIENT, false);
    let stdout = run(&dir, &[&p1, &p2], &program);
    assert!(stdout.contains("HELLO-FROM-TARGET"), "{stdout:?}");
    // The first hop was asked for the second, not for the target.
    assert_eq!(rx1.recv().unwrap(), format!("unix:{}:0", p2.display()));
    assert_eq!(rx2.recv().unwrap(), "93.184.216.34:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_relays_udp() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-udp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");

    // A UDP echo, the thing the client believes it is talking to.
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, from)) = echo.recv_from(&mut buf) {
            let mut reply = b"ECHO:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = echo.send_to(&reply, from);
        }
    });

    // A SOCKS5 proxy with UDP ASSOCIATE on a unix control socket.
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            let Some((cmd, _host, _port)) = read_request(&mut c) else {
                continue;
            };
            if cmd != 3 {
                continue;
            }
            let mut bnd = vec![5u8, 0, 0, 1];
            bnd.extend_from_slice(
                &relay_addr
                    .ip()
                    .to_string()
                    .parse::<Ipv4Addr>()
                    .unwrap()
                    .octets(),
            );
            bnd.extend_from_slice(&relay_addr.port().to_be_bytes());
            let _ = c.write_all(&bnd);
            // Hold the control connection open for the life of the test.
            let mut buf = [0u8; 1];
            while c.read(&mut buf).unwrap_or(0) == 1 {}
        }
    });
    // The relay: unwrap a SOCKS5 UDP header, forward, wrap the reply.
    {
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                if n < 4 {
                    continue;
                }
                let off = match buf[3] {
                    1 => 10,
                    3 => 4 + 1 + buf[4] as usize + 2,
                    4 => 22,
                    _ => continue,
                };
                if n < off {
                    continue;
                }
                let up = UdpSocket::bind("127.0.0.1:0").unwrap();
                up.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let _ = up.send_to(&buf[off..n], echo_addr);
                let mut reply = [0u8; 65535];
                if let Ok((rn, _)) = up.recv_from(&mut reply) {
                    let mut out = vec![0u8, 0, 0, 1, 127, 0, 0, 1];
                    out.extend_from_slice(&echo_addr.port().to_be_bytes());
                    out.extend_from_slice(&reply[..rn]);
                    let _ = relay.send_to(&out, from);
                }
            }
        });
    }

    let program = build_program(&dir, "udp-client", UDP_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("UDP:9:ECHO:PING"), "{stdout:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_routes_by_rule() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-route-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p1 = dir.join("p1.sock");
    let p2 = dir.join("p2.sock");
    let l1 = UnixListener::bind(&p1).unwrap();
    let l2 = UnixListener::bind(&p2).unwrap();
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(l1, tx1, false));
    std::thread::spawn(move || socks5_proxy(l2, tx2, false));

    let program = build_program(&dir, "client-route", CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("unix:{}", p1.display()))
        .args(["-r"])
        .arg(format!("cidr:93.184.0.0/16=unix:{}", p2.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("HELLO-FROM-TARGET"));
    // The rule proxy saw it; the default did not.
    assert_eq!(rx2.recv().unwrap(), "93.184.216.34:80");
    assert!(
        rx1.try_recv().is_err(),
        "the default proxy must not be used"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_accepts_inbound() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-inbound-{}", std::process::id()));
    let inbound = dir.join("in");
    std::fs::create_dir_all(&inbound).unwrap();
    let proxy = dir.join("socks.sock");
    let listener = UnixListener::bind(&proxy).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let server = build_program(&dir, "server", SERVER, false);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--inbound-dir"])
        .arg(&inbound)
        .args(["-x"])
        .arg(format!("unix:{}", proxy.display()))
        .arg("--")
        .arg(&server)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // The listener is a unix socket named after the bound port.
    let sockpath = inbound.join("8080.sock");
    let mut conn = None;
    for _ in 0..100 {
        if let Ok(c) = UnixStream::connect(&sockpath) {
            conn = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut c = conn.expect("the inbound listener did not appear");
    c.write_all(b"PING\n").unwrap();
    let mut buf = [0u8; 16];
    let n = c.read(&mut buf).unwrap();
    assert_eq!(
        &buf[..n],
        b"PONG\n",
        "got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
    drop(c);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pod_netns_serves_a_front_door_and_chains_with_itself() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let echo = dir.join("echo.sock");
    let front = dir.join("front.sock");
    let listener = UnixListener::bind(&echo).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    // One instance serves SOCKS5 and forwards through the echo proxy.
    let mut server = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--serve"])
        .arg(format!("unix:{}", front.display()))
        .args(["-x"])
        .arg(format!("unix:{}", echo.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if front.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // A second instance runs a client through the first one's front door.
    let program = build_program(&dir, "client-serve", CLIENT, false);
    let stdout = run(&dir, &[&front], &program);
    assert!(stdout.contains("HELLO-FROM-TARGET"), "{stdout:?}");

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_dials_the_tailnet_with_no_shim() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-ts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let api = dir.join("tailscaled.sock");
    let listener = UnixListener::bind(&api).unwrap();
    // A stand-in for tailscaled's LocalAPI: accept the ts-dial upgrade, greet,
    // then echo.
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while c.read(&mut b).unwrap_or(0) == 1 {
                    head.push(b[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if !String::from_utf8_lossy(&head).contains("Upgrade: ts-dial") {
                    return;
                }
                let _ = c.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\nConnection: upgrade\r\n\r\n",
                );
                let _ = c.write_all(b"HELLO-FROM-TAILNET\n");
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });

    let program = build_program(&dir, "client-ts", CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("tailscale:{}", api.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("HELLO-FROM-TAILNET"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pod_netns_serves_a_udp_front_door() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-udpfront-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, from)) = echo.recv_from(&mut buf) {
            let mut reply = b"ECHO:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = echo.send_to(&reply, from);
        }
    });

    // A UDP ASSOCIATE proxy for the front door to forward through.
    let socks = dir.join("udp.sock");
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let listener = UnixListener::bind(&socks).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut c = match conn {
                Ok(c) => c,
                Err(_) => break,
            };
            let Some((cmd, _, _)) = read_request(&mut c) else {
                continue;
            };
            if cmd != 3 {
                continue;
            }
            let mut bnd = vec![5u8, 0, 0, 1];
            bnd.extend_from_slice(
                &relay_addr
                    .ip()
                    .to_string()
                    .parse::<Ipv4Addr>()
                    .unwrap()
                    .octets(),
            );
            bnd.extend_from_slice(&relay_addr.port().to_be_bytes());
            let _ = c.write_all(&bnd);
            let mut buf = [0u8; 1];
            while c.read(&mut buf).unwrap_or(0) == 1 {}
        }
    });
    {
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                if n < 4 {
                    continue;
                }
                let off = match buf[3] {
                    1 => 10,
                    3 => 4 + 1 + buf[4] as usize + 2,
                    4 => 22,
                    _ => continue,
                };
                if n < off {
                    continue;
                }
                let up = UdpSocket::bind("127.0.0.1:0").unwrap();
                up.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let _ = up.send_to(&buf[off..n], echo_addr);
                let mut reply = [0u8; 65535];
                if let Ok((rn, _)) = up.recv_from(&mut reply) {
                    let mut out = vec![0u8, 0, 0, 1, 127, 0, 0, 1];
                    out.extend_from_slice(&echo_addr.port().to_be_bytes());
                    out.extend_from_slice(&reply[..rn]);
                    let _ = relay.send_to(&out, from);
                }
            }
        });
    }

    let front = dir.join("front.sock");
    let mut server = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--serve"])
        .arg(format!("unix:{}", front.display()))
        .args(["-x"])
        .arg(format!("unix:{}", socks.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if front.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let program = build_program(&dir, "udp-client-front", UDP_CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("unix:{}", front.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("UDP:9:ECHO:PING"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_proxies_ipv6_targets() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-v6-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client6", IPV6_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("HELLO-FROM-TARGET"), "{stdout:?}");
    // The address reaches the proxy as an IPv6 target, not as a name.
    assert_eq!(rx.recv().unwrap(), "2001:db8::1:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_uses_an_ambient_proxy() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client-env", CLIENT, false);
    // No -x: the proxy comes from the environment.
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--"])
        .arg(&program)
        .env("ALL_PROXY", format!("socks5://unix:{}", sock.display()))
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("HELLO-FROM-TARGET"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seccomp_backend_pins_names_with_map() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-map-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client-map", DNS_CLIENT, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--map", "example.com=1.2.3.4", "-x"])
        .arg(format!("unix:{}", sock.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DNS:1.2.3.4:18:HELLO-FROM-TARGET"),
        "{stdout:?}"
    );
    // The pinned address reaches the proxy, not a fake IP.
    assert_eq!(rx.recv().unwrap(), "1.2.3.4:80");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn doctor_json_is_machine_readable() {
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json is JSON");
    assert!(value["capabilities"].is_object());
    assert!(value["backend_seccomp"].is_boolean());
    assert!(value["backend_available"].is_boolean());
    // The exit code must agree with the report.
    let any = value["backend_available"].as_bool().unwrap();
    assert_eq!(out.status.success(), any);
}

/// A program named without a `/` is found in PATH, as `execvp` does.
#[test]
fn both_backends_find_a_program_in_path() {
    let dir = std::env::temp_dir().join(format!("pod-netns-path-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    if seccomp_available() {
        run_on("seccomp", &[&sock], std::path::Path::new("true"));
    }
    if netns_available() {
        run_on("netns", &[&sock], std::path::Path::new("true"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Issue 69: on the seccomp backend, an epoll listener wakes for an inbound
/// connection and is not readable again after the accept; and a thread
/// that blocks in accept does not stop the other system calls of the child.
const EPOLL_SERVER: &str = r#"
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
static int listen_on(int port, int flags){
  int s=socket(AF_INET,SOCK_STREAM|flags,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET;
  a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return -1;}
  if(listen(s,4)<0){perror("listen");return -1;}
  return s;
}
static void *blocked(void *arg){
  int c=accept(*(int*)arg,0,0);
  if(c>=0){ if(write(c,"T\n",2)<0){} close(c); }
  return 0;
}
int main(void){
  int s=listen_on(8090,SOCK_NONBLOCK); if(s<0) return 1;
  int ep=epoll_create1(0); struct epoll_event ev; memset(&ev,0,sizeof ev);
  ev.events=EPOLLIN; ev.data.fd=s; epoll_ctl(ep,EPOLL_CTL_ADD,s,&ev);
  int n=epoll_wait(ep,&ev,1,20000);
  if(n!=1){ printf("no event\n"); return 2; }
  int c=accept(s,0,0); if(c<0){ perror("accept"); return 3; }
  if(write(c,"E\n",2)<0){} close(c);
  printf("again %d\n", epoll_wait(ep,&ev,1,300));
  int s2=listen_on(8091,0); if(s2<0) return 4;
  pthread_t t; pthread_create(&t,0,blocked,&s2);
  usleep(300000);
  int u=socket(AF_INET,SOCK_DGRAM,0);
  printf("socket while blocked %d\n", u>=0); fflush(stdout);
  if(u>=0) close(u);
  pthread_join(t,0);
  printf("done\n");
  return 0;
}
"#;

#[test]
fn seccomp_inbound_wakes_epoll_and_accept_does_not_block_the_child() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-epoll-{}", std::process::id()));
    let inbound = dir.join("in");
    std::fs::create_dir_all(&inbound).unwrap();
    let proxy = dir.join("socks.sock");
    let listener = UnixListener::bind(&proxy).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));
    let server = build_program(&dir, "epoll-server", EPOLL_SERVER, false);
    let mut child = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--inbound-dir"])
        .arg(&inbound)
        .args(["-x"])
        .arg(format!("unix:{}", proxy.display()))
        .arg("--")
        .arg(&server)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let fetch = |port: u16| {
        let path = inbound.join(format!("{port}.sock"));
        for _ in 0..200 {
            if let Ok(mut c) = UnixStream::connect(&path) {
                c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut buf = [0u8; 8];
                let n = c.read(&mut buf).unwrap_or(0);
                return String::from_utf8_lossy(&buf[..n]).into_owned();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no inbound listener for port {port}");
    };
    assert_eq!(fetch(8090), "E\n", "epoll did not wake for the connection");
    assert_eq!(fetch(8091), "T\n");
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("the child did not end in 20 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert!(status.success(), "{out}");
    assert!(
        out.contains("again 0"),
        "the listener stayed readable: {out}"
    );
    assert!(out.contains("socket while blocked 1"), "{out}");
    assert!(out.contains("done"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Issue 61: the program does not get the proxy variables of the host (the
/// pod is its egress), and --keep-proxy-env keeps them.
#[test]
fn the_program_does_not_get_the_host_proxy() {
    if !seccomp_available() {
        eprintln!("skipping: no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let run = |keep: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pod-netns"));
        cmd.args(["--backend", "seccomp"]);
        if keep {
            cmd.arg("--keep-proxy-env");
        }
        let out = cmd
            .args(["-x", "socks5://127.0.0.1:1", "--", "sh", "-c", "env"])
            .env("HTTPS_PROXY", "http://127.0.0.1:3128")
            .env("no_proxy", "localhost")
            .output()
            .unwrap();
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (env, stderr) = run(false);
    assert!(!env.lines().any(|l| l.starts_with("HTTPS_PROXY=")), "{env}");
    assert!(!env.lines().any(|l| l.starts_with("no_proxy=")), "{env}");
    assert!(stderr.contains("does not get"), "{stderr}");
    let (env, _) = run(true);
    assert!(
        env.lines()
            .any(|l| l == "HTTPS_PROXY=http://127.0.0.1:3128"),
        "{env}"
    );
}

/// Issue 80: a connect to 127.0.0.1 in a seccomp pod goes to the host
/// listener, not to the proxy (here the proxy socket does not exist, so a
/// connect through it fails).
#[test]
fn seccomp_backend_sends_loopback_direct() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-loop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
            let _ = conn.write_all(b"LOCAL-SERVICE\n");
        }
    });
    let source = CLIENT
        .replace("htons(80)", &format!("htons({port})"))
        .replace("93.184.216.34", "127.0.0.1");
    let program = build_program(&dir, "client-loop", &source, false);
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "-x"])
        .arg(format!("unix:{}", dir.join("no-proxy.sock").display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("LOCAL-SERVICE"),
        "stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

const DNS6_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
    alarm(10);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6; hints.ai_socktype = SOCK_STREAM;
    int r = getaddrinfo("example.com", "80", &hints, &res);
    if (r != 0) { printf("GAI6:%d\n", r); return 1; }
    char ip[64] = {0};
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, ip, sizeof ip);
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 1; }
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("DNS6:%s:%d:%s", ip, n, b);
    return 0;
}
"#;

/// Issue 99: AAAA gets a fake ULA address, and connect maps it to the name.
#[test]
fn seccomp_backend_resolves_ipv6_by_name() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-dns6-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));

    let program = build_program(&dir, "client-dns6", DNS6_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(
        stdout.contains("DNS6:fd63:6672:7300::c612:0:18:HELLO-FROM-TARGET"),
        "{stdout:?}"
    );
    // The proxy gets the name, not the fake IPv6 address.
    assert_eq!(rx.recv().unwrap(), "example.com:80");

    // A name pinned to an IPv4 address has no AAAA: a clean EAI_NODATA, not
    // EAI_SYSTEM.
    let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--map", "example.com=1.2.3.4", "-x"])
        .arg(format!("unix:{}", sock.display()))
        .arg("--")
        .arg(&program)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("GAI6:-5") || stdout.contains("GAI6:-2"),
        "{stdout:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

const SOCKNAME_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    alarm(10);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in d; memset(&d, 0, sizeof d);
    d.sin_family = AF_INET; d.sin_port = htons(123);
    inet_pton(AF_INET, "162.159.200.1", &d.sin_addr);
    if (connect(s, (struct sockaddr *)&d, sizeof d) < 0) { perror("connect"); return 1; }
    /* A guard after the length: an 8-byte write over socklen_t breaks it. */
    struct { struct sockaddr_in a; socklen_t len; unsigned guard; } p;
    memset(&p, 0, sizeof p); p.len = sizeof p.a; p.guard = 0x5a5a5a5a;
    int r = getpeername(s, (struct sockaddr *)&p.a, &p.len);
    if (r < 0) { printf("PEER:-1:%s\n", errno == EOPNOTSUPP ? "EOPNOTSUPP" : strerror(errno)); return 0; }
    char ip[32]; inet_ntop(AF_INET, &p.a.sin_addr, ip, sizeof ip);
    printf("PEER:%d:%u:%s:%d:guard=%x\n", p.a.sin_family, (unsigned)p.len, ip, ntohs(p.a.sin_port), p.guard);
    return 0;
}
"#;

/// Issue 98: getpeername of a pod socket gives the AF_INET address, through
/// /proc/<pid>/mem or through process_vm_writev; with no way to write the
/// memory of the program, it fails with EOPNOTSUPP (not the AF_UNIX pair).
#[test]
fn getpeername_is_the_inet_address_or_eopnotsupp() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-sockname-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, _rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));
    let program = build_program(&dir, "sockname", SOCKNAME_CLIENT, false);
    let run_with = |hook: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
            .args(["--backend", "seccomp", "-x"])
            .arg(format!("unix:{}", sock.display()))
            .arg("--")
            .arg(&program)
            .env("POD_NETNS_TEST_MEM", hook)
            .output()
            .unwrap();
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    };
    let want = "PEER:2:16:162.159.200.1:123:guard=5a5a5a5a";
    let (out, err) = run_with("");
    assert!(out.contains(want), "{out:?} {err:?}");
    let (out, err) = run_with("no-fd");
    assert!(out.contains(want), "process_vm_writev: {out:?} {err:?}");
    let (out, err) = run_with("none");
    assert!(out.contains("PEER:-1:EOPNOTSUPP"), "{out:?} {err:?}");
    assert!(err.contains("refuses writes to the memory"), "{err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

const UNSPEC_CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
int main(void) {
    alarm(20);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    int r = getaddrinfo("example.com", "80", &hints, &res);
    printf("GAI:%d\n", r);
    if (r != 0) return 1;
    int s = socket(res->ai_family, SOCK_STREAM, 0);
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) { perror("connect"); return 1; }
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("READ:%d:%s", n, b);
    return 0;
}
"#;

/// Issue 113: getaddrinfo with AF_UNSPEC (the default of most programs)
/// works in the pod, also when the supervisor cannot write the memory of
/// the program (glibc sends A and AAAA with one sendmmsg; the pod sets
/// RES_OPTIONS=single-request). Before, it failed with "Temporary failure
/// in name resolution" under POD_NETNS_TEST_MEM=none.
#[test]
fn seccomp_backend_resolves_unspec_without_memory_writes() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-unspec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_proxy(listener, tx, false));
    let program = build_program(&dir, "unspec", UNSPEC_CLIENT, false);
    for (hook, res_options) in [
        ("", None),
        ("no-fd", None),
        ("none", None),
        ("none", Some("ndots:1")),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pod-netns"));
        command
            .args(["--backend", "seccomp", "-x"])
            .arg(format!("unix:{}", sock.display()))
            .arg("--")
            .arg(&program)
            .env("POD_NETNS_TEST_MEM", hook);
        match res_options {
            Some(v) => command.env("RES_OPTIONS", v),
            None => command.env_remove("RES_OPTIONS"),
        };
        let output = command.output().unwrap();
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(
            out.contains("GAI:0"),
            "{hook:?} {res_options:?}: {out:?} {err:?}"
        );
        assert!(
            out.contains("HELLO-FROM-TARGET"),
            "{hook:?}: {out:?} {err:?}"
        );
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            "example.com:80"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

const IO_URING_CLIENT: &str = r#"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(void) {
    char params[120]; memset(params, 0, sizeof params);
    long r = syscall(SYS_io_uring_setup, 4, params);
    printf("URING:%ld:%s\n", r, r < 0 && errno == EPERM ? "EPERM" : strerror(errno));
    return 0;
}
"#;

/// Issue 98: an errno of the supervisor is a failure of the system call
/// (-1 and errno), not a positive return value. io_uring is refused with
/// EPERM.
#[test]
fn a_refused_system_call_fails_with_its_errno() {
    if !have_compiler() || !seccomp_available() {
        eprintln!("skipping: no compiler or no SECCOMP_RET_USER_NOTIF");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pod-netns-uring-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let program = build_program(&dir, "uring", IO_URING_CLIENT, false);
    let stdout = run(&dir, &[&sock], &program);
    assert!(stdout.contains("URING:-1:EPERM"), "{stdout:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
