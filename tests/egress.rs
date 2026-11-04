//! The egress of cfrs, end to end, with local stand-ins: a quick-tunnel API,
//! a SOCKS5 proxy, an HTTP proxy that answers 407, and an edge that only
//! counts its connections. No test here uses the network.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A quick-tunnel API on plain HTTP. With `ok`, it gives a tunnel; else 503.
fn api(ok: bool) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let (status, body) = if ok {
                (
                    "200 OK",
                    r#"{"success":true,"result":{"id":"6ff42ae2-765d-4adf-8112-31c55c1551ef","hostname":"test.trycloudflare.com","account_tag":"0123456789abcdef","secret":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}}"#,
                )
            } else {
                ("403 Forbidden", "the stand-in API")
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, hits)
}

/// A SOCKS5 proxy. With `auth`, it asks for that user and password. It keeps
/// each target that it is asked for.
fn socks5(auth: Option<(&'static str, &'static str)>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = targets.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let _ = serve_socks5(client, auth, &seen);
            });
        }
    });
    (port, targets)
}

fn serve_socks5(
    mut c: TcpStream,
    auth: Option<(&str, &str)>,
    seen: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    c.read_exact(&mut head)?;
    let mut methods = vec![0u8; head[1] as usize];
    c.read_exact(&mut methods)?;
    match auth {
        None => c.write_all(&[5, 0])?,
        Some((user, pass)) => {
            if !methods.contains(&2) {
                c.write_all(&[5, 0xff])?;
                return Ok(());
            }
            c.write_all(&[5, 2])?;
            let mut v = [0u8; 2];
            c.read_exact(&mut v)?;
            let mut u = vec![0u8; v[1] as usize];
            c.read_exact(&mut u)?;
            let mut l = [0u8; 1];
            c.read_exact(&mut l)?;
            let mut p = vec![0u8; l[0] as usize];
            c.read_exact(&mut p)?;
            if u != user.as_bytes() || p != pass.as_bytes() {
                c.write_all(&[1, 1])?;
                return Ok(());
            }
            c.write_all(&[1, 0])?;
        }
    }
    let mut req = [0u8; 4];
    c.read_exact(&mut req)?;
    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            c.read_exact(&mut ip)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l)?;
            let mut name = vec![0u8; l[0] as usize];
            c.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    c.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    seen.lock().unwrap().push(format!("{host}:{port}"));
    let target = match TcpStream::connect((
        if host == "localhost" {
            "127.0.0.1"
        } else {
            host.as_str()
        },
        port,
    )) {
        Ok(t) => t,
        Err(_) => {
            c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return Ok(());
        }
    };
    c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
    let (mut a, mut b) = (c.try_clone()?, target.try_clone()?);
    let (mut c2, mut t2) = (c, target);
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut a, &mut t2);
        let _ = t2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut b, &mut c2);
    let _ = c2.shutdown(std::net::Shutdown::Write);
    Ok(())
}

/// An HTTP proxy that answers each CONNECT with 407.
fn proxy_407() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM, Negotiate\r\nContent-Length: 0\r\n\r\n");
        }
    });
    port
}

/// An "edge" that counts its connections and closes each one.
fn edge() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    (port, hits)
}

fn cfrs(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
    cmd.args(args)
        .env("RUST_LOG", "cfrs=info")
        .env_remove("CFRS_ERROR_PROGRAM")
        .env_remove("CFRS_EDGE");
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A SOCKS5 proxy, with and without a password, carries the request of the
/// quick-tunnel API and the HTTP/2 dial of the edge. With a proxy, auto does
/// not try QUIC, and one line says why.
#[test]
fn socks5_carries_the_api_and_the_edge() {
    for auth in [None, Some(("alice", "s3cret"))] {
        let (api_port, api_hits) = api(true);
        let (edge_port, edge_hits) = edge();
        let (socks_port, targets) = socks5(auth);
        let proxy = match auth {
            None => format!("socks5h://127.0.0.1:{socks_port}"),
            Some((u, p)) => format!("socks5h://{u}:{p}@127.0.0.1:{socks_port}"),
        };
        let api_url = format!("http://localhost:{api_port}");
        let edge_addr = format!("127.0.0.1:{edge_port}");
        let (code, text) = cfrs(
            &[
                "tunnel",
                "--hello-world",
                "--service-url",
                &api_url,
                "--no-verify",
            ],
            &[("ALL_PROXY", &proxy), ("CFRS_EDGE", &edge_addr)],
        );
        assert_ne!(code, Some(0), "{text}");
        assert_eq!(api_hits.load(Ordering::SeqCst), 1, "{text}");
        assert!(
            edge_hits.load(Ordering::SeqCst) >= 1,
            "the edge got no connection:\n{text}"
        );
        let targets = targets.lock().unwrap().clone();
        assert!(
            targets.contains(&format!("localhost:{api_port}")),
            "{targets:?}"
        );
        assert!(targets.contains(&edge_addr), "{targets:?}");
        assert!(text.contains("no proxy carries UDP"), "{text}");
        assert!(!text.contains("leg=quic "), "{text}");
        if let Some((_, pass)) = auth {
            assert!(!text.contains(pass), "{text}");
        }
    }

    // A wrong password is refused by the proxy, and the message says so.
    let (api_port, _) = api(true);
    let (socks_port, _) = socks5(Some(("alice", "s3cret")));
    let proxy = format!("socks5h://alice:wrong@127.0.0.1:{socks_port}");
    let api_url = format!("http://localhost:{api_port}");
    let (_, text) = cfrs(
        &["tunnel", "--hello-world", "--service-url", &api_url],
        &[("ALL_PROXY", &proxy), ("CFRS_EDGE", "127.0.0.1:9")],
    );
    assert!(
        text.contains("the proxy refused the user and the password"),
        "{text}"
    );
}

/// NO_PROXY sends the request around the proxy; without it, the request
/// takes the proxy (which is closed here).
#[test]
fn no_proxy_bypasses_the_proxy() {
    let (api_port, hits) = api(false);
    let api_url = format!("http://127.0.0.1:{api_port}");
    let closed = "http://127.0.0.1:9";
    let args = ["tunnel", "--hello-world", "--service-url", &api_url];
    let env = [("HTTPS_PROXY", closed), ("CFRS_EDGE", "127.0.0.1:9")];

    let (_, text) = cfrs(&args, &env);
    assert!(
        text.contains("through the proxy http://127.0.0.1:9"),
        "{text}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let (_, text) = cfrs(
        &args,
        &[env[0], env[1], ("NO_PROXY", "127.0.0.1,.example.com")],
    );
    assert!(text.contains("HTTP 403"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let (_, text) = cfrs(&[&args[..], &["--no-proxy"]].concat(), &env);
    assert!(text.contains("HTTP 403"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// A 407 names each scheme that the proxy asks for.
#[test]
fn a_407_names_the_schemes() {
    let port = proxy_407();
    let proxy = format!("http://127.0.0.1:{port}");
    let (code, text) = cfrs(
        &[
            "tunnel",
            "--hello-world",
            "--service-url",
            "http://api.example:80",
        ],
        &[("HTTPS_PROXY", &proxy), ("CFRS_EDGE", "127.0.0.1:9")],
    );
    assert_ne!(code, Some(0));
    assert!(text.contains("HTTP 407"), "{text}");
    assert!(text.contains("NTLM or Negotiate"), "{text}");
    assert!(
        text.contains("cfrs supports Basic and Digest only"),
        "{text}"
    );
}

/// An address that does not answer delays the dial by one attempt delay,
/// not by its own time-out.
#[tokio::test]
async fn a_silent_address_does_not_hold_the_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let good = listener.local_addr().unwrap();
    // TEST-NET-1: no host answers there.
    let silent: std::net::SocketAddr = "192.0.2.1:9".parse().unwrap();
    let start = Instant::now();
    let (index, _stream) = cfrs::egress::dial_addrs(&[silent, good], Duration::from_secs(10))
        .await
        .unwrap();
    let took = start.elapsed();
    assert_eq!(index, 1);
    assert!(took < Duration::from_millis(1000), "the dial took {took:?}");
}

/// A proxy that refuses with a text: the error line keeps the text, and
/// the second line names the proxy hop.
#[test]
fn a_proxy_refusal_names_the_hop_and_keeps_the_text() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let body = "not on the egress allowlist\n";
            let _ = write!(
                s,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
    });
    let proxy = format!("http://127.0.0.1:{port}");
    let (code, text) = cfrs(
        &[
            "tunnel",
            "--hello-world",
            "--service-url",
            "https://api.example",
        ],
        &[("HTTPS_PROXY", &proxy), ("CFRS_EDGE", "127.0.0.1:9")],
    );
    assert_eq!(code, Some(69), "{text}");
    assert!(
        text.contains(
            "the proxy refused CONNECT with HTTP 403: Forbidden: not on the egress allowlist"
        ),
        "{text}"
    );
    assert!(text.contains("cfrs: the proxy hop failed; "), "{text}");
}

/// Issue 259: a proxy host that does not resolve. The DoH query of the
/// chain went through the same proxy, whose dial resolved the host again:
/// the stack overflowed (SIGABRT). Now the run exits 69 and names the
/// proxy host.
#[test]
fn a_proxy_host_that_does_not_resolve_is_an_error_not_a_crash() {
    let (code, text) = cfrs(
        &["update", "--check"],
        &[("HTTPS_PROXY", "http://cfrs-proxy.invalid:8080")],
    );
    assert_eq!(code, Some(69), "{text}");
    assert!(text.contains("the proxy host cfrs-proxy.invalid"), "{text}");
}
