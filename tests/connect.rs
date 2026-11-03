//! `cfrs connect` against local fakes: the egress layer (issues 191 and
//! 198), the start check (issue 207) and the socket file (issue 202).

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const NAME: &str = "ws-pin-test.invalid";

/// Echo each message of a server WebSocket on `socket`.
async fn echo<S>(socket: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
        return;
    };
    while let Some(Ok(message)) = ws.next().await {
        if message.is_binary() || message.is_text() {
            if ws.send(message).await.is_err() {
                return;
            }
        } else if message.is_close() {
            return;
        }
    }
}

/// A WebSocket echo server on loopback; its port.
async fn echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(echo(socket));
        }
    });
    port
}

/// An HTTP CONNECT proxy on loopback that records each request line and
/// then speaks the WebSocket echo itself (no dial).
async fn fake_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = lines.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                seen.lock()
                    .unwrap()
                    .push(head.lines().next().unwrap_or("").to_string());
                if socket
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                echo(socket).await;
            });
        }
    });
    (port, lines)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cfrs-connect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cfrs(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
    cmd.args(args)
        .env_remove("CFRS_ERROR_PROGRAM")
        .env_remove("CFRS_RESOLVE")
        .env_remove("CFRS_PROXY")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

fn wait_for(path: &Path, child: &mut Child) {
    let start = Instant::now();
    while !path.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            panic!("cfrs ended: {status:?}: {err}");
        }
        assert!(start.elapsed() < Duration::from_secs(30), "no listener");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Send `data` through the unix listener at `path`; the echo.
fn round_trip(path: &Path, data: &[u8]) -> Vec<u8> {
    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream.write_all(data).unwrap();
    let mut back = vec![0u8; data.len()];
    stream.read_exact(&mut back).unwrap();
    back
}

fn stop(child: Child) -> (Option<i32>, String) {
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// Issue 191: connect dials through --proxy; the name goes to the proxy, and
// no DNS is used. Issue 202: the socket file is removed at the end.
#[tokio::test(flavor = "multi_thread")]
async fn connect_dials_through_the_proxy() {
    let (port, lines) = fake_proxy().await;
    let dir = temp_dir("proxy");
    let sock = dir.join("s.sock");
    let proxy = format!("http://127.0.0.1:{port}");
    let local = format!("unix://{}", sock.display());
    let remote = format!("ws://{NAME}/__cfrs/ws");
    let mut child = cfrs(&["--proxy", &proxy, "connect", &remote, "-L", &local])
        .spawn()
        .unwrap();
    let path = sock.clone();
    let child = tokio::task::spawn_blocking(move || {
        wait_for(&path, &mut child);
        assert_eq!(round_trip(&path, b"hello"), b"hello");
        child
    })
    .await
    .unwrap();
    let (code, err) = stop(child);
    assert_eq!(code, Some(0), "{err}");
    let lines = lines.lock().unwrap().clone();
    // The check at start, then the client.
    assert_eq!(lines.len(), 2, "{lines:?}");
    for line in &lines {
        assert!(line.starts_with(&format!("CONNECT {NAME}:80 ")), "{line}");
    }
    assert!(!sock.exists(), "the socket file is left");
    let _ = std::fs::remove_dir_all(&dir);
}

// Issue 191: connect uses the pins of --resolve.
#[tokio::test(flavor = "multi_thread")]
async fn connect_uses_resolve_pins() {
    let port = echo_server().await;
    let dir = temp_dir("pins");
    let sock = dir.join("s.sock");
    let local = format!("unix://{}", sock.display());
    let remote = format!("ws://{NAME}:{port}/__cfrs/ws");
    let pin = format!("{NAME}=127.0.0.1");
    let mut child = cfrs(&[
        "--no-proxy",
        "--resolve",
        &pin,
        "connect",
        &remote,
        "-L",
        &local,
    ])
    .spawn()
    .unwrap();
    let path = sock.clone();
    let child = tokio::task::spawn_blocking(move || {
        wait_for(&path, &mut child);
        assert_eq!(round_trip(&path, b"pinned"), b"pinned");
        child
    })
    .await
    .unwrap();
    let (code, err) = stop(child);
    assert_eq!(code, Some(0), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

// Issue 207: a remote that does not answer at start exits 69, and no
// listener stays.
#[test]
fn connect_exits_69_when_the_remote_does_not_answer() {
    let dir = temp_dir("dead");
    let sock = dir.join("s.sock");
    let local = format!("unix://{}", sock.display());
    let out = cfrs(&[
        "--proxy",
        "http://127.0.0.1:1",
        "connect",
        "ws://dead.invalid/__cfrs/ws",
        "-L",
        &local,
    ])
    .output()
    .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(69), "{err}");
    assert!(err.contains("--no-check"), "{err}");
    assert!(!sock.exists(), "the socket file is left");
    // --no-check starts with the same dead remote.
    let out = cfrs(&[
        "--proxy",
        "http://127.0.0.1:1",
        "connect",
        "ws://dead.invalid/__cfrs/ws",
        "-L",
        &local,
        "--no-check",
        "--run-for",
        "1",
    ])
    .output()
    .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// Issue 202: a socket that answers is not taken, except with --replace. A
// stale socket file is replaced. Another kind of file is not removed.
#[test]
fn connect_keeps_a_live_socket_and_other_files() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = temp_dir("live");
    let sock = dir.join("s.sock");
    let local = format!("unix://{}", sock.display());
    let base = [
        "connect",
        "ws://127.0.0.1:9/__cfrs/ws",
        "-L",
        local.as_str(),
        "--no-check",
        "--run-for",
        "1",
    ];

    let live = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let ino = std::fs::metadata(&sock).unwrap().ino();
    let out = cfrs(&base).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(69), "{err}");
    assert!(err.contains("served by another process"), "{err}");
    assert_eq!(std::fs::metadata(&sock).unwrap().ino(), ino);

    let mut replace = base.to_vec();
    replace.push("--replace");
    let out = cfrs(&replace).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(live);

    // A stale socket file (nobody answers) is replaced.
    let _stale = std::os::unix::net::UnixListener::bind(&sock).map(drop);
    let out = cfrs(&base).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!sock.exists(), "the socket file is left");

    std::fs::write(&sock, "data").unwrap();
    let out = cfrs(&base).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(64), "{err}");
    assert_eq!(std::fs::read_to_string(&sock).unwrap(), "data");
    let _ = std::fs::remove_dir_all(&dir);
}

// Issue 207: connect --detach prints the ready document with the
// listeners; cfrs ps lists it; cfrs stop ends it and removes the socket.
#[test]
fn connect_detach_is_in_ps_and_stops() {
    let dir = temp_dir("detach");
    let run = dir.join("run");
    let sock = dir.join("s.sock");
    let local = format!("unix://{}", sock.display());
    let with_run = |args: &[&str]| {
        let mut cmd = cfrs(args);
        cmd.env("CFRS_RUN_DIR", &run).stdout(Stdio::piped());
        cmd.output().unwrap()
    };
    let start = with_run(&[
        "connect",
        "ws://127.0.0.1:9/__cfrs/ws",
        "-L",
        &local,
        "--no-check",
        "--detach",
        "--name",
        "c1",
    ]);
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let text = String::from_utf8_lossy(&start.stdout);
    let doc: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(doc["name"], "c1", "{doc}");
    assert!(doc["listen"].as_str().unwrap().contains("s.sock"), "{doc}");
    let ps = with_run(&["ps", "--json"]);
    let ps: serde_json::Value = serde_json::from_slice(&ps.stdout).unwrap();
    assert!(
        ps["instances"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["name"] == "c1"),
        "{ps}"
    );
    assert!(sock.exists());
    let stop = with_run(&["stop", "c1", "--timeout", "5"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let start = Instant::now();
    while sock.exists() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!sock.exists(), "the socket file is left");
    let _ = std::fs::remove_dir_all(&dir);
}
