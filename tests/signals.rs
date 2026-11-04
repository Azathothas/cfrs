//! Stop signals (issue 91): SIGHUP and SIGTERM start the clean shutdown
//! also with --run-for, and SIGHUP stays ignored when the parent ignored
//! it (nohup).

mod test_host;

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cfrs-signals-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `cfrs net proxy --run-for 300` on a unix socket in `dir`; ready when the
/// socket is there.
fn start(dir: &Path, ignore_hup: bool) -> Child {
    let socket = dir.join("s.sock");
    let mut command = Command::new(env!("CARGO_BIN_EXE_cfrs"));
    command
        .args(["net", "proxy", "--run-for", "300", "--listen"])
        .arg(format!("unix:{}", socket.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("err.txt")).unwrap());
    if ignore_hup {
        // SAFETY: signal() only, between fork and exec.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                Ok(())
            });
        }
    }
    let child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "net proxy did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    // The socket comes just before the ready, which arms the stop signals.
    std::thread::sleep(Duration::from_millis(300));
    child
}

fn wait(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn signal(child: &Child, signal: libc::c_int) {
    // SAFETY: kill() to our own child.
    unsafe { libc::kill(child.id() as i32, signal) };
}

#[test]
fn sighup_and_sigterm_stop_with_run_for_and_exit_0() {
    for (number, name) in [(libc::SIGHUP, "SIGHUP"), (libc::SIGTERM, "SIGTERM")] {
        let dir = temp_dir(name);
        let mut child = start(&dir, false);
        signal(&child, number);
        let status = wait(&mut child, Duration::from_secs(10)).expect("the process did not stop");
        let log = std::fs::read_to_string(dir.join("err.txt")).unwrap();
        assert_eq!(status.code(), Some(0), "{name}: {status:?}\n{log}");
        assert!(log.contains(&format!("{name}: stopping")), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn an_ignored_sighup_stays_ignored() {
    let dir = temp_dir("nohup");
    let mut child = start(&dir, true);
    signal(&child, libc::SIGHUP);
    assert!(
        wait(&mut child, Duration::from_secs(1)).is_none(),
        "SIGHUP stopped a process that started with SIGHUP ignored"
    );
    signal(&child, libc::SIGTERM);
    let status = wait(&mut child, Duration::from_secs(10)).expect("the process did not stop");
    assert_eq!(status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A provisioning service that answers each request with 429 and
/// Retry-After: 100; its port.
fn refusing_service() -> u16 {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = r#"{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 100\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

/// The PID (in this namespace) of the one child of `pid`.
fn child_of(pid: u32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

// Issue 208: cfrs as PID 1 of a PID namespace (a container with no init)
// stops on SIGTERM before the ready line. Before, the kernel dropped the
// raised signal, and cfrs went on.
#[test]
fn a_sigterm_to_pid_1_during_provisioning_stops_cfrs() {
    test_host::need_loopback!();
    let ok = Command::new("unshare")
        .args([
            "--pid",
            "--fork",
            "--user",
            "--map-root-user",
            "--mount-proc",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping: no unshare of a PID namespace");
        return;
    }
    let service = refusing_service();
    let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = origin.local_addr().unwrap().port().to_string();
    let dir = temp_dir("pid1");
    let err = dir.join("err.txt");
    let mut child = Command::new("unshare")
        .args([
            "--pid",
            "--fork",
            "--user",
            "--map-root-user",
            "--mount-proc",
        ])
        .arg(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--port", &port, "--no-verify", "--service-url"])
        .arg(format!("http://127.0.0.1:{service}"))
        .env_remove("CFRS_ERROR_PROGRAM")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&err).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let log = std::fs::read_to_string(&err).unwrap_or_default();
        if log.contains("429") || log.to_lowercase().contains("again") {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("cfrs ended before the retry: {status:?}\n{log}");
        }
        assert!(Instant::now() < deadline, "no retry line\n{log}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let cfrs = child_of(child.id()).expect("the cfrs process");
    // SAFETY: kill() to our own grandchild.
    unsafe { libc::kill(cfrs as i32, libc::SIGTERM) };
    let status = wait(&mut child, Duration::from_secs(5));
    let log = std::fs::read_to_string(&err).unwrap_or_default();
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        unsafe { libc::kill(cfrs as i32, libc::SIGKILL) };
    }
    let status = status.unwrap_or_else(|| panic!("cfrs did not stop\n{log}"));
    assert_eq!(status.code(), Some(143), "{status:?}\n{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
