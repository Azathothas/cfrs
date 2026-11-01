//! Stop signals (issue 91): SIGHUP and SIGTERM start the clean shutdown
//! also with --run-for, and SIGHUP stays ignored when the parent ignored
//! it (nohup).

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
