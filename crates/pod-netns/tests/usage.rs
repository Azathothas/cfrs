//! Usage errors of `pod-netns` (issue 62): each bad upstream or rule exits
//! 64, and the program does not run (it would make a marker file).

use std::process::Command;

#[path = "../../../tests/test_host/mod.rs"]
mod test_host;

#[test]
fn a_bad_upstream_or_rule_exits_64_and_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let cases: &[&[&str]] = &[
        &["-x", "bad"],
        &["-x", "socks4://127.0.0.1:1080"],
        &["-x", "http://"],
        &["-x", "socks5://"],
        &["-x", "https://unix:/x"],
        &["-x", "http://unix:"],
        &["-x", "socks5://127.0.0.1:1", "--rule", "bad"],
        &[
            "-x",
            "socks5://127.0.0.1:1",
            "--rule",
            "domain:example.com=bad",
        ],
    ];
    for case in cases {
        let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
            .args(*case)
            .arg("--")
            .arg("touch")
            .arg(&marker)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(64),
            "{case:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!marker.exists(), "{case:?}: the program ran");
    }
}

/// Issue 306: the seccomp backend refuses an inbound directory that the
/// group or others can write, before the program runs.
#[test]
fn an_inbound_directory_that_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let open = dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let marker = dir.path().join("ran");
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--backend", "seccomp", "--inbound-dir"])
        .arg(&open)
        .args(["-x", "socks5://127.0.0.1:9", "--", "touch"])
        .arg(&marker)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("writable by the group or by others"), "{err}");
    assert!(!marker.exists(), "the program ran");
}

/// Issue 300: `--serve tcp://127.0.0.1:0` prints the port that the kernel
/// chose, and a client connects to it.
#[test]
fn a_port_0_front_door_prints_the_bound_port() {
    test_host::need_loopback!();
    use std::io::BufRead;
    let mut child = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .args(["--serve", "tcp://127.0.0.1:0", "-x", "socks5://127.0.0.1:9"])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let line = lines
        .find_map(|l| l.ok().filter(|l| l.starts_with("pod-netns: serving ")))
        .expect("a serving line");
    let addr: std::net::SocketAddr = line
        .trim_start_matches("pod-netns: serving tcp://")
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap_or_else(|e| panic!("{line}: {e}"));
    let connect = std::net::TcpStream::connect(addr);
    let _ = child.kill();
    let _ = child.wait();
    assert_ne!(addr.port(), 0, "{line}");
    connect.unwrap_or_else(|e| panic!("connect to {addr}: {e}"));
}
