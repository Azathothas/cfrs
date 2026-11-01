//! Usage errors of `pod-netns` (issue 62): each bad upstream or rule exits
//! 64, and the program does not run (it would make a marker file).

use std::process::Command;

#[test]
fn a_bad_upstream_or_rule_exits_64_and_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let cases: &[&[&str]] = &[
        &["-x", "bad"],
        &["-x", "socks4://127.0.0.1:1080"],
        &["-x", "http://"],
        &["-x", "socks5://"],
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
