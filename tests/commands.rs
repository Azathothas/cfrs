//! T-011: the behaviour of the commands that only the pins of the command
//! tree covered: `bug-report`, `qr`, `net demo`, `autostart run` and
//! `agent status`. Each test runs the binary with its own state directory
//! and run directory.

mod test_host;

use std::path::PathBuf;
use std::process::{Command, Output};

struct Env {
    tmp: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Env {
            tmp: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podnet"));
        cmd.args(args)
            .env("HOME", self.tmp.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("PODNET_RUN_DIR", self.path("run"))
            .env_remove("RUST_LOG")
            .env_remove("PODNET_ERROR_PROGRAM")
            .env_remove("PODNET_EDGE");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }
}

fn text(out: &Output) -> String {
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

#[test]
fn bug_report_names_the_version_and_no_secret() {
    let env = Env::new();
    let secret = "pw0f-the-bug-report-test";
    let token = "tok3n-of-the-bug-report-test";
    let out = env
        .cmd(&["bug-report"])
        .env("HTTPS_PROXY", format!("http://user:{secret}@127.0.0.1:9"))
        .env("TUNNEL_TOKEN", token)
        .output()
        .unwrap();
    let report = text(&out);
    let version = env!("CARGO_PKG_VERSION");
    assert!(report.starts_with("podnet bug-report\n"), "{report}");
    assert!(report.contains(&format!("podnet {version}")), "{report}");
    // The status part is there, and the names of the variables.
    assert!(report.contains("## status"), "{report}");
    assert!(report.contains("\"credentials\": true"), "{report}");
    let names = report.split("variables that are set").nth(1).unwrap();
    assert!(
        names.lines().any(|l| l.trim() == "TUNNEL_TOKEN"),
        "{report}"
    );
    assert!(names.lines().any(|l| l.trim() == "HTTPS_PROXY"), "{report}");
    // No value of a secret.
    assert!(!report.contains(secret), "{report}");
    assert!(!report.contains(token), "{report}");
}

#[test]
fn qr_prints_the_matrix_of_a_url() {
    let env = Env::new();
    let url = "https://example.trycloudflare.com/";
    let out = text(&env.run(&["qr", url]));
    let want = podnet::qr::render_terminal(url).unwrap();
    assert_eq!(out.trim_end(), want.trim_end());
    // A square matrix with its quiet zone: two modules for each line of
    // text, each line of the same width.
    let lines: Vec<&str> = out.lines().collect();
    let width = lines[0].chars().count();
    assert!(width >= 29, "{out}");
    assert!(lines.iter().all(|l| l.chars().count() == width), "{out}");
    assert_eq!(lines.len(), width.div_ceil(2), "{out}");
    assert!(out.contains('█'), "{out}");
    // Another URL gives another matrix.
    let other = text(&env.run(&["qr", "https://example.org/"]));
    assert_ne!(out, other);
}

#[test]
fn net_demo_ends_with_success() {
    let env = Env::new();
    let out = text(&env.run(&["net", "demo"]));
    assert!(
        out.contains("states at the exchange: server ESTABLISHED, client ESTABLISHED"),
        "{out}"
    );
    assert!(
        out.contains("PROOF: userspace TCP handshake, request/response and teardown complete"),
        "{out}"
    );
}

#[test]
fn autostart_run_starts_the_recorded_command() {
    let env = Env::new();
    let dir = env.path("autostart");
    std::fs::create_dir_all(&dir).unwrap();
    // The entry runs `podnet bug-report` with one variable of its env file:
    // the report names the variable, so the arguments and the env file
    // both reached the new process.
    std::fs::write(dir.join("web.args"), r#"["bug-report"]"#).unwrap();
    std::fs::write(
        dir.join("web.env"),
        "# podnet autostart: the variables of this entry. Mode 0600.\nPODNET_AUTOSTART_PROBE=1\n",
    )
    .unwrap();
    let out = text(&env.run(&["autostart", "run", "web", "--dir", dir.to_str().unwrap()]));
    assert!(out.starts_with("podnet bug-report\n"), "{out}");
    assert!(
        out.lines().any(|l| l.trim() == "PODNET_AUTOSTART_PROBE"),
        "{out}"
    );
    // An entry that does not exist is a configuration fault (exit 78).
    let out = env.run(&["autostart", "run", "none", "--dir", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(78));
}

#[test]
fn agent_status_with_no_agent_names_each_task() {
    test_host::need_loopback!();
    let env = Env::new();
    // A proxy that refuses at once, so that each proxy probe ends fast.
    let out = env
        .cmd(&["agent", "status"])
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env_remove("ALL_PROXY")
        .env_remove("NO_PROXY")
        .output()
        .unwrap();
    let out = text(&out);
    assert!(out.starts_with("podnet: no detached instance\n"), "{out}");
    assert!(out.contains("podnet warp up: does not run"), "{out}");
    let head = out
        .lines()
        .find(|l| l.starts_with("TASK"))
        .unwrap_or_else(|| panic!("{out}"));
    for col in ["TARGET", "DIRECT", "PROXY", "WARP"] {
        assert!(head.contains(col), "{head}");
    }
    for task in [
        "git (HTTPS)",
        "git (SSH)",
        "pip (pypi.org)",
        "npm",
        "docker pull",
    ] {
        assert!(out.lines().any(|l| l.starts_with(task)), "{task}: {out}");
    }
    assert!(out.contains("This host, direct (no WARP):"), "{out}");
}
