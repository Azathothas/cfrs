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

/// A SOCKS5 server on a unix socket that stands in for the socket of a
/// running `podnet warp up`: it takes one CONNECT and joins it to the
/// target on the loopback.
fn socks_stand_in(path: &std::path::Path) -> std::thread::JoinHandle<()> {
    let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        // The first connections can be probes that send nothing.
        for c in listener.incoming() {
            if serve(c.unwrap()).is_ok() {
                return;
            }
        }
    })
}

fn serve(mut c: std::os::unix::net::UnixStream) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};
    let mut b = [0u8; 2];
    c.read_exact(&mut b)?;
    let mut m = vec![0u8; b[1] as usize];
    c.read_exact(&mut m)?;
    c.write_all(&[5, 0])?;
    let mut h = [0u8; 4];
    c.read_exact(&mut h)?;
    let host = match h[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a)?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            c.read_exact(&mut n)?;
            let mut a = vec![0u8; n[0] as usize];
            c.read_exact(&mut a)?;
            String::from_utf8(a).unwrap()
        }
        t => panic!("address type {t}"),
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p)?;
    let t = std::net::TcpStream::connect((host.as_str(), u16::from_be_bytes(p)))?;
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let (mut c2, mut t2) = (c.try_clone()?, t.try_clone()?);
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut t2);
        let _ = t2.shutdown(std::net::Shutdown::Write);
    });
    let (mut t3, mut c3) = (t, c);
    let _ = std::io::copy(&mut t3, &mut c3);
    let _ = c3.shutdown(std::net::Shutdown::Write);
    up.join().unwrap();
    Ok(())
}

#[test]
fn warp_nc_finds_warp_up_of_another_state_directory() {
    use std::io::{Read as _, Write as _};
    test_host::need_loopback!();
    let env = Env::new();
    // An echo server, the target of warp nc.
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut s, _) = echo.accept().unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        s.write_all(&buf).unwrap();
    });
    // The socket of a warp up with another state directory. Only the
    // pointer file in the runtime directory names it.
    let other = env.path("other-run");
    std::fs::create_dir_all(&other).unwrap();
    let socket = other.join("warp.sock");
    let stand_in = socks_stand_in(&socket);
    let pointer_dir = env.path("runtime").join("podnet");
    std::fs::create_dir_all(&pointer_dir).unwrap();
    let pointer = serde_json::json!({"socket": socket, "state_dir": env.path("other")});
    let file = pointer_dir.join("warp-up.json");
    std::fs::write(&file, pointer.to_string()).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut child = env
        .cmd(&["warp", "nc", "-N", "127.0.0.1", &port.to_string()])
        .env_remove("PODNET_WARP_SOCKET")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(text(&out), "hello\n");
    stand_in.join().unwrap();
}

#[test]
fn warp_exec_names_each_socket_tried() {
    let env = Env::new();
    let out = env
        .cmd(&["warp", "exec", "--", "true"])
        .env("PODNET_WARP_SOCKET", env.path("nothing.sock"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(69));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("nothing.sock (PODNET_WARP_SOCKET)"), "{err}");
    assert!(err.contains("warp.sock (the run directory)"), "{err}");
    // --socket: only that socket.
    let out = env
        .cmd(&[
            "warp",
            "exec",
            "--socket",
            "/nonexistent/s.sock",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("/nonexistent/s.sock (--socket)"), "{err}");
    assert!(!err.contains("run directory"), "{err}");
}

/// T-069: `warp tun` takes `--session-max-age` (it was a usage error).
#[test]
fn warp_tun_takes_session_max_age() {
    use std::os::unix::fs::PermissionsExt as _;
    let env = Env::new();
    // An identity with no device: the command ends there, with no network.
    let identity = env.path("id.json");
    std::fs::write(&identity, "{}").unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = env
        .cmd(&["warp", "tun", "--session-max-age", "60", "--identity"])
        .arg(&identity)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(64), "{err}");
    assert!(!err.contains("--session-max-age works with"), "{err}");
    assert!(err.contains("parsing the WARP identity"), "{err}");
}

/// T-074: `warp export --check` writes no config, so it refuses `--out`
/// and `--delete`; the help names the reserved bytes.
#[test]
fn warp_export_check_is_a_flag() {
    let env = Env::new();
    for extra in ["--out=w.conf", "--delete"] {
        let out = env
            .cmd(&["warp", "export", "--check", extra])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{extra}: {err}");
        assert!(err.contains("cannot be used with"), "{extra}: {err}");
    }
    let help = text(&env.run(&["warp", "export", "--help"]));
    assert!(help.contains("--check"), "{help}");
    assert!(help.contains("needs reserved bytes"), "{help}");
}

/// T-078: `pod doctor --json` has the schema and the verdict words of
/// `podnet doctor`.
#[test]
fn pod_doctor_json_has_the_schema_and_the_verdicts() {
    let env = Env::new();
    let out = env.run(&["pod", "doctor", "--json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["schema"], 1, "{doc}");
    let words = ["ok", "fail"];
    for (name, cap) in doc["capabilities"].as_object().unwrap() {
        let v = cap["verdict"].as_str().unwrap_or_default();
        assert!(words.contains(&v), "{name}: {cap}");
        assert_eq!(cap["ok"].as_bool(), Some(v == "ok"), "{name}: {cap}");
    }
    for key in ["netns", "seccomp", "any"] {
        let v = doc["verdicts"][key].as_str().unwrap_or_default();
        assert!(words.contains(&v), "{key}: {doc}");
    }
    let any = doc["verdicts"]["any"] == "ok";
    assert_eq!(out.status.code(), Some(if any { 0 } else { 3 }));
    // The text form uses the same words.
    let text = String::from_utf8(env.run(&["pod", "doctor"]).stdout).unwrap();
    assert!(!text.contains("available"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with("podnet-netns: backend netns:")),
        "{text}"
    );
}

/// A live instance `fw1` of `warp forward` in the run directory of `env`,
/// with two forwards in its ready document. It is alive while the result
/// is held.
fn forward_instance(env: &Env) -> podnet::instances::Held {
    use std::os::unix::fs::DirBuilderExt as _;
    let run = env.path("run");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&run)
        .unwrap();
    let record = podnet::instances::Record {
        name: "fw1".into(),
        pid: std::process::id(),
        started: podnet::instances::now(),
        command: "warp forward".into(),
        state: "ready".into(),
        ready: Some(serde_json::json!({
            "listen": "tcp://127.0.0.1:2201",
            "forward": [
                { "listen": "tcp://127.0.0.1:2201", "to": "db.example:22" },
                { "listen": "unix:/tmp/t073.sock", "to": "10.0.0.9:5432" },
            ],
        })),
        ..Default::default()
    };
    podnet::instances::write(&run, &record).unwrap();
    podnet::instances::lock(&podnet::instances::paths(&run, "fw1").unwrap().lock).unwrap()
}

/// T-073: `ps` prints each forward of an array `forward` as `LISTEN -> TO`.
/// Before, it printed the first listen address only, and no target.
#[test]
fn ps_prints_each_forward() {
    let env = Env::new();
    let _alive = forward_instance(&env);
    let out = text(&env.run(&["ps"]));
    for row in [
        "forward tcp://127.0.0.1:2201 -> db.example:22",
        "forward unix:/tmp/t073.sock -> 10.0.0.9:5432",
    ] {
        assert!(out.contains(row), "{out}");
    }
}

/// T-073: `warp forward --list` prints the forwards of `ps`, one line for
/// each, with no `-L` and no WARP session.
#[test]
fn warp_forward_list_prints_the_forwards_of_ps() {
    let env = Env::new();
    let none = text(&env.run(&["warp", "forward", "--list"]));
    assert!(none.contains("no forward"), "{none}");
    let _alive = forward_instance(&env);
    let out = text(&env.run(&["warp", "forward", "--list"]));
    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(
        rows,
        [
            "fw1  tcp://127.0.0.1:2201 -> db.example:22",
            "fw1  unix:/tmp/t073.sock -> 10.0.0.9:5432",
        ],
        "{out}"
    );
}
