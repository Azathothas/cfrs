//! The command line of the cfrs binary: exit codes, usage messages and the
//! generated manual. No test here uses the network.

use std::process::{Command, Output};

fn cfrs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(args)
        .env_remove("CFRS_ERROR_PROGRAM")
        .env_remove("CFRS_EDGE")
        .env("PAGER", "cat")
        .output()
        .expect("cfrs runs")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn help_and_version_exit_0() {
    for args in [&["--help"][..], &["--version"], &["tunnel", "--help"]] {
        let out = cfrs(args);
        assert_eq!(out.status.code(), Some(0), "cfrs {args:?}");
    }
}

#[test]
fn a_usage_error_exits_64() {
    let out = cfrs(&["tunel"]);
    assert_eq!(out.status.code(), Some(64));
}

/// A flag with no value and an unknown flag give different messages.
#[test]
fn a_missing_value_is_not_an_unknown_flag() {
    let missing = cfrs(&["tunnel", "--protocol"]);
    assert_eq!(missing.status.code(), Some(64));
    let text = stderr(&missing);
    assert!(
        text.contains("a value is required for '--protocol"),
        "{text}"
    );
    assert!(!text.contains("unexpected argument"), "{text}");

    let unknown = cfrs(&["tunnel", "--protocl", "quic"]);
    assert_eq!(unknown.status.code(), Some(64));
    let text = stderr(&unknown);
    assert!(text.contains("unexpected argument '--protocl'"), "{text}");
    assert!(
        text.contains("--protocol"),
        "clap names the nearest flag: {text}"
    );
}

#[test]
fn a_bad_configuration_exits_78() {
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--url", "http://127.0.0.1:9"])
        .env_remove("CFRS_ERROR_PROGRAM")
        .env("CFRS_EDGE", "not-an-address")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
    assert!(stderr(&out).contains("CFRS_EDGE"), "{}", stderr(&out));

    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.yml");
    let out = cfrs(&["tunnel", "--config", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
}

/// Each `.B` line of the man page has text, and each long flag of
/// `cfrs man --json` is in the page.
#[test]
fn the_man_page_names_each_flag() {
    let roff = cfrs(&["man", "--roff"]);
    assert_eq!(roff.status.code(), Some(0));
    let roff = String::from_utf8(roff.stdout).unwrap();
    for line in roff.lines() {
        if let Some(rest) = line.strip_prefix(".B") {
            if rest.is_empty() || rest.starts_with(' ') {
                assert!(!rest.trim().is_empty(), "an empty .B line");
            }
        }
    }

    let json = cfrs(&["man", "--json"]);
    assert_eq!(json.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).expect("valid JSON");
    let mut flags = 0;
    for command in json["commands"].as_array().unwrap() {
        for arg in command["args"].as_array().unwrap() {
            if arg["positional"] == false {
                let long = format!("\\-\\-{}", arg["id"].as_str().unwrap().replace('-', "\\-"));
                assert!(roff.contains(&long), "the man page has no {long}");
                flags += 1;
            }
        }
    }
    assert!(flags > 50, "only {flags} flags");

    let table = &json["exit_status"];
    for (code, name) in [
        (0, "success"),
        (64, "usage"),
        (69, "unavailable"),
        (78, "config"),
    ] {
        assert!(
            table
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["code"] == code && row["name"] == name),
            "no row {code} ({name})"
        );
    }
}

#[test]
fn ports_json_is_one_object() {
    let out = cfrs(&["ports", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(json["ports"].is_array(), "{json}");
}

/// Run cfrs with the log at its highest level, and give stderr and stdout.
fn trace(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
    cmd.args(args)
        .env_remove("CFRS_ERROR_PROGRAM")
        .env_remove("CFRS_EDGE")
        .env("RUST_LOG", "trace")
        .env("NO_PROXY", "");
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(key);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

/// The log at the highest level holds no tunnel secret, no WARP token and no
/// proxy password.
#[test]
fn the_log_holds_no_secret() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let secret = b64.encode(b"tunnel-secret-0123456789abcdef!!");
    let token = b64.encode(format!(
        r#"{{"a":"0123456789abcdef0123456789abcdef","t":"6ff42ae2-765d-4adf-8112-31c55c1551ef","s":"{secret}"}}"#
    ));
    let (code, text) = trace(
        &["tunnel", "--token", &token, "--hello-world"],
        &[("CFRS_EDGE", "not-an-address")],
    );
    assert_eq!(code, Some(78), "{text}");
    assert!(!text.contains(&token), "the token is in the log:\n{text}");
    assert!(!text.contains(&secret), "the secret is in the log:\n{text}");

    // A quick tunnel through a proxy with a password; the proxy is closed.
    let password = "Pr0xyPassw0rdValue";
    let proxy = format!("http://alice:{password}@127.0.0.1:9");
    let (code, text) = trace(
        &["tunnel", "--hello-world"],
        &[("HTTPS_PROXY", &proxy), ("ALL_PROXY", &proxy)],
    );
    assert_ne!(code, Some(0), "{text}");
    assert!(
        text.contains("127.0.0.1:9"),
        "the run used the proxy:\n{text}"
    );
    assert!(
        !text.contains(password),
        "the proxy password is in the log:\n{text}"
    );

    // A WARP identity with a bearer token, refreshed through the closed proxy.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("warp.json");
    let warp_token = "warp-bearer-token-0123456789abcdef";
    let device: cfrs::warp::register::Device = serde_json::from_value(serde_json::json!({
        "id": "t.0123456789",
        "account": {"id": "acct", "license": "LICENSE-KEY-0123"},
        "config": {},
        "token": warp_token,
        "tunnel_type": "masque",
    }))
    .unwrap();
    let identity = cfrs::warp::identity::Identity::generate().unwrap();
    cfrs::warp::WarpClient::from_parts(device, identity)
        .save(&path)
        .unwrap();
    let (code, text) = trace(
        &["warp", "--identity", path.to_str().unwrap(), "status"],
        &[("HTTPS_PROXY", &proxy), ("ALL_PROXY", &proxy)],
    );
    assert_ne!(code, Some(0), "{text}");
    assert!(
        !text.contains(warp_token),
        "the WARP token is in the log:\n{text}"
    );
    assert!(
        !text.contains("LICENSE-KEY-0123"),
        "the license is in the log:\n{text}"
    );
    assert!(
        !text.contains(password),
        "the proxy password is in the log:\n{text}"
    );
}

/// Each default address in the table "What listens" of SECURITY.md is the
/// default of the --listen flag of that command, and each command with a
/// --listen default has a row.
#[test]
fn the_listen_defaults_agree_with_the_manual() {
    let security =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/SECURITY.md")).unwrap();
    let mut table = std::collections::BTreeMap::new();
    for line in security.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 {
            continue;
        }
        let (command, address) = (cells[1], cells[2]);
        let (Some(command), Some(address)) = (
            command
                .strip_prefix("`cfrs ")
                .and_then(|c| c.strip_suffix('`')),
            address.strip_prefix('`').and_then(|a| a.strip_suffix('`')),
        ) else {
            continue;
        };
        if address.starts_with("tcp://") || address.starts_with("unix:") {
            table.insert(command.to_string(), address.to_string());
        }
    }
    let json = cfrs(&["man", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let mut manual = std::collections::BTreeMap::new();
    for command in json["commands"].as_array().unwrap() {
        for arg in command["args"].as_array().unwrap() {
            if arg["id"] == "listen" {
                if let Some(default) = arg["default"].as_str() {
                    let path: Vec<&str> = command["path"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|w| w.as_str().unwrap())
                        .collect();
                    manual.insert(path.join(" "), default.to_string());
                }
            }
        }
    }
    assert!(manual.len() >= 4, "{manual:?}");
    assert_eq!(table, manual, "SECURITY.md and cfrs man --json differ");
}

/// With an empty environment (no HOME, no XDG variables, no user name),
/// the commands that need no network run, and the state directory is in
/// the temporary directory, never in the current directory.
#[test]
fn an_empty_environment_works() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env_clear()
            .env("TMPDIR", dir.path())
            .current_dir(dir.path())
            .output()
            .unwrap()
    };
    for args in [
        &["--version"][..],
        &["man", "--no-pager", "files"],
        &["ports"],
        &["net", "addresses"],
    ] {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "cfrs {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = run(&["status"]);
    assert_eq!(out.status.code(), Some(0));
    let status: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let path = status["warp_identity"]["path"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(path.starts_with(dir.path().to_str().unwrap()), "{path}");
    assert!(path.contains("/cfrs-"), "{path}");
    assert!(!dir.path().join("cfrs-warp.json").exists());

    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .arg("status")
        .env_clear()
        .env("CFRS_STATE_DIR", "none")
        .current_dir(dir.path())
        .output()
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(status["warp_identity"]["reason"], "CFRS_STATE_DIR=none");
}

/// A log that goes to a file or a pipe has no escape sequences.
#[test]
fn a_log_to_a_pipe_has_no_colours() {
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--hello-world"])
        .env("CFRS_EDGE", "not-an-address")
        .env("RUST_LOG", "cfrs=debug")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!text.contains('\u{1b}'), "{text:?}");
}

/// SIGTERM stops cfrs as SIGINT does: a clean shutdown and exit 0.
#[test]
fn sigterm_is_a_clean_stop() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args([
                "connect",
                "-L",
                &format!("tcp://127.0.0.1:{port}"),
                "wss://127.0.0.1:9/__cfrs/ws",
            ])
            .env_remove("CFRS_ERROR_PROGRAM")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Wait for the listener.
        let start = std::time::Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(20),
                "no listener"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        unsafe { libc::kill(child.id() as i32, signal) };
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(0), "signal {signal}: {status:?}");
    }
}

/// warp status, license, rotate and delete use a saved device and register
/// none.
#[test]
fn warp_status_registers_no_device() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("none.json");
    for command in ["status", "rotate", "delete"] {
        let out = cfrs(&["warp", "--identity", path.to_str().unwrap(), command]);
        assert_eq!(out.status.code(), Some(78), "{command}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("no WARP identity at"),
            "{}",
            stderr(&out)
        );
        assert!(!path.exists(), "{command} made a file");
    }
}

/// Each completion script names the commands and the flags; the bash script
/// is valid bash.
#[test]
fn completion_scripts() {
    for shell in ["bash", "zsh", "fish"] {
        let out = cfrs(&["completions", shell]);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        let text = String::from_utf8(out.stdout).unwrap();
        for word in ["tunnel", "warp", "update", "leg-failover"] {
            assert!(text.contains(word), "{shell}: no {word}");
        }
        if shell == "bash" {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("cfrs.bash");
            std::fs::write(&path, &text).unwrap();
            let check = Command::new("bash").arg("-n").arg(&path).status().unwrap();
            assert!(check.success(), "bash -n failed");
        }
    }
    assert_eq!(cfrs(&["completions", "tcsh"]).status.code(), Some(64));
}
