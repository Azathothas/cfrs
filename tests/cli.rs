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
                "--no-check",
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

/// A bad value of a tunnel flag is a usage error (exit 64) before any
/// network work.
#[test]
fn bad_flag_values_are_usage_errors() {
    for (args, want) in [
        (
            &["tunnel", "--hello-world", "--ha-connections", "0"][..],
            "1..=8",
        ),
        (
            &["tunnel", "--hello-world", "--ha-connections", "9"],
            "1..=8",
        ),
        (
            &["tunnel", "--hello-world", "--protocol", "bogus"],
            "possible values",
        ),
        (
            &["tunnel", "--hello-world", "--transport", "bogus"],
            "possible values",
        ),
        (&["tunnel", "--port", "0"], "1..=65535"),
        (
            &["tunnel", "--unix", "/nonexistent/x.sock"],
            "--unix /nonexistent/x.sock",
        ),
        (&["tunnel", "--tcp", "bogus"], "--tcp bogus"),
        (&["tunnel", "--tcp", "127.0.0.1:0"], "--tcp 127.0.0.1:0"),
        (&["tunnel", "--url", "http://127.0.0.1:0"], "the port 0"),
        (
            &[
                "connect",
                "-L",
                "tcp://127.0.0.1:1",
                "http://127.0.0.1:19200/",
            ],
            "not a WebSocket URL",
        ),
    ] {
        let start = std::time::Instant::now();
        let out = cfrs(args);
        let text = stderr(&out);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {text}");
        assert!(text.contains(want), "{args:?}: {text}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "{args:?} was slow"
        );
    }
}

/// --log-format json writes one JSON object for each log line; -q drops
/// the info and debug lines; -v adds the debug lines.
#[test]
fn log_controls() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno");
        }
    });
    let url = format!("http://localhost:{port}");
    let run = |flags: &[&str]| {
        let mut args = vec!["--no-proxy"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["tunnel", "--hello-world", "--service-url", &url]);
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(&args)
            .env_remove("RUST_LOG")
            .env_remove("CFRS_ERROR_PROGRAM")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let json = run(&["--log-format", "json", "-v"]);
    let lines: Vec<&str> = json.lines().filter(|l| l.starts_with('{')).collect();
    assert!(!lines.is_empty(), "{json}");
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(value["level"].is_string(), "{line}");
    }
    assert!(run(&["-v"]).contains("DEBUG"));
    let quiet = run(&["-q"]);
    assert!(
        !quiet.contains("DEBUG") && !quiet.contains(" INFO "),
        "{quiet}"
    );
    assert!(quiet.contains("HTTP 403"), "the error line stays: {quiet}");
}

/// `--check` (issue 45): exit 0 or 1, no call to the API, no file written,
/// no token in the output.
#[test]
fn check_mode() {
    const TOKEN: &str = "eyJhIjogIjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwgInQiOiAiZmZkODZiZDUtMWJmZi00NTZiLThjMmMtNzVhMDE0Y2RjNGM4IiwgInMiOiAiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0ifQ==";
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let site = dir.path().join("site");
    std::fs::create_dir(&site).unwrap();
    // A stand-in for the quick-tunnel API: it must get no connection.
    let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    api.set_nonblocking(true).unwrap();
    let service_url = format!("http://{}", api.local_addr().unwrap());
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port().to_string()
    };
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(args)
            .args(["--service-url", &service_url])
            .env_remove("CFRS_ERROR_PROGRAM")
            .env_remove("CFRS_EDGE")
            .env_remove("TUNNEL_TOKEN")
            .env("CFRS_STATE_DIR", &state);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), text, out.stdout)
    };
    let site_arg = site.to_str().unwrap();

    let (code, text, _) = run(&["tunnel", "--check", "--port", &closed], &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains(&format!("127.0.0.1:{closed}")), "{text}");

    let (code, text, _) = run(&["serve", "--check", "--dir", site_arg, "--spa"], &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("--spa needs an index.html"), "{text}");

    let (code, text, stdout) = run(&["serve", "--check", "--json", "--dir", site_arg], &[]);
    assert_eq!(code, Some(0), "{text}");
    let doc: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(doc["ok"], true, "{doc}");
    assert_eq!(doc["plan"]["tunnel"]["kind"], "quick");

    for env in [&[("TUNNEL_TOKEN", TOKEN)][..], &[]] {
        let mut args = vec!["demo", "--check", "--transport", "warp"];
        if env.is_empty() {
            args.extend(["--token", TOKEN]);
        }
        let (code, text, _) = run(&args, env);
        assert_eq!(code, Some(0), "{text}");
        assert!(
            text.contains("ffd86bd5-1bff-456b-8c2c-75a014cdc4c8"),
            "{text}"
        );
        assert!(
            !text.contains(TOKEN) && !text.contains("AAECAwQF"),
            "{text}"
        );
    }

    let file = site.join("a.txt");
    std::fs::write(&file, "x").unwrap();
    let (code, text, _) = run(
        &[
            "share",
            "--check",
            "--mode",
            "upload",
            "--dir",
            file.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("not a directory"), "{text}");

    let config = dir.path().join("config.yml");
    std::fs::write(
        &config,
        "credentails-file: /x\ningress:\n  - service: http_status:404\n",
    )
    .unwrap();
    let (code, text, _) = run(
        &["tunnel", "--check", "--config", config.to_str().unwrap()],
        &[],
    );
    assert_eq!(code, Some(78), "{text}");
    assert!(text.contains("did you mean credentials-file"), "{text}");

    assert!(
        api.accept().is_err(),
        "a check connected to the quick-tunnel API"
    );
    assert_eq!(
        std::fs::read_dir(&state).unwrap().count(),
        0,
        "a check wrote a file"
    );
}

/// `net doctor` under a seccomp filter that refuses listen(2) and sendto(2)
/// with EPERM: each bind stays OK, each listen line is FAIL, and the UDP line
/// is refused (issue 12).
#[test]
fn doctor_tells_listen_from_bind() {
    use std::os::unix::process::CommandExt;
    fn deny_listen_and_sendto() -> std::io::Result<()> {
        const RET_ALLOW: u32 = 0x7fff_0000;
        const RET_ERRNO: u32 = 0x0005_0000;
        let deny = RET_ERRNO | libc::EPERM as u32;
        let stmt = |code: u16, k: u32| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        };
        let filter = [
            // Load the syscall number (offset 0 of seccomp_data).
            stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
            jeq(libc::SYS_listen as u32, 2, 0),
            jeq(libc::SYS_sendto as u32, 1, 0),
            stmt((libc::BPF_RET | libc::BPF_K) as u16, RET_ALLOW),
            stmt((libc::BPF_RET | libc::BPF_K) as u16, deny),
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: prctl with valid arguments; `prog` lives for the call.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &prog as *const libc::sock_fprog,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
    cmd.args(["net", "doctor"])
        .env_remove("CFRS_ERROR_PROGRAM")
        .env_remove("CFRS_EDGE")
        .env("CC", "/nonexistent-cc");
    // SAFETY: the closure calls only prctl, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(deny_listen_and_sendto);
    }
    let out = cmd.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = |name: &str| {
        text.lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("no line {name}:\n{text}"))
            .to_string()
    };
    for (bind, listen) in [
        ("bind(AF_INET, 127.0.0.1:0)", "listen(AF_INET, 127.0.0.1:0)"),
        ("bind(AF_UNIX, path)", "listen(AF_UNIX, path)"),
    ] {
        assert!(line(bind).contains("ok       allowed"), "{text}");
        assert!(line(listen).contains("fail     EPERM"), "{text}");
    }
    assert!(line("UDP egress").contains("fail     refused"), "{text}");
}

/// `cfrs autostart` with a fake systemctl (no user manager) and a fake
/// crontab (issue 23): the crontab line holds no secret, other lines stay,
/// the env file is private, and with no way at all the exit is 69.
#[test]
fn autostart_with_cron_and_with_nothing() {
    use std::os::unix::fs::PermissionsExt;
    const TOKEN: &str = "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwiLCJzIjoic2VjcmV0In0=";
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("bin");
    std::fs::create_dir(&fake).unwrap();
    let script = |name: &str, body: &str| {
        let path = fake.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    script("systemctl", "echo 'Failed to connect to bus' >&2; exit 1");
    script(
        "crontab",
        r#"f="$FAKE_CRONTAB"
if [ "$1" = "-l" ]; then if [ -f "$f" ]; then cat "$f"; exit 0; fi; echo "no crontab for user" >&2; exit 1; fi
if [ "$1" = "-" ]; then cat > "$f"; exit 0; fi
exit 2"#,
    );
    let crontab = dir.path().join("crontab");
    std::fs::write(&crontab, "MAILTO=\"\"\n@daily /usr/bin/true # mine\n").unwrap();
    let state = dir.path().join("state");
    let run = |args: &[&str], path: &str| {
        Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env("PATH", path)
            .env("HOME", dir.path())
            .env("CFRS_STATE_DIR", &state)
            .env("FAKE_CRONTAB", &crontab)
            .env("TUNNEL_TOKEN", TOKEN)
            .env_remove("CFRS_ERROR_PROGRAM")
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap()
    };
    let path = format!("{}:/usr/bin:/bin", fake.display());
    let out = run(
        &[
            "autostart",
            "add",
            "web",
            "--",
            "status",
            "--proxy=http://u:pw@127.0.0.1:9",
        ],
        &path,
    );
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("added (cron)"), "{text}");
    let cron = std::fs::read_to_string(&crontab).unwrap();
    assert!(
        cron.starts_with("MAILTO=\"\"\n@daily /usr/bin/true # mine\n"),
        "{cron}"
    );
    assert!(
        cron.contains("@reboot ") && cron.contains(" autostart run web --dir "),
        "{cron}"
    );
    assert!(cron.trim_end().ends_with("# cfrs autostart web"), "{cron}");
    assert!(!cron.contains(TOKEN) && !cron.contains("pw@"), "{cron}");
    let entry = state.join("autostart");
    let env = std::fs::read_to_string(entry.join("web.env")).unwrap();
    assert!(env.contains(&format!("TUNNEL_TOKEN={TOKEN}")), "{env}");
    assert!(env.contains("CFRS_PROXY=http://u:pw@127.0.0.1:9"), "{env}");
    let mode = std::fs::metadata(entry.join("web.env"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let args = std::fs::read_to_string(entry.join("web.args")).unwrap();
    assert_eq!(args, r#"["status"]"#);

    // Issue 117: a leading cfrs is dropped; a command that does not parse
    // is exit 64, and no entry is written.
    let out = run(&["autostart", "add", "web2", "--", "cfrs", "status"], &path);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let args = std::fs::read_to_string(entry.join("web2.args")).unwrap();
    assert_eq!(args, r#"["status"]"#);
    let out = run(&["autostart", "remove", "web2"], &path);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let out = run(
        &["autostart", "add", "web3", "--", "no-such-command"],
        &path,
    );
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("is not a cfrs command"),
        "{}",
        stderr(&out)
    );
    assert!(!entry.join("web3.args").exists());
    let out = run(&["autostart", "list"], &path);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "web\n");

    let out = run(&["autostart", "remove", "web"], &path);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let cron = std::fs::read_to_string(&crontab).unwrap();
    assert_eq!(cron, "MAILTO=\"\"\n@daily /usr/bin/true # mine\n");
    assert!(!entry.join("web.env").exists() && !entry.join("web.args").exists());

    // Issue 117: a crontab that takes the input and keeps nothing: exit 69.
    let lossy = dir.path().join("lossy");
    std::fs::create_dir(&lossy).unwrap();
    let path_lossy = format!("{}:/usr/bin:/bin", lossy.display());
    std::fs::copy(fake.join("systemctl"), lossy.join("systemctl")).unwrap();
    let crontab_lossy = lossy.join("crontab");
    std::fs::write(
        &crontab_lossy,
        "#!/bin/sh\n[ \"$1\" = \"-\" ] && cat > /dev/null\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&crontab_lossy, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = run(&["autostart", "add", "web4", "--", "status"], &path_lossy);
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("does not keep the entry"),
        "{}",
        stderr(&out)
    );

    // No systemctl and no crontab: exit 69, and the line to run.
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = run(
        &["autostart", "add", "web", "--", "status"],
        empty.to_str().unwrap(),
    );
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("autostart run web --dir"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains(TOKEN));
}

/// Issue 41: `net tailscale` with no tailscaled socket fails at start with
/// exit 69, and `pod -x` to a dead upstream warns and still runs.
#[test]
fn a_missing_upstream_is_named_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("nope.sock");
    let out = cfrs(&[
        "net",
        "tailscale",
        "--socket",
        socket.to_str().unwrap(),
        "--listen",
        &format!("unix:{}", dir.path().join("front.sock").display()),
        "--run-for",
        "5",
    ]);
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the LocalAPI socket") && stderr(&out).contains("nope.sock"),
        "{}",
        stderr(&out)
    );

    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let out = cfrs(&[
        "pod",
        "-x",
        &format!("socks5://127.0.0.1:{closed}"),
        "--",
        "true",
    ]);
    assert!(
        stderr(&out).contains(&format!("the upstream 127.0.0.1:{closed} does not answer")),
        "{}",
        stderr(&out)
    );
}

/// Issue 63: `net socksify --socket PATH` and the default work. Before, the
/// option was --proxy, which the global proxy parser took first: each run
/// exited 64. Skipped with no C compiler.
#[test]
fn socksify_takes_a_socket_path() {
    if cfrs::vnet::shim::compiler().is_err() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().to_str().unwrap();
    let with = cfrs(&[
        "net",
        "socksify",
        "--out",
        out,
        "--socket",
        "/tmp/x.sock",
        "--json",
    ]);
    assert_eq!(with.status.code(), Some(0), "{}", stderr(&with));
    let text = String::from_utf8_lossy(&with.stdout);
    assert!(text.contains("/tmp/x.sock"), "{text}");
    let default = cfrs(&["net", "socksify", "--out", out, "--json"]);
    assert_eq!(default.status.code(), Some(0), "{}", stderr(&default));
    assert!(String::from_utf8_lossy(&default.stdout).contains("/tmp/cfrssocks.sock"));
}

/// Issue 247: `net ts-shims` with no `--out` does not use a directory in
/// the temporary directory that other users can write.
#[test]
fn ts_shims_skips_a_directory_open_to_others() {
    use std::os::unix::fs::PermissionsExt;
    if cfrs::vnet::shim::compiler().is_err() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path().join("tmp");
    let hostile = tmp.join("cfrs-ts-shims");
    std::fs::create_dir_all(&hostile).unwrap();
    std::fs::set_permissions(&hostile, std::fs::Permissions::from_mode(0o777)).unwrap();
    let state = dir.path().join("state");
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["net", "ts-shims"])
        .env("TMPDIR", &tmp)
        .env("CFRS_STATE_DIR", &state)
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    let chosen = state.join("cfrs-ts-shims");
    assert!(text.contains(&*chosen.to_string_lossy()), "{text}");
    assert_eq!(std::fs::read_dir(&hostile).unwrap().count(), 0);
}

/// Issue 227: `update --version` with a path is a usage error, and cfrs
/// sends no request.
#[test]
fn update_refuses_a_tag_with_a_path() {
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["update", "--version", "v1/../x", "--check"])
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("CFRS_STATE_DIR", "none")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not a release tag"),
        "{}",
        stderr(&out)
    );
}

/// Issue 57: no panic on a bad argument or a closed pipe; a missing
/// subcommand and a missing origin are usage errors; --json is accepted.
#[test]
fn bad_input_gives_usage_errors_not_panics() {
    use std::os::unix::ffi::OsStrExt;
    let bad = std::ffi::OsStr::from_bytes(b"\xff\xfe");
    for args in [vec![bad], vec![std::ffi::OsStr::new("tunnel"), bad]] {
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(&args)
            .env_remove("CFRS_ERROR_PROGRAM")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    for args in [&[][..], &["net"][..], &["warp"][..], &["tunnel"][..]] {
        let out = cfrs(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    assert_eq!(cfrs(&["--help"]).status.code(), Some(0));
    let no_host = cfrs(&["tunnel", "--check", "--url", "http://"]);
    assert_eq!(no_host.status.code(), Some(64), "{}", stderr(&no_host));
    assert!(stderr(&no_host).contains("has no host"));
    for args in [
        &["status", "--json"][..],
        &["net", "addresses", "--json"][..],
    ] {
        let out = cfrs(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", stderr(&out));
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
    }
    // A closed stdout: the default SIGPIPE ends the command, no panic (101).
    let mut child = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["completions", "bash"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(101), "{}", stderr(&out));
    assert!(!stderr(&out).contains("panicked"), "{}", stderr(&out));
}

/// Issue 55: the failure report has the error in "error" only; "messages"
/// holds the log lines before it, not the same text again.
#[test]
fn the_failure_report_has_the_error_once() {
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("report.json");
    let program = dir.path().join("save.sh");
    std::fs::write(&program, format!("#!/bin/sh\ncat > {}\n", saved.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--url", "ftp://x"])
        .env("CFRS_ERROR_PROGRAM", &program)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&saved).unwrap()).unwrap();
    let error = doc["error"].to_string();
    assert!(error.contains("ftp"), "{doc}");
    for line in doc["messages"].as_array().unwrap() {
        assert!(
            !line.as_str().unwrap().contains("ftp://x"),
            "the error is twice: {doc}"
        );
    }
}

/// Issue 66: CFRS_EDGE is checked the same way by tunnel and the doctors;
/// a bad CFRS_UDP gives one failed legs row in --check, not two rows.
#[test]
fn the_environment_is_checked_alike() {
    for args in [&["doctor", "--samples", "1"][..], &["net", "doctor"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env("CFRS_EDGE", "not-an-address")
            .env_remove("CFRS_ERROR_PROGRAM")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(78), "{args:?}: {}", stderr(&out));
        assert!(stderr(&out).contains("CFRS_EDGE"), "{}", stderr(&out));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--hello-world", "--check", "--json"])
        .env("CFRS_UDP", "bogus")
        .env_remove("CFRS_EDGE")
        .env_remove("CFRS_ERROR_PROGRAM")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let legs: Vec<_> = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["name"] == "legs")
        .collect();
    assert_eq!(legs.len(), 1, "{doc}");
    assert_eq!(legs[0]["status"], "fail");
    // Issue 111: a bad CFRS_WARP_TCP_BURST is exit 78 before any network
    // wait. Before, it gave the default with no message.
    for args in [&["warp", "probe"][..], &["agent", "up"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env("CFRS_WARP_TCP_BURST", "abc")
            .env("CFRS_STATE_DIR", "none")
            .env_remove("CFRS_ERROR_PROGRAM")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(78), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("CFRS_WARP_TCP_BURST"),
            "{}",
            stderr(&out)
        );
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["status"])
        .env("RUST_LOG", "cfrs=deubg")
        .output()
        .unwrap();
    assert!(stderr(&out).contains("RUST_LOG"), "{}", stderr(&out));
}

/// Issue 74: a write that fails (a full disk) does not panic. Before, the
/// std print macros panicked with exit 101.
#[test]
fn a_full_stdout_is_no_panic() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["status"])
        .stdout(full)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

/// Issue 126: cfrs raises the soft limit of open files to the hard limit,
/// and `status` shows it. `warp exec` leaves it as it is (it runs a program
/// of the user).
#[test]
#[allow(clippy::unnecessary_cast)]
fn the_soft_limit_of_open_files_is_raised() {
    use std::os::unix::process::CommandExt;
    let status_with = |soft: u64, hard: u64| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.arg("status").env("CFRS_STATE_DIR", "none");
        // SAFETY: setrlimit is async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: soft as libc::rlim_t,
                    rlim_max: hard as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        doc["nofile"].clone()
    };
    let mut hard = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut hard) };
    let hard = (hard.rlim_max as u64).min(4096);
    if hard <= 256 {
        eprintln!("skipping: the hard limit is {hard}");
        return;
    }
    let nofile = status_with(256, hard);
    assert_eq!(nofile["soft"], hard, "{nofile}");
    assert_eq!(nofile["raised_from"], 256, "{nofile}");
    let nofile = status_with(hard, hard);
    assert_eq!(nofile["soft"], hard, "{nofile}");
    assert!(nofile["raised_from"].is_null(), "{nofile}");
}

/// Issue 130: warp ssh-config --write, --check and --remove own one block
/// of the file and change no other byte.
#[test]
fn warp_ssh_config_owns_its_block() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("config");
    let mine = "Host box\n  User me\n";
    std::fs::write(&conf, mine).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(["warp", "ssh-config", "--config", conf.to_str().unwrap()])
            .args(args)
            .env_remove("CFRS_ERROR_PROGRAM")
            .output()
            .unwrap()
    };
    assert_eq!(
        run(&["--check", "--host", "github.com"]).status.code(),
        Some(1)
    );
    assert_eq!(
        run(&["--write", "--host", "github.com"]).status.code(),
        Some(0)
    );
    let text = std::fs::read_to_string(&conf).unwrap();
    assert!(
        text.starts_with("# >>> cfrs warp ssh-config: github.com >>>\nHost github.com\n"),
        "{text}"
    );
    assert!(text.ends_with(mine), "{text}");
    assert_eq!(
        run(&["--check", "--host", "github.com"]).status.code(),
        Some(0)
    );
    assert_eq!(run(&["--write"]).status.code(), Some(64));
    assert_eq!(run(&["--write", "--host", "box"]).status.code(), Some(1));
    assert_eq!(run(&["--remove"]).status.code(), Some(0));
    assert_eq!(std::fs::read_to_string(&conf).unwrap(), mine);
}

/// Issue 189: a global option before `pod` does not panic, and a network
/// option of cfrs is refused with a pointer to `-x`.
#[test]
fn a_global_flag_before_pod_does_not_panic() {
    for args in [
        &["-v", "pod", "--", "true"][..],
        &["-q", "pod", "--", "true"],
    ] {
        let out = cfrs(args);
        let err = stderr(&out);
        assert_ne!(out.status.code(), Some(101), "{args:?}: {err}");
        assert!(!err.contains("panicked"), "{args:?}: {err}");
    }
    let out = cfrs(&["--proxy", "http://127.0.0.1:1", "pod", "--", "true"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(stderr(&out).contains("-x"), "{}", stderr(&out));
}

/// Issue 171: protocol and ha-connections of a config file are used; a
/// flag wins over the file.
#[test]
fn the_config_file_gives_the_protocol_and_the_connections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yml");
    std::fs::write(
        &path,
        "protocol: http2\nha-connections: 1\ningress:\n  - service: http_status:404\n",
    )
    .unwrap();
    let path = path.to_str().unwrap();
    let plan = |extra: &[&str]| {
        let mut args = vec!["tunnel", "--check", "--json", "--config", path];
        args.extend_from_slice(extra);
        let out = cfrs(&args);
        assert!(out.status.success(), "{}", stderr(&out));
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        doc["plan"].clone()
    };
    let p = plan(&[]);
    assert_eq!(p["ha_connections"], 1, "{p}");
    assert_eq!(p["legs"], serde_json::json!(["http2"]), "{p}");
    let p = plan(&["--ha-connections", "3", "--protocol", "quic"]);
    assert_eq!(p["ha_connections"], 3, "{p}");
    assert_eq!(p["legs"][0], "quic", "{p}");
}

/// Issue 199: --tcp takes tcp://host:port; the check warns that a quick
/// tunnel receives HTTP; the public URL is not verified.
#[test]
fn tunnel_tcp_takes_the_scheme_and_warns() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("tcp://{addr}");
    let out = cfrs(&["tunnel", "--tcp", &url, "--check", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["plan"]["ingress"][0]["service"], url, "{doc}");
    assert_eq!(doc["plan"]["verify"], false, "{doc}");
    let origin = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "origin 1")
        .unwrap();
    assert_eq!(origin["status"], "warn", "{doc}");
    let out = cfrs(&["tunnel", "--tcp", "http://127.0.0.1:1", "--check"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}

/// Issue 172: a bad credentials file exits 78 as a flag and as a key; a
/// bad token exits 78; --token with --credentials-file exits 64.
#[test]
fn bad_credentials_exit_78() {
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("c.json");
    std::fs::write(&creds, "{}").unwrap();
    let creds = creds.to_str().unwrap();
    let config = dir.path().join("config.yml");
    std::fs::write(
        &config,
        format!("credentials-file: {creds}\ningress:\n  - service: http_status:404\n"),
    )
    .unwrap();
    for args in [
        vec![
            "tunnel",
            "--hello-world",
            "--credentials-file",
            creds,
            "--check",
        ],
        vec!["tunnel", "--config", config.to_str().unwrap(), "--check"],
        vec!["tunnel", "--hello-world", "--token", "garbage", "--check"],
        vec!["serve", "--dir", ".", "--token", "garbage", "--check"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(&args)
            .env_remove("TUNNEL_TOKEN")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(78), "{args:?}: {}", stderr(&out));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args([
            "tunnel",
            "--hello-world",
            "--token",
            "x",
            "--credentials-file",
            creds,
        ])
        .env_remove("TUNNEL_TOKEN")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}

/// Issue 269: a config file with no rule fails --check with exit 78.
#[test]
fn a_config_with_no_rule_fails_the_check() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("empty.yml");
    std::fs::write(&config, "ingress: []\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--config", config.to_str().unwrap(), "--check"])
        .env("CFRS_EDGE", "127.0.0.1:9")
        .env_remove("TUNNEL_TOKEN")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert!(text.contains("no ingress rules"), "{text}");
}

/// Issue 250: a bare `cfrs share` names the modes, and starts nothing.
#[test]
fn a_bare_share_names_the_modes() {
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["share", "--check"])
        .env("CFRS_EDGE", "bogus::")
        .env_remove("TUNNEL_TOKEN")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    let text = stderr(&out);
    for flag in ["--mode upload", "--dir", "--file", "--port", "--unix"] {
        assert!(text.contains(flag), "{text}");
    }
}

/// Issue 173: the exit code of each class of error.
#[test]
fn exit_codes_of_flags_and_configuration() {
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(args)
            .env_remove("CFRS_EDGE")
            .env_remove("TUNNEL_TOKEN");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        (out.status.code(), stderr(&out))
    };
    for (args, env, want) in [
        // Issue 250: a bare `cfrs share` is a usage error.
        // CFRS_EDGE=bogus:: makes sure that no tunnel starts.
        (&["share"][..], &[("CFRS_EDGE", "bogus::")][..], 64),
        (&["share", "--check"], &[], 64),
        (&["share", "--mode", "download", "--check"], &[], 64),
        (&["share", "--mode", "proxy", "--check"], &[], 64),
        (
            &["tunnel", "--hello-world", "--check"],
            &[("CFRS_EDGE", "bogus::")][..],
            78,
        ),
        (
            &[
                "tunnel",
                "--hello-world",
                "--protocol",
                "http2",
                "--transport",
                "warp",
                "--check",
            ],
            &[],
            64,
        ),
        (&["--ca-file", "/nonexistent/roots.pem", "status"], &[], 78),
        (
            &[
                "--ca-file",
                "/nonexistent/roots.pem",
                "tunnel",
                "--hello-world",
                "--check",
            ],
            &[],
            78,
        ),
        (&["autostart", "add", "bad name", "--", "tunnel"], &[], 64),
        // Issue 249.
        (&["tunnel", "--hello-world", "--name", ""], &[], 64),
        (&["tunnel", "--hello-world", "--name", "a b"], &[], 64),
        (
            &["connect", "--local", "tcp://abc", "wss://x.example/y"],
            &[],
            64,
        ),
        (
            &["connect", "--local", "tcp://99999", "wss://x.example/y"],
            &[],
            64,
        ),
        (&["update", "--version", ""], &[], 64),
        (&["update", "--version", "v1 x"], &[], 64),
    ] {
        let (code, err) = run(args, env);
        assert_eq!(code, Some(want), "{args:?}: {err}");
    }
    // Issue 249: no pair is 69, a pair file that does not parse is 78, a
    // --file that is not there is 78.
    let state = tempfile::tempdir().unwrap();
    let st = state.path().to_str().unwrap();
    let env = [("CFRS_STATE_DIR", st)];
    for args in [
        &["relay", "connect", "nosuchpair"][..],
        &["relay", "stop", "nosuchpair"],
    ] {
        let (code, err) = run(args, &env);
        assert_eq!(code, Some(69), "{args:?}: {err}");
    }
    std::fs::create_dir_all(state.path().join("relay")).unwrap();
    std::fs::write(state.path().join("relay/bad.json"), "{").unwrap();
    for args in [&["relay", "connect", "bad"][..], &["relay", "stop", "bad"]] {
        let (code, err) = run(args, &env);
        assert_eq!(code, Some(78), "{args:?}: {err}");
    }
    let (code, err) = run(&["share", "--file", "/nonexistent/f"], &[]);
    assert_eq!(code, Some(78), "{err}");
}

/// Issue 204: share --mode proxy takes a unix socket origin.
#[test]
fn share_proxy_takes_a_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("api.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let sock = sock.to_str().unwrap();
    let out = cfrs(&["share", "--unix", sock, "--check", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let service = doc["plan"]["ingress"][0]["service"].as_str().unwrap();
    assert!(service.contains(&format!("unix:{sock}")), "{doc}");
    let out = cfrs(&["share", "--unix", sock, "--port", "1", "--check"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    let out = cfrs(&["share", "--unix", "/nonexistent.sock", "--check"]);
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
}

/// Issue 181: with --log-format json, each line of stderr is JSON, also
/// the last error line and a usage error.
#[test]
fn log_format_json_gives_json_lines_only() {
    for args in [
        &[
            "--log-format",
            "json",
            "tunnel",
            "--url",
            "http://127.0.0.1:1",
            "--check",
        ][..],
        &["--log-format=json", "tunnel", "--bogus"],
    ] {
        let out = cfrs(args);
        assert!(!out.status.success());
        let err = stderr(&out);
        for line in err.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {line}"));
            assert!(v["level"].is_string(), "{line}");
        }
    }
}

/// Issue 196: the fault flags of net proxy need --switch and a value from
/// 0.0 to 1.0.
#[test]
fn the_fault_flags_need_a_switch_and_a_probability() {
    let out = cfrs(&["net", "proxy", "--drop", "0.1", "--run-for", "1"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    let out = cfrs(&[
        "net",
        "proxy",
        "--switch",
        "unix:/nonexistent.sock",
        "--address",
        "10.66.0.3",
        "--reorder",
        "1.5",
    ]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not from 0.0 to 1.0"),
        "{}",
        stderr(&out)
    );
}

/// Issue 205: --auth-user is refused with a raw --tcp origin; a password
/// file that others can read is a configuration error.
#[test]
fn auth_user_flags() {
    let dir = tempfile::tempdir().unwrap();
    let pass = dir.path().join("pass");
    std::fs::write(&pass, "secret\n").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pass = pass.to_str().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let out = cfrs(&[
        "tunnel",
        "--tcp",
        &addr,
        "--auth-user",
        "u",
        "--auth-password-file",
        pass,
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    let out = cfrs(&[
        "tunnel",
        "--hello-world",
        "--auth-user",
        "u",
        "--auth-password-file",
        pass,
        "--check",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    std::fs::set_permissions(pass, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = cfrs(&[
        "tunnel",
        "--hello-world",
        "--auth-user",
        "u",
        "--auth-password-file",
        pass,
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
    let out = cfrs(&["tunnel", "--hello-world", "--auth-user", "u", "--check"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}

/// The program of CFRS_ERROR_PROGRAM gets the report, and no secret of
/// cfrs in its environment (podssh).
#[test]
fn the_error_program_gets_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("report.sh");
    let seen = dir.path().join("env.txt");
    std::fs::write(
        &program,
        format!("#!/bin/sh\ncat > /dev/null\nenv > {}\n", seen.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--bogus-flag"])
        .env("CFRS_ERROR_PROGRAM", &program)
        .env("TUNNEL_TOKEN", "secret-token")
        .env("CFRS_RELAY_TOKEN", "secret-relay")
        .env("CFRS_PROXY", "http://user:secret-pw@127.0.0.1:1")
        .env("CFRS_SOMETHING", "kept")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    let env = std::fs::read_to_string(&seen).unwrap();
    assert!(!env.contains("secret"), "{env}");
    assert!(env.contains("CFRS_SOMETHING=kept"), "{env}");
}

/// podssh #118: root with the HOME of another user writes no file there.
/// ssh-config --write exits 78; CFRS_FOREIGN_HOME=allow writes. The state
/// directory skips that HOME. Needs root (to chown); skipped otherwise.
#[test]
fn root_writes_no_file_in_the_home_of_another_user() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let c = |p: &std::path::Path| {
        let p = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(p.as_ptr(), 4242, 4242) }, 0);
    };
    c(&home);
    c(&home.join(".ssh"));
    let run = |extra: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(["warp", "ssh-config", "--write", "--host", "example.org"])
            .env("HOME", &home)
            .env_remove("XDG_STATE_HOME")
            .env_remove("CFRS_STATE_DIR")
            .env_remove("CFRS_FOREIGN_HOME")
            .env_remove("CFRS_ERROR_PROGRAM");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("CFRS_FOREIGN_HOME=allow"),
        "{}",
        stderr(&out)
    );
    assert!(!home.join(".ssh/config").exists());
    let out = run(&[("CFRS_FOREIGN_HOME", "allow")]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(home.join(".ssh/config").exists());
    // The state directory is not made in that HOME.
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["status"])
        .env("HOME", &home)
        .env_remove("XDG_STATE_HOME")
        .env_remove("CFRS_STATE_DIR")
        .env_remove("CFRS_ERROR_PROGRAM")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!home.join(".local/state/cfrs").exists());
}

/// One rule for a unix socket path (podssh, issue 202): net switch, net
/// proxy and relay connect --listen refuse a socket that answers (69) and
/// never remove a file that is not a socket (64).
#[test]
fn the_socket_rule_of_net_and_relay() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data");
    std::fs::write(&file, "keep").unwrap();
    let live = dir.path().join("live.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
    let run = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(args).env_remove("CFRS_ERROR_PROGRAM");
        let out = cmd.output().unwrap();
        (out.status.code(), stderr(&out))
    };
    let f = format!("unix:{}", file.display());
    let l = format!("unix:{}", live.display());
    for args in [
        vec!["net", "switch", "--listen", f.as_str(), "--run-for", "1"],
        vec!["net", "proxy", "--listen", f.as_str(), "--run-for", "1"],
    ] {
        let (code, err) = run(&args);
        assert_eq!(code, Some(64), "{args:?}: {err}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep");
    }
    for args in [
        vec!["net", "switch", "--listen", l.as_str(), "--run-for", "1"],
        vec!["net", "proxy", "--listen", l.as_str(), "--run-for", "1"],
    ] {
        let (code, err) = run(&args);
        assert_eq!(code, Some(69), "{args:?}: {err}");
        assert!(err.contains("served by another process"), "{err}");
    }
}

/// podssh: status, ps, stop, logs and wait read the run directory and make
/// none.
#[test]
fn the_read_commands_make_no_run_directory() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let state = dir.path().join("state");
    for args in [
        &["status"][..],
        &["ps"],
        &["ps", "--json"],
        &["stop", "x"],
        &["logs", "x"],
        &["wait", "x", "--timeout", "1"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_STATE_HOME", &state)
            .env("HOME", dir.path())
            .env_remove("CFRS_RUN_DIR")
            .env_remove("CFRS_STATE_DIR")
            .env_remove("CFRS_ERROR_PROGRAM")
            .output()
            .unwrap();
        assert_ne!(out.status.code(), Some(101), "{args:?}: {}", stderr(&out));
        assert!(
            !runtime.join("cfrs").exists(),
            "{args:?} made the run directory"
        );
        assert!(
            !state.join("cfrs").exists(),
            "{args:?} made the state directory"
        );
    }
}

/// E4: --token-file and TUNNEL_TOKEN_FILE read the token; it is not on the
/// command line. An empty file, or a token flag and a file, exit 64.
#[test]
fn a_token_comes_from_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, "  bad*token*value\n").unwrap();
    let path = file.to_str().unwrap();
    let run = |args: &[&str], env: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(args)
            .env_remove("TUNNEL_TOKEN")
            .env_remove("TUNNEL_TOKEN_FILE")
            .env("CFRS_STATE_DIR", "none");
        if let Some(env) = env {
            cmd.env("TUNNEL_TOKEN_FILE", env);
        }
        cmd.output().unwrap()
    };
    for out in [
        run(
            &[
                "tunnel",
                "--token-file",
                path,
                "--url",
                "http://127.0.0.1:1",
            ],
            None,
        ),
        run(
            &[
                "tunnel",
                &format!("--token-file={path}"),
                "--url",
                "http://127.0.0.1:1",
            ],
            None,
        ),
        run(&["tunnel", "--url", "http://127.0.0.1:1"], Some(path)),
    ] {
        let err = stderr(&out);
        // The token of the file was read: it is not a valid token.
        assert!(err.contains("not valid base64"), "{err}");
        assert!(!err.contains("bad*token*value"), "{err}");
    }
    std::fs::write(&file, " \n").unwrap();
    let out = run(&["tunnel", "--token-file", path], None);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    assert!(stderr(&out).contains("is empty"));
    let out = run(&["tunnel", "--token", "x", "--token-file", path], None);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}

/// E11: status gives the kind of the proxy that cfrs dials (before, each
/// proxy was "http"), and its source.
#[test]
fn status_names_the_kind_and_the_source_of_the_proxy() {
    let status = |args: &[&str], proxy: Option<&str>| -> serde_json::Value {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(args).arg("status");
        for key in [
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "CFRS_PROXY",
        ] {
            cmd.env_remove(key);
        }
        if let Some(proxy) = proxy {
            cmd.env("HTTPS_PROXY", proxy);
        }
        let out = cmd.output().unwrap();
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let doc = status(&[], Some("socks5h://u:p@127.0.0.1:1080"));
    assert_eq!(doc["proxy"]["kind"], "socks5h");
    assert_eq!(doc["proxy"]["source"], "HTTPS_PROXY");
    assert_eq!(doc["proxy"]["credentials"], true);
    assert!(!doc.to_string().contains("u:p@"), "{doc}");
    let doc = status(&["--no-proxy"], Some("http://127.0.0.1:3128"));
    assert_eq!(doc["proxy"]["kind"], "direct");
    let doc = status(&["--proxy", "socks5h+unix:/tmp/x.sock"], None);
    assert_eq!(doc["proxy"]["kind"], "socks5h+unix");
    assert_eq!(doc["proxy"]["source"], "--proxy");
}

/// E3: the JSON documents have schema and cfrs; ps --json names its dir.
#[test]
fn json_documents_have_the_schema_and_the_version() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        &["ps", "--json"][..],
        &["ports", "--json"][..],
        &["status"][..],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env("CFRS_RUN_DIR", dir.path())
            .output()
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: {e}: {}", stderr(&out)));
        assert_eq!(doc["schema"], 1, "{args:?}: {doc}");
        assert!(
            doc["cfrs"]
                .as_str()
                .unwrap()
                .starts_with(env!("CARGO_PKG_VERSION")),
            "{args:?}: {doc}"
        );
        if args[0] == "ps" {
            assert!(doc["dir"].is_string(), "{doc}");
        }
    }
}

// Issue 252: a --host with a newline wrote an own Host block with a
// ProxyCommand into the SSH config.
#[test]
fn ssh_config_refuses_a_host_with_a_newline_or_a_space() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(&config, "Host box\n    User me\n").unwrap();
    let config = config.to_str().unwrap();
    for host in ["x\nHost *\n    ProxyCommand evil\n#", "a b", "a\tb", ""] {
        for extra in [&["--write", "--config", config][..], &[]] {
            let mut args = vec!["warp", "ssh-config", "--host", host];
            args.extend_from_slice(extra);
            let out = cfrs(&args);
            assert_eq!(out.status.code(), Some(64), "{host:?}: {}", stderr(&out));
            assert!(out.stdout.is_empty(), "{host:?}");
        }
    }
    assert_eq!(
        std::fs::read_to_string(config).unwrap(),
        "Host box\n    User me\n"
    );
}

// Issue 265: autostart add --from NAME copies the secrets of the instance
// (its record has none), and explicit arguments lose the options of a
// detached start.
#[test]
fn autostart_from_an_instance_keeps_its_secrets_and_drops_detach_options() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let run_dir = dir.path().join("run");
    // No systemctl and no crontab: add writes the entry, then exits 69.
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let listen = format!("unix:{}", dir.path().join("s.sock").display());
    let cfrs = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cfrs"))
            .args(args)
            .env("PATH", &empty)
            .env("HOME", dir.path())
            .env("CFRS_STATE_DIR", &state)
            .env("CFRS_RUN_DIR", &run_dir)
            .env_remove("TUNNEL_TOKEN")
            .env_remove("CFRS_PROXY")
            .env_remove("CFRS_ERROR_PROGRAM")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RUST_LOG")
            .output()
            .unwrap()
    };
    let start = cfrs(&[
        "--proxy",
        "http://u:pw265@127.0.0.1:9",
        "net",
        "switch",
        "--listen",
        &listen,
        "--detach",
        "--name",
        "src",
    ]);
    assert!(start.status.success(), "{}", stderr(&start));
    let out = cfrs(&["autostart", "add", "x", "--from", "src"]);
    let stopped = cfrs(&["stop", "src", "--timeout", "5"]);
    assert!(stopped.status.success(), "{}", stderr(&stopped));
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
    let entry = state.join("autostart");
    let env = std::fs::read_to_string(entry.join("x.env")).unwrap();
    assert!(
        env.contains("CFRS_PROXY=http://u:pw265@127.0.0.1:9"),
        "{env}"
    );
    let mode = std::fs::metadata(entry.join("x.env"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let args = std::fs::read_to_string(entry.join("x.args")).unwrap();
    assert!(!args.contains("pw265"), "{args}");
    assert!(args.contains("switch"), "{args}");
    assert!(
        !args.contains("--detach") && !args.contains("--name"),
        "{args}"
    );
    assert!(
        !run_dir.join("src.secrets").exists(),
        "stop removes the secrets"
    );

    let out = cfrs(&[
        "autostart",
        "add",
        "y",
        "--",
        "net",
        "switch",
        "--listen",
        &listen,
        "--detach",
        "--name",
        "inner",
    ]);
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
    assert!(stderr(&out).contains("are removed"), "{}", stderr(&out));
    let args = std::fs::read_to_string(entry.join("y.args")).unwrap();
    assert!(
        !args.contains("--detach") && !args.contains("inner"),
        "{args}"
    );
}

// Issue 255: warp env with no proxy variables (warp up on the socket only)
// exits 69 and prints nothing on stdout.
#[test]
fn warp_env_with_no_proxy_variables_exits_69() {
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path().join("run");
    std::fs::create_dir(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("warp.env"),
        "# cfrs warp up\nCFRS_WARP_SOCKET=/x\n",
    )
    .unwrap();
    // The lock of a live warp up: a child holds it.
    let lock = run_dir.join("warp.lock");
    std::fs::write(&lock, "").unwrap();
    let mut holder = Command::new("flock")
        .arg("-o")
        .arg(&lock)
        .args(["sleep", "30"])
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while Command::new("flock")
        .args(["-n"])
        .arg(&lock)
        .arg("true")
        .status()
        .unwrap()
        .success()
    {
        assert!(std::time::Instant::now() < until, "the child holds no lock");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["warp", "env"])
        .env("CFRS_RUN_DIR", &run_dir)
        .env_remove("CFRS_ERROR_PROGRAM")
        .output()
        .unwrap();
    let _ = holder.kill();
    let _ = holder.wait();
    assert_eq!(out.status.code(), Some(69), "{}", stderr(&out));
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr(&out).contains("no proxy variables"),
        "{}",
        stderr(&out)
    );
}

// Issue 252: invalid values are errors, not silent.
#[test]
fn invalid_values_are_refused() {
    for args in [
        &["warp", "scan", "--timeout-ms", "0"][..],
        &["warp", "scan", "--timeout-ms", "999999"],
    ] {
        let out = cfrs(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["ports"])
        .env("CFRS_RESOLVE", "bad")
        .env_remove("CFRS_ERROR_PROGRAM")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
    assert!(stderr(&out).contains("CFRS_RESOLVE"), "{}", stderr(&out));
    let out = cfrs(&["--resolve", "bad", "ports"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    let state = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["status"])
        .env("CFRS_EDGE", "zz")
        .env("CFRS_STATE_DIR", state.path())
        .env_remove("CFRS_ERROR_PROGRAM")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("CFRS_EDGE entry \"zz\""),
        "{}",
        stderr(&out)
    );
}

// Issue 253: the shape of the error messages.
#[test]
fn error_messages_have_one_shape() {
    // A parent command with no subcommand: an error and a short usage.
    for parent in ["net", "warp", "relay", "autostart", "agent"] {
        let out = cfrs(&[parent]);
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(64), "{parent}: {err}");
        assert!(err.contains("error:"), "{parent}: {err}");
        assert!(err.lines().count() < 15, "{parent}: {err}");
    }
    // --ca-file is named once.
    let out = cfrs(&["--ca-file", "/nonexistent/roots.pem", "status"]);
    assert_eq!(out.status.code(), Some(78));
    assert_eq!(
        stderr(&out).matches("--ca-file").count(),
        1,
        "{}",
        stderr(&out)
    );
    // --port 0 is refused by the parser, for tunnel and share.
    for args in [&["tunnel", "--port", "0"][..], &["share", "--port", "0"]] {
        let out = cfrs(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("--port"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    // An empty value names its flag.
    for flag in ["--url", "--tcp", "--forward", "--unix"] {
        let out = cfrs(&["tunnel", flag, ""]);
        assert_eq!(out.status.code(), Some(64), "{flag}: {}", stderr(&out));
        assert!(stderr(&out).contains(flag), "{flag}: {}", stderr(&out));
    }
    // stop with no target names --all too.
    let out = cfrs(&["stop"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("--all"), "{}", stderr(&out));
    // net addresses names its columns.
    let out = cfrs(&["net", "addresses"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("ADDRESS"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
