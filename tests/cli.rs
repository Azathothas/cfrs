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
        (&["tunnel", "--port", "0"], "--port 0"),
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
        assert!(line(bind).contains("OK   allowed"), "{text}");
        assert!(line(listen).contains("FAIL EPERM"), "{text}");
    }
    assert!(line("UDP egress").contains("FAIL refused"), "{text}");
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
    let out = run(&["autostart", "list"], &path);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "web\n");

    let out = run(&["autostart", "remove", "web"], &path);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let cron = std::fs::read_to_string(&crontab).unwrap();
    assert_eq!(cron, "MAILTO=\"\"\n@daily /usr/bin/true # mine\n");
    assert!(!entry.join("web.env").exists() && !entry.join("web.args").exists());

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
