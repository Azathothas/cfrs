//! `--detach` (issues 70, 71, 72): an instance in the background, with no
//! network. `cfrs net switch` is ready when its listener is bound.

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Env {
    _tmp: tempfile::TempDir,
    run: PathBuf,
    sock: PathBuf,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        let sock = tmp.path().join("sw.sock");
        Env {
            _tmp: tmp,
            run,
            sock,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
        cmd.args(args)
            .env("CFRS_RUN_DIR", &self.run)
            .env_remove("RUST_LOG")
            .env_remove("CFRS_ERROR_PROGRAM");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    fn switch(&self) -> String {
        format!("unix:{}", self.sock.display())
    }

    fn ps(&self) -> serde_json::Value {
        let out = self.run(&["ps", "--json"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn pid_of(&self, name: &str) -> Option<i32> {
        self.ps()["instances"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == name)
            .map(|i| i["pid"].as_i64().unwrap() as i32)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["stop", "--all", "--timeout", "2"]);
    }
}

/// The last line of stdout: the ready document.
fn ready_doc(out: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    let last = text.lines().last().unwrap_or("");
    serde_json::from_str(last).unwrap_or_else(|e| panic!("{e}: {text:?}"))
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 tests for the process only.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < until, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn connects(sock: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

#[test]
fn a_detached_instance_outlives_the_shell_that_started_it() {
    let env = Env::new();
    let switch = env.switch();
    // A shell in its own process group starts cfrs and exits; then the
    // group gets SIGHUP and SIGKILL, as when a terminal or an agent's
    // shell closes.
    let mut shell = Command::new("sh");
    shell
        .arg("-c")
        .arg(format!(
            "{} net switch --listen {switch} --detach --name t",
            env!("CARGO_BIN_EXE_cfrs")
        ))
        .env("CFRS_RUN_DIR", &env.run)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = shell.spawn().unwrap();
    let pgid = child.id() as i32;
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = ready_doc(&out);
    assert_eq!(doc["name"], "t");
    assert_eq!(doc["event"], "detached");
    assert_eq!(doc["listen"], switch);
    let pid = doc["pid"].as_i64().unwrap() as i32;
    // SAFETY: signals to the process group of the test's own shell.
    unsafe {
        libc::kill(-pgid, libc::SIGHUP);
        libc::kill(-pgid, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(alive(pid), "the instance ended with the group of its shell");
    // SAFETY: getsid of a process.
    assert_eq!(
        unsafe { libc::getsid(pid) },
        pid,
        "the instance leads its own session"
    );
    assert!(connects(&env.sock), "the instance still serves");
    assert_eq!(env.pid_of("t"), Some(pid));
}

#[test]
fn the_start_returns_and_releases_the_streams_of_the_caller() {
    let env = Env::new();
    let switch = env.switch();
    // fd 7 is a copy of the stdout pipe: a child that keeps it would keep
    // the pipe open, and this read would not end.
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(format!(
            "exec 7>&1; exec {} net switch --listen {switch} --detach --name s",
            env!("CARGO_BIN_EXE_cfrs")
        ))
        .env("CFRS_RUN_DIR", &env.run)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        let _ = tx.send(text);
    });
    let text = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the pipe of the caller is released");
    assert!(child.wait().unwrap().success());
    assert!(text.contains("\"event\":\"detached\""), "{text}");
    assert!(connects(&env.sock));
}

#[test]
fn a_second_start_with_the_same_name_is_the_same_instance() {
    let env = Env::new();
    let switch = env.switch();
    let args = [
        "net", "switch", "--listen", &switch, "--detach", "--name", "same",
    ];
    let first = env.run(&args);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = env.run(&args);
    assert!(second.status.success());
    assert_eq!(ready_doc(&first), ready_doc(&second));
    // Another --ready-timeout is the same instance too.
    let third = env.run(&[
        "net",
        "switch",
        "--listen",
        &switch,
        "--detach",
        "--name",
        "same",
        "--ready-timeout",
        "5",
    ]);
    assert!(third.status.success());
    assert_eq!(ready_doc(&first)["pid"], ready_doc(&third)["pid"]);
    // Other arguments: 69, and the instance stays.
    let other_sock = format!("{switch}.2");
    let other = env.run(&[
        "net",
        "switch",
        "--listen",
        &other_sock,
        "--detach",
        "--name",
        "same",
    ]);
    assert_eq!(other.status.code(), Some(69));
    assert!(String::from_utf8_lossy(&other.stderr).contains("--replace"));
    // --replace: a new instance with the new arguments.
    let replaced = env.run(&[
        "net",
        "switch",
        "--listen",
        &other_sock,
        "--detach",
        "--name",
        "same",
        "--replace",
    ]);
    assert!(
        replaced.status.success(),
        "{}",
        String::from_utf8_lossy(&replaced.stderr)
    );
    assert_ne!(ready_doc(&first)["pid"], ready_doc(&replaced)["pid"]);
    assert_eq!(ready_doc(&replaced)["listen"], other_sock);
}

#[test]
fn two_starts_at_the_same_time_give_one_instance() {
    let env = Env::new();
    let switch = env.switch();
    let spawn = || {
        env.cmd(&[
            "net", "switch", "--listen", &switch, "--detach", "--name", "race",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
    };
    let (a, b) = (spawn(), spawn());
    let (a, b) = (a.wait_with_output().unwrap(), b.wait_with_output().unwrap());
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    assert!(b.status.success(), "{}", String::from_utf8_lossy(&b.stderr));
    assert_eq!(ready_doc(&a)["pid"], ready_doc(&b)["pid"]);
    assert_eq!(env.ps()["instances"].as_array().unwrap().len(), 1);
}

#[test]
fn a_failure_before_ready_gives_the_code_and_leaves_no_record() {
    let env = Env::new();
    let out = env.run(&[
        "net", "switch", "--listen", "bad:x", "--detach", "--name", "bad",
    ]);
    assert!(!out.status.success());
    assert_ne!(out.status.code(), Some(75));
    assert!(
        !String::from_utf8_lossy(&out.stderr).is_empty(),
        "the error of the child"
    );
    assert!(env.ps()["instances"].as_array().unwrap().is_empty());
}

#[test]
fn stop_logs_and_wait() {
    let env = Env::new();
    let switch = env.switch();
    let start = env.run(&[
        "net", "switch", "--listen", &switch, "--detach", "--name", "w",
    ]);
    assert!(start.status.success());
    let pid = ready_doc(&start)["pid"].as_i64().unwrap() as i32;
    let wait = env.run(&["wait", "w", "--timeout", "5"]);
    assert!(wait.status.success());
    assert_eq!(ready_doc(&wait), ready_doc(&start));
    let logs = env.run(&["logs", "w"]);
    assert!(logs.status.success());
    let stop = env.run(&["stop", "w", "--timeout", "5"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    wait_until("the instance ends", || !alive(pid));
    assert!(env.ps()["instances"].as_array().unwrap().is_empty());
    assert_eq!(env.run(&["stop", "w"]).status.code(), Some(69));
    assert_eq!(
        env.run(&["wait", "w", "--timeout", "1"]).status.code(),
        Some(69)
    );
}

#[test]
fn a_killed_instance_is_removed_and_can_start_again() {
    let env = Env::new();
    let switch = env.switch();
    let args = [
        "net",
        "switch",
        "--listen",
        &switch,
        "--detach",
        "--name",
        "k",
        "--no-restart",
    ];
    let start = env.run(&args);
    assert!(start.status.success());
    let pid = ready_doc(&start)["pid"].as_i64().unwrap() as i32;
    // SAFETY: a signal to the instance of this test.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    wait_until("the instance ends", || !alive(pid));
    assert!(
        env.ps()["instances"].as_array().unwrap().is_empty(),
        "a stale record is removed"
    );
    let again = env.run(&args);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_ne!(ready_doc(&again)["pid"].as_i64().unwrap() as i32, pid);
}

#[test]
fn no_secret_in_the_arguments_of_the_child_or_in_the_record() {
    let env = Env::new();
    let switch = env.switch();
    let start = env.run(&[
        "--proxy",
        "http://user:hunter2@127.0.0.1:9",
        "net",
        "switch",
        "--listen",
        &switch,
        "--detach",
        "--name",
        "sec",
    ]);
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let pid = ready_doc(&start)["pid"].as_i64().unwrap();
    let supervisor = env.ps()["instances"][0]["supervisor"].as_i64().unwrap();
    for pid in [pid, supervisor] {
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
        assert!(!String::from_utf8_lossy(&cmdline).contains("hunter2"));
    }
    let record = std::fs::read_to_string(env.run.join("sec.json")).unwrap();
    assert!(!record.contains("hunter2"));
    use std::os::unix::fs::PermissionsExt as _;
    for file in ["sec.json", "sec.log"] {
        let mode = std::fs::metadata(env.run.join(file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }
}

#[test]
fn detach_options_need_detach_and_other_commands_refuse_it() {
    let env = Env::new();
    assert_eq!(
        env.run(&["net", "switch", "--name", "x"]).status.code(),
        Some(64)
    );
    assert_eq!(env.run(&["status", "--detach"]).status.code(), Some(64));
    assert_eq!(
        env.run(&["--detach-child", "status"]).status.code(),
        Some(64)
    );
}

#[test]
fn no_ready_in_time_exits_75_and_leaves_no_record() {
    let env = Env::new();
    // A provisioning endpoint that accepts and never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", silent.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((conn, _)) = silent.accept() {
            held.push(conn);
        }
    });
    let started = Instant::now();
    let out = env.run(&[
        "--no-proxy",
        "tunnel",
        "--service-url",
        &url,
        "--hello-world",
        "--detach",
        "--name",
        "slow",
        "--ready-timeout",
        "2",
    ]);
    assert_eq!(
        out.status.code(),
        Some(75),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    assert!(env.ps()["instances"].as_array().unwrap().is_empty());
}

fn instance(env: &Env, name: &str) -> serde_json::Value {
    env.ps()["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == name)
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

#[test]
fn the_supervisor_starts_a_killed_child_again() {
    let env = Env::new();
    let switch = env.switch();
    let start = env.run(&[
        "net", "switch", "--listen", &switch, "--detach", "--name", "sup",
    ]);
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let first = ready_doc(&start)["pid"].as_i64().unwrap() as i32;
    let supervisor = instance(&env, "sup")["supervisor"].as_i64().unwrap() as i32;
    assert_ne!(first, supervisor);
    // SAFETY: a signal to the child of this test.
    unsafe { libc::kill(first, libc::SIGKILL) };
    wait_until("a new child is ready", || {
        let i = instance(&env, "sup");
        i["restarts"] == 1 && i["state"] == "ready" && i["pid"].as_i64() != Some(first as i64)
    });
    assert!(alive(supervisor));
    assert!(connects(&env.sock), "the new child serves");
    let log = std::fs::read_to_string(env.run.join("sup.log")).unwrap();
    assert!(log.contains("start 1"), "{log}");
    // SIGTERM to the supervisor (cfrs stop) ends both, with no new start.
    let child = instance(&env, "sup")["pid"].as_i64().unwrap() as i32;
    assert!(env.run(&["stop", "sup"]).status.success());
    wait_until("both end", || !alive(child) && !alive(supervisor));
    assert!(instance(&env, "sup").is_null());
}

#[test]
fn a_child_goes_on_when_its_supervisor_is_killed() {
    let env = Env::new();
    let switch = env.switch();
    let start = env.run(&[
        "net", "switch", "--listen", &switch, "--detach", "--name", "orphan",
    ]);
    assert!(start.status.success());
    let child = ready_doc(&start)["pid"].as_i64().unwrap() as i32;
    let supervisor = instance(&env, "orphan")["supervisor"].as_i64().unwrap() as i32;
    // SAFETY: a signal to the supervisor of this test.
    unsafe { libc::kill(supervisor, libc::SIGKILL) };
    wait_until("the supervisor ends", || !alive(supervisor));
    assert!(alive(child));
    assert!(connects(&env.sock));
    assert_eq!(instance(&env, "orphan")["pid"].as_i64(), Some(child as i64));
    // stop signals the child (it holds its lock), not the dead supervisor.
    let started = Instant::now();
    assert!(env
        .run(&["stop", "orphan", "--timeout", "5"])
        .status
        .success());
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "SIGTERM, not the SIGKILL timeout"
    );
    wait_until("the child ends", || !alive(child));
}

/// Issue 103: the log of an instance has its startup lines (before the
/// ready) after a separator with its pid; a second start of the same name
/// adds a second separator, and its lines come after it.
#[test]
fn the_log_has_the_startup_lines_of_this_start() {
    let env = Env::new();
    let switch = env.switch();
    for run in 1..=2 {
        let start = env.run(&[
            "net", "switch", "--listen", &switch, "--detach", "--name", "l",
        ]);
        assert!(
            start.status.success(),
            "{}",
            String::from_utf8_lossy(&start.stderr)
        );
        let pid = ready_doc(&start)["pid"].as_i64().unwrap();
        let logs = env.run(&["logs", "l"]);
        let text = String::from_utf8_lossy(&logs.stdout).into_owned();
        assert_eq!(text.matches("---- start").count(), run, "{text}");
        let lines: Vec<&str> = text.lines().collect();
        let last = lines
            .iter()
            .rposition(|l| l.contains("---- start"))
            .unwrap();
        let tail = &lines[last..];
        assert!(tail[0].contains(&format!("pid {pid} ")), "{text}");
        let listening = tail
            .iter()
            .filter(|l| l.contains("switch is listening"))
            .count();
        assert_eq!(listening, 1, "the line of this start, one time: {text}");
        assert!(!text.contains('\u{1b}'), "no colour codes: {text}");
        let stop = env.run(&["stop", "l", "--timeout", "5"]);
        assert!(stop.status.success());
        wait_until("the instance ends", || !alive(pid as i32));
    }
}
