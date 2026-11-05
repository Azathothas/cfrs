//! `podnet autostart`: start a podnet command at boot and after a logout, with
//! no root.
//!
//! The way is found by a probe, in this order:
//!
//! 1. a systemd user unit, when `systemctl --user` answers;
//! 2. an `@reboot` line in the crontab, when `crontab -l` answers.
//!
//! With neither, `add` prints the line to run at login and fails with exit
//! 69. Each program that a probe or an install runs has a limit of
//! [`PROGRAM_LIMIT`].
//!
//! Each entry has two private files (mode 0600) in `<state>/autostart/`:
//! `NAME.args` (the arguments of the command, one JSON list) and `NAME.env`
//! (`KEY=VALUE` lines: the token, the proxy and the variables of podnet). The
//! unit and the cron line run `podnet autostart run NAME --dir DIR`, so they
//! hold no secret. `--token` and a `--proxy` with a password move from the
//! arguments to `TUNNEL_TOKEN` and `PODNET_PROXY` in the env file, so `ps`
//! shows no secret either.
//!
//! `remove` deletes only what `add` wrote: the unit file has a marker
//! line, and the cron line ends with a marker comment.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

/// The time limit of each program that a probe or an install runs.
pub const PROGRAM_LIMIT: Duration = Duration::from_secs(10);

/// The variables that `add` copies into the env file when they are set.
pub const COPIED: &[&str] = &[
    "TUNNEL_TOKEN",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "RUST_LOG",
    "NO_COLOR",
];

/// The variables of an entry: `(KEY, VALUE)` pairs.
pub type Vars = Vec<(String, String)>;

/// How an entry starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    Systemd,
    Cron,
}

impl Way {
    pub fn name(self) -> &'static str {
        match self {
            Way::Systemd => "systemd",
            Way::Cron => "cron",
        }
    }
}

/// The output of a program with a time limit.
#[derive(Debug)]
pub struct Ran {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Run `program` with `args` and `input` on stdin, for at most `limit`. A
/// program that runs longer is killed, and the result is an error.
pub fn run_limited(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    limit: Duration,
) -> Result<Ran> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {program}"))?;
    // Issue 265: the pipes are read while the program runs. Before, a
    // program that wrote more than a pipe holds blocked until the limit.
    fn drain(
        pipe: Option<impl std::io::Read + Send + 'static>,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut out);
            }
            out
        })
    }
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let writer = match (input, child.stdin.take()) {
        (Some(text), Some(mut stdin)) => {
            let text = text.to_string();
            Some(std::thread::spawn(move || {
                let _ = stdin.write_all(text.as_bytes());
            }))
        }
        _ => None,
    };
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{program} {} did not end in {} s",
                args.join(" "),
                limit.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    Ok(Ran {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Check a name: letters, digits, `-` and `_`, 1 to 64 bytes.
pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        bail!("the name {name:?}: give 1 to 64 letters, digits, - or _");
    }
    Ok(())
}

/// The directory of the entries.
pub fn dir() -> Result<PathBuf> {
    let state = crate::state::state_dir()?
        .context("autostart needs a state directory (PODNET_STATE_DIR is none)")?;
    let dir = state.join("autostart");
    crate::state::prepare(&dir)?;
    Ok(dir)
}

/// The arguments and the variables of an entry: the secrets move from the
/// arguments to the variables.
pub fn split_secrets(args: &[String], env: &dyn Fn(&str) -> Option<String>) -> (Vec<String>, Vars) {
    let mut vars: Vars = COPIED
        .iter()
        .filter_map(|k| env(k).map(|v| (k.to_string(), v)))
        .collect();
    for (k, v) in std::env::vars() {
        if k.starts_with("PODNET_") && k != "PODNET_ERROR_PROGRAM" && env(&k).is_some() {
            vars.push((k, v));
        }
    }
    let mut set = |key: &str, value: String| {
        vars.retain(|(k, _)| k != key);
        vars.push((key.to_string(), value));
    };
    let mut kept = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let secret_key = match flag {
            "--token" => Some("TUNNEL_TOKEN"),
            "--proxy" => Some("PODNET_PROXY"),
            _ => None,
        };
        if let Some(key) = secret_key {
            let value = match inline {
                Some(v) => Some(v),
                None => {
                    i += 1;
                    args.get(i).cloned()
                }
            };
            if let Some(value) = value {
                if key == "PODNET_PROXY" && !value.contains('@') {
                    kept.push("--proxy".to_string());
                    kept.push(value);
                } else {
                    set(key, value);
                }
            }
        } else {
            kept.push(arg.clone());
        }
        i += 1;
    }
    (kept, vars)
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// The text of the env file. A value with a newline is refused.
pub fn env_text(vars: &[(String, String)]) -> Result<String> {
    let mut out = String::from("# podnet autostart: the variables of this entry. Mode 0600.\n");
    for (k, v) in vars {
        if v.contains('\n') || v.contains('\r') {
            bail!("the variable {k} has a newline");
        }
        out.push_str(&format!("{k}={v}\n"));
    }
    Ok(out)
}

/// Read an env file.
pub fn parse_env(text: &str) -> Vars {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// The marker of the unit and of the cron line.
pub fn marker(name: &str) -> String {
    format!("# podnet autostart {name}")
}

/// The command that the cron line runs (words quoted for `sh`).
pub fn run_line(exe: &Path, name: &str, dir: &Path) -> String {
    format!(
        "{} autostart run {name} --dir {}",
        quote(&exe.display().to_string()),
        quote(&dir.display().to_string())
    )
}

/// The command of `ExecStart=` (issue 265): words quoted for systemd. In
/// a unit, `%` starts a specifier and `$` a variable; the quotes of `sh`
/// are not the quotes of systemd.
pub fn unit_line(exe: &Path, name: &str, dir: &Path) -> String {
    format!(
        "{} autostart run {name} --dir {}",
        systemd_quote(&exe.display().to_string()),
        systemd_quote(&dir.display().to_string())
    )
}

fn systemd_quote(s: &str) -> String {
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
    {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn quote(s: &str) -> String {
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The text of the systemd user unit. It restarts after a failure, with
/// no start limit, but not after exit 64 (usage) or 78 (configuration):
/// another start cannot fix them (issue 74).
pub fn unit_text(name: &str, line: &str) -> String {
    format!(
        "{}\n[Unit]\nDescription=podnet autostart {name}\nWants=network-online.target\nAfter=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nExecStart={line}\nRestart=on-failure\nRestartSec=5\nRestartPreventExitStatus=64 78\n\n[Install]\nWantedBy=default.target\n",
        marker(name)
    )
}

/// The crontab with the line of `name` added (and an old line of `name`
/// removed). Other lines stay as they are.
pub fn crontab_with(current: &str, name: &str, line: &str, log: &Path) -> String {
    let mut out = crontab_without(current, name);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "@reboot {line} >> {} 2>&1 {}\n",
        quote(&log.display().to_string()),
        marker(name)
    ));
    out
}

/// The crontab with the line of `name` removed. Other lines stay as they
/// are.
pub fn crontab_without(current: &str, name: &str) -> String {
    let mark = marker(name);
    current
        .split_inclusive('\n')
        .filter(|l| !l.trim_end().ends_with(&mark))
        .collect()
}

fn unit_path(name: &str) -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    let unit = base
        .join("systemd/user")
        .join(format!("podnet-{name}.service"));
    crate::state::check_own(&unit)?;
    Ok(unit)
}

/// The way of this host, with the reason when there is none.
pub fn probe(limit: Duration) -> std::result::Result<Way, String> {
    let systemd = run_limited("systemctl", &["--user", "show-environment"], None, limit);
    let why_systemd = match &systemd {
        Ok(r) if r.code == Some(0) => return Ok(Way::Systemd),
        Ok(r) => format!("systemctl --user: {}", r.stderr.trim()),
        Err(e) => format!("{e:#}"),
    };
    let cron = run_limited("crontab", &["-l"], None, limit);
    match &cron {
        Ok(r) if r.code == Some(0) || r.stderr.contains("no crontab") => Ok(Way::Cron),
        Ok(r) => Err(format!("{why_systemd}; crontab -l: {}", r.stderr.trim())),
        Err(e) => Err(format!("{why_systemd}; {e:#}")),
    }
}

/// The result of `add`.
pub struct Added {
    pub way: Way,
    pub detail: String,
}

/// Add the entry `name` that runs `podnet ARGS`. The variables of `extra`
/// (the secrets of an instance, for `--from`) replace those of the
/// environment.
pub fn add(
    name: &str,
    args: &[String],
    extra: &[(String, String)],
    limit: Duration,
) -> Result<Added> {
    // Issue 173: a bad name, command or place of the binary is a usage
    // error (64); a failed write stays an error (1).
    let usage = |err: anyhow::Error| crate::exit::fault(crate::exit::Fault::Usage, err);
    check_name(name).map_err(usage)?;
    let Some(first) = args.first() else {
        return Err(usage(anyhow::anyhow!("give the command after --, for example: podnet autostart add web -- tunnel --config /etc/podnet.yml")));
    };
    if ["autostart", "pod", "update", "man", "completions"].contains(&first.as_str()) {
        return Err(usage(anyhow::anyhow!(
            "podnet {first} cannot run as an autostart entry"
        )));
    }
    let exe = std::env::current_exe().context("the path of this binary")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    for tmp in [
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ] {
        let tmp = tmp.canonicalize().unwrap_or(tmp);
        if exe.starts_with(&tmp) {
            return Err(usage(anyhow::anyhow!(
                "{} is in a temporary directory: copy podnet to a lasting place (for example ~/.local/bin) first",
                exe.display()
            )));
        }
    }
    let dir = dir()?;
    let (kept, mut vars) = split_secrets(args, &|k| std::env::var(k).ok());
    for (key, value) in extra {
        vars.retain(|(k, _)| k != key);
        vars.push((key.clone(), value.clone()));
    }
    write_private(
        &dir.join(format!("{name}.args")),
        &serde_json::to_string(&kept)?,
    )?;
    write_private(&dir.join(format!("{name}.env")), &env_text(&vars)?)?;
    let line = run_line(&exe, name, &dir);
    let way = match probe(limit) {
        Ok(way) => way,
        Err(why) => {
            return Err(crate::exit::fault(
                crate::exit::Fault::Unavailable,
                anyhow::anyhow!(
                    "no way to start at boot: {why}. Run this line at login (for example in ~/.profile):\n  nohup {line} >/dev/null 2>&1 &"
                ),
            ))
        }
    };
    let detail = match way {
        Way::Systemd => {
            let unit = unit_path(name)?;
            if let Some(parent) = unit.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("making {}", parent.display()))?;
            }
            if unit.exists() && !is_ours(&unit, name) {
                bail!("{} exists and podnet did not write it", unit.display());
            }
            std::fs::write(&unit, unit_text(name, &unit_line(&exe, name, &dir)))
                .with_context(|| format!("writing {}", unit.display()))?;
            let service = format!("podnet-{name}.service");
            ok(run_limited(
                "systemctl",
                &["--user", "daemon-reload"],
                None,
                limit,
            )?)?;
            ok(run_limited(
                "systemctl",
                &["--user", "enable", "--now", &service],
                None,
                limit,
            )?)?;
            let linger = linger_hint(limit);
            format!(
                "{} (systemctl --user status {service}){linger}",
                unit.display()
            )
        }
        Way::Cron => {
            let current = crontab_list(limit)?;
            let log = dir.join(format!("{name}.log"));
            let next = crontab_with(&current, name, &line, &log);
            ok(run_limited("crontab", &["-"], Some(&next), limit)?)?;
            // Issue 117: a crontab that took the input and kept nothing is
            // no way to start at boot.
            let marker = marker(name);
            if !crontab_list(limit)?
                .lines()
                .any(|l| l.trim_end().ends_with(&marker))
            {
                return Err(crate::exit::fault(
                    crate::exit::Fault::Unavailable,
                    anyhow::anyhow!("crontab - exited 0, and crontab -l has no line for {name}: cron does not keep the entry"),
                ));
            }
            // Start it now too: cron starts it at the next boot.
            let started = start_now(&exe, name, &dir, &log);
            format!(
                "an @reboot line in the crontab; started now: {started}; the log: {}",
                log.display()
            )
        }
    };
    Ok(Added { way, detail })
}

/// Start the entry now, in its own session (not in the process group of
/// the caller, and with no descriptor of the caller), with its output in
/// `log`. It counts as started when it still runs after 1 s.
fn start_now(exe: &Path, name: &str, dir: &Path, log: &Path) -> String {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(log)
    };
    let (Ok(out), Ok(err)) = (open(), open()) else {
        return format!("no (cannot write {})", log.display());
    };
    let mut cmd = Command::new(exe);
    cmd.args(["autostart", "run", name, "--dir"])
        .arg(dir)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    // SAFETY: setsid and close_range are async-signal-safe; they run in
    // the child between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return format!("no ({e})"),
    };
    std::thread::sleep(Duration::from_secs(1));
    match child.try_wait() {
        Ok(None) => format!("yes (pid {})", child.id()),
        Ok(Some(status)) => format!("no (it ended with {status}; see the log)"),
        Err(e) => format!("unknown ({e})"),
    }
}

fn ok(ran: Ran) -> Result<()> {
    if ran.code != Some(0) {
        bail!("{}", ran.stderr.trim());
    }
    Ok(())
}

fn crontab_list(limit: Duration) -> Result<String> {
    let ran = run_limited("crontab", &["-l"], None, limit)?;
    if ran.code == Some(0) {
        Ok(ran.stdout)
    } else if ran.stderr.contains("no crontab") {
        Ok(String::new())
    } else {
        bail!("crontab -l: {}", ran.stderr.trim())
    }
}

fn linger_hint(limit: Duration) -> String {
    let user = std::env::var("USER").unwrap_or_default();
    match run_limited(
        "loginctl",
        &["show-user", &user, "-p", "Linger"],
        None,
        limit,
    ) {
        Ok(r) if r.stdout.trim() == "Linger=yes" => String::new(),
        _ => "; the user manager stops at logout: run `loginctl enable-linger` to keep it".into(),
    }
}

fn is_ours(path: &Path, name: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|t| t.lines().next() == Some(marker(name).as_str()))
        .unwrap_or(false)
}

/// Remove the entry `name`: what `add` wrote, and nothing else.
pub fn remove(name: &str, limit: Duration) -> Result<Vec<String>> {
    check_name(name)?;
    let mut done = Vec::new();
    if let Ok(unit) = unit_path(name) {
        if is_ours(&unit, name) {
            let service = format!("podnet-{name}.service");
            let _ = run_limited(
                "systemctl",
                &["--user", "disable", "--now", &service],
                None,
                limit,
            );
            std::fs::remove_file(&unit)?;
            let _ = run_limited("systemctl", &["--user", "daemon-reload"], None, limit);
            done.push(format!("removed {}", unit.display()));
        } else if unit.exists() {
            done.push(format!("kept {}: podnet did not write it", unit.display()));
        }
    }
    if let Ok(current) = crontab_list(limit) {
        let next = crontab_without(&current, name);
        if next != current {
            ok(run_limited("crontab", &["-"], Some(&next), limit)?)?;
            done.push("removed the crontab line".into());
        }
    }
    if let Ok(dir) = dir() {
        for ext in ["args", "env", "log"] {
            let path = dir.join(format!("{name}.{ext}"));
            if path.exists() {
                std::fs::remove_file(&path)?;
                done.push(format!("removed {}", path.display()));
            }
        }
    }
    if done.is_empty() {
        bail!("no autostart entry {name}");
    }
    Ok(done)
}

/// The names of the entries.
pub fn list() -> Result<Vec<String>> {
    let dir = dir()?;
    let mut names: Vec<String> = std::fs::read_dir(&dir)?
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".args"))
                .map(str::to_string)
        })
        .collect();
    names.sort();
    Ok(names)
}

/// The arguments and the variables of the entry `name` in `dir`.
pub fn load(name: &str, dir: &Path) -> Result<(Vec<String>, Vars)> {
    check_name(name)?;
    let args_path = dir.join(format!("{name}.args"));
    let args: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(&args_path)
            .with_context(|| format!("reading {}", args_path.display()))?,
    )
    .with_context(|| format!("parsing {}", args_path.display()))?;
    let env_path = dir.join(format!("{name}.env"));
    let vars = parse_env(&std::fs::read_to_string(&env_path).unwrap_or_default());
    Ok((args, vars))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "eyJhIjoiYSIsInQiOiJ0IiwicyI6InMifQ==";

    #[test]
    fn the_secrets_leave_the_arguments() {
        let args: Vec<String> = [
            "tunnel",
            "--token",
            TOKEN,
            "--proxy=http://u:pw@proxy:3128",
            "--url",
            "http://127.0.0.1:8080",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let env = |k: &str| (k == "NO_PROXY").then(|| "localhost".to_string());
        let (kept, vars) = split_secrets(&args, &env);
        assert_eq!(kept, ["tunnel", "--url", "http://127.0.0.1:8080"]);
        assert!(vars.contains(&("TUNNEL_TOKEN".into(), TOKEN.into())));
        assert!(vars.contains(&("PODNET_PROXY".into(), "http://u:pw@proxy:3128".into())));
        assert!(vars.contains(&("NO_PROXY".into(), "localhost".into())));
        // A proxy with no password stays on the command line.
        let (kept, _) = split_secrets(
            &["tunnel".into(), "--proxy".into(), "http://p:3128".into()],
            &|_| None,
        );
        assert_eq!(kept, ["tunnel", "--proxy", "http://p:3128"]);
        // The env file reads back; a newline is refused.
        let text = env_text(&vars).unwrap();
        assert_eq!(parse_env(&text), vars);
        assert!(env_text(&[("A".into(), "x\ny".into())]).is_err());
    }

    #[test]
    fn the_unit_and_the_cron_line_hold_no_secret() {
        let line = run_line(
            Path::new("/home/u/.local/bin/podnet"),
            "web",
            Path::new("/home/u/.local/state/podnet/autostart"),
        );
        assert_eq!(
            line,
            "/home/u/.local/bin/podnet autostart run web --dir /home/u/.local/state/podnet/autostart"
        );
        let unit = unit_text("web", &line);
        assert!(unit.starts_with("# podnet autostart web\n"));
        assert!(unit.contains("ExecStart=/home/u/.local/bin/podnet autostart run web"));
        assert!(unit.contains("\nRestartPreventExitStatus=64 78\n"));
        assert!(unit.contains("\nStartLimitIntervalSec=0\n"));
        assert!(!unit.contains(TOKEN));
    }

    // Issue 265: a unit takes % and $ as its own specifiers.
    #[test]
    fn the_unit_line_quotes_for_systemd() {
        let line = unit_line(
            Path::new("/opt/c f/podnet"),
            "web",
            Path::new("/tmp/%h/$X/a\"b"),
        );
        assert_eq!(
            line,
            r#""/opt/c f/podnet" autostart run web --dir "/tmp/%%h/$$X/a\"b""#
        );
        let plain = unit_line(Path::new("/b/podnet"), "web", Path::new("/d"));
        assert_eq!(plain, "/b/podnet autostart run web --dir /d");
        let unit = unit_text("web", &line);
        assert!(unit.contains(&format!("\nExecStart={line}\n")), "{unit}");
    }

    // Issue 265: a program that writes more than a pipe holds ends in time.
    #[test]
    fn run_limited_reads_a_large_output() {
        let ran = run_limited(
            "sh",
            &[
                "-c",
                "head -c 300000 /dev/zero; head -c 200000 /dev/zero >&2",
            ],
            None,
            Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(ran.code, Some(0));
        assert_eq!(ran.stdout.len(), 300000);
        assert_eq!(ran.stderr.len(), 200000);
    }

    #[test]
    fn the_crontab_keeps_other_lines() {
        let other = "MAILTO=\"\"\n0 3 * * * backup # podnet autostart webx\n@daily x\n";
        let with = crontab_with(
            other,
            "web",
            "/b/podnet autostart run web --dir /d",
            Path::new("/d/web.log"),
        );
        assert!(with.starts_with(other));
        assert!(with.ends_with(
            "@reboot /b/podnet autostart run web --dir /d >> /d/web.log 2>&1 # podnet autostart web\n"
        ));
        // Again: one line, not two.
        let twice = crontab_with(
            &with,
            "web",
            "/b/podnet autostart run web --dir /d",
            Path::new("/d/web.log"),
        );
        assert_eq!(twice, with);
        assert_eq!(crontab_without(&with, "web"), other);
        // No newline at the end of the old crontab.
        let bare = crontab_with("@daily x", "web", "c", Path::new("/l"));
        assert!(bare.starts_with("@daily x\n@reboot c"));
    }

    #[test]
    fn a_hung_program_ends_at_the_limit() {
        let start = Instant::now();
        let err = run_limited("sleep", &["30"], None, Duration::from_millis(500)).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(format!("{err:#}").contains("did not end"), "{err:#}");
        let ran = run_limited("cat", &[], Some("in"), Duration::from_secs(5)).unwrap();
        assert_eq!(ran.stdout, "in");
    }

    #[test]
    fn names() {
        assert!(check_name("web-1_a").is_ok());
        for bad in ["", "a/b", "a b", "..", &"x".repeat(65)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }
}
