//! The report of a failure, for the program in `CFRS_ERROR_PROGRAM`.
//!
//! When cfrs fails (an exit code that is not 0), it starts that program by its
//! name, with no shell and no arguments, and writes one JSON object and a line
//! break to its stdin:
//!
//! `schema` (1), `cfrs` (the version and the commit), `os`, `arch`, `command`
//! (for example `tunnel` or `warp run`, or null), `exit`, `error` (the error
//! chain) and `messages` (the last [`KEEP`] log lines, each at most
//! [`LINE_MAX`] bytes).
//!
//! * The program gets the environment of cfrs without `CFRS_ERROR_PROGRAM`,
//!   so that a cfrs that it runs starts no program of its own. Its stdout and
//!   stderr go to the stderr of cfrs. After 30 s cfrs stops it. Its status
//!   does not change the exit code of cfrs.
//! * The report holds no credential: each line goes through [`mask`], which
//!   hides the user and the password of each URL, the value of each proxy
//!   variable with a user part, and the values that [`hide`] names (a tunnel
//!   token).

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// The number of log lines that the report keeps.
pub const KEEP: usize = 64;
/// The longest line of the report, in bytes.
pub const LINE_MAX: usize = 2048;
/// The variable that names the program.
pub const PROGRAM_VARIABLE: &str = "CFRS_ERROR_PROGRAM";
/// The longest time that the program may run.
pub const PROGRAM_TIMEOUT: Duration = Duration::from_secs(30);

fn lines() -> &'static Mutex<VecDeque<String>> {
    static LINES: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

fn secrets() -> &'static Mutex<Vec<String>> {
    static SECRETS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    SECRETS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Hide `value` (for example a tunnel token) in each line of the report.
pub fn hide(value: &str) {
    if value.len() >= 4 {
        secrets().lock().unwrap().push(value.to_string());
    }
}

/// Remove the ANSI escape sequences of `text`.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

/// Remove the control characters of `text` that a terminal acts on: each
/// escape sequence (ESC and what follows it), BEL, CR, the other C0 and C1
/// controls and DEL. Tab and line feed stay. Text from a peer (an edge
/// error, an HTTP body, a proxy reply) goes through this function before it
/// reaches a terminal.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                // CSI: ESC [ parameters final-byte.
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: ESC ] text, ended by BEL or ESC \.
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                // Another escape: ESC and one character.
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        if c == '\t' || c == '\n' || !(c.is_control()) {
            out.push(c);
        }
    }
    out
}

/// The line that cfrs prints for the error `err`: masked and clean.
pub fn error_line(err: &anyhow::Error) -> String {
    let mut line = format!("cfrs: {}", clean(&mask(&format!("{err:#}"))));
    if let Some(hint) = crate::trust::clock_hint(err) {
        line.push_str("\ncfrs: ");
        line.push_str(&hint);
    } else if let Some(hop) = crate::hop::of(err) {
        line.push_str(&format!("\ncfrs: the {hop} hop failed; {}", hop.hint()));
    }
    line
}

/// Hide the credentials in `line`: `user:pass@` of each URL, the value of
/// each proxy variable that has a user part, and each value given to
/// [`hide`].
pub fn mask(line: &str) -> String {
    let mut out = line.to_string();
    let mut values: Vec<String> = secrets().lock().unwrap().clone();
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        // A value with no user part holds no secret, and a message that
        // names the proxy helps; a value with one is hidden whole.
        if let Ok(v) = std::env::var(key) {
            if v.len() >= 4 && v.contains('@') {
                values.push(v);
            }
        }
    }
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    for v in values {
        out = out.replace(&v, "<hidden>");
    }
    // scheme://user:pass@host -> scheme://<hidden>@host
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        result.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '/' || c == '"' || c == '\'')
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) => {
                result.push_str("<hidden>");
                result.push_str(&authority[at..]);
            }
            None => result.push_str(authority),
        }
        rest = &tail[end..];
    }
    result.push_str(rest);
    result
}

/// Keep `line` for the report.
pub fn record(line: &str) {
    let line = strip_ansi(line);
    let mut line = mask(line.trim_end());
    if line.is_empty() {
        return;
    }
    if line.len() > LINE_MAX {
        let mut cut = LINE_MAX;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
    }
    let mut lines = lines().lock().unwrap();
    if lines.len() == KEEP {
        lines.pop_front();
    }
    lines.push_back(line);
}

/// A writer for tracing-subscriber: it writes to stderr and keeps each line
/// for the report.
#[derive(Clone, Copy, Debug, Default)]
pub struct TeeStderr;

/// The log of a detached instance before its ready (issue 103): the lines
/// of the log go to stderr (the starter) and to this file.
static LOG_TEE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

/// Write each log line to `file` too, until [`clear_log_tee`].
pub fn set_log_tee(file: std::fs::File) {
    *LOG_TEE.lock().unwrap_or_else(|e| e.into_inner()) = Some(file);
}

/// Stop the copy of [`set_log_tee`] (at the ready, stderr is the log).
pub fn clear_log_tee() {
    *LOG_TEE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

impl Write for TeeStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = std::io::stderr().write(buf)?;
        let text = String::from_utf8_lossy(&buf[..written]);
        for line in text.lines() {
            record(line);
        }
        if let Some(file) = LOG_TEE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let mut out = String::new();
            for line in text.lines() {
                out.push_str(&mask(&strip_ansi(line)));
                out.push('\n');
            }
            let _ = file.write_all(out.as_bytes());
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeStderr {
    type Writer = TeeStderr;
    fn make_writer(&'a self) -> Self::Writer {
        TeeStderr
    }
}

/// The report as JSON.
pub fn document(
    command: Option<&str>,
    exit: i32,
    error: Option<&anyhow::Error>,
) -> serde_json::Value {
    let error_hop = error.and_then(crate::hop::of).map(|h| h.name());
    // Issue 210: the refusal of a provision as fields.
    let refusal = error.and_then(crate::quicktunnel::retry_of);
    let error: Vec<String> = error
        .map(|e| e.chain().map(|c| clean(&mask(&c.to_string()))).collect())
        .unwrap_or_default();
    serde_json::json!({
        "schema": 1,
        "cfrs": concat!(env!("CARGO_PKG_VERSION"), " (", env!("CFRS_BUILD_COMMIT"), ")"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "command": command,
        "exit": exit,
        "error": error,
        "hop": error_hop,
        "status": refusal.as_ref().map(|r| r.status),
        "code": refusal.as_ref().and_then(|r| r.code),
        "retry_after_s": refusal.as_ref().and_then(|r| r.retry_after_s),
        "retryable": refusal.as_ref().map(|r| r.retryable),
        "messages": lines().lock().unwrap().iter().cloned().collect::<Vec<_>>(),
    })
}

/// Give the report to the program of `CFRS_ERROR_PROGRAM`, when it is set.
/// Errors go to stderr as one line; they do not change the exit code.
pub fn send(command: Option<&str>, exit: i32, error: Option<&anyhow::Error>) {
    let Some(program) = std::env::var_os(PROGRAM_VARIABLE).filter(|v| !v.is_empty()) else {
        return;
    };
    let report = document(command, exit, error).to_string() + "\n";
    // The stdout of the program is the stderr of cfrs: stdout is data.
    use std::os::fd::AsFd;
    let stdout = std::io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map(std::process::Stdio::from)
        .unwrap_or_else(|_| std::process::Stdio::inherit());
    let mut child = match std::process::Command::new(&program)
        .env_remove(PROGRAM_VARIABLE)
        .stdin(std::process::Stdio::piped())
        .stdout(stdout)
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!(
                "cfrs: {PROGRAM_VARIABLE}: could not start {}: {err}",
                program.to_string_lossy()
            );
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(report.as_bytes());
    }
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if started.elapsed() < PROGRAM_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!(
                    "cfrs: {PROGRAM_VARIABLE}: stopped after {} s",
                    PROGRAM_TIMEOUT.as_secs()
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_url_credentials_and_hidden_values() {
        hide("eyJsecret-token-value");
        let line = "dial http://alice:pw1@proxy:3128 with token eyJsecret-token-value";
        let masked = mask(line);
        assert_eq!(
            masked,
            "dial http://<hidden>@proxy:3128 with token <hidden>"
        );
        assert_eq!(mask("http://host:80/path"), "http://host:80/path");
    }

    #[test]
    fn the_error_line_has_no_control_characters() {
        let peer = "bad gateway\u{1b}[2J\u{1b}]0;owned\u{7}\u{7} from\rthe edge\u{9b}31m\u{7f}";
        let err = anyhow::anyhow!("{peer}").context("registering with the edge");
        let line = error_line(&err);
        assert_eq!(
            line,
            "cfrs: registering with the edge: bad gateway fromthe edge31m"
        );
        for c in ['\u{1b}', '\u{7}', '\r', '\u{9b}', '\u{7f}'] {
            assert!(!line.contains(c), "{c:?} in {line:?}");
        }
        let doc = document(None, 1, Some(&err));
        assert!(!doc.to_string().contains("\\u001b"), "{doc}");
        assert_eq!(clean("a\tb\nc"), "a\tb\nc");
    }

    #[test]
    fn the_ring_keeps_the_last_lines_and_strips_controls() {
        for i in 0..(KEEP + 10) {
            record(&format!("\u{1b}[32mline {i}\u{1b}[0m"));
        }
        let doc = document(
            Some("tunnel"),
            69,
            Some(&anyhow::anyhow!("no edge leg worked")),
        );
        let messages = doc["messages"].as_array().unwrap();
        assert_eq!(messages.len(), KEEP);
        assert_eq!(messages.last().unwrap(), &format!("line {}", KEEP + 9));
        assert_eq!(doc["exit"], 69);
        assert_eq!(doc["command"], "tunnel");
        assert_eq!(doc["error"][0], "no edge leg worked");
    }

    #[test]
    fn the_program_gets_the_report_on_stdin() {
        let dir = std::env::temp_dir().join(format!("cfrs-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("report.json");
        let script = dir.join("program.sh");
        std::fs::write(&script, format!("#!/bin/sh\ncat > {}\n", out.display())).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The variable is read by `send`; this test runs it with the value.
        std::env::set_var(PROGRAM_VARIABLE, &script);
        send(Some("warp run"), 1, Some(&anyhow::anyhow!("failed")));
        std::env::remove_var(PROGRAM_VARIABLE);
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(report["command"], "warp run");
        assert_eq!(report["schema"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
