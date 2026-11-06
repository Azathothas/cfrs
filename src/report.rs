//! The report of a failure, for the program in `PODNET_ERROR_PROGRAM`.
//!
//! When podnet fails (an exit code that is not 0), it starts that program by its
//! name, with no shell and no arguments, and writes one JSON object and a line
//! break to its stdin:
//!
//! `schema` (1), `podnet` (the version and the commit), `os`, `arch`, `command`
//! (for example `tunnel` or `warp run`, or null), `exit`, `error` (the error
//! chain) and `messages` (the last [`KEEP`] log lines, each at most
//! [`LINE_MAX`] bytes).
//!
//! * The program gets the environment of podnet without `PODNET_ERROR_PROGRAM`,
//!   so that a podnet that it runs starts no program of its own. Its stdout and
//!   stderr go to the stderr of podnet. After 30 s podnet stops it. Its status
//!   does not change the exit code of podnet.
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
pub const PROGRAM_VARIABLE: &str = "PODNET_ERROR_PROGRAM";
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

/// The line that podnet prints for the error `err`: masked and clean.
pub fn error_line(err: &anyhow::Error) -> String {
    let mut line = format!("podnet: {}", clean(&mask(&format!("{err:#}"))));
    if let Some(hint) = pod_tls::clock_hint(&format!("{err:#} {err:?}")) {
        line.push_str("\npodnet: ");
        line.push_str(&hint);
    } else if let Some(status) = crate::egress::refusal(err)
        .map(|r| r.status)
        .filter(|s| (502..=504).contains(s))
    {
        // Issue 178: a 502, 503 or 504 of the proxy is the destination:
        // the proxy could not reach it.
        line.push_str(&format!(
            "\npodnet: the proxy answered HTTP {status}: it could not reach the destination; check the address of the destination (--masque-endpoint, --url, the edge)"
        ));
    } else if let Some(hop) = crate::hop::of(err) {
        line.push_str(&format!("\npodnet: the {hop} hop failed; {}", hop.hint()));
    }
    line
}

/// Hide the credentials in `line`: `user:pass@` of each URL, the value of
/// each proxy variable that has a user part, each value given to
/// [`hide`], the value of an `Authorization:` or `Proxy-Authorization:`
/// header (the scheme word stays), the word after `Bearer`, and each run
/// of 32 or more hexadecimal characters (issue 267).
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
    hide_hex(&hide_bearer(&hide_authorization(&result)))
}

const HIDDEN: &str = "<hidden>";

/// `Authorization: Basic abc` -> `Authorization: Basic <hidden>`, to the
/// end of the line. `Proxy-Authorization` has the same suffix.
fn hide_authorization(line: &str) -> String {
    const KEY: &str = "authorization:";
    let lower = line.to_ascii_lowercase();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find(KEY) {
        let value_start = at + i + KEY.len();
        out.push_str(&line[at..value_start]);
        let end = line[value_start..]
            .find(['\n', '\r'])
            .map_or(line.len(), |n| value_start + n);
        let value = &line[value_start..end];
        let trimmed = value.trim_start();
        out.push_str(&value[..value.len() - trimmed.len()]);
        // The scheme word stays when a credential comes after it.
        match trimmed.split_once(' ') {
            Some((scheme, rest)) if !rest.trim().is_empty() => {
                out.push_str(scheme);
                out.push(' ');
                out.push_str(HIDDEN);
            }
            _ if trimmed.is_empty() => {}
            _ => out.push_str(HIDDEN),
        }
        at = end;
    }
    out.push_str(&line[at..]);
    out
}

/// `Bearer abc` -> `Bearer <hidden>`.
fn hide_bearer(line: &str) -> String {
    const KEY: &str = "bearer ";
    let lower = line.to_ascii_lowercase();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find(KEY) {
        let start = at + i;
        let word_start = start + KEY.len();
        // Only the word "bearer", not the end of a longer word.
        let boundary = start == 0 || !line.as_bytes()[start - 1].is_ascii_alphanumeric();
        let end = line[word_start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
            .map_or(line.len(), |n| word_start + n);
        out.push_str(&line[at..word_start]);
        let word = &line[word_start..end];
        if boundary && !word.is_empty() && word != HIDDEN {
            out.push_str(HIDDEN);
        } else {
            out.push_str(word);
        }
        at = end;
    }
    out.push_str(&line[at..]);
    out
}

/// Each run of 32 or more hexadecimal characters that is a whole word (a
/// key, a token, an account id) -> `<hidden>`. A shorter run stays.
fn hide_hex(line: &str) -> String {
    let bytes = line.as_bytes();
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() && (i == 0 || !word(bytes[i - 1])) {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j - i >= 32 && (j == bytes.len() || !word(bytes[j])) {
                out.push_str(&line[at..i]);
                out.push_str(HIDDEN);
                at = j;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.push_str(&line[at..]);
    out
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
        "podnet": concat!(env!("CARGO_PKG_VERSION"), " (", env!("PODNET_BUILD_COMMIT"), ")"),
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

/// The variables that hold a secret of podnet. The program of
/// `PODNET_ERROR_PROGRAM` does not get them (podssh): it reads a report, not
/// the credentials of the run.
const SECRET_VARIABLES: &[&str] = &[
    "TUNNEL_TOKEN",
    "PODNET_RELAY_TOKEN",
    "PODNET_RELAY_CONNECT_TOKEN",
];

/// The proxy variables, which hold a secret when they have a user part.
const PROXY_VARIABLES: &[&str] = &[
    "PODNET_PROXY",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// The variables that the program of `PODNET_ERROR_PROGRAM` does not get:
/// the secrets, and a proxy variable with a user and a password.
pub fn withheld(env: &dyn Fn(&str) -> Option<String>) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = SECRET_VARIABLES.to_vec();
    for key in PROXY_VARIABLES {
        if env(key).is_some_and(|v| {
            v.split("://")
                .nth(1)
                .unwrap_or(&v)
                .split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
        }) {
            out.push(key);
        }
    }
    out
}

/// Give the report to the program of `PODNET_ERROR_PROGRAM`, when it is set.
/// Errors go to stderr as one line; they do not change the exit code.
pub fn send(command: Option<&str>, exit: i32, error: Option<&anyhow::Error>) {
    let Some(program) = std::env::var_os(PROGRAM_VARIABLE).filter(|v| !v.is_empty()) else {
        return;
    };
    let report = document(command, exit, error).to_string() + "\n";
    // The stdout of the program is the stderr of podnet: stdout is data.
    use std::os::fd::AsFd;
    let stdout = std::io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map(std::process::Stdio::from)
        .unwrap_or_else(|_| std::process::Stdio::inherit());
    let mut command = std::process::Command::new(&program);
    command.env_remove(PROGRAM_VARIABLE);
    for key in withheld(&|k| std::env::var(k).ok()) {
        command.env_remove(key);
    }
    let mut child = match command
        .stdin(std::process::Stdio::piped())
        .stdout(stdout)
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!(
                "podnet: {PROGRAM_VARIABLE}: could not start {}: {err}",
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
                    "podnet: {PROGRAM_VARIABLE}: stopped after {} s",
                    PROGRAM_TIMEOUT.as_secs()
                );
                return;
            }
        }
    }
}

/// The log filter of `level` (`warn`, `info`, `debug`, `trace`): podnet and
/// the crates of PodUtils/podcrates that write its diagnostics (the resolver,
/// the dial, TLS), so that `-v` shows their lines too.
pub fn log_filter(level: &str) -> String {
    [
        "podnet",
        "pod_core",
        "pod_dns",
        "pod_proxy",
        "pod_tls",
        "pod_services",
    ]
    .map(|target| format!("{target}={level}"))
    .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The program of PODNET_ERROR_PROGRAM gets no secret of podnet.
    #[test]
    fn the_error_program_gets_no_secret() {
        let env = |k: &str| match k {
            "PODNET_PROXY" => Some("http://user:pw@proxy:3128".to_string()),
            "HTTPS_PROXY" => Some("http://proxy:3128".to_string()),
            "ALL_PROXY" => Some("socks5h://u:p@10.0.0.1:1080".to_string()),
            _ => None,
        };
        let out = withheld(&env);
        for key in [
            "TUNNEL_TOKEN",
            "PODNET_RELAY_TOKEN",
            "PODNET_RELAY_CONNECT_TOKEN",
            "PODNET_PROXY",
            "ALL_PROXY",
        ] {
            assert!(out.contains(&key), "{key}: {out:?}");
        }
        assert!(!out.contains(&"HTTPS_PROXY"), "{out:?}");
    }

    // Issue 178: a 502 of the proxy names the destination, not the proxy.
    #[test]
    fn a_502_of_the_proxy_names_the_destination() {
        let err = anyhow::Error::new(crate::egress::Refusal {
            status: 502,
            text: "the proxy refused CONNECT with HTTP 502".into(),
        });
        let err = crate::hop::at(crate::hop::Hop::Proxy, err);
        let line = error_line(&err);
        assert!(line.contains("could not reach the destination"), "{line}");
        assert!(!line.contains("allow-list"), "{line}");
    }

    // Issue 267: the lines of the issue, and the limits of each rule.
    #[test]
    fn mask_hides_authorization_values_and_hex_tokens() {
        assert_eq!(
            mask("auth Authorization: Basic dXNlcjpwYXNzd29yZA=="),
            "auth Authorization: Basic <hidden>"
        );
        assert_eq!(
            mask("proxy-authorization:Bearer abc.def"),
            "proxy-authorization:Bearer <hidden>"
        );
        assert_eq!(mask("authorization: tok"), "authorization: <hidden>");
        assert_eq!(
            mask("sent header Bearer eyJabc, then"),
            "sent header Bearer <hidden>, then"
        );
        assert_eq!(
            mask("account 0123456789abcdef0123456789abcdef and api 0123456789abcdef0123456789abcdef01234567"),
            "account <hidden> and api <hidden>"
        );
        let short = "id 0123456789abcdef0123456789abcde";
        assert_eq!(mask(short), short, "31 hex characters stay");
        let word = "x0123456789abcdef0123456789abcdef";
        assert_eq!(mask(word), word, "part of a longer word");
        assert_eq!(mask("hash 1a2b3c4d5e6f7a8b"), "hash 1a2b3c4d5e6f7a8b");
    }

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
            "podnet: registering with the edge: bad gateway fromthe edge31m"
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
        let dir = std::env::temp_dir().join(format!("podnet-report-{}", std::process::id()));
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
