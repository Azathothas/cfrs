//! `cfrs bug-report` (issue 117): one text with what a report needs, and no
//! secret. It opens no connection unless `--doctor` is given.
//!
//! The text has the version, the document of `cfrs status`, the detached
//! instances, the last lines of the log of each instance, and the names of
//! the variables of cfrs and of the proxies that are set (not their values).
//! Each line goes through [`scrub`]: the credentials of [`crate::report`],
//! UUIDs (device ids, tunnel ids), tokens (`eyJ...`, `t.` tokens) and the
//! names of quick tunnels are replaced.

/// The lines of the log of each instance in the report.
pub const LOG_LINES: usize = 100;

/// Hide the secrets of `line`.
pub fn scrub(line: &str) -> String {
    let line = crate::report::mask(line);
    let mut out = String::with_capacity(line.len());
    for word in split_keep(&line) {
        out.push_str(&scrub_word(word));
    }
    out
}

/// Split into words and the characters between them, all kept.
fn split_keep(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_word = false;
    for (i, c) in text.char_indices() {
        let word_char = c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '+' | '/' | '=');
        if word_char != in_word {
            if i > start {
                out.push(&text[start..i]);
            }
            start = i;
            in_word = word_char;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

fn is_uuid(word: &str) -> bool {
    let parts: Vec<&str> = word.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn scrub_word(word: &str) -> String {
    if word.contains('-') && word.split(['/', '.', '=']).any(is_uuid) {
        return word
            .split_inclusive(['/', '.', '='])
            .map(|part| {
                let bare = part.trim_end_matches(['/', '.', '=']);
                if is_uuid(bare) {
                    format!("<uuid>{}", &part[bare.len()..])
                } else {
                    part.to_string()
                }
            })
            .collect();
    }
    if word.starts_with("eyJ") && word.len() > 20 {
        return "<token>".into();
    }
    if word.starts_with("t.") && word.len() > 20 {
        return "<token>".into();
    }
    if let Some(i) = word.find(".trycloudflare.com") {
        let host_start = word[..i].rfind('/').map(|j| j + 1).unwrap_or(0);
        if i > host_start {
            return format!("{}<tunnel>{}", &word[..host_start], &word[i..]);
        }
    }
    word.to_string()
}

/// The names of the variables of cfrs and of the proxies that are set.
fn variables() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| {
            k.starts_with("CFRS_")
                || k.starts_with("POD_NETNS_")
                || k.to_ascii_uppercase().ends_with("_PROXY")
                || k == "TUNNEL_TOKEN"
                || k == "SSL_CERT_FILE"
                || k == "RUST_LOG"
        })
        .collect();
    names.sort();
    names
}

/// The last `n` lines of the file at `path`.
fn tail(path: &str, n: usize) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return vec![format!("(the log {path} cannot be read)")];
    };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| l.to_string())
        .collect()
}

/// The text of the report. `doctor` is the JSON of `cfrs doctor`, when it
/// ran.
pub fn text(doctor: Option<&serde_json::Value>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "cfrs bug-report\n\ncfrs {} ({})\n\n## status\n\n{}\n",
        env!("CARGO_PKG_VERSION"),
        env!("CFRS_BUILD_COMMIT"),
        serde_json::to_string_pretty(&crate::status::document()).unwrap_or_default()
    ));
    out.push_str("\n## variables that are set (no values)\n\n");
    let vars = variables();
    if vars.is_empty() {
        out.push_str("(none)\n");
    }
    for name in vars {
        out.push_str(&format!("{name}\n"));
    }
    out.push_str("\n## detached instances\n\n");
    let entries = crate::instances::list(&crate::instances::lookup_dir());
    if entries.is_empty() {
        out.push_str("(none)\n");
    }
    for e in &entries {
        let r = &e.record;
        out.push_str(&format!(
            "{} {} state={} alive={} restarts={}\n",
            r.name, r.command, r.state, e.alive, r.restarts
        ));
    }
    for e in &entries {
        out.push_str(&format!(
            "\n## the last {LOG_LINES} lines of the log of {}\n\n",
            e.record.name
        ));
        for line in tail(&e.record.log, LOG_LINES) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(doctor) = doctor {
        out.push_str("\n## cfrs doctor --json\n\n");
        out.push_str(&serde_json::to_string_pretty(doctor).unwrap_or_default());
        out.push('\n');
    }
    out.lines().map(scrub).collect::<Vec<_>>().join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_scrubbed() {
        let line = "device 1f2e3d4c-aaaa-bbbb-cccc-0123456789ab url=https://big-red-dog.trycloudflare.com/s/x token eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwifQ== t.0123456789abcdef0123";
        let out = scrub(line);
        assert!(!out.contains("1f2e3d4c"), "{out}");
        assert!(out.contains("<uuid>"), "{out}");
        assert!(
            out.contains("https://<tunnel>.trycloudflare.com/s/x"),
            "{out}"
        );
        assert!(!out.contains("eyJhIjoi"), "{out}");
        assert!(!out.contains("t.0123456789"), "{out}");
        assert!(out.starts_with("device "), "{out}");
        assert_eq!(
            scrub("plain text: 127.0.0.1:40000"),
            "plain text: 127.0.0.1:40000"
        );
        assert_eq!(
            scrub("/run/1f2e3d4c-aaaa-bbbb-cccc-0123456789ab.json"),
            "/run/<uuid>.json"
        );
    }

    #[test]
    fn the_report_has_its_parts() {
        let text = text(None);
        for part in [
            "cfrs bug-report",
            "## status",
            "## variables",
            "## detached instances",
        ] {
            assert!(text.contains(part), "{part}");
        }
    }
}
