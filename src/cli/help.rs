//! The top help (the commands by purpose, the "Start here" block, the
//! examples of each command), the hints after a usage error and the last
//! error line.

use clap::CommandFactory as _;

use crate::cli::argv::{CLOUDFLARED_FLAGS, LOG_JSON};
use crate::Cli;

/// The commands of the top help, by purpose (E1). Each subcommand is in
/// one group; a test checks it.
pub(crate) const HELP_GROUPS: &[(&str, &[&str])] = &[
    (
        "Publish a local service",
        &["tunnel", "serve", "share", "demo", "qr"],
    ),
    (
        "Reach the internet from a limited host",
        &["agent", "warp", "pod", "net", "connect", "relay"],
    ),
    (
        "Run in the background",
        &["ps", "logs", "wait", "stop", "autostart"],
    ),
    (
        "Check this host and podnet",
        &[
            "doctor",
            "status",
            "ports",
            "bug-report",
            "update",
            "man",
            "completions",
            "help",
        ],
    ),
];

/// The "Start here" block of the top help.
const START_HERE: &str = "\
Start here:
  podnet doctor                              test the path from this host to the edge
  podnet tunnel --url http://localhost:8080  a public URL for a local service
  podnet agent up                            a sandbox: test, start WARP if needed, expose ports
  podnet man                                 the full manual";

/// The first part of `text`: up to the end of the first sentence or the
/// first colon, with no issue reference.
pub(crate) fn first_sentence(text: &str) -> String {
    let end = [". ", ": "]
        .iter()
        .filter_map(|mark| text.find(mark))
        .min()
        .unwrap_or(text.len());
    let mut part = text[..end].to_string();
    while let Some(start) = part.find(" (issue ") {
        match part[start..].find(')') {
            Some(len) => part.replace_range(start..start + len + 1, ""),
            None => break,
        }
    }
    part
}

/// The commands of `cmd` by purpose, with the first sentence of each.
fn grouped_commands(cmd: &clap::Command) -> String {
    let width = cmd
        .get_subcommands()
        .map(|c| c.get_name().len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (title, names) in HELP_GROUPS {
        out.push_str(&format!("{title}:\n"));
        for name in *names {
            let about = cmd
                .find_subcommand(name)
                .and_then(|c| c.get_about())
                .map(|a| a.to_string())
                .unwrap_or_else(|| {
                    "Print this message or the help of the given subcommand(s)".into()
                });
            out.push_str(&format!("  {name:width$}  {}\n", first_sentence(&about)));
        }
        out.push('\n');
    }
    out
}

/// The top command, with the commands by purpose and a "Start here" block
/// in its help.
pub(crate) fn top_command() -> clap::Command {
    let cmd = Cli::command();
    let template = format!(
        "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{START_HERE}\n\n{}Options:\n{{options}}{{after-help}}",
        grouped_commands(&cmd)
    );
    let root = Cli::command();
    with_examples(cmd.help_template(template), "podnet", &root)
}

/// The command path of an example: `podnet`, then each word that names a
/// subcommand (`podnet warp proxy -r` is `podnet warp proxy`).
pub(crate) fn example_path(cmd: &clap::Command, line: &str) -> String {
    let mut path = String::from("podnet");
    let mut at = cmd;
    for word in line.split_whitespace().skip(1) {
        match at.find_subcommand(word) {
            Some(sub) => {
                path.push(' ');
                path.push_str(word);
                at = sub;
            }
            None => break,
        }
    }
    path
}

/// E7: the examples of `podnet man examples` in the help of their command
/// (`podnet tunnel --help`), from the one table of the manual.
fn with_examples(cmd: clap::Command, path: &str, root: &clap::Command) -> clap::Command {
    let examples: Vec<&podnet::manual::facts::Example> = podnet::manual::facts::EXAMPLES
        .iter()
        .filter(|e| path != "podnet" && example_path(root, e.command) == path)
        .collect();
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    let mut cmd = cmd;
    for name in names {
        let sub_path = format!("{path} {name}");
        cmd = cmd.mut_subcommand(&name, |sub| with_examples(sub, &sub_path, root));
    }
    if examples.is_empty() {
        return cmd;
    }
    let mut text = String::from("Examples:");
    for e in examples {
        text.push_str(&format!("\n  {}\n      {}", e.command, e.meaning));
    }
    cmd.after_help(text)
}

/// The lines after a usage error (E8, E10): a word that is no command but
/// looks like a port, a URL or a path names the command for it; an unknown
/// command or flag names the version and `podnet update --check`.
pub(crate) fn usage_hints(err: &clap::Error) -> Vec<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let invalid = || match err
        .get(ContextKind::InvalidSubcommand)
        .or(err.get(ContextKind::InvalidArg))
    {
        Some(ContextValue::String(word)) => Some(word.clone()),
        _ => None,
    };
    let mut lines = Vec::new();
    match err.kind() {
        ErrorKind::InvalidSubcommand => {
            if let Some(hint) = invalid().as_deref().and_then(word_hint) {
                lines.push(hint);
            }
        }
        ErrorKind::UnknownArgument => {
            let word = invalid().unwrap_or_default();
            let name = word.split('=').next().unwrap_or("");
            if let Some((flag, advice)) = CLOUDFLARED_FLAGS.iter().find(|(f, _)| *f == name) {
                lines.push(format!(
                    "hint: {flag} is a flag of cloudflared, not of podnet; {advice}"
                ));
                return lines;
            }
        }
        _ => return lines,
    }
    lines.push(format!(
        "podnet {} does not know {}; a newer release can: podnet update --check",
        env!("CARGO_PKG_VERSION"),
        invalid().map_or_else(|| "it".to_string(), |w| format!("'{w}'"))
    ));
    lines
}

/// The command for a word that is no command of podnet.
pub(crate) fn word_hint(word: &str) -> Option<String> {
    if !word.is_empty() && word.len() <= 5 && word.bytes().all(|b| b.is_ascii_digit()) {
        return Some(format!(
            "hint: for a public URL of the local port {word}: podnet tunnel --url http://localhost:{word}"
        ));
    }
    let lower = word.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(format!(
            "hint: for a public URL of the local service {word}: podnet tunnel --url {word}"
        ));
    }
    if lower.starts_with("wss://") || lower.starts_with("ws://") {
        return Some(format!(
            "hint: for a local socket to the WebSocket forward {word}: podnet connect --local 127.0.0.1:2222 {word}"
        ));
    }
    let path = std::path::Path::new(word);
    if word.starts_with('/') || word.starts_with("./") || word.starts_with("~/") || path.exists() {
        return Some(if path.is_file() {
            format!("hint: to send the file {word}: podnet share --mode download --file {word}")
        } else {
            format!("hint: to serve the directory {word}: podnet serve --dir {word}")
        });
    }
    None
}

/// Whether `argv` asks for `--log-format json` (before a parse).
pub(crate) fn json_wanted(argv: &[String]) -> bool {
    argv.windows(2)
        .any(|w| w[0] == "--log-format" && w[1] == "json")
        || argv.iter().any(|a| a == "--log-format=json")
}

/// The last error line as one JSON object, in the shape of a log line of
/// `--log-format json`.
pub(crate) fn error_json(text: &str, code: i32) -> String {
    let message = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.strip_prefix("podnet: ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("; ");
    serde_json::json!({
        "level": "ERROR",
        "fields": { "message": message.trim_end(), "exit_code": code },
        "target": "podnet",
    })
    .to_string()
}

/// Print the last error line: text, or JSON with --log-format json.
pub(crate) fn print_error(line: &str, code: i32) {
    if LOG_JSON.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("{}", error_json(line, code));
    } else {
        eprintln!("{line}");
    }
}
