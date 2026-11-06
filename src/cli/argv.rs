//! The argument rewrites before the parse: the cloudflared flags, the token
//! files, the name of the command, the arguments of `podnet pod` and the
//! hint for a server command in the foreground.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::cli::Cli;

/// `--log-format json` (issue 181): the last error line is JSON too.
pub(crate) static LOG_JSON: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Flags of cloudflared that podnet does not have, with the advice for each
/// (E9).
pub(crate) const CLOUDFLARED_FLAGS: &[(&str, &str)] = &[
    (
        "--logfile",
        "the log goes to stderr: redirect it (2>FILE), or use --detach and podnet logs",
    ),
    (
        "--log-directory",
        "the log goes to stderr: redirect it, or use --detach and podnet logs",
    ),
    (
        "--pidfile",
        "use --detach: podnet ps shows the pid, podnet stop stops it",
    ),
    ("--metrics", "podnet has no metrics listener flag"),
    (
        "--origincert",
        "a named tunnel needs --token, --token-file or --credentials-file",
    ),
    (
        "--autoupdate-freq",
        "podnet does not update itself: podnet update",
    ),
    (
        "--grace-period",
        "podnet drains the open streams for up to 90 s at a stop",
    ),
    (
        "--edge-ip-version",
        "podnet tries IPv4 and IPv6 edge addresses",
    ),
    ("--region", "podnet uses the global region"),
    (
        "--retries",
        "podnet connects again with a backoff and no limit",
    ),
    ("--tag", "podnet sends no tags"),
    ("--post-quantum", "podnet has no post-quantum option"),
];

/// cloudflared arguments for `tunnel` (E9): `tunnel run` is `tunnel`;
/// `--no-autoupdate` is ignored; `--loglevel LEVEL` becomes -v, -vv or -q
/// (info: nothing). Other arguments stay. Only before `--`, and only when
/// the command is `tunnel`.
pub(crate) fn cloudflared_compat(args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let Some(words) = args
        .iter()
        .map(|a| a.to_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()
    else {
        return args;
    };
    let end = words.iter().position(|w| w == "--").unwrap_or(words.len());
    let Some(at) = words[..end].iter().position(|w| w == "tunnel") else {
        return args;
    };
    // The command is tunnel (not a value "tunnel" of another command).
    let plain: Vec<String> = words
        .iter()
        .filter(|w| *w != "--no-autoupdate")
        .cloned()
        .collect();
    if command_name(&plain).as_deref() != Some("tunnel") {
        return args;
    }
    let mut out: Vec<String> = Vec::with_capacity(words.len());
    let mut i = 0;
    while i < words.len() {
        let word = &words[i];
        if i >= end {
            out.push(word.clone());
            i += 1;
            continue;
        }
        if i == at + 1 && word == "run" {
            i += 1;
            continue;
        }
        if word == "--no-autoupdate" {
            i += 1;
            continue;
        }
        let level = if let Some(level) = word.strip_prefix("--loglevel=") {
            i += 1;
            Some(level.to_string())
        } else if word == "--loglevel" {
            i += 2;
            words.get(i - 1).cloned()
        } else {
            None
        };
        if let Some(level) = level {
            match level.to_ascii_lowercase().as_str() {
                "debug" => out.push("-v".into()),
                "trace" => out.push("-vv".into()),
                "warn" | "error" | "fatal" | "panic" => out.push("-q".into()),
                _ => {}
            }
            continue;
        }
        out.push(word.clone());
        i += 1;
    }
    out.into_iter().map(Into::into).collect()
}

/// The token of a file (E4): the text with no white space at the ends; an
/// error for an empty or a large file.
fn read_token_file(path: &std::path::Path) -> Result<String> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if meta.len() > 64 * 1024 {
        bail!(
            "{} is not a token file: it has {} bytes",
            path.display(),
            meta.len()
        );
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let token = text.trim();
    if token.is_empty() {
        bail!("the token file {} is empty", path.display());
    }
    Ok(token.to_string())
}

/// Read the token of --token-file (or of TUNNEL_TOKEN_FILE) into the token
/// variable of the command, before the parse: the token is then not on a
/// command line, and each user of the token reads it as before. A token
/// flag together with a token file is an error.
pub(crate) fn apply_token_files(argv: &[String]) -> Result<()> {
    let relay_connect = command_name(argv).as_deref() == Some("relay connect");
    let variable = if relay_connect {
        podnet::relay_reverse::CONNECT_TOKEN_VARIABLE
    } else {
        "TUNNEL_TOKEN"
    };
    let mut path = None;
    let mut words = argv.iter().skip(1);
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if (word == "--token" || word.starts_with("--token="))
            && argv
                .iter()
                .any(|w| w == "--token-file" || w.starts_with("--token-file="))
        {
            bail!("--token and --token-file: give one of them");
        }
        if let Some(value) = word.strip_prefix("--token-file=") {
            path = Some(PathBuf::from(value));
        } else if word == "--token-file" {
            path = words.next().map(PathBuf::from);
        }
    }
    if path.is_none() && !relay_connect && std::env::var_os("TUNNEL_TOKEN").is_none() {
        path = std::env::var_os("TUNNEL_TOKEN_FILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
    }
    let Some(path) = path else {
        return Ok(());
    };
    let token = read_token_file(&path)?;
    podnet::report::hide(&token);
    // SAFETY: one thread: the runtime does not exist yet.
    unsafe { std::env::set_var(variable, token) };
    Ok(())
}

/// Whether stdin and stderr are both no terminal (an agent, a pipe, a
/// service).
pub(crate) fn no_terminal() -> bool {
    use std::io::IsTerminal as _;
    !std::io::stdin().is_terminal() && !std::io::stderr().is_terminal()
}

/// The commands that serve until a stop signal.
const SERVER_COMMANDS: &[&str] = &["tunnel", "serve", "share", "connect", "relay node"];

/// E12: one line for a server command in the foreground with no terminal
/// (a tool call of an agent waits for its end): --detach or --run-for.
pub(crate) fn foreground_hint(
    command: Option<&str>,
    argv: &[String],
    child: bool,
    no_terminal: bool,
) -> Option<String> {
    let command = command?;
    if child || !no_terminal || !SERVER_COMMANDS.contains(&command) {
        return None;
    }
    let given = |flag: &str| {
        argv.iter()
            .any(|a| a == flag || a.starts_with(&format!("{flag}=")))
    };
    if ["--detach", "--run-for", "--exit-on-verify", "--help", "-h"]
        .iter()
        .any(|f| given(f))
    {
        return None;
    }
    Some(format!(
        "podnet {command} runs in the foreground until a stop signal, and no terminal is attached: add --detach to run it in the background (podnet ps, podnet stop), or --run-for SECS"
    ))
}

/// The command of `argv` for the report: `tunnel`, `warp run`, or `None`.
pub(crate) fn command_name(argv: &[String]) -> Option<String> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let mut words = Vec::new();
    let mut rest = argv.iter().skip(1);
    // Issue 181: an option before the subcommand (podnet -q tunnel, podnet
    // --proxy URL warp run) is skipped, with its value; before, the name
    // stopped at the first option.
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        if let Some(option) = arg.strip_prefix('-') {
            let (name, inline) = match option.split_once('=') {
                Some((n, _)) => (n, true),
                None => (option, false),
            };
            let found = match name.strip_prefix('-') {
                Some(long) => cmd.get_arguments().find(|a| a.get_long() == Some(long)),
                // -vv, -q: the first letter names the option.
                None => name
                    .chars()
                    .next()
                    .and_then(|c| cmd.get_arguments().find(|a| a.get_short() == Some(c))),
            };
            let Some(found) = found else { break };
            let takes_value = found.get_action().takes_values();
            let short_with_value = !name.starts_with('-') && name.chars().count() > 1;
            if takes_value && !inline && !short_with_value {
                rest.next();
            }
            continue;
        }
        match cmd.find_subcommand(arg) {
            Some(sub) => {
                words.push(arg.clone());
                cmd = sub.clone();
            }
            None => break,
        }
    }
    (!words.is_empty()).then(|| words.join(" "))
}

/// The global network option of `podnet OPTION pod`, which the pod does not
/// use (issue 189): its proxy is `-x`.
pub(crate) fn pod_network_option(cli: &Cli) -> Option<&'static str> {
    if cli.proxy.is_some() {
        Some("--proxy")
    } else if cli.no_proxy {
        Some("--no-proxy")
    } else if cli.resolve.is_some() {
        Some("--resolve")
    } else if cli.ca_file.is_some() {
        Some("--ca-file")
    } else {
        None
    }
}

/// The arguments of the pod: what follows the word `pod` in `argv` (clap
/// can drop the first `--` of the trailing arguments).
pub(crate) fn pod_args_of(argv: &[String], parsed: &[String]) -> Vec<String> {
    let tail = &argv[argv.len().saturating_sub(parsed.len() + 1)..];
    if tail.first().map(String::as_str) == Some("--") && tail[1..] == *parsed {
        return tail.to_vec();
    }
    parsed.to_vec()
}
