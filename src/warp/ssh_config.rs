//! The block of `cfrs warp ssh-config --write` in an SSH config file (issue
//! 130). cfrs owns the lines between its two markers, and changes no other
//! byte of the file.
//!
//! ```text
//! # >>> cfrs warp ssh-config: github.com >>>
//! Host github.com
//!     ProxyCommand '/usr/local/bin/cfrs' warp nc %h %p
//! # <<< cfrs warp ssh-config: github.com <<<
//! ```
//!
//! A new block goes before the first `Host` or `Match` line: SSH uses the
//! first value of each option, and the lines at the top of the file stay
//! global. A `Host` line outside the markers that names the same pattern is
//! a conflict: cfrs changes nothing and names its line. Files of `Include`
//! are not read.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

fn begin(host: &str) -> String {
    format!("# >>> cfrs warp ssh-config: {host} >>>")
}

fn end(host: &str) -> String {
    format!("# <<< cfrs warp ssh-config: {host} <<<")
}

const BEGIN_PREFIX: &str = "# >>> cfrs warp ssh-config: ";
const END_PREFIX: &str = "# <<< cfrs warp ssh-config: ";

/// A word for `sh`: in single quotes.
fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// Check a `--host` pattern before it goes into a config line (issue 252).
/// A newline would start a new line of the file (for example a second
/// `Host *` with its own `ProxyCommand`), and a space gives more than one
/// pattern. One pattern has 1 to 255 characters from
/// `A-Z a-z 0-9 . _ - * ? ! : @ % , [ ]`.
pub fn check_host(host: &str) -> Result<()> {
    let good = !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-*?!:@%,[]".contains(&b));
    if !good {
        bail!(
            "--host {host:?}: give one Host pattern of 1 to 255 characters from \
             A-Z a-z 0-9 . _ - * ? ! : @ % , [ ] (no space, no control character)"
        );
    }
    Ok(())
}

/// The block for `host`, with its markers and a final newline. The caller
/// checks `host` with [`check_host`].
pub fn block(exe: &Path, host: &str) -> String {
    debug_assert!(check_host(host).is_ok(), "{host:?}");
    format!(
        "{}\nHost {host}\n    ProxyCommand {} warp nc %h %p\n{}\n",
        begin(host),
        shell_quote(&exe.display().to_string()),
        end(host)
    )
}

/// A block of cfrs in a file: the host and the byte range (with the final
/// newline).
struct Owned {
    host: String,
    start: usize,
    stop: usize,
}

/// The lines of `text` with their byte offsets.
fn lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        out.push((at, line));
        at += line.len();
    }
    out
}

fn trimmed(line: &str) -> &str {
    line.trim_end_matches(['\n', '\r'])
}

/// The blocks of cfrs. A marker with no pair is an error.
fn owned(text: &str) -> Result<Vec<Owned>> {
    let mut out = Vec::new();
    let mut open: Option<(String, usize, usize)> = None;
    for (n, (at, line)) in lines(text).into_iter().enumerate() {
        let line_text = trimmed(line);
        if let Some(rest) = line_text.strip_prefix(BEGIN_PREFIX) {
            if let Some((_, _, l)) = open {
                bail!(
                    "line {}: a begin marker of cfrs with no end (line {})",
                    n + 1,
                    l
                );
            }
            let host = rest.trim_end_matches(" >>>").to_string();
            open = Some((host, at, n + 1));
        } else if let Some(rest) = line_text.strip_prefix(END_PREFIX) {
            let host = rest.trim_end_matches(" <<<");
            match open.take() {
                Some((h, start, _)) if h == host => out.push(Owned {
                    host: h,
                    start,
                    stop: at + line.len(),
                }),
                _ => bail!("line {}: an end marker of cfrs with no begin", n + 1),
            }
        }
    }
    if let Some((_, _, l)) = open {
        bail!("line {l}: a begin marker of cfrs with no end");
    }
    Ok(out)
}

fn inside(blocks: &[Owned], at: usize) -> bool {
    blocks.iter().any(|b| at >= b.start && at < b.stop)
}

/// The text with the block of `host` added or replaced.
pub fn write(text: &str, host: &str, block: &str) -> Result<String> {
    let blocks = owned(text)?;
    if let Some(b) = blocks.iter().find(|b| b.host == host) {
        return Ok(format!("{}{block}{}", &text[..b.start], &text[b.stop..]));
    }
    let mut first_section = None;
    for (n, (at, line)) in lines(text).into_iter().enumerate() {
        if inside(&blocks, at) {
            continue;
        }
        let mut words = trimmed(line).split_whitespace();
        let Some(keyword) = words.next() else {
            continue;
        };
        let keyword = keyword.to_ascii_lowercase();
        if keyword == "host" || keyword == "match" {
            if keyword == "host"
                && words
                    .flat_map(|w| w.split(','))
                    .any(|w| w.eq_ignore_ascii_case(host))
            {
                bail!(
                    "line {}: \"{}\" names {host} already; remove it, or give another --host",
                    n + 1,
                    trimmed(line).trim()
                );
            }
            first_section.get_or_insert(at);
        }
    }
    Ok(match first_section {
        Some(at) => format!("{}{block}{}", &text[..at], &text[at..]),
        None if text.is_empty() || text.ends_with('\n') => format!("{text}{block}"),
        None => format!("{text}\n{block}"),
    })
}

/// The text with the blocks of cfrs removed: the one of `host`, or all.
pub fn remove(text: &str, host: Option<&str>) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for b in owned(text)? {
        if host.is_none_or(|h| h == b.host) {
            out.push_str(&text[at..b.start]);
            at = b.stop;
        }
    }
    out.push_str(&text[at..]);
    Ok(out)
}

/// The state of the block of `host`.
#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Missing,
    Stale,
    Current,
}

pub fn state(text: &str, host: &str, block: &str) -> Result<State> {
    Ok(match owned(text)?.iter().find(|b| b.host == host) {
        None => State::Missing,
        Some(b) if &text[b.start..b.stop] == block => State::Current,
        Some(_) => State::Stale,
    })
}

/// The path of `--config`: a leading `~/` is HOME (from the environment).
pub fn expand(config: &str) -> Result<PathBuf> {
    let Some(rest) = config.strip_prefix("~/") else {
        return Ok(PathBuf::from(config));
    };
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .context("HOME is not set: give --config FILE")?;
    Ok(PathBuf::from(home).join(rest))
}

/// Write `text` to `path` with a rename, when it differs from `old`. A new
/// file has mode 0600 in a directory of mode 0700; a file keeps its mode.
/// A symbolic link stays: its target is written.
pub fn save(path: &Path, old: Option<&str>, text: &str) -> Result<bool> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if old == Some(text) {
        return Ok(false);
    }
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = path.parent().context("the config file has no directory")?;
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("making {}", dir.display()))?;
    }
    let mode = std::fs::metadata(&path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o600);
    let tmp = dir.join(format!(
        ".{}.cfrs-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        std::fs::write(&tmp, text)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "/opt/c f/cfrs";

    fn b(host: &str) -> String {
        block(Path::new(EXE), host)
    }

    #[test]
    fn a_host_with_a_space_or_a_control_character_is_refused() {
        for bad in [
            "",
            "x\nHost *\n    ProxyCommand evil\n#",
            "x\r",
            "a b",
            "a\tb",
            "a\0b",
            "pat*tern with spaces",
            "x\u{7f}",
            "\u{e9}",
        ] {
            assert!(check_host(bad).is_err(), "{bad:?}");
        }
        for good in ["*", "*.corp", "a-b.example", "!x", "10.0.0.?", "u@h:22"] {
            check_host(good).unwrap();
        }
    }

    #[test]
    fn the_block_quotes_the_binary() {
        let text = block(Path::new("/a/it's/cfrs"), "github.com");
        assert!(
            text.contains("    ProxyCommand '/a/it'\\''s/cfrs' warp nc %h %p\n"),
            "{text}"
        );
        assert!(text.starts_with("# >>> cfrs warp ssh-config: github.com >>>\nHost github.com\n"));
    }

    #[test]
    fn a_new_block_goes_before_the_first_host_and_stays_global_above() {
        let text = "ServerAliveInterval 30\n\nHost box\n    User me\n";
        let out = write(text, "github.com", &b("github.com")).unwrap();
        assert!(
            out.starts_with("ServerAliveInterval 30\n\n# >>> cfrs"),
            "{out}"
        );
        assert!(out.ends_with("Host box\n    User me\n"), "{out}");
        assert_eq!(remove(&out, None).unwrap(), text);
    }

    #[test]
    fn a_file_with_no_section_gets_the_block_at_the_end() {
        assert_eq!(write("", "g", &b("g")).unwrap(), b("g"));
        let out = write("User me", "g", &b("g")).unwrap();
        assert_eq!(out, format!("User me\n{}", b("g")));
    }

    #[test]
    fn a_second_write_is_the_same_and_a_stale_block_is_replaced() {
        let text = "Host box\r\n  User me";
        let once = write(text, "g", &b("g")).unwrap();
        assert_eq!(write(&once, "g", &b("g")).unwrap(), once);
        assert_eq!(state(&once, "g", &b("g")).unwrap(), State::Current);
        let other = block(Path::new("/old/cfrs"), "g");
        assert_eq!(state(&once, "g", &other).unwrap(), State::Stale);
        let replaced = write(&once, "g", &other).unwrap();
        assert!(replaced.contains("'/old/cfrs'") && !replaced.contains(EXE));
        assert!(replaced.ends_with("Host box\r\n  User me"));
        assert_eq!(state(text, "g", &b("g")).unwrap(), State::Missing);
    }

    #[test]
    fn two_hosts_have_two_blocks_and_remove_takes_one() {
        let text = write("", "a", &b("a")).unwrap();
        let text = write(&text, "b", &b("b")).unwrap();
        assert_eq!(state(&text, "a", &b("a")).unwrap(), State::Current);
        assert_eq!(state(&text, "b", &b("b")).unwrap(), State::Current);
        let one = remove(&text, Some("a")).unwrap();
        assert_eq!(state(&one, "a", &b("a")).unwrap(), State::Missing);
        assert_eq!(state(&one, "b", &b("b")).unwrap(), State::Current);
        assert_eq!(remove(&one, Some("x")).unwrap(), one);
        assert_eq!(remove(&text, None).unwrap(), "");
    }

    #[test]
    fn a_host_line_of_the_user_is_a_conflict() {
        for text in [
            "Host github.com\n  User git\n",
            "Host a GitHub.com b\n",
            "host x,github.com\n",
        ] {
            let err = write(text, "github.com", &b("github.com")).unwrap_err();
            assert!(format!("{err}").starts_with("line 1: "), "{err}");
        }
        assert!(write("Host *\n  User me\n", "github.com", &b("github.com")).is_ok());
    }

    #[test]
    fn a_marker_with_no_pair_is_an_error() {
        let begin_only = format!("{}\nHost g\n", begin("g"));
        assert!(write(&begin_only, "g", &b("g")).is_err());
        assert!(remove(&begin_only, None).is_err());
        let end_only = format!("Host x\n{}\n", end("g"));
        assert!(write(&end_only, "g", &b("g")).is_err());
    }

    #[test]
    fn save_makes_a_private_file_and_keeps_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh/config");
        assert!(save(&path, None, "Host x\n").unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert!(!save(&path, Some("Host x\n"), "Host x\n").unwrap());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(save(&link, Some("Host x\n"), "Host y\n").unwrap());
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "Host y\n");
        let left: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(left.len(), 1, "no temporary file stays");
    }
}
