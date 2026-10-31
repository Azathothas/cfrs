//! The pager of `cfrs man`. It is used only when stdin and stdout are both a
//! terminal and `--no-pager` is not given. The choice is made on each run:
//!
//! 1. `PAGER`, when it is set. An empty value, or `cat`, means no pager.
//! 2. `less`, when `PATH` has it and `TERM` names a terminal that is not
//!    `dumb`.
//! 3. The built-in pager: one screen at a time, Enter for the next screen,
//!    `q` to stop. It needs nothing from the host.
//!
//! A pager program that does not start falls back to the built-in pager.

use std::io::{BufRead, Write};

/// True when stdin and stdout are both a terminal.
pub fn interactive() -> bool {
    unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}

fn in_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// The pager program to use, or `None` for the built-in pager, or
/// `Some(None)` for no pager at all.
fn choice() -> Option<Option<Vec<String>>> {
    if let Ok(pager) = std::env::var("PAGER") {
        let words: Vec<String> = pager.split_whitespace().map(str::to_string).collect();
        if words.is_empty() || words[0] == "cat" {
            return Some(None);
        }
        return Some(Some(words));
    }
    let term = std::env::var("TERM").unwrap_or_default();
    if !term.is_empty() && term != "dumb" {
        if let Some(less) = in_path("less") {
            return Some(Some(vec![less.display().to_string()]));
        }
    }
    None
}

/// Write `text` to the terminal through the pager, or to stdout.
pub fn show(text: &str, no_pager: bool) -> std::io::Result<()> {
    if no_pager || !interactive() {
        return write_all(text);
    }
    match choice() {
        Some(None) => write_all(text),
        Some(Some(words)) => {
            let mut command = std::process::Command::new(&words[0]);
            command
                .args(&words[1..])
                .stdin(std::process::Stdio::piped());
            if std::env::var_os("LESS").is_none() {
                command.env("LESS", "FRX");
            }
            match command.spawn() {
                Ok(mut child) => {
                    if let Some(mut stdin) = child.stdin.take() {
                        // A pager that stops early closes the pipe: not an error.
                        let _ = stdin.write_all(text.as_bytes());
                    }
                    child.wait()?;
                    Ok(())
                }
                Err(_) => builtin(text),
            }
        }
        None => builtin(text),
    }
}

fn write_all(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|_| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// The number of lines of the terminal, from `LINES` or `TIOCGWINSZ`.
fn rows() -> usize {
    if let Some(n) = std::env::var("LINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        return n.max(5);
    }
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ as _, &mut size) } == 0 && size.ws_row > 0 {
        return usize::from(size.ws_row).max(5);
    }
    24
}

fn builtin(text: &str) -> std::io::Result<()> {
    let page = rows() - 1;
    let mut out = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    let lines: Vec<&str> = text.lines().collect();
    for (i, chunk) in lines.chunks(page).enumerate() {
        for line in chunk {
            writeln!(out, "{line}")?;
        }
        out.flush()?;
        if (i + 1) * page >= lines.len() {
            break;
        }
        eprint!("-- more (Enter: next page, q: quit) --");
        let mut answer = String::new();
        input.read_line(&mut answer)?;
        if answer.trim().eq_ignore_ascii_case("q") {
            break;
        }
    }
    Ok(())
}
