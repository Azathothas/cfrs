//! The manual as plain text: what `cfrs man` writes. The lines are filled to
//! [`WIDTH`] columns, so the page reads in an 80-column terminal. The text is
//! ASCII, so it reads on any terminal and in any log.

use super::model::{ArgPage, CommandPage, Manual};

/// The width of the text, in columns.
pub const WIDTH: usize = 78;

/// Fill `text` to `WIDTH`, with `indent` spaces before each line. A line
/// break in `text` starts a new line; an empty line stays.
pub fn fill(text: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let width = WIDTH.saturating_sub(indent).max(20);
    let mut out = String::new();
    for paragraph in text.split('\n') {
        if paragraph.trim().is_empty() {
            out.push('\n');
            continue;
        }
        // Keep the indentation of a line that starts with spaces (a list or
        // a block of code).
        let lead = paragraph.len() - paragraph.trim_start().len();
        let inner = " ".repeat(lead);
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && line.len() + 1 + word.len() > width.saturating_sub(lead) {
                out.push_str(&pad);
                out.push_str(&inner);
                out.push_str(&line);
                out.push('\n');
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        if !line.is_empty() {
            out.push_str(&pad);
            out.push_str(&inner);
            out.push_str(&line);
            out.push('\n');
        }
    }
    ascii(&out)
}

/// Replace the characters that are not ASCII with ASCII equivalents.
pub fn ascii(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201c}' | '\u{201d}' => '"',
            '\u{2013}' | '\u{2014}' => '-',
            '\u{2026}' => '.',
            c if c.is_ascii() => c,
            _ => '?',
        })
        .collect()
}

fn heading(out: &mut String, title: &str) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
}

fn arg(out: &mut String, a: &ArgPage) {
    out.push_str(&fill(&a.synopsis, 8));
    let mut help = a.help.clone();
    let mut extra = Vec::new();
    if let Some(default) = &a.default {
        extra.push(format!("Default: {default}."));
    }
    if !a.values.is_empty() {
        extra.push(format!("Values: {}.", a.values.join(", ")));
    }
    if let Some(env) = &a.env {
        extra.push(format!("Variable: {env}."));
    }
    if a.required {
        extra.push("Required.".into());
    }
    if !extra.is_empty() {
        if !help.is_empty() {
            if !help.trim_end().ends_with(['.', '!', '?', ':']) {
                help.push('.');
            }
            help.push(' ');
        }
        help.push_str(&extra.join(" "));
    }
    if !help.is_empty() {
        out.push_str(&fill(&help, 12));
    }
}

/// One command, as its section of the manual.
pub fn command(manual: &Manual, c: &CommandPage) -> String {
    let mut out = String::new();
    let name = if c.path.is_empty() {
        manual.name.clone()
    } else {
        format!("{} {}", manual.name, c.name())
    };
    out.push_str(&fill(&c.usage, 4));
    let about = if c.long_about.is_empty() {
        &c.about
    } else {
        &c.long_about
    };
    if !about.is_empty() {
        out.push_str(&fill(about, 8));
    }
    if c.path == ["pod"] {
        out.push('\n');
        out.push_str(&fill(&manual.pod_usage, 8));
    }
    let (positional, flags): (Vec<&ArgPage>, Vec<&ArgPage>) =
        c.args.iter().partition(|a| a.positional);
    for a in positional.iter().chain(flags.iter()) {
        out.push('\n');
        arg(&mut out, a);
    }
    if !c.subcommands.is_empty() {
        out.push('\n');
        out.push_str(&fill(
            &format!("Commands of {name}: {}.", c.subcommands.join(", ")),
            8,
        ));
    }
    out
}

/// The section `ENVIRONMENT`.
pub fn environment(manual: &Manual) -> String {
    let mut out = String::new();
    for v in manual.environment {
        out.push_str(&fill(&v.names.join(", "), 4));
        out.push_str(&fill(&format!("{} ({})", v.meaning, v.used_by), 8));
    }
    out
}

/// The section `FILES`.
pub fn files(manual: &Manual) -> String {
    let mut out = String::new();
    for f in manual.files {
        out.push_str(&fill(f.path, 4));
        out.push_str(&fill(f.meaning, 8));
    }
    out
}

/// The section `EXIT STATUS`.
pub fn exit_status(manual: &Manual) -> String {
    let mut out = String::new();
    for row in &manual.exit_status {
        out.push_str(&fill(&format!("{} ({})", row.code, row.name), 4));
        out.push_str(&fill(row.meaning, 8));
    }
    out
}

/// The section `EXAMPLES`.
pub fn examples(manual: &Manual) -> String {
    let mut out = String::new();
    for e in manual.examples {
        out.push_str(&fill(e.meaning, 4));
        out.push_str(&fill(&format!("$ {}", e.command), 8));
        out.push('\n');
    }
    out
}

/// The whole manual.
pub fn render(manual: &Manual) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}(1){:>width$}\n",
        manual.name.to_ascii_uppercase(),
        format!("cfrs {}", manual.version),
        width = WIDTH - manual.name.len() - 3
    ));
    heading(&mut out, "NAME");
    out.push_str(&fill(&format!("{} - {}", manual.name, manual.about), 4));
    heading(&mut out, "SYNOPSIS");
    out.push_str(&fill(&format!("{} COMMAND [OPTIONS]", manual.name), 4));
    out.push_str(&fill(
        &format!(
            "{} man [SECTION] [--no-pager | --roff | --json]",
            manual.name
        ),
        4,
    ));
    heading(&mut out, "DESCRIPTION");
    for (i, p) in manual.description.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&fill(p, 4));
    }
    heading(&mut out, "COMMANDS");
    for c in manual.commands.iter().filter(|c| !c.path.is_empty()) {
        out.push('\n');
        out.push_str(&command(manual, c));
    }
    heading(&mut out, "ENVIRONMENT");
    out.push_str(&environment(manual));
    heading(&mut out, "FILES");
    out.push_str(&files(manual));
    heading(&mut out, "EXIT STATUS");
    out.push_str(&exit_status(manual));
    heading(&mut out, "EXAMPLES");
    out.push_str(&examples(manual));
    heading(&mut out, "SEE ALSO");
    out.push_str(&fill(
        "pod-netns --help; cloudflared(1); https://github.com/Azathothas/cfrs (README.md, docs/protocol.md, docs/virtual-network.md).",
        4,
    ));
    out
}
