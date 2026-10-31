//! The manual as a man(7) page: `cfrs man --roff`. It uses the standard
//! macros only (TH, SH, SS, TP, PP, RS, RE, nf, fi, B, I), so that groff and
//! mandoc render it in the same way.

use super::model::{CommandPage, Manual};

/// Escape `text` for roff: backslashes, hyphens, and a dot or an apostrophe at
/// the start of a line.
pub fn escape(text: &str) -> String {
    let text = super::text::ascii(text);
    let mut out = String::with_capacity(text.len());
    for line in text.split('\n') {
        let mut escaped = line.replace('\\', "\\e").replace('-', "\\-");
        if escaped.starts_with('.') || escaped.starts_with('\'') {
            escaped.insert_str(0, "\\&");
        }
        out.push_str(&escaped);
        out.push('\n');
    }
    out.pop();
    out
}

fn para(out: &mut String, text: &str) {
    for (i, p) in text.split("\n\n").enumerate() {
        if i > 0 {
            out.push_str(".PP\n");
        }
        // Lines that start with spaces are a block: keep them as they are.
        if p.lines().any(|l| l.starts_with("  ")) {
            out.push_str(".nf\n");
            out.push_str(&escape(p));
            out.push_str("\n.fi\n");
        } else {
            out.push_str(&escape(&p.split_whitespace().collect::<Vec<_>>().join(" ")));
            out.push('\n');
        }
    }
}

fn command(out: &mut String, manual: &Manual, c: &CommandPage) {
    out.push_str(&format!(".SS \"{}\"\n", escape(&c.usage)));
    let about = if c.long_about.is_empty() {
        &c.about
    } else {
        &c.long_about
    };
    para(out, about);
    if c.path == ["pod"] {
        out.push_str(".PP\n.nf\n");
        out.push_str(&escape(&manual.pod_usage));
        out.push_str("\n.fi\n");
    }
    let (positional, flags): (Vec<_>, Vec<_>) = c.args.iter().partition(|a| a.positional);
    for a in positional.iter().chain(flags.iter()) {
        out.push_str(".TP\n");
        out.push_str(&format!(".B {}\n", escape(&a.synopsis)));
        let mut help = a.help.clone();
        if !help.is_empty() && !help.trim_end().ends_with(['.', '!', '?', ':']) {
            help.push('.');
        }
        if let Some(d) = &a.default {
            help.push_str(&format!(" Default: {d}."));
        }
        if !a.values.is_empty() {
            help.push_str(&format!(" Values: {}.", a.values.join(", ")));
        }
        if let Some(env) = &a.env {
            help.push_str(&format!(" Variable: {env}."));
        }
        para(out, help.trim());
    }
}

/// The whole manual.
pub fn render(manual: &Manual) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        ".TH {} 1 \"\" \"cfrs {}\" \"User Commands\"\n",
        manual.name.to_ascii_uppercase(),
        escape(&manual.version)
    ));
    out.push_str(".SH NAME\n");
    out.push_str(&format!("{} \\- {}\n", manual.name, escape(&manual.about)));
    out.push_str(".SH SYNOPSIS\n");
    out.push_str(&format!(
        ".B {}\n\\fICOMMAND\\fR [\\fIOPTIONS\\fR]\n",
        manual.name
    ));
    out.push_str(".SH DESCRIPTION\n");
    for (i, p) in manual.description.iter().enumerate() {
        if i > 0 {
            out.push_str(".PP\n");
        }
        para(&mut out, p);
    }
    out.push_str(".SH COMMANDS\n");
    for c in manual.commands.iter().filter(|c| !c.path.is_empty()) {
        command(&mut out, manual, c);
    }
    out.push_str(".SH ENVIRONMENT\n");
    for v in manual.environment {
        out.push_str(&format!(".TP\n.B {}\n", escape(&v.names.join(", "))));
        para(&mut out, &format!("{} ({})", v.meaning, v.used_by));
    }
    out.push_str(".SH FILES\n");
    for f in manual.files {
        out.push_str(&format!(".TP\n.I {}\n", escape(f.path)));
        para(&mut out, f.meaning);
    }
    out.push_str(".SH \"EXIT STATUS\"\n");
    for row in &manual.exit_status {
        out.push_str(&format!(".TP\n.B {} ({})\n", row.code, row.name));
        para(&mut out, row.meaning);
    }
    out.push_str(".SH EXAMPLES\n");
    for e in manual.examples {
        para(&mut out, e.meaning);
        out.push_str(".RS\n.nf\n");
        out.push_str(&escape(&format!("$ {}", e.command)));
        out.push_str("\n.fi\n.RE\n");
    }
    out.push_str(".SH \"SEE ALSO\"\n");
    out.push_str(".BR pod\\-netns (1),\n.BR cloudflared (1)\n");
    out
}

/// One command, or one topic, as a man(7) page.
pub fn render_section(manual: &Manual, title: &str, body: impl FnOnce(&mut String)) -> String {
    let mut out = format!(
        ".TH {} 1 \"\" \"cfrs {}\" \"User Commands\"\n.SH \"{}\"\n",
        manual.name.to_ascii_uppercase(),
        escape(&manual.version),
        escape(&title.to_ascii_uppercase())
    );
    body(&mut out);
    out
}

/// The section of one command.
pub fn render_command(manual: &Manual, c: &CommandPage) -> String {
    render_section(manual, &c.name(), |out| command(out, manual, c))
}
