//! Reading the record's Markdown. Each shape is a fixed line, so that a
//! number or a status that one file quotes can be compared with the file
//! that owns it.

use crate::model::{Counts, Entry, Field, Problem, Row, Section, FIELDS};

/// The lines of a text with their numbers, and whether each is inside a
/// fenced code block (a fence line itself counts as inside).
pub fn lines_with_fences(text: &str) -> Vec<(usize, &str, bool)> {
    let mut out = Vec::new();
    let mut fenced = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            out.push((i + 1, line, true));
        } else {
            out.push((i + 1, line, fenced));
        }
    }
    out
}

/// The cells of a Markdown table line, trimmed, without the outer pipes.
pub fn cells(line: &str) -> Vec<String> {
    let t = line.trim();
    let inner = t.strip_prefix('|').unwrap_or(t);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

/// The rows of the table of entries: each line that starts with `| [T-`.
pub fn rows(file: &str, index: &str) -> (Vec<Row>, Vec<Problem>) {
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for (line_no, line, fenced) in lines_with_fences(index) {
        if fenced || !line.trim_start().starts_with("| [T-") {
            continue;
        }
        let c = cells(line);
        let link = c.first().map(String::as_str).unwrap_or("");
        let parsed = link
            .strip_prefix('[')
            .and_then(|s| s.split_once("]("))
            .and_then(|(id, rest)| rest.strip_suffix(')').map(|f| (id.to_string(), f.to_string())));
        match parsed {
            Some((id, target)) if c.len() == 7 => rows.push(Row {
                id,
                file: target,
                priority: c[1].clone(),
                effort: c[2].clone(),
                milestone: c[3].clone(),
                category: c[4].clone(),
                status: c[5].clone(),
                title: c[6].clone(),
                line: line_no,
            }),
            _ => problems.push(Problem::new(
                file,
                line_no,
                "a row must be | [T-NNN](area.md) | priority | effort | milestone | category | status | title | (7 cells, no `|` in the title)",
            )),
        }
    }
    (rows, problems)
}

/// The entries of an area file. Problems are reported for an H1 that is not
/// an entry, and for a header line that is not a known field.
pub fn entries(file: &str, text: &str) -> (Vec<Entry>, Vec<Problem>) {
    let mut entries: Vec<Entry> = Vec::new();
    let mut problems = Vec::new();
    // Inside an entry: in the header (before the first `##`), or in a section.
    let mut in_header = false;
    for (line_no, line, fenced) in lines_with_fences(text) {
        if !fenced && line.starts_with("# ") {
            match line[2..].split_once(": ") {
                Some((id, title)) if crate::model::is_id(id) => {
                    entries.push(Entry {
                        id: id.to_string(),
                        title: title.trim().to_string(),
                        file: file.to_string(),
                        line: line_no,
                        fields: Vec::new(),
                        sections: Vec::new(),
                    });
                    in_header = true;
                }
                _ => problems.push(Problem::new(file, line_no, "an H1 that is not an entry (`# T-NNN: Title`)")),
            }
            continue;
        }
        let Some(entry) = entries.last_mut() else { continue };
        if !fenced && line.starts_with("## ") {
            entry.sections.push(Section { name: line[3..].trim().to_string(), line: line_no, body: String::new() });
            in_header = false;
            continue;
        }
        if in_header {
            header_line(entry, line, line_no, file, &mut problems);
        } else if let Some(section) = entry.sections.last_mut() {
            section.body.push_str(line);
            section.body.push('\n');
        }
    }
    (entries, problems)
}

/// One line of an entry's header: `**Name:** value`, or the continuation of
/// the field above it.
fn header_line(entry: &mut Entry, line: &str, line_no: usize, file: &str, problems: &mut Vec<Problem>) {
    if line.trim().is_empty() {
        return;
    }
    if let Some(rest) = line.strip_prefix("**") {
        if let Some((name, value)) = rest.split_once(":**") {
            if FIELDS.contains(&name) {
                entry.fields.push(Field { name: name.to_string(), value: value.trim().to_string(), line: line_no });
            } else {
                problems.push(Problem::new(file, line_no, format!("`{name}` is not a field of an entry")));
            }
            return;
        }
    }
    match entry.fields.last_mut() {
        Some(f) => {
            f.value.push(' ');
            f.value.push_str(line.trim());
        }
        None => problems.push(Problem::new(file, line_no, "text before the first field of the entry")),
    }
}

/// The counts phrase `N entries: A open, B partial, C blocked, D done.` in a
/// line: the counts, and the byte range of the phrase.
pub fn counts_phrase(line: &str) -> Option<(usize, Counts, std::ops::Range<usize>)> {
    let key = " entries: ";
    let at = line.find(key)?;
    let start = line[..at].rfind(|c: char| !c.is_ascii_digit()).map_or(0, |i| i + 1);
    let total: usize = line[start..at].parse().ok()?;
    let rest = &line[at + key.len()..];
    let end_rel = rest.find('.')?;
    let mut c = Counts::default();
    for (part, want) in rest[..end_rel].split(", ").zip(["open", "partial", "blocked", "done"]) {
        let (n, word) = part.split_once(' ')?;
        if word != want {
            return None;
        }
        let n: usize = n.parse().ok()?;
        match want {
            "open" => c.open = n,
            "partial" => c.partial = n,
            "blocked" => c.blocked = n,
            _ => c.done = n,
        }
    }
    if rest[..end_rel].split(", ").count() != 4 {
        return None;
    }
    let end = at + key.len() + end_rel + 1;
    Some((total, c, start..end))
}

/// The first line that carries the counts phrase, with its number.
pub fn find_counts(text: &str) -> Option<(usize, usize, Counts)> {
    lines_with_fences(text)
        .into_iter()
        .filter(|(_, _, fenced)| !fenced)
        .find_map(|(no, line, _)| counts_phrase(line).map(|(total, c, _)| (no, total, c)))
}

/// A row of the table of counts: `| P1 | a | b | c | d | total |`, or the
/// `| **All** | ... |` row. Returns the label, the counts and the total.
pub fn counts_row(line: &str) -> Option<(String, Counts, usize)> {
    let c = cells(line);
    if c.len() != 6 {
        return None;
    }
    let n: Vec<usize> = c[1..].iter().map(|v| v.parse().ok()).collect::<Option<_>>()?;
    let label = c[0].trim_matches('*').to_string();
    Some((label, Counts { open: n[0], partial: n[1], blocked: n[2], done: n[3] }, n[4]))
}

/// The body of the `## Heading` section of a document, up to the next `## `.
pub fn doc_section<'a>(text: &'a str, heading: &str) -> Option<(usize, Vec<(usize, &'a str)>)> {
    let mut out = None;
    for (no, line, fenced) in lines_with_fences(text) {
        if !fenced && line.starts_with("## ") {
            if out.is_some() {
                break;
            }
            if line[3..].trim() == heading {
                out = Some((no, Vec::new()));
            }
            continue;
        }
        if let Some((_, body)) = out.as_mut() {
            body.push((no, line));
        }
    }
    out
}

/// The backtick code spans of a line (single backticks).
pub fn code_spans(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        out.push(&after[..close]);
        rest = &after[close + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counts_phrase_is_read_where_it_stands() {
        let line = "**12 entries: 5 open, 1 partial, 2 blocked, 4 done.**";
        let (total, c, range) = counts_phrase(line).unwrap();
        assert_eq!(total, 12);
        assert_eq!((c.open, c.partial, c.blocked, c.done), (5, 1, 2, 4));
        assert_eq!(&line[range], "12 entries: 5 open, 1 partial, 2 blocked, 4 done.");
        let line = "`TODO/INDEX.md` holds 7 entries: 1 open, 2 partial, 3 blocked, 1 done.";
        assert_eq!(counts_phrase(line).unwrap().0, 7);
        assert!(counts_phrase("7 entries: 1 open, 2 partial, 3 done.").is_none());
    }

    #[test]
    fn a_heading_in_a_fence_is_not_an_entry() {
        let text = "# T-001: One\n\n**Status:** open\n\n## Prove\n\n```sh\n# T-002: not an entry\n## Done\n```\n";
        let (e, p) = entries("a.md", text);
        assert!(p.is_empty(), "{p:?}");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].sections.len(), 1);
        assert!(e[0].sections[0].body.contains("# T-002"));
    }

    #[test]
    fn a_field_can_wrap() {
        let text = "# T-001: One\n\n**Source:** the operator,\nin two lines.\n**Status:** open\n";
        let (e, _) = entries("a.md", text);
        assert_eq!(e[0].field("Source"), Some("the operator, in two lines."));
        assert_eq!(e[0].field("Status"), Some("open"));
    }
}
