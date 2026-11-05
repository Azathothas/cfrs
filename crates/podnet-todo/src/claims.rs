//! The claims of the pages that a session reads first (T-362). A "yet" says
//! that something is not built, and it goes stale on the day its work is
//! done, in a file that the work did not touch; so does a status written
//! beside an id. Each "yet" of the documents (`docs/`, `README.md`,
//! `AGENTS.md`, `SECURITY.md`), outside fenced blocks, is in a unit that
//! names an entry that is not done, or a date; a done entry beside it is
//! named. Each status beside an id (`T-NNN, partial`) agrees with the index,
//! unless its unit reads at a date or at a commit. A unit is a paragraph, a
//! list item or a row of a table: an id in another item covers no claim.
//! The release notes (`docs/releases/`) are readings at their tags.

use std::collections::HashMap;
use std::path::Path;

use crate::model::{ids_in, Problem};

/// The statuses that a reader may write beside an id.
const STATUSES: [&str; 4] = ["open", "partial", "blocked", "done"];

/// The documents whose claims are read.
fn files(root: &Path) -> Vec<String> {
    crate::refs::documents(root)
        .into_iter()
        .filter(|rel| !rel.starts_with("TODO/") && !rel.starts_with("docs/releases/"))
        .collect()
}

/// Whether `line` starts a unit of its own: a heading, an item of a list, a
/// row of a table.
fn starts_unit(line: &str) -> bool {
    let t = line.trim_start();
    let numbered = t.split_once(". ").is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    t.starts_with('#')
        || t.starts_with("- ")
        || t.starts_with("* ")
        || t.starts_with("+ ")
        || t.starts_with('|')
        || numbered
}

/// The units of `text` outside fenced blocks: each its first line (from 1)
/// and its lines.
pub fn units(text: &str) -> Vec<(usize, Vec<&str>)> {
    let mut out: Vec<(usize, Vec<&str>)> = Vec::new();
    let mut fenced = false;
    let mut open = false;
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            open = false;
            continue;
        }
        if fenced || line.trim().is_empty() {
            open = false;
            continue;
        }
        if !open || starts_unit(line) || line.trim_start().starts_with('|') {
            out.push((i + 1, Vec::new()));
            open = true;
        }
        if let Some((_, lines)) = out.last_mut() {
            lines.push(line);
        }
    }
    out
}

/// `line` with each code span blanked: a span quotes what a program
/// prints, as `(not implemented yet)`, and claims nothing.
fn prose(line: &str) -> String {
    line.split('`')
        .enumerate()
        .map(|(i, part)| if i % 2 == 1 { " ".repeat(part.len()) } else { part.to_string() })
        .collect()
}

/// Whether `word` is in the prose of `line` as a word, in any case.
fn has_word(line: &str, word: &str) -> bool {
    let lower = prose(line).to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut at = 0;
    while let Some(pos) = lower[at..].find(word) {
        let start = at + pos;
        let end = start + word.len();
        let before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before && after {
            return true;
        }
        at = end;
    }
    false
}

/// Whether `text` holds a date (`YYYY-MM-DD`) or a commit in a code span
/// (seven to forty hexadecimal digits): a reading at a time.
pub fn dated(text: &str) -> bool {
    let b = text.as_bytes();
    let date = (0..b.len().saturating_sub(9)).any(|i| {
        let w = &b[i..i + 10];
        let shape = w.iter().enumerate().all(|(k, c)| if k == 4 || k == 7 { *c == b'-' } else { c.is_ascii_digit() });
        let edge = |j: usize| j >= b.len() || !b[j].is_ascii_alphanumeric();
        shape && (i == 0 || edge(i - 1)) && edge(i + 10)
    });
    let commit = text.split('`').skip(1).step_by(2).any(|span| {
        (7..=40).contains(&span.len()) && span.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    });
    date || commit
}

/// Each status written beside an id in `line`: `T-NNN, STATUS`.
fn statuses(line: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for (id, _) in ids_in(line) {
        let mut at = 0;
        while let Some(pos) = line[at..].find(&id) {
            let rest = &line[at + pos + id.len()..];
            if let Some(after) = rest.strip_prefix(", ") {
                if let Some(status) = STATUSES.iter().find(|s| {
                    after.starts_with(**s) && !after[s.len()..].starts_with(|c: char| c.is_ascii_alphanumeric())
                }) {
                    out.push((id.clone(), *status));
                }
            }
            at += pos + id.len();
        }
    }
    out
}

/// The claims of the text of `rel`, against the status of each id.
pub fn check_text(rel: &str, text: &str, status: &HashMap<&str, &str>, p: &mut Vec<Problem>) {
    for (first, lines) in units(text) {
        let joined = lines.join("\n");
        let reading = dated(&joined);
        let ids: Vec<String> = ids_in(&joined).into_iter().map(|(id, _)| id).collect();
        let pending = ids.iter().any(|id| status.get(id.as_str()).is_some_and(|s| *s != "done"));
        for (k, line) in lines.iter().enumerate() {
            let at = first + k;
            if has_word(line, "yet") && !reading {
                let beside: Vec<String> = ids_in(line).into_iter().map(|(id, _)| id).collect();
                let done: Vec<&String> = beside.iter().filter(|id| status.get(id.as_str()) == Some(&"done")).collect();
                if !beside.is_empty() && done.len() == beside.len() {
                    let named: Vec<&str> = done.iter().map(|id| id.as_str()).collect();
                    p.push(Problem::new(
                        rel,
                        at,
                        format!(
                            "\"yet\" beside {}, done: the claim is stale, or it names the wrong entry",
                            named.join(", ")
                        ),
                    ));
                } else if !pending {
                    p.push(Problem::new(
                        rel,
                        at,
                        "\"yet\" with no entry that is not done and no date in its paragraph: name its entry or \
                         its date, or say it with no \"yet\"",
                    ));
                }
            }
            if reading {
                continue;
            }
            for (id, said) in statuses(line) {
                match status.get(id.as_str()) {
                    Some(actual) if *actual != said => p.push(Problem::new(
                        rel,
                        at,
                        format!("{id}, {said}: the index says {actual}; a reading of a past state names its date"),
                    )),
                    _ => {}
                }
            }
        }
    }
}

/// The claims of each document of `root`.
pub fn check(root: &Path, status: &HashMap<&str, &str>, p: &mut Vec<Problem>) {
    for rel in files(root) {
        if let Ok(text) = std::fs::read_to_string(root.join(&rel)) {
            check_text(&rel, &text, status, p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<String> {
        let status: HashMap<&str, &str> = [("T-001", "open"), ("T-002", "done"), ("T-003", "partial")].into();
        let mut p = Vec::new();
        check_text("docs/x.md", text, &status, &mut p);
        p.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn a_yet_needs_an_entry_that_is_not_done_or_a_date() {
        assert_eq!(found("It does not exist yet.\n").len(), 1);
        assert!(found("It does not exist yet (T-001).\n").is_empty());
        assert!(found("It is not built yet;\nT-003 builds it.\n").is_empty(), "the entry may be on another line");
        assert!(found("On 2026-10-10 it was not built yet.\n").is_empty());
        assert!(found("At `8554930` it was not built yet.\n").is_empty());
    }

    #[test]
    fn a_done_entry_beside_a_yet_is_named() {
        let said = found("It does not exist yet (T-002).\n");
        assert!(said.len() == 1 && said[0].contains("T-002, done"), "{said:?}");
    }

    #[test]
    fn each_item_of_a_list_and_each_row_is_its_own_unit() {
        // The id of the next item covers no claim of this one.
        assert_eq!(found("- It does not exist yet.\n- T-001 is another.\n").len(), 1);
        assert_eq!(found("| a | not yet |\n| b | T-001 |\n").len(), 1);
        assert!(found("- It does not exist yet,\n  and T-001 builds it.\n").is_empty(), "a continued item");
    }

    #[test]
    fn a_fenced_block_is_no_claim_and_yet_is_a_word() {
        assert!(found("```\nnot yet\n```\n").is_empty());
        assert!(found("It prints `(not implemented yet)`.\n").is_empty(), "a span quotes output");
        assert!(found("The yeti and the eyetest.\n").is_empty());
        assert_eq!(found("Yet it is not built.\n").len(), 1);
    }

    #[test]
    fn a_status_beside_an_id_agrees_with_the_index_unless_it_is_a_reading() {
        let said = found("Over IRC too (T-002, partial).\n");
        assert!(said.len() == 1 && said[0].contains("T-002, partial: the index says done"), "{said:?}");
        assert!(found("Over IRC too (T-003, partial).\n").is_empty());
        assert!(found("On 2026-10-10, T-002, partial, carried it.\n").is_empty());
        assert!(found("T-002, partially so.\n").is_empty(), "partially is no status");
    }

    #[test]
    fn a_date_is_a_whole_date() {
        assert!(dated("2026-10-31"));
        assert!(dated("(at `1a46970`)"));
        assert!(!dated("version 1.0.0-beta.2"));
        assert!(!dated("12026-10-31x"));
        assert!(!dated("`main`"));
    }
}
