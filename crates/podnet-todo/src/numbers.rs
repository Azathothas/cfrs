//! Line numbers in the text of the record. A citation `FILE:N` moves with
//! FILE (`remap`) and is read (`check`), and so does a bare `:N` that follows
//! a citation of FILE in its paragraph. A number written as plain text after
//! a citation ("line 12", "lines 3-4") does neither, so it can come to name a
//! line that holds other code. "line 12 at `COMMIT`" is a reading of a past
//! tree, which needs no move, and so is each number of a paragraph that reads
//! at a named commit.

use std::fs;
use std::ops::Range;
use std::path::Path;

use crate::model::Problem;
use crate::parse::lines_with_fences;
use crate::refs::citation;

/// The bare `:N` of each paragraph, read in the file that it follows, and
/// each line number in plain text after a citation.
pub fn check(root: &Path, rel: &str, text: &str, p: &mut Vec<Problem>) {
    for para in paragraphs(text) {
        let (joined, starts) = join(&para);
        let line_at = |at: usize| starts.iter().rev().find(|(o, _)| *o <= at).map_or(0, |(_, no)| *no);
        let spans = spans_of(&para, &starts);
        bare(root, rel, &spans, &line_at, p);
        for (range, words) in plain(&joined, &spans) {
            let cited = spans.iter().any(|s| s.range.end <= range.start && s.cites.is_some());
            let read = spans.iter().any(|s| s.range.end <= range.start && s.commit_read);
            if cited && !read && !at_commit(&joined[range.end..]) {
                p.push(Problem::new(
                    rel,
                    line_at(range.start),
                    format!(
                        "\"{words}\" follows a citation as plain text, which remap does not move and check \
                         does not read: write `:N`, or \"{words} at `COMMIT`\" for a reading of a past tree"
                    ),
                ));
            }
        }
    }
}

/// A code span of a paragraph: where it is in the joined text, what it
/// holds, the file that it cites, and whether it is a commit after "at".
struct Span {
    range: Range<usize>,
    inner: String,
    cites: Option<String>,
    commit_read: bool,
}

/// The paragraphs of a text, as `remap` reads them: a blank line, a
/// heading or a fence ends one.
fn paragraphs(text: &str) -> Vec<Vec<(usize, &str)>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for (no, line, fenced) in lines_with_fences(text) {
        if fenced || line.trim().is_empty() || line.starts_with('#') {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push((no, line));
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A paragraph as one text, and the offset and number of each of its lines.
fn join(para: &[(usize, &str)]) -> (String, Vec<(usize, usize)>) {
    let mut joined = String::new();
    let mut starts = Vec::new();
    for &(no, line) in para {
        starts.push((joined.len(), no));
        joined.push_str(line);
        joined.push('\n');
    }
    (joined, starts)
}

/// The code spans of each line, as CommonMark reads them: a run of backticks
/// opens a span that the next run of the same length closes, so that
/// `` `FILE:12` and `:40` `` is one span, which cites nothing.
fn spans_of(para: &[(usize, &str)], starts: &[(usize, usize)]) -> Vec<Span> {
    let mut out: Vec<Span> = Vec::new();
    for (&(_, line), &(offset, _)) in para.iter().zip(starts) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'`' {
                i += 1;
                continue;
            }
            let open = i;
            while i < b.len() && b[i] == b'`' {
                i += 1;
            }
            let run = i - open;
            let mut j = i;
            let mut close = None;
            while j < b.len() {
                if b[j] != b'`' {
                    j += 1;
                    continue;
                }
                let s = j;
                while j < b.len() && b[j] == b'`' {
                    j += 1;
                }
                if j - s == run {
                    close = Some((s, j));
                    break;
                }
            }
            // A run that nothing closes is text.
            let Some((s, e)) = close else { continue };
            let inner = if run == 1 { &line[i..s] } else { line[i..s].trim_matches(' ') };
            let before = line[..open].trim_end();
            let after_at = before.ends_with(" at") || before == "at" || before.ends_with("(at");
            out.push(Span {
                range: offset + open..offset + e,
                inner: inner.to_string(),
                cites: citation(inner).map(|(path, _)| path.to_string()),
                commit_read: after_at && is_commit(inner),
            });
            i = e;
        }
    }
    out
}

/// Each bare `:N` names a line of the file that the last citation before it
/// in its paragraph names. A bare `:N` that follows no citation names no
/// file, as for `remap`, and is not read.
fn bare(root: &Path, rel: &str, spans: &[Span], line_at: &dyn Fn(usize) -> usize, p: &mut Vec<Problem>) {
    let mut context: Option<&str> = None;
    for s in spans {
        if let Some(path) = &s.cites {
            context = Some(path.as_str());
            continue;
        }
        let (Some(path), Some((first, last))) = (context, s.inner.strip_prefix(':').and_then(numbers)) else {
            continue;
        };
        let at = line_at(s.range.start);
        if first == 0 || first > last {
            p.push(Problem::new(
                rel,
                at,
                format!("`{}`: a range runs from line 1 or later to a line at or after its start", s.inner),
            ));
            continue;
        }
        let Ok(cited) = fs::read_to_string(root.join(path)) else { continue };
        let count = cited.lines().count();
        if last > count {
            p.push(Problem::new(rel, at, format!("`{}` after `{path}`: {path} has {count} lines", s.inner)));
        }
    }
}

/// `N` or `N-M`, digits only: the first line and the last.
fn numbers(s: &str) -> Option<(usize, usize)> {
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    match s.split_once('-') {
        Some((a, b)) if digits(a) && digits(b) => Some((a.parse().ok()?, b.parse().ok()?)),
        None if digits(s) => {
            let n = s.parse().ok()?;
            Some((n, n))
        }
        _ => None,
    }
}

/// A commit as the record writes one: 7 to 40 lower-case hex digits.
fn is_commit(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The text after a number begins "at `COMMIT`", on the same line or the next.
fn at_commit(rest: &str) -> bool {
    let Some(r) = rest.trim_start().strip_prefix("at") else { return false };
    let Some(r) = r.trim_start().strip_prefix('`') else { return false };
    r.split_once('`').is_some_and(|(inner, _)| is_commit(inner))
}

/// Each "line N" or "lines N-M" (also "lines 3 and 5", "lines 3, 5 or 7")
/// in the plain text of a paragraph: outside code spans and outside double
/// quotes, which quote text rather than name a line.
fn plain(joined: &str, spans: &[Span]) -> Vec<(Range<usize>, String)> {
    let b = joined.as_bytes();
    let mut text = vec![true; b.len()];
    for s in spans {
        text[s.range.clone()].iter_mut().for_each(|t| *t = false);
    }
    let mut quoted = false;
    for (i, t) in text.iter_mut().enumerate() {
        if *t && b[i] == b'"' {
            quoted = !quoted;
            *t = false;
        } else if quoted {
            *t = false;
        }
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        // A byte inside a character of more than one byte starts no word.
        if !joined.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let word_start = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        let rest = &joined[i..];
        let head = ["line ", "lines ", "Line ", "Lines "].iter().find(|w| rest.starts_with(**w));
        let (true, true, Some(head)) = (text[i], word_start, head) else {
            i += 1;
            continue;
        };
        let mut e = i + head.len();
        let Some(end) = number_list(joined, e, &text) else {
            i += 1;
            continue;
        };
        e = end;
        out.push((i..e, joined[i..e].to_string()));
        i = e;
    }
    out
}

/// The end of a list of numbers that starts at `at`: "12", "3-4", "3 and
/// 5", "3, 5 or 7-9". None when no number starts there.
fn number_list(s: &str, at: usize, text: &[bool]) -> Option<usize> {
    let b = s.as_bytes();
    let number = |from: usize| -> Option<usize> {
        let mut k = from;
        while k < b.len() && b[k].is_ascii_digit() && text[k] {
            k += 1;
        }
        if k == from {
            return None;
        }
        if k + 1 < b.len() && b[k] == b'-' && b[k + 1].is_ascii_digit() {
            k += 1;
            while k < b.len() && b[k].is_ascii_digit() {
                k += 1;
            }
        }
        Some(k)
    };
    let mut end = number(at)?;
    loop {
        let more = [", and ", ", or ", " and ", " or ", ", "].iter().find(|sep| s[end..].starts_with(**sep));
        let Some(sep) = more else { break };
        match number(end + sep.len()) {
            Some(next) => end = next,
            None => break,
        }
    }
    // A number that runs into a word or a decimal point is not a line.
    let next = b.get(end).copied().unwrap_or(b' ');
    (!next.is_ascii_alphanumeric() && !(next == b'.' && b.get(end + 1).is_some_and(u8::is_ascii_digit))).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<String> {
        let mut p = Vec::new();
        check(Path::new("."), "TODO/t.md", text, &mut p);
        p.into_iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn a_plain_number_after_a_citation_is_found() {
        let p = found("Read `crates/podssh-todo/src/lib.rs:3`, and lines 5 and 7-8.\n");
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("\"lines 5 and 7-8\" follows a citation"), "{p:?}");
        // A character of more than one byte before it.
        let p = found("Read `crates/podssh-todo/src/lib.rs:3` — and line 5.\n");
        assert_eq!(p.len(), 1, "{p:?}");
    }

    #[test]
    fn readings_quotes_and_other_numbers_pass() {
        for text in [
            "Read `crates/podssh-todo/src/lib.rs:3`, line 5 at `0123abc`.\n",
            "Read `crates/podssh-todo/src/lib.rs:3`, line 5\nat `0123abc`.\n",
            "Read, at `0123abc`: `crates/podssh-todo/src/lib.rs:3`, and line 5.\n",
            "Read `crates/podssh-todo/src/lib.rs:3`; it says \"line 5\".\n",
            "Line 5 of the output, before any citation: `crates/podssh-todo/src/lib.rs:3`.\n",
            "Read `crates/podssh-todo/src/lib.rs:3`.\n\nA new paragraph: line 5 of a log.\n",
            "Read `crates/podssh-todo/src/lib.rs:3`, in 5 lines, with a pipeline 2.5 long.\n",
        ] {
            assert_eq!(found(text), Vec::<String>::new(), "{text:?}");
        }
    }

    #[test]
    fn a_double_backtick_span_is_one_span() {
        let mut p = Vec::new();
        let para = vec![(1, "(the record writes `` `FILE:12` and `:40` ``)")];
        let (_, starts) = join(&para);
        let spans = spans_of(&para, &starts);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].inner, "`FILE:12` and `:40`");
        bare(Path::new("."), "TODO/t.md", &spans, &|_| 1, &mut p);
        assert!(p.is_empty(), "{p:?}");
    }
}
