//! `remap FILE...`: after an edit of FILE, move each citation of it in the
//! documents by a line diff of FILE against its version in the base: `HEAD`,
//! or the revision that `--base` names, as `HEAD~1` for a commit that was
//! made without a remap. A citation is `FILE:N` or `FILE:N-M` in a code
//! span, or a bare `:N` that follows a citation of FILE in the same
//! paragraph.
//!
//! Each document is compared with the base too, and a line of it is rebuilt
//! from its line in the base, where the numbers are the base's. So a second
//! run after a second edit gives the right numbers, not a second shift. A
//! line that is new in this change is kept as it is: its writer used the new
//! numbers.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;
use std::path::Path;

use crate::diff::line_map;
use crate::parse::lines_with_fences;
use crate::refs::{citation, documents};

/// The text of a file in the base; `Ok(None)` when the base has no such file.
pub type Head<'a> = dyn Fn(&str) -> Result<Option<String>, String> + 'a;

/// What a run moved, and what a person must read.
#[derive(Debug, Default)]
pub struct Report {
    /// Each citation that moved: `doc:line: old -> new`.
    pub moved: Vec<String>,
    /// Each citation of a line that this change removed or changed. It is
    /// not moved.
    pub review: Vec<String>,
    /// Each line that is new in this change and cites FILE. Its numbers are
    /// taken to be the new ones.
    pub kept: Vec<String>,
    pub notes: Vec<String>,
}

/// One citation on a line: the byte range of its numbers in the line, the
/// file, the first and the last line, and whether this run moves it (its
/// file is one of the files given).
#[derive(Debug, Clone)]
struct Cite {
    range: Range<usize>,
    path: String,
    first: usize,
    last: Option<usize>,
    moves: bool,
}

/// The line map of a file: each old line's new number, and which old lines
/// are blank. A blank line is no anchor: a diff may match it with any other
/// blank line, also one in a part that the edit added.
struct FileMap {
    to: Vec<Option<usize>>,
    blank: Vec<bool>,
}

type Maps = HashMap<String, FileMap>;

/// The text of `rel` in the revision `rev`, read with `git show`; `Ok(None)`
/// when the revision has no such file, or none that is UTF-8 text, which no
/// citation could name by its lines.
pub fn git_at(root: &Path, rev: &str, rel: &str) -> Result<Option<String>, String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["show", &format!("{rev}:{rel}")])
        .output()
        .map_err(|e| format!("git cannot run here ({e}); remap needs each file as it is in {rev}"))?;
    if out.status.success() {
        return Ok(String::from_utf8(out.stdout).ok());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    if why.contains("does not exist in") || why.contains("exists on disk, but not in") {
        Ok(None)
    } else {
        Err(format!("git show {rev}:{rel}: {}", why.trim()))
    }
}

/// The files of the tree that differ from the revision `rev` and still
/// exist, by `git diff --name-only REV`; `None` when git cannot say (no git,
/// no repository, no such revision).
pub fn changed_since(root: &Path, rev: &str) -> Option<Vec<String>> {
    let out =
        std::process::Command::new("git").arg("-C").arg(root).args(["diff", "--name-only", rev, "--"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.lines().filter(|l| !l.is_empty() && root.join(l).is_file()).map(str::to_string).collect())
}

/// Move the citations of `files` in each document. With `write` false,
/// only report what would move.
pub fn remap(root: &Path, files: &[String], head: &Head, write: bool) -> Result<Report, String> {
    let mut report = Report::default();
    let mut maps: Maps = HashMap::new();
    for f in files {
        let rel = f.replace('\\', "/");
        let rel = rel.trim_start_matches("./").to_string();
        let bytes = fs::read(root.join(&rel)).map_err(|e| format!("{rel}: {e}"))?;
        // A file that is not text, as a binary fixture, has no lines to
        // cite. It is passed over, so that the other files still move and
        // the check of a commit that changed it still runs.
        let Ok(now) = String::from_utf8(bytes) else {
            report.notes.push(format!("{rel} is not UTF-8 text: it has no lines to move"));
            continue;
        };
        match head(&rel)? {
            None => report.notes.push(format!("{rel} has no text in the base: a new file has no old line numbers")),
            Some(old) => {
                let old: Vec<&str> = old.lines().collect();
                let now: Vec<&str> = now.lines().collect();
                let blank = old.iter().map(|l| l.trim().is_empty()).collect();
                maps.insert(rel, FileMap { to: line_map(&old, &now), blank });
            }
        }
    }
    let names: HashSet<&str> = maps.keys().map(String::as_str).collect();
    if names.is_empty() {
        return Ok(report);
    }
    for doc in documents(root) {
        let Ok(now) = fs::read_to_string(root.join(&doc)) else { continue };
        // A bare `:N` needs a full citation earlier in its paragraph, so a
        // document that names no file has nothing to move.
        if !names.iter().any(|f| now.contains(f)) {
            continue;
        }
        let old = head(&doc)?.unwrap_or_default();
        if let Some(text) = remap_doc(&doc, &now, &old, &names, &maps, &mut report) {
            if write {
                let crlf = now.contains("\r\n");
                let mut out = if crlf { text.replace('\n', "\r\n") } else { text };
                if !now.ends_with('\n') && out.ends_with('\n') {
                    out.pop();
                    if crlf {
                        out.pop();
                    }
                }
                fs::write(root.join(&doc), out).map_err(|e| format!("{doc}: {e}"))?;
            }
        }
    }
    Ok(report)
}

/// The new text of one document, when a citation in it moved.
fn remap_doc(
    doc: &str,
    now: &str,
    old: &str,
    names: &HashSet<&str>,
    maps: &Maps,
    report: &mut Report,
) -> Option<String> {
    let now_lines: Vec<&str> = now.lines().collect();
    let old_lines: Vec<&str> = old.lines().collect();
    let now_cites = cites(now, names);
    let old_cites = cites(old, names);
    // For each line of the document now, its line in HEAD when unchanged.
    let mut from: Vec<Option<usize>> = vec![None; now_lines.len()];
    for (o, n) in line_map(&old_lines, &now_lines).iter().enumerate() {
        if let Some(n) = n {
            from[n - 1] = Some(o);
        }
    }
    let mut used = HashSet::new();
    let mut moved = false;
    let mut out = String::with_capacity(now.len());
    for (i, line) in now_lines.iter().enumerate() {
        let mine = &now_cites[i];
        let source = if !mine.iter().any(|c| c.moves) {
            None
        } else {
            from[i].or_else(|| same_line(i, &from, &old_lines, &old_cites, &key(line, mine), &mut used))
        };
        let new_line = match source {
            Some(o) => rebuild(line, mine, old_lines[o], &old_cites[o], maps, &format!("{doc}:{}", i + 1), report),
            None => {
                for c in mine.iter().filter(|c| c.moves) {
                    report.kept.push(format!("{doc}:{}: {} {}", i + 1, c.path, &line[c.range.clone()]));
                }
                line.to_string()
            }
        };
        moved |= new_line != *line;
        out.push_str(&new_line);
        out.push('\n');
    }
    moved.then_some(out)
}

/// A line of HEAD for a changed line `i`: in the block of HEAD between the
/// unchanged lines around `i`, the first unused line with the same text when
/// the numbers of the citations are set aside. Such a line is one that a
/// remap moved before; another kind of change makes it a new line.
fn same_line(
    i: usize,
    from: &[Option<usize>],
    old_lines: &[&str],
    old_cites: &[Vec<Cite>],
    want: &str,
    used: &mut HashSet<usize>,
) -> Option<usize> {
    let lo = from[..i].iter().rev().find_map(|o| *o).map_or(0, |o| o + 1);
    let hi = from[i + 1..].iter().find_map(|o| *o).unwrap_or(old_lines.len());
    let found = (lo..hi)
        .find(|&o| !used.contains(&o) && !old_cites[o].is_empty() && key(old_lines[o], &old_cites[o]) == want)?;
    used.insert(found);
    Some(found)
}

/// A line with the numbers of each citation set aside, also of the files
/// that this run does not move: an earlier run in the same change can have
/// moved those.
fn key(line: &str, cites: &[Cite]) -> String {
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    for c in cites {
        out.push_str(&line[at..c.range.start]);
        out.push('#');
        at = c.range.end;
    }
    out.push_str(&line[at..]);
    out
}

/// A line with each citation moved by its numbers in HEAD (`was`, the same
/// line in HEAD). A citation of a line that this change removed or changed
/// keeps the numbers that it has now: when they are still HEAD's, it is
/// listed for review; else a person moved it already.
fn rebuild(
    line: &str,
    mine: &[Cite],
    was: &str,
    theirs: &[Cite],
    maps: &Maps,
    at: &str,
    report: &mut Report,
) -> String {
    let mut out = String::with_capacity(line.len());
    let mut from = 0;
    for (c, h) in mine.iter().zip(theirs) {
        out.push_str(&line[from..c.range.start]);
        let now = &line[c.range.clone()];
        if !c.moves {
            out.push_str(now);
            from = c.range.end;
            continue;
        }
        let then = &was[h.range.clone()];
        match moved_range(h, maps) {
            Some((a, b)) => {
                let new = b.map_or_else(|| a.to_string(), |b| format!("{a}-{b}"));
                if new != now {
                    report.moved.push(format!("{at}: {} {now} -> {new}", c.path));
                }
                if changed_inside(h, maps) {
                    report.review.push(format!(
                        "{at}: {} {new}: moved by its ends, but a line inside it changed; read it",
                        c.path
                    ));
                }
                out.push_str(&new);
            }
            None => {
                if now == then {
                    report.review.push(format!(
                        "{at}: {} {now}: names a line that this change removed or changed; read it, and move the citation by hand",
                        c.path
                    ));
                }
                out.push_str(now);
            }
        }
        from = c.range.end;
    }
    out.push_str(&line[from..]);
    out
}

/// The new first and last line of a citation, when the lines at its ends
/// are unchanged: a range moves by its ends, also when a line inside it
/// changed (`changed_inside` lists that for review), so that it keeps naming
/// the same part of the file.
fn moved_range(c: &Cite, maps: &Maps) -> Option<(usize, Option<usize>)> {
    let map = maps.get(&c.path)?;
    let end = c.last.unwrap_or(c.first);
    if c.first == 0 || end < c.first || end > map.to.len() {
        return None;
    }
    // A range moves by its first and last lines with text, and keeps its
    // blank margins: a blank end could have matched any blank line.
    let text = |n: &usize| !map.blank[n - 1];
    let first = (c.first..=end).find(text).unwrap_or(c.first);
    let start = map.to[first - 1]?.checked_sub(first - c.first).filter(|n| *n > 0)?;
    let last = match c.last {
        Some(l) => {
            let at = (c.first..=l).rev().find(text).unwrap_or(l);
            Some(map.to[at - 1]? + (l - at))
        }
        None => None,
    };
    Some((start, last))
}

/// Whether the change removed or changed a line inside a cited range.
fn changed_inside(c: &Cite, maps: &Maps) -> bool {
    let Some(map) = maps.get(&c.path) else { return false };
    let end = c.last.unwrap_or(c.first).min(map.to.len());
    (c.first.max(1)..=end).any(|n| map.to[n - 1].is_none())
}

/// The citations on each line of a text; those of `names` move. A blank
/// line, a heading or a fence ends a paragraph, and with it the file that a
/// bare `:N` means.
fn cites(text: &str, names: &HashSet<&str>) -> Vec<Vec<Cite>> {
    let mut out = Vec::new();
    let mut context: Option<String> = None;
    for (_, line, fenced) in lines_with_fences(text) {
        let mut here = Vec::new();
        if fenced || line.trim().is_empty() || line.starts_with('#') {
            context = None;
            out.push(here);
            continue;
        }
        for (start, span) in spans(line) {
            if let Some(nums) = span.strip_prefix(':') {
                if let (Some(path), Some((first, last))) = (context.as_ref(), numbers(nums)) {
                    let moves = names.contains(path.as_str());
                    here.push(Cite { range: start + 1..start + span.len(), path: path.clone(), first, last, moves });
                }
                continue;
            }
            let Some((path, _)) = citation(span) else { continue };
            context = Some(path.to_string());
            let Some((_, nums)) = span.split_once(':') else { continue };
            if let Some((first, last)) = numbers(nums) {
                let end = start + span.len();
                let moves = names.contains(path);
                here.push(Cite { range: end - nums.len()..end, path: path.to_string(), first, last, moves });
            }
        }
        out.push(here);
    }
    out
}

/// `N` or `N-M`, digits only.
fn numbers(s: &str) -> Option<(usize, Option<usize>)> {
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    match s.split_once('-') {
        Some((a, b)) if digits(a) && digits(b) => Some((a.parse().ok()?, Some(b.parse().ok()?))),
        None if digits(s) => Some((s.parse().ok()?, None)),
        _ => None,
    }
}

/// The code spans of a line, each with the byte offset of its text.
fn spans(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(open) = line[at..].find('`') {
        let start = at + open + 1;
        let Some(close) = line[start..].find('`') else { break };
        out.push((start, &line[start..start + close]));
        at = start + close + 1;
    }
    out
}
