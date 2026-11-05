//! The writer: it moves the status of an entry in the entry and in its row,
//! then derives each count from the rows again. No count is ever typed by
//! hand. The reader then checks the result on its own.

use std::fs;
use std::path::Path;

use crate::check::{read, INDEX, PROGRESS};
use crate::model::{Counts, Row, PRIORITIES, STATUSES};
use crate::parse;

/// Write a text back with the line endings that the file had.
fn write_like(root: &Path, rel: &str, text: &str) -> Result<(), String> {
    let path = root.join(rel);
    let crlf = fs::read(&path).map(|b| b.windows(2).any(|w| w == b"\r\n")).unwrap_or(false);
    let out = if crlf { text.replace('\n', "\r\n") } else { text.to_string() };
    fs::write(&path, out).map_err(|e| format!("{rel}: {e}"))
}

/// Replace the value of one header field of one entry in an area file.
fn set_field(text: &str, id: &str, field: &str, value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut in_entry = false;
    let mut done = false;
    for (_, line, fenced) in parse::lines_with_fences(text) {
        if !fenced && line.starts_with("# ") {
            in_entry = line[2..].split_once(": ").is_some_and(|(i, _)| i == id);
        }
        let prefix = format!("**{field}:**");
        if in_entry && !done && !fenced && line.starts_with(&prefix) {
            out.push_str(&format!("{prefix} {value}"));
            done = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if done {
        Ok(out)
    } else {
        Err(format!("{id} has no **{field}:** line"))
    }
}

/// Rewrite the counts phrase, the counts table and the progress line from
/// the rows. Returns the new index and progress texts.
pub fn recount(index: &str, progress: &str, rows: &[Row]) -> (String, String) {
    let all = Counts::of(rows, None);
    let fix_phrase = |text: &str| -> String {
        let mut done = false;
        let mut out = String::with_capacity(text.len());
        for (_, line, fenced) in parse::lines_with_fences(text) {
            match (!fenced && !done).then(|| parse::counts_phrase(line)).flatten() {
                Some((_, _, range)) => {
                    out.push_str(&line[..range.start]);
                    out.push_str(&all.phrase());
                    out.push_str(&line[range.end..]);
                    done = true;
                }
                None => out.push_str(line),
            }
            out.push('\n');
        }
        out
    };
    let mut new_index = String::with_capacity(index.len());
    for (_, line, fenced) in parse::lines_with_fences(&fix_phrase(index)) {
        match (!fenced).then(|| parse::counts_row(line)).flatten() {
            Some((label, ..)) if PRIORITIES.contains(&label.as_str()) => {
                new_index.push_str(&Counts::of(rows, Some(&label)).table_row(&label))
            }
            Some((label, ..)) if label == "All" => new_index.push_str(&all.table_row("**All**")),
            _ => new_index.push_str(line),
        }
        new_index.push('\n');
    }
    (new_index, fix_phrase(progress))
}

/// Move the status of `id` to `status`, in its entry and its row, and derive
/// the counts again. `done` needs the evidence first, and `blocked` the
/// blocker: the writer refuses a status that the entry cannot support.
pub fn set_status(root: &Path, id: &str, status: &str) -> Result<(), String> {
    if !STATUSES.contains(&status) {
        return Err(format!("`{status}` is not a status; use one of {}", STATUSES.join(", ")));
    }
    let index = read(root, INDEX).ok_or("TODO/INDEX.md is missing")?;
    let progress = read(root, PROGRESS).ok_or("TODO/PROGRESS.md is missing")?;
    let (mut rows, problems) = parse::rows(INDEX, &index);
    if let Some(p) = problems.first() {
        return Err(format!("the index must be read first: {p}"));
    }
    let row = rows.iter_mut().find(|r| r.id == id).ok_or(format!("{id} has no row in the index"))?;
    let area = format!("TODO/{}", row.file);
    let text = read(root, &area).ok_or(format!("{area} is missing"))?;
    let (entries, _) = parse::entries(&area, &text);
    let entry = entries.iter().find(|e| e.id == id).ok_or(format!("{id} is not an entry of {area}"))?;
    match status {
        "done" if !entry.section("Done").is_some_and(|d| crate::check::has_date(&d.body)) => {
            return Err(format!("{id}: write the evidence first, in `## Done` with its date"))
        }
        // A Prove that names what the tree does not hold did not run (T-361).
        "done" => {
            let packages = crate::prove::Packages::of(root);
            if let Some((_, what)) = crate::check::prove_gaps(root, &packages, entry).into_iter().next() {
                return Err(format!("{id}: {what}"));
            }
        }
        "blocked" if entry.section("Blocker").is_none() => {
            return Err(format!("{id}: write what blocks it first, in `## Blocker`"))
        }
        s if s != "blocked" && entry.section("Blocker").is_some() => {
            return Err(format!("{id}: the entry still has `## Blocker`; record how it cleared, then remove it"))
        }
        s if !matches!(s, "done" | "partial") && entry.section("Done").is_some() => {
            return Err(format!("{id}: the entry has `## Done`; move that text to `## Correction` to open it again"))
        }
        _ => {}
    }
    let old_line = index.lines().nth(row.line - 1).unwrap_or_default().to_string();
    let mut cells = parse::cells(&old_line);
    cells[5] = status.to_string();
    let new_line = format!("| {} |", cells.join(" | "));
    row.status = status.to_string();

    let new_area = set_field(&text, id, "Status", status)?;
    let index_with_row: String = index
        .lines()
        .enumerate()
        .map(|(i, l)| if i + 1 == row.line { new_line.clone() } else { l.to_string() })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let (new_index, new_progress) = recount(&index_with_row, &progress, &rows);
    write_like(root, &area, &new_area)?;
    write_like(root, INDEX, &new_index)?;
    write_like(root, PROGRESS, &new_progress)
}

/// Derive the counts again after rows were added or removed by hand.
pub fn counts(root: &Path) -> Result<(), String> {
    let index = read(root, INDEX).ok_or("TODO/INDEX.md is missing")?;
    let progress = read(root, PROGRESS).ok_or("TODO/PROGRESS.md is missing")?;
    let (rows, problems) = parse::rows(INDEX, &index);
    if let Some(p) = problems.first() {
        return Err(format!("the index must be read first: {p}"));
    }
    let (new_index, new_progress) = recount(&index, &progress, &rows);
    write_like(root, INDEX, &new_index)?;
    write_like(root, PROGRESS, &new_progress)
}

/// The next free id.
pub fn next_id(root: &Path) -> Result<String, String> {
    let index = read(root, INDEX).ok_or("TODO/INDEX.md is missing")?;
    let (rows, _) = parse::rows(INDEX, &index);
    let max = rows.iter().map(|r| crate::model::id_number(&r.id)).max().unwrap_or(0);
    Ok(format!("T-{:03}", max + 1))
}
