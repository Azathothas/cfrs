//! The reader: it reads the index, each entry and the progress record, and
//! asserts that they agree. It derives each count from the rows and trusts
//! no number that a file states.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::model::{
    Counts, Entry, Problem, Row, CATEGORIES, EFFORTS, FIELDS, MILESTONES, PRIORITIES, RECORD_FILES, REQUIRED_SECTIONS,
    SECTIONS, STATUSES,
};
use crate::parse;

pub const INDEX: &str = "TODO/INDEX.md";
pub const PROGRESS: &str = "TODO/PROGRESS.md";

/// What the reader found, and the counts that the rows give.
pub struct Report {
    pub problems: Vec<Problem>,
    pub counts: Counts,
}

/// The record as files: the rows of the index and the entries of each area.
pub struct Record {
    pub rows: Vec<Row>,
    pub entries: Vec<Entry>,
    pub index: String,
    pub progress: String,
}

/// Read a file of the tree as text, with `\r\n` read as `\n`.
pub fn read(root: &Path, rel: &str) -> Option<String> {
    fs::read_to_string(root.join(rel)).ok().map(|t| t.replace("\r\n", "\n"))
}

/// The area files of `TODO/`: each Markdown file that is not a record file.
pub fn area_files(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(root.join("TODO"))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".md") && !RECORD_FILES.contains(&n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Load the record. Problems of form go to `problems`.
pub fn load(root: &Path, problems: &mut Vec<Problem>) -> Option<Record> {
    let Some(index) = read(root, INDEX) else {
        problems.push(Problem::new(INDEX, 0, "the index is missing"));
        return None;
    };
    let progress = read(root, PROGRESS).unwrap_or_else(|| {
        problems.push(Problem::new(PROGRESS, 0, "the progress record is missing"));
        String::new()
    });
    let (rows, mut p) = parse::rows(INDEX, &index);
    problems.append(&mut p);
    let mut entries = Vec::new();
    for name in area_files(root) {
        let rel = format!("TODO/{name}");
        let text = read(root, &rel).unwrap_or_default();
        let (mut e, mut p) = parse::entries(&rel, &text);
        for entry in &mut e {
            entry.file = name.clone();
        }
        entries.append(&mut e);
        problems.append(&mut p);
    }
    Some(Record { rows, entries, index, progress })
}

/// Run every check of the reader on the tree at `root`, and, when git can
/// say which files changed since the base, the check that no citation of
/// them was left behind by a forgotten `remap`. The base is `HEAD`, or the
/// revision that `base` names: `HEAD~1` checks a commit that was made
/// without the check, as CI does. A base that is named and that git cannot
/// read is a problem: the check that it asks for did not run.
pub fn check(root: &Path, base: Option<&str>) -> Report {
    let rev = base.unwrap_or("HEAD");
    let head = |rel: &str| crate::remap::git_at(root, rev, rel);
    let changed = crate::remap::changed_since(root, rev);
    let unread = base.is_some() && changed.is_none();
    let mut report = check_with(root, changed, &head, rev);
    if unread {
        report.problems.push(Problem::new(
            "--base",
            0,
            format!(
                "git cannot compare the tree with `{rev}` here, so no citation that a change left behind can be found"
            ),
        ));
    }
    report
}

/// [`check`], given the files changed since the base `rev` (`None`:
/// unknown) and their texts in it, so a test needs no git.
pub fn check_with(root: &Path, changed: Option<Vec<String>>, head: &crate::remap::Head, rev: &str) -> Report {
    let mut problems = Vec::new();
    let Some(record) = load(root, &mut problems) else {
        return Report { problems, counts: Counts::default() };
    };
    if record.rows.is_empty() {
        problems.push(Problem::new(INDEX, 0, "the index has no rows"));
    }
    check_rows(&record.rows, &mut problems);
    check_agreement(&record.rows, &record.entries, &mut problems);
    for e in &record.entries {
        check_entry(e, &mut problems);
    }
    check_counts(&record, &mut problems);
    crate::refs::check(root, &record, &mut problems);
    // GitHub's numbers in the map (T-360).
    crate::github::check(root, &mut problems);
    // The claims of "yet", and a status beside an id (T-362).
    let status: std::collections::HashMap<&str, &str> =
        record.rows.iter().map(|r| (r.id.as_str(), r.status.as_str())).collect();
    crate::claims::check(root, &status, &mut problems);
    check_proves(root, &record.entries, &mut problems);
    if let Some(files) = changed.filter(|f| !f.is_empty()) {
        unmoved(root, &files, head, rev, &mut problems);
    }
    Report { problems, counts: Counts::of(&record.rows, None) }
}

/// A citation of a file that changed since the base `rev` which a remap
/// would still move: the file was edited and its citations were not moved,
/// so they name other lines now. The check of a cited line cannot see this,
/// because the line still exists. A citation that a person must read is not
/// counted: only `remap` decides those, and it lists them. A remap that
/// fails is a problem, not a pass.
fn unmoved(root: &Path, files: &[String], head: &crate::remap::Head, rev: &str, p: &mut Vec<Problem>) {
    let r = match crate::remap::remap(root, files, head, false) {
        Ok(r) => r,
        Err(e) => {
            p.push(Problem::new(
                "remap",
                0,
                format!("the check of the citations of the files changed since {rev} could not run: {e}"),
            ));
            return;
        }
    };
    let command = if rev == "HEAD" { "cargo todo remap".to_string() } else { format!("cargo todo remap --base {rev}") };
    for moved in r.moved {
        let Some((at, rest)) = moved.split_once(": ") else { continue };
        let path = rest.split(' ').next().unwrap_or(rest);
        p.push(Problem {
            at: at.to_string(),
            what: format!("cites {rest}, as {path} changed since {rev}: run `{command} {path}`"),
        });
    }
}

fn check_rows(rows: &[Row], p: &mut Vec<Problem>) {
    let allowed = |what: &str, value: &str, set: &[&str], line: usize, p: &mut Vec<Problem>| {
        if !set.contains(&value) {
            p.push(Problem::new(INDEX, line, format!("{what} `{value}` is not one of {}", set.join(", "))));
        }
    };
    let mut last = 0;
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for r in rows {
        if !crate::model::is_id(&r.id) {
            p.push(Problem::new(INDEX, r.line, format!("`{}` is not an id (T-NNN)", r.id)));
        }
        if let Some(first) = seen.insert(&r.id, r.line) {
            p.push(Problem::new(INDEX, r.line, format!("{} has a row already, on line {first}", r.id)));
        }
        let n = crate::model::id_number(&r.id);
        if n <= last {
            p.push(Problem::new(INDEX, r.line, format!("{} is out of order: the rows are sorted by id", r.id)));
        }
        last = last.max(n);
        allowed("the priority", &r.priority, &PRIORITIES, r.line, p);
        allowed("the effort", &r.effort, &EFFORTS, r.line, p);
        allowed("the milestone", &r.milestone, &MILESTONES, r.line, p);
        allowed("the category", &r.category, &CATEGORIES, r.line, p);
        allowed("the status", &r.status, &STATUSES, r.line, p);
        if RECORD_FILES.contains(&r.file.as_str()) || r.file.contains('/') || !r.file.ends_with(".md") {
            p.push(Problem::new(
                INDEX,
                r.line,
                format!("{} links `{}`, which is not an area file of TODO/", r.id, r.file),
            ));
        }
        if r.title.is_empty() {
            p.push(Problem::new(INDEX, r.line, format!("{} has no title", r.id)));
        }
    }
}

/// Each row names an entry in the file it links, with the same fields; each
/// entry has a row; no id is used twice.
fn check_agreement(rows: &[Row], entries: &[Entry], p: &mut Vec<Problem>) {
    let mut by_id: HashMap<&str, &Entry> = HashMap::new();
    for e in entries {
        if let Some(first) = by_id.insert(&e.id, e) {
            p.push(Problem::new(
                &format!("TODO/{}", e.file),
                e.line,
                format!("{} is also an entry in TODO/{}:{}", e.id, first.file, first.line),
            ));
        }
    }
    for r in rows {
        let Some(e) = by_id.get(r.id.as_str()) else {
            p.push(Problem::new(INDEX, r.line, format!("{} has a row and no entry in TODO/{}", r.id, r.file)));
            continue;
        };
        let at = format!("TODO/{}", e.file);
        if e.file != r.file {
            p.push(Problem::new(
                &at,
                e.line,
                format!("{} is in TODO/{}, but its row links TODO/{}", r.id, e.file, r.file),
            ));
        }
        if e.title != r.title {
            p.push(Problem::new(&at, e.line, format!("{}: the title differs from the row's: \"{}\"", r.id, r.title)));
        }
        for (name, want) in [
            ("Priority", &r.priority),
            ("Effort", &r.effort),
            ("Milestone", &r.milestone),
            ("Category", &r.category),
            ("Status", &r.status),
        ] {
            if let Some(have) = e.field(name) {
                if have != want {
                    p.push(Problem::new(
                        &at,
                        e.line,
                        format!("{}: the entry says {name} {have}, the index says {want}", r.id),
                    ));
                }
            }
        }
    }
    let with_row: std::collections::HashSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    for e in entries {
        if !with_row.contains(e.id.as_str()) {
            p.push(Problem::new(&format!("TODO/{}", e.file), e.line, format!("{} has no row in the index", e.id)));
        }
    }
}

/// The targets of each done Prove (T-361): what it names must exist, but a
/// target that its Correction names, which moved since the entry closed.
fn check_proves(root: &Path, entries: &[Entry], p: &mut Vec<Problem>) {
    let packages = crate::prove::Packages::of(root);
    for e in entries.iter().filter(|e| e.field("Status") == Some("done")) {
        for (line, what) in prove_gaps(root, &packages, e) {
            p.push(Problem::new(&format!("TODO/{}", e.file), line, format!("{}: {what}", e.id)));
        }
    }
}

/// What the Prove of `e` names and the tree does not hold, each with its
/// line and its words.
pub fn prove_gaps(root: &Path, packages: &crate::prove::Packages, e: &Entry) -> Vec<(usize, String)> {
    let Some(prove) = e.section("Prove") else { return Vec::new() };
    let correction = e.section("Correction").map(|c| c.body.as_str()).unwrap_or("");
    crate::prove::missing(root, packages, &prove.body, prove.line, correction)
        .into_iter()
        .map(|(line, what)| (line, format!("its Prove names {what}; a target that moved is named in `## Correction`")))
        .collect()
}

/// The form of one entry: its fields, its sections, and what its status
/// requires.
fn check_entry(e: &Entry, p: &mut Vec<Problem>) {
    let at = format!("TODO/{}", e.file);
    for name in FIELDS {
        match e.fields.iter().filter(|f| f.name == name).count() {
            0 => p.push(Problem::new(&at, e.line, format!("{}: the field {name} is missing", e.id))),
            1 => {}
            _ => p.push(Problem::new(&at, e.line, format!("{}: the field {name} is given more than once", e.id))),
        }
    }
    for f in &e.fields {
        let set: &[&str] = match f.name.as_str() {
            "Category" => &CATEGORIES,
            "Milestone" => &MILESTONES,
            "Priority" => &PRIORITIES,
            "Effort" => &EFFORTS,
            "Status" => &STATUSES,
            _ => continue,
        };
        if !set.contains(&f.value.as_str()) {
            p.push(Problem::new(
                &at,
                f.line,
                format!("{}: {} `{}` is not one of {}", e.id, f.name, f.value, set.join(", ")),
            ));
        }
    }
    if e.field("Source").is_some_and(str::is_empty) {
        p.push(Problem::new(&at, e.line, format!("{}: the source is empty", e.id)));
    }
    let mut last = None;
    for s in &e.sections {
        let Some(pos) = SECTIONS.iter().position(|n| *n == s.name) else {
            p.push(Problem::new(&at, s.line, format!("{}: `## {}` is not a section of an entry", e.id, s.name)));
            continue;
        };
        if last.is_some_and(|l| pos <= l) {
            p.push(Problem::new(&at, s.line, format!("{}: `## {}` is out of order or repeated", e.id, s.name)));
        }
        last = Some(pos);
        if s.body.trim().is_empty() {
            p.push(Problem::new(&at, s.line, format!("{}: `## {}` is empty", e.id, s.name)));
        }
    }
    for name in REQUIRED_SECTIONS {
        if e.section(name).is_none() {
            p.push(Problem::new(&at, e.line, format!("{}: the section `## {name}` is missing", e.id)));
        }
    }
    if let Some(prove) = e.section("Prove") {
        if !prove.body.contains('`') {
            p.push(Problem::new(&at, prove.line, format!("{}: a Prove with no command is a paragraph", e.id)));
        }
    }
    let status = e.field("Status").unwrap_or("");
    match (status, e.section("Blocker")) {
        ("blocked", None) => p.push(Problem::new(&at, e.line, format!("{}: blocked, with no `## Blocker`", e.id))),
        (s, Some(b)) if s != "blocked" => {
            p.push(Problem::new(&at, b.line, format!("{}: a `## Blocker` on an entry that is {s}", e.id)))
        }
        _ => {}
    }
    match (status, e.section("Done")) {
        ("done", None) => p.push(Problem::new(&at, e.line, format!("{}: done, with no `## Done` evidence", e.id))),
        ("done" | "partial", Some(d)) if !has_date(&d.body) => {
            p.push(Problem::new(&at, d.line, format!("{}: `## Done` gives no date (YYYY-MM-DD)", e.id)))
        }
        ("open" | "blocked", Some(d)) => {
            p.push(Problem::new(&at, d.line, format!("{}: a `## Done` on an entry that is {status}", e.id)))
        }
        _ => {}
    }
}

/// True when a text holds a date of the form YYYY-MM-DD.
pub fn has_date(text: &str) -> bool {
    let b = text.as_bytes();
    (0..b.len().saturating_sub(9)).any(|i| {
        let d = |k: usize| b[i + k].is_ascii_digit();
        d(0) && d(1) && d(2) && d(3) && b[i + 4] == b'-' && d(5) && d(6) && b[i + 7] == b'-' && d(8) && d(9)
    })
}

/// The counts that the index and the progress record state, against the rows.
fn check_counts(r: &Record, p: &mut Vec<Problem>) {
    let all = Counts::of(&r.rows, None);
    match parse::find_counts(&r.index) {
        Some((line, total, c)) if total != all.total() || c != all => p.push(Problem::new(
            INDEX,
            line,
            format!("the counts line says {total} entries ({c:?}); the rows give {}", all.phrase()),
        )),
        Some(_) => {}
        None => p.push(Problem::new(INDEX, 0, format!("no counts line; it reads: {}", all.phrase()))),
    }
    for label in PRIORITIES.iter().copied().chain(["All"]) {
        let want = Counts::of(&r.rows, (label != "All").then_some(label));
        let found = parse::lines_with_fences(&r.index).into_iter().find_map(|(no, line, fenced)| {
            (!fenced).then(|| parse::counts_row(line)).flatten().filter(|(l, ..)| l == label).map(|x| (no, x))
        });
        match found {
            Some((no, (_, c, total))) if c != want || total != want.total() => p.push(Problem::new(
                INDEX,
                no,
                format!(
                    "the {label} row of the counts table disagrees with the rows; it reads: {}",
                    want.table_row(label)
                ),
            )),
            Some(_) => {}
            None => p.push(Problem::new(INDEX, 0, format!("the counts table has no {label} row"))),
        }
    }
    match parse::find_counts(&r.progress) {
        Some((line, total, c)) if total != all.total() || c != all => p.push(Problem::new(
            PROGRESS,
            line,
            format!("the counts line says {total} entries ({c:?}); the rows give {}", all.phrase()),
        )),
        Some(_) => {}
        None => p.push(Problem::new(PROGRESS, 0, format!("no counts line; it reads: {}", all.phrase()))),
    }
}
