//! The checker of podssh's work record (`TODO/`).
//!
//! The record is the index (`TODO/INDEX.md`), the progress record with the
//! work order (`TODO/PROGRESS.md`) and the entries (`TODO/<area>.md`).
//! Closing one entry moves several numbers in two files, so no number is
//! typed by hand: the writer moves a status and derives the counts, and the
//! reader, which the gate runs, checks that the files agree. When a cited
//! file changes, `remap` moves its citations by a line diff against `HEAD`,
//! or against the revision that `--base` names.

pub mod check;
pub mod claims;
pub mod diff;
pub mod github;
pub mod interop;
pub mod model;
pub mod numbers;
pub mod parse;
pub mod prove;
pub mod refs;
pub mod remap;
pub mod write;

use std::path::{Path, PathBuf};

pub const USAGE: &str = "usage: podssh-todo check
       podssh-todo set T-NNN open|partial|blocked|done
       podssh-todo counts
       podssh-todo next
       podssh-todo remap [--dry-run] FILE...   (after an edit of FILE: move its citations by a diff against HEAD)
       podssh-todo interop [--logs LOG...]     (the ids of the interop harnesses against scripts/interop-baseline.txt,
                                                and with logs, each run's results; a log's file stem names its run)
Options: --root DIR (default: the nearest directory above the current one with TODO/INDEX.md)
         --base REV (default: HEAD): check and remap compare each file with its text in REV,
                    as HEAD~1 for a commit that was made without them";

/// The nearest directory at or above `start` that has `TODO/INDEX.md`.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find(|d| d.join("TODO").join("INDEX.md").is_file()).map(Path::to_path_buf)
}

/// Run the command line; returns the exit code (0, 1 for a disagreement, 64
/// for a usage error).
pub fn run(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let mut words: Vec<&str> = Vec::new();
    let mut root: Option<PathBuf> = None;
    let mut base: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--root" => match it.next() {
                Some(d) => root = Some(PathBuf::from(d)),
                None => return usage(err, "--root needs a directory"),
            },
            // A revision that starts with `-` would reach git as an option.
            "--base" => match it.next() {
                Some(r) if !r.is_empty() && !r.starts_with('-') => base = Some(r.as_str()),
                _ => return usage(err, "--base needs a revision, as HEAD~1"),
            },
            "-h" | "--help" => {
                let _ = writeln!(out, "{USAGE}");
                return 0;
            }
            w => words.push(w),
        }
    }
    let root = match root.or_else(|| std::env::current_dir().ok().and_then(|d| find_root(&d))) {
        Some(r) => r,
        None => return usage(err, "no TODO/INDEX.md here or above; give --root"),
    };
    match words.as_slice() {
        ["check"] => report(&root, base, out, err),
        ["set", id, status] => match write::set_status(&root, id, status) {
            Ok(()) => report(&root, base, out, err),
            Err(e) => {
                let _ = writeln!(err, "podssh-todo: {e}");
                1
            }
        },
        ["counts"] => match write::counts(&root) {
            Ok(()) => report(&root, base, out, err),
            Err(e) => {
                let _ = writeln!(err, "podssh-todo: {e}");
                1
            }
        },
        ["next"] => match write::next_id(&root) {
            Ok(id) => {
                let _ = writeln!(out, "{id}");
                0
            }
            Err(e) => {
                let _ = writeln!(err, "podssh-todo: {e}");
                1
            }
        },
        ["remap", rest @ ..] => {
            let dry = rest.iter().any(|w| *w == "--dry-run" || *w == "-n");
            let files: Vec<String> = rest.iter().filter(|w| !w.starts_with('-')).map(|w| w.to_string()).collect();
            if files.is_empty() || rest.iter().any(|w| w.starts_with('-') && *w != "--dry-run" && *w != "-n") {
                return usage(err, "remap needs one FILE or more, and takes only --dry-run");
            }
            remap_command(&root, &files, dry, base, out, err)
        }
        ["interop"] => interop_command(&root, &[], out, err),
        ["interop", "--logs", logs @ ..] if !logs.is_empty() => interop_command(&root, logs, out, err),
        ["interop", ..] => usage(err, "interop takes only --logs LOG..."),
        _ => usage(err, "unknown command"),
    }
}

/// Move the citations of `files`, print what moved and what a person must
/// read, then check the record (unless nothing was written).
fn remap_command(
    root: &Path,
    files: &[String],
    dry: bool,
    base: Option<&str>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> i32 {
    let rev = base.unwrap_or("HEAD");
    let head = |rel: &str| remap::git_at(root, rev, rel);
    let r = match remap::remap(root, files, &head, !dry) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "podssh-todo: remap: {e}");
            return 1;
        }
    };
    for line in &r.notes {
        let _ = writeln!(out, "note: {line}");
    }
    for line in &r.moved {
        let _ = writeln!(out, "moved: {line}");
    }
    for line in &r.kept {
        let _ = writeln!(out, "kept (new in this change): {line}");
    }
    for line in &r.review {
        let _ = writeln!(out, "REVIEW: {line}");
    }
    let verb = if dry { "would move" } else { "moved" };
    let _ = writeln!(
        out,
        "podssh-todo: remap: {verb} {} citations; {} to review; {} on new lines kept",
        r.moved.len(),
        r.review.len(),
        r.kept.len()
    );
    if dry {
        0
    } else {
        report(root, base, out, err)
    }
}

/// Check the interop harnesses against their baseline, and score the logs
/// named, each a run named by its file's stem (T-199).
fn interop_command(root: &Path, logs: &[&str], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let checked = interop::check(root);
    let mut problems = checked.problems;
    if !logs.is_empty() {
        let mut runs = Vec::new();
        for log in logs {
            let path = Path::new(log);
            let run = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
            match std::fs::read_to_string(path) {
                Ok(text) => runs.push(interop::Log { shown: log.to_string(), run, text }),
                Err(e) => problems.push(model::Problem::new(log, 0, format!("cannot be read: {e}"))),
            }
        }
        let (rows, more) = interop::score(&checked.baseline, &runs);
        let _ = writeln!(out, "score harness pass fail env skip missing floor");
        for row in rows {
            let _ = writeln!(out, "{row}");
        }
        problems.extend(more);
    }
    if problems.is_empty() {
        let harnesses = checked.baseline.harnesses.len();
        let _ = writeln!(
            out,
            "podssh-todo: interop: {} ids of {harnesses} harnesses meet {}",
            checked.ids,
            interop::BASELINE
        );
        0
    } else {
        for p in &problems {
            let _ = writeln!(err, "{p}");
        }
        let _ = writeln!(err, "podssh-todo: {} problems in the interop checks", problems.len());
        1
    }
}

fn usage(err: &mut dyn std::io::Write, why: &str) -> i32 {
    let _ = writeln!(err, "podssh-todo: {why}\n{USAGE}");
    64
}

/// Run the reader and print what it found.
fn report(root: &Path, base: Option<&str>, out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let r = check::check(root, base);
    if r.problems.is_empty() {
        let _ = writeln!(out, "podssh-todo: the record agrees: {}", r.counts.phrase());
        0
    } else {
        for p in &r.problems {
            let _ = writeln!(err, "{p}");
        }
        let _ = writeln!(err, "podssh-todo: {} problems in the record", r.problems.len());
        1
    }
}
