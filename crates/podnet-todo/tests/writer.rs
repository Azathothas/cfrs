//! The writer moves a status in the entry and its row, derives each count
//! again, and refuses a status that the entry cannot support yet. After each
//! move, the reader finds no problem.

mod common;

use common::Tree;

fn run(t: &Tree, args: &[&str]) -> (i32, String, String) {
    let mut a: Vec<String> = vec!["--root".into(), t.path().display().to_string()];
    a.extend(args.iter().map(|s| s.to_string()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = podssh_todo::run(&a, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn a_status_moves_in_the_entry_the_row_and_every_count() {
    let t = Tree::new("w-partial");
    let (code, out, err) = run(&t, &["set", "T-001", "partial"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(t.read("TODO/area.md").contains("**Status:** partial"));
    let index = t.read("TODO/INDEX.md");
    assert!(index.contains("| [T-001](area.md) | P1 | S | M3 | defect | partial | The first entry |"));
    assert!(index.contains("**3 entries: 0 open, 1 partial, 1 blocked, 1 done.**"));
    assert!(index.contains("| P1 | 0 | 1 | 0 | 1 | 2 |"));
    assert!(index.contains("| **All** | 0 | 1 | 1 | 1 | 3 |"));
    assert!(t.read("TODO/PROGRESS.md").contains("holds 3 entries: 0 open, 1 partial, 1 blocked, 1 done."));
    assert_eq!(t.problems(), Vec::<String>::new());
    assert!(out.contains("the record agrees: 3 entries: 0 open, 1 partial, 1 blocked, 1 done."), "{out}");
}

#[test]
fn done_needs_the_evidence_first() {
    let t = Tree::new("w-done");
    let (code, _, err) = run(&t, &["set", "T-001", "done"]);
    assert_eq!(code, 1);
    assert!(err.contains("write the evidence first"), "{err}");
    assert!(t.read("TODO/area.md").contains("**Status:** open"), "nothing was written");
}

#[test]
fn blocked_needs_the_blocker_first() {
    let t = Tree::new("w-blocked");
    let (code, _, err) = run(&t, &["set", "T-001", "blocked"]);
    assert_eq!(code, 1);
    assert!(err.contains("write what blocks it first"), "{err}");
}

#[test]
fn an_unknown_id_or_status_is_refused() {
    let t = Tree::new("w-unknown");
    assert_eq!(run(&t, &["set", "T-077", "done"]).0, 1);
    assert_eq!(run(&t, &["set", "T-001", "finished"]).0, 1);
    assert_eq!(run(&t, &["set", "T-001"]).0, 64);
    assert_eq!(run(&t, &["frobnicate"]).0, 64);
}

#[test]
fn counts_are_derived_after_a_row_is_added_by_hand() {
    let t = Tree::new("w-counts");
    let area = t.read("TODO/area.md");
    let first = area.split("# T-002").next().unwrap().split("# T-001").nth(1).unwrap();
    t.write("TODO/more.md", &format!("More.\n\n# T-004{}", first.replace(": The first entry", ": A fourth entry")));
    t.plant(
        "TODO/INDEX.md",
        "| [T-003](area.md) | P1 | S | M3 | defect | done | The third entry |",
        "| [T-003](area.md) | P1 | S | M3 | defect | done | The third entry |\n| [T-004](more.md) | P1 | S | M3 | defect | open | A fourth entry |",
    );
    assert!(!t.problems().is_empty(), "the counts are stale before `counts`");
    let (code, out, err) = run(&t, &["counts"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(t.read("TODO/INDEX.md").contains("**4 entries: 2 open, 0 partial, 1 blocked, 1 done.**"));
    assert_eq!(run(&t, &["next"]).1.trim(), "T-005");
}

#[test]
fn the_check_command_exits_one_on_a_disagreement() {
    let t = Tree::new("w-check");
    assert_eq!(run(&t, &["check"]).0, 0);
    t.plant("TODO/area.md", "**Status:** open", "**Status:** done");
    let (code, _, err) = run(&t, &["check"]);
    assert_eq!(code, 1);
    assert!(err.contains("problems in the record"), "{err}");
}

#[test]
fn crlf_files_keep_their_line_endings() {
    let t = Tree::new("w-crlf");
    t.write("TODO/area.md", &common::AREA.replace('\n', "\r\n"));
    let (code, out, err) = run(&t, &["set", "T-001", "partial"]);
    assert_eq!(code, 0, "{out}{err}");
    let bytes = std::fs::read(t.path().join("TODO/area.md")).unwrap();
    assert!(bytes.windows(2).filter(|w| w == b"\r\n").count() > 50);
    assert!(!String::from_utf8(bytes).unwrap().replace("\r\n", "").contains('\n'), "a bare LF crept in");
}
