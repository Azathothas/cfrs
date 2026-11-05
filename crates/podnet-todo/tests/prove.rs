//! The targets of a done Prove (T-361): a test target or a script that the
//! tree does not hold is named, with the entry and the line, unless the
//! entry's Correction names it; and `set` refuses to close an entry whose
//! Prove names one.

mod common;

use common::Tree;

fn names(t: &Tree, says: &str) -> bool {
    t.problems().iter().any(|p| p.contains(says))
}

#[test]
fn the_control_and_a_test_target_that_exists_pass() {
    let t = Tree::new("prove-control");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
    t.plant("TODO/area.md", "`cargo test -p x -- third`\n\n## Done", "`cargo test -p x --test third`\n\n## Done");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
}

#[test]
fn a_test_target_that_does_not_exist_is_named_with_its_entry_and_line() {
    let t = Tree::new("prove-target");
    t.plant("TODO/area.md", "`cargo test -p x -- third`\n\n## Done", "`cargo test -p x --test gone`\n\n## Done");
    let found = t.problems();
    assert!(
        found.iter().any(|p| p.starts_with("TODO/area.md:84: T-003: its Prove names the test target gone")),
        "{found:#?}"
    );
}

#[test]
fn a_script_that_does_not_exist_is_named() {
    let t = Tree::new("prove-script");
    t.plant("TODO/area.md", "`cargo test -p x -- third`\n\n## Done", "`sh scripts/check.sh`\n\n## Done");
    assert!(names(&t, "T-003: its Prove names scripts/check.sh, which does not exist"), "{:#?}", t.problems());
    t.write("scripts/check.sh", "true\n");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
}

#[test]
fn a_target_that_the_correction_names_is_taken() {
    let t = Tree::new("prove-correction");
    t.plant(
        "TODO/area.md",
        "`cargo test -p x -- third`\n\n## Done",
        "`cargo test -p y --test gone`\n\n## Correction\n\n2026-10-31: `y` and its `gone` moved into `x`.\n\n## Done",
    );
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
}

#[test]
fn set_refuses_to_close_an_entry_whose_prove_names_a_missing_target() {
    let t = Tree::new("prove-set");
    t.plant("TODO/area.md", "\ncargo test -p x\n", "\ncargo test -p x --test gone\n");
    t.plant("TODO/area.md", "```\n\n# T-002", "```\n\n## Done\n\n2026-10-31: planted.\n\n# T-002");
    let refused =
        podssh_todo::write::set_status(t.path(), "T-001", "done").expect_err("a Prove that names a missing target");
    assert!(refused.contains("T-001: its Prove names the test target gone"), "{refused}");
    t.plant("TODO/area.md", "\ncargo test -p x --test gone\n", "\ncargo test -p x --test third\n");
    podssh_todo::write::set_status(t.path(), "T-001", "done").expect("a Prove whose targets exist");
}
