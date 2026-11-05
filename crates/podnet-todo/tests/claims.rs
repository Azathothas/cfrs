//! The claims of the documents (T-362), on the checker's own tree: a "yet"
//! with no entry that is not done and no date, a "yet" beside a done entry,
//! and a status beside an id that the index does not give, are each named
//! with their line; each passes once its entry, its date or its status is
//! right.

mod common;

use common::Tree;

fn names(t: &Tree, says: &str) -> bool {
    t.problems().iter().any(|p| p.contains(says))
}

#[test]
fn the_control_has_no_claim() {
    let t = Tree::new("claims-control");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
}

#[test]
fn a_yet_with_no_entry_or_date_is_named_with_its_line() {
    let t = Tree::new("claims-yet");
    t.write("docs/design.md", "# Design\n\nReverse mode does not exist yet.\n");
    let found = t.problems();
    assert!(found.iter().any(|p| p.starts_with("docs/design.md:3: \"yet\" with no entry")), "{found:#?}");
    t.write("docs/design.md", "# Design\n\nReverse mode does not exist yet (T-001).\n");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
    t.write("docs/design.md", "# Design\n\nOn 2026-10-08 reverse mode did not exist yet.\n");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
}

#[test]
fn a_yet_beside_a_done_entry_is_named() {
    let t = Tree::new("claims-done");
    t.write("docs/irc.md", "# IRC\n\nNo command uses the IRC client yet (T-003).\n");
    assert!(names(&t, "docs/irc.md:3: \"yet\" beside T-003, done"), "{:#?}", t.problems());
}

#[test]
fn a_status_beside_an_id_agrees_with_the_index() {
    let t = Tree::new("claims-status");
    t.write("docs/status.md", "# Status\n\nOver IRC too (T-003, partial).\n");
    assert!(names(&t, "docs/status.md:3: T-003, partial: the index says done"), "{:#?}", t.problems());
    t.write("docs/status.md", "# Status\n\nOver IRC too (T-003, done).\n");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
    t.write("docs/status.md", "# Status\n\nOn 2026-10-10, over IRC too (T-003, partial).\n");
    assert!(t.problems().is_empty(), "{:#?}", t.problems());
}
