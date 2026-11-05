//! The check of GitHub's numbers in the map (podssh T-360): the record's own
//! `TODO/issues.md` and `TODO/github.txt` agree, and each disagreement that
//! is planted into a small list and map is named.

use std::path::Path;

use podnet_todo::github::{agree, read_list, read_map};

fn record(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../TODO")
        .join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A list and a map that agree: two closed issues, an open one, a deleted
/// one, and three pull requests.
const LIST: &str = "# The numbers.
68 issue closed
69 issue open
70 issue closed
71 issue deleted
76 pull closed
77 pull open
78 pull closed
";

const MAP: &str = "# Issues

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #68 | a | closed (`0000000`) | T-001 |
| #69 | b | open | T-002 |
| #70 | c | closed | T-003 |
| #71 | d | deleted (closed before) | T-003 |

#76 to #78 are pull requests; none maps to an entry.
";

fn problems(list: &str, map: &str) -> Vec<String> {
    let mut p = Vec::new();
    let list = read_list(list, &mut p);
    agree(&list, &read_map(map), &mut p);
    p.iter().map(ToString::to_string).collect()
}

fn names(found: &[String], says: &str) -> bool {
    found.iter().any(|p| p.contains(says))
}

#[test]
fn the_record_s_map_agrees_with_its_list() {
    let found = problems(&record("github.txt"), &record("issues.md"));
    assert!(found.is_empty(), "{found:#?}");
}

/// A list with no open issue would make the check of the record a check of
/// nothing: the deferred issues are open.
#[test]
fn the_record_s_list_has_an_open_issue() {
    let mut p = Vec::new();
    let numbers = read_list(&record("github.txt"), &mut p);
    assert!(p.is_empty(), "{p:#?}");
    assert!(
        numbers.values().any(|n| n.open),
        "TODO/github.txt lists no open issue"
    );
}

#[test]
fn the_control_agrees() {
    let found = problems(LIST, MAP);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn each_planted_disagreement_is_named() {
    let row = MAP
        .lines()
        .find(|l| l.starts_with("| #70 |"))
        .expect("the row of #70")
        .to_string();

    let gone = MAP.replacen(&format!("{row}\n"), "", 1);
    let found = problems(LIST, &gone);
    assert!(
        names(&found, "issue #70 has no place in the map"),
        "{found:#?}"
    );

    let twice = MAP.replacen(&format!("{row}\n"), &format!("{row}\n{row}\n"), 1);
    let found = problems(LIST, &twice);
    assert!(
        names(&found, "issue #70 has 2 places in the map"),
        "{found:#?}"
    );

    let open = MAP.replacen(&row, &row.replacen("| closed |", "| open |", 1), 1);
    let found = problems(LIST, &open);
    assert!(
        names(
            &found,
            "issue #70 is closed on GitHub, and its row says \"open\""
        ),
        "{found:#?}"
    );

    // #77 leaves the line of pull requests, whatever words stand around it.
    let line = MAP
        .lines()
        .find(|l| l.contains("are pull requests"))
        .expect("the line of pull requests");
    let out = MAP.replacen(line, &line.replacen("#76 to #78", "#76 and #78", 1), 1);
    assert_ne!(out, MAP, "the plant of the line of pull requests applies");
    let found = problems(LIST, &out);
    assert!(
        names(
            &found,
            "pull request #77 is not in the line of pull requests"
        ),
        "{found:#?}"
    );

    let unlisted = LIST.replacen("\n70 issue closed\n", "\n", 1);
    assert_ne!(unlisted, LIST, "the plant of the list applies");
    let found = problems(&unlisted, MAP);
    assert!(
        names(
            &found,
            "the map names #70, which TODO/github.txt does not hold"
        ),
        "{found:#?}"
    );

    let deleted = MAP.replacen("| deleted (closed before) |", "| closed |", 1);
    assert_ne!(deleted, MAP, "the plant of the deleted row applies");
    let found = problems(LIST, &deleted);
    assert!(
        names(&found, "issue #71 is deleted on GitHub"),
        "{found:#?}"
    );
}
