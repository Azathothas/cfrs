//! The check of GitHub's numbers in the map (T-360), on the record's own
//! `TODO/issues.md` and `TODO/github.txt`: they agree, and each planted
//! disagreement is named.

use std::path::Path;

use podssh_todo::github::{agree, read_list, read_map};

fn record(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../TODO").join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

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

#[test]
fn each_planted_disagreement_is_named() {
    let (list, map) = (record("github.txt"), record("issues.md"));
    let row = map.lines().find(|l| l.starts_with("| #70 |")).expect("the row of #70").to_string();

    let gone = map.replacen(&format!("{row}\n"), "", 1);
    let found = problems(&list, &gone);
    assert!(names(&found, "issue #70 has no place in the map"), "{found:#?}");

    let twice = map.replacen(&format!("{row}\n"), &format!("{row}\n{row}\n"), 1);
    let found = problems(&list, &twice);
    assert!(names(&found, "issue #70 has 2 places in the map"), "{found:#?}");

    let open = map.replacen(&row, &row.replacen("| closed |", "| open |", 1), 1);
    let found = problems(&list, &open);
    assert!(names(&found, "issue #70 is closed on GitHub, and its row says \"open\""), "{found:#?}");

    // #77 leaves the line of pull requests, whatever words stand around it.
    let line = map.lines().find(|l| l.contains("are pull requests")).expect("the line of pull requests");
    let out = map.replacen(line, &line.replacen("#77", "#76", 1), 1);
    assert_ne!(out, map, "the plant of the line of pull requests applies");
    let found = problems(&list, &out);
    assert!(names(&found, "pull request #77 is not in the line of pull requests"), "{found:#?}");

    let unlisted = list.replacen("\n70 issue closed\n", "\n", 1);
    assert_ne!(unlisted, list, "the plant of the list applies");
    let found = problems(&unlisted, &map);
    assert!(names(&found, "the map names #70, which TODO/github.txt does not hold"), "{found:#?}");
}
