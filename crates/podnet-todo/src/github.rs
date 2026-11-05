//! The map of GitHub's numbers (T-360): `TODO/github.txt` lists each number
//! of the repository, an issue or a pull request, with its state, as GitHub
//! gives them, and `TODO/issues.md` must agree with it. Each issue has one
//! place in the map: the first cell of a row of a table, or the bold head of
//! a paragraph (`**#18, ...**`); each pull request is in the map's line of
//! them (`#37 to #50, #52 ... are pull requests`); and the State of a row
//! begins with its issue's state. The list is held to GitHub each day by a
//! job of CI (`.github/workflows/record-issues.yml`), as the gate has no
//! network.

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::Problem;

/// The list, in `TODO/`.
pub const LIST: &str = "github.txt";
/// The map, in `TODO/`.
pub const MAP: &str = "issues.md";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Issue,
    Pull,
}

/// One number of the list: what it is, whether it is open, whether GitHub
/// no longer has it (an issue that its owner deleted), and its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Number {
    pub kind: Kind,
    pub open: bool,
    pub deleted: bool,
    pub line: usize,
}

/// A place of an issue in the map: its line, and the State of its row, when
/// it is a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub line: usize,
    pub state: Option<String>,
}

/// What the map names: each issue's places, and the line that names the
/// pull requests, with each that it names.
#[derive(Debug, Default)]
pub struct Map {
    pub issues: BTreeMap<u32, Vec<Place>>,
    pub pulls: Option<(usize, Vec<u32>)>,
}

/// The list: `NUMBER issue|pull open|closed` on each line, or `NUMBER issue
/// deleted` for an issue that GitHub no longer has; `#` a comment.
pub fn read_list(text: &str, p: &mut Vec<Problem>) -> BTreeMap<u32, Number> {
    let mut list = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let parsed = match words.as_slice() {
            [n, kind, state] => match (n.parse::<u32>(), *kind, *state) {
                (Ok(n), "issue" | "pull", "open" | "closed") => {
                    Some((n, if *kind == "issue" { Kind::Issue } else { Kind::Pull }, *state == "open", false))
                }
                // Only an issue can be deleted on GitHub; a pull request stays.
                (Ok(n), "issue", "deleted") => Some((n, Kind::Issue, false, true)),
                _ => None,
            },
            _ => None,
        };
        let Some((n, kind, open, deleted)) = parsed else {
            p.push(Problem::new(
                LIST,
                i + 1,
                format!("not NUMBER issue|pull open|closed, or NUMBER issue deleted: {line:?}"),
            ));
            continue;
        };
        if list.insert(n, Number { kind, open, deleted, line: i + 1 }).is_some() {
            p.push(Problem::new(LIST, i + 1, format!("#{n} is listed twice")));
        }
    }
    list
}

/// `#N` at the start of `text`: its number.
fn number_at(text: &str) -> Option<u32> {
    let digits: String = text.strip_prefix('#')?.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Each number of `text`, a range `#A to #B` as each number in it.
fn numbers_in(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let words: Vec<&str> = text.split(|c: char| c.is_whitespace() || c == ',').filter(|w| !w.is_empty()).collect();
    let mut i = 0;
    while i < words.len() {
        if let Some(a) = number_at(words[i]) {
            match (words.get(i + 1), words.get(i + 2).and_then(|w| number_at(w))) {
                (Some(&"to"), Some(b)) if b >= a => {
                    out.extend(a..=b);
                    i += 3;
                    continue;
                }
                _ => out.push(a),
            }
        }
        i += 1;
    }
    out
}

/// The places of the map: the rows whose first cell is `#N`, the bold heads
/// `**#N, ...**`, and the line that ends its numbers with "are pull
/// requests".
pub fn read_map(text: &str) -> Map {
    let mut map = Map::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if let Some(rest) = line.strip_prefix('|') {
            let cells: Vec<&str> = rest.split('|').map(str::trim).collect();
            if let Some(n) = cells.first().and_then(|c| number_at(c)).filter(|_| cells[0].len() > 1) {
                if cells[0][1..].chars().all(|c| c.is_ascii_digit()) {
                    let state = cells.get(2).map(|s| s.to_string());
                    map.issues.entry(n).or_default().push(Place { line: i + 1, state });
                }
            }
        } else if let Some(n) = line.strip_prefix("**").and_then(number_at) {
            map.issues.entry(n).or_default().push(Place { line: i + 1, state: None });
        } else if let Some((before, _)) = line.split_once("are pull requests") {
            map.pulls = Some((i + 1, numbers_in(before)));
        }
    }
    map
}

/// The map against the list; nothing to hold where the tree has neither.
pub fn check(root: &Path, p: &mut Vec<Problem>) {
    let dir = root.join("TODO");
    let map_text = std::fs::read_to_string(dir.join(MAP));
    let list_text = std::fs::read_to_string(dir.join(LIST));
    let (map_text, list_text) = match (map_text, list_text) {
        (Err(_), Err(_)) => return,
        (Ok(map), Ok(list)) => (map, list),
        (Ok(_), Err(e)) => {
            return p.push(Problem::new(LIST, 0, format!("the map has no list of GitHub's numbers: {e}")))
        }
        (Err(e), Ok(_)) => {
            return p.push(Problem::new(MAP, 0, format!("the list of GitHub's numbers has no map: {e}")))
        }
    };
    let list = read_list(&list_text, p);
    agree(&list, &read_map(&map_text), p);
}

/// Each disagreement of `map` with `list`, by number.
pub fn agree(list: &BTreeMap<u32, Number>, map: &Map, p: &mut Vec<Problem>) {
    let (pull_line, pulls) = map.pulls.clone().unwrap_or((0, Vec::new()));
    for (n, number) in list {
        match number.kind {
            Kind::Issue => match map.issues.get(n).map(Vec::as_slice) {
                None | Some([]) => p.push(Problem::new(MAP, 0, format!("issue #{n} has no place in the map"))),
                Some([one]) => {
                    let want = match (number.deleted, number.open) {
                        (true, _) => "deleted",
                        (false, true) => "open",
                        (false, false) => "closed",
                    };
                    if let Some(state) = one.state.as_deref().filter(|s| !s.starts_with(want)) {
                        p.push(Problem::new(
                            MAP,
                            one.line,
                            format!("issue #{n} is {want} on GitHub, and its row says {state:?}"),
                        ));
                    }
                }
                Some(many) => p.push(Problem::new(
                    MAP,
                    many[1].line,
                    format!("issue #{n} has {} places in the map, at lines {}", many.len(), lines(many)),
                )),
            },
            Kind::Pull => {
                if !pulls.contains(n) {
                    p.push(Problem::new(
                        MAP,
                        pull_line,
                        format!("pull request #{n} is not in the line of pull requests"),
                    ));
                }
                if let Some(places) = map.issues.get(n) {
                    p.push(Problem::new(
                        MAP,
                        places[0].line,
                        format!("#{n} is a pull request, and has a place as an issue"),
                    ));
                }
            }
        }
    }
    for (n, places) in &map.issues {
        if !list.contains_key(n) {
            p.push(Problem::new(MAP, places[0].line, format!("the map names #{n}, which TODO/{LIST} does not hold")));
        }
    }
    for n in &pulls {
        match list.get(n) {
            None => p.push(Problem::new(
                MAP,
                pull_line,
                format!("the line of pull requests names #{n}, which TODO/{LIST} does not hold"),
            )),
            Some(number) if number.kind == Kind::Issue => {
                p.push(Problem::new(MAP, pull_line, format!("the line of pull requests names #{n}, an issue")))
            }
            Some(_) => {}
        }
    }
}

fn lines(places: &[Place]) -> String {
    places.iter().map(|place| place.line.to_string()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_is_each_number_in_it() {
        assert_eq!(numbers_in("#37 to #40, #52, #57 and #77"), [37, 38, 39, 40, 52, 57, 77]);
    }

    #[test]
    fn the_map_s_places_are_rows_heads_and_the_line_of_pull_requests() {
        let map = read_map(
            "| Issue | Subject | State | Entries |\n| --- | --- | --- | --- |\n| #1 | a | closed (`f502fba`) | T-1 |\n\
             **#18, transports.** text\n#37 to #39 and #41 are pull requests; more\n| Report | Entries |\n| lablup | T-1 |\n",
        );
        assert_eq!(map.issues[&1], [Place { line: 3, state: Some("closed (`f502fba`)".into()) }]);
        assert_eq!(map.issues[&18], [Place { line: 4, state: None }]);
        assert_eq!(map.pulls, Some((5, vec![37, 38, 39, 41])));
        assert_eq!(map.issues.len(), 2, "a report's row is no issue");
    }

    #[test]
    fn a_line_of_the_list_that_is_not_its_form_is_named() {
        let mut p = Vec::new();
        let list = read_list("# a comment\n1 issue open\n2 pull closed\nthree issue open\n1 issue closed\n", &mut p);
        assert_eq!(list.len(), 2);
        assert_eq!(p.len(), 2, "{p:?}");
    }

    /// An issue that GitHub no longer has is `deleted`, and its row says so;
    /// a pull request cannot be.
    #[test]
    fn a_deleted_issue_is_listed_and_its_row_must_say_so() {
        let mut p = Vec::new();
        let list = read_list("15 issue deleted\n16 pull deleted\n", &mut p);
        assert_eq!(list.len(), 1, "{p:?}");
        assert!(list[&15].deleted && !list[&15].open);
        assert_eq!(p.len(), 1, "a deleted pull request is no form: {p:?}");
        let map = |state: &str| {
            read_map(&format!(
                "| Issue | Subject | State | Entries |\n| --- | --- | --- | --- |\n| #15 | a | {state} | T-1 |\n"
            ))
        };
        let mut p = Vec::new();
        agree(&list, &map("deleted (closed before)"), &mut p);
        assert!(p.is_empty(), "{p:?}");
        agree(&list, &map("closed"), &mut p);
        assert_eq!(p.len(), 1, "a row that still says closed: {p:?}");
    }
}
