//! The words of the record: the values that an entry's fields can take, and
//! the shapes that the reader and the writer share. `TODO/INDEX.md` gives the
//! meaning of each value; this file is the list the checker accepts.

use std::fmt;

pub const STATUSES: [&str; 4] = ["open", "partial", "blocked", "done"];
pub const PRIORITIES: [&str; 4] = ["P0", "P1", "P2", "P3"];
/// No `XL`: an entry that big is two entries.
pub const EFFORTS: [&str; 3] = ["S", "M", "L"];
pub const MILESTONES: [&str; 10] = ["M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "backlog", "none"];
pub const CATEGORIES: [&str; 7] = ["defect", "feature", "measurement", "release", "chore", "research", "docs"];

/// The header fields of an entry, each given once.
pub const FIELDS: [&str; 6] = ["Source", "Category", "Milestone", "Priority", "Effort", "Status"];

/// The sections an entry can have, in this order.
pub const SECTIONS: [&str; 9] =
    ["Problem", "Premise", "Approach", "Decision", "Prove", "Blocker", "Start condition", "Correction", "Done"];
pub const REQUIRED_SECTIONS: [&str; 4] = ["Problem", "Premise", "Approach", "Prove"];

/// The files of `TODO/` that hold no entries.
pub const RECORD_FILES: [&str; 4] = ["INDEX.md", "PROGRESS.md", "RULES.md", "issues.md"];

/// One finding of the reader: where, and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub at: String,
    pub what: String,
}

impl Problem {
    pub fn new(file: &str, line: usize, what: impl Into<String>) -> Self {
        let at = if line == 0 { file.to_string() } else { format!("{file}:{line}") };
        Self { at, what: what.into() }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.what)
    }
}

/// A row of the table of entries in `TODO/INDEX.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub file: String,
    pub priority: String,
    pub effort: String,
    pub milestone: String,
    pub category: String,
    pub status: String,
    pub title: String,
    pub line: usize,
}

/// A header field of an entry, with the line where it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub line: usize,
}

/// A `## Name` section of an entry, with its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub line: usize,
    pub body: String,
}

/// One entry: `# T-NNN: Title`, its fields and its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub file: String,
    pub line: usize,
    pub fields: Vec<Field>,
    pub sections: Vec<Section>,
}

impl Entry {
    /// The value of a field, when the entry gives it.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.name == name).map(|f| f.value.as_str())
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }
}

/// The entries in each status. The total is their sum, never a stored number.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub open: usize,
    pub partial: usize,
    pub blocked: usize,
    pub done: usize,
}

impl Counts {
    pub fn total(&self) -> usize {
        self.open + self.partial + self.blocked + self.done
    }

    pub fn add(&mut self, status: &str) {
        match status {
            "open" => self.open += 1,
            "partial" => self.partial += 1,
            "blocked" => self.blocked += 1,
            "done" => self.done += 1,
            _ => {}
        }
    }

    /// The counts of the rows, for one priority or (with `None`) for all.
    pub fn of(rows: &[Row], priority: Option<&str>) -> Self {
        let mut c = Self::default();
        for r in rows.iter().filter(|r| priority.is_none_or(|p| r.priority == p)) {
            c.add(&r.status);
        }
        c
    }

    /// The fixed phrase that the index and the progress record carry, so a
    /// checker can read it: `N entries: A open, B partial, C blocked, D done.`
    pub fn phrase(&self) -> String {
        format!(
            "{} entries: {} open, {} partial, {} blocked, {} done.",
            self.total(),
            self.open,
            self.partial,
            self.blocked,
            self.done
        )
    }

    /// A row of the table of counts in the index.
    pub fn table_row(&self, label: &str) -> String {
        format!("| {label} | {} | {} | {} | {} | {} |", self.open, self.partial, self.blocked, self.done, self.total())
    }
}

/// True for an id of the form `T-NNN` (three digits or more).
pub fn is_id(s: &str) -> bool {
    s.len() >= 5 && s.starts_with("T-") && s[2..].bytes().all(|b| b.is_ascii_digit())
}

/// The number of an id, for ordering.
pub fn id_number(id: &str) -> u32 {
    id.get(2..).and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// Each `T-NNN` in a text, with the line where it is.
pub fn ids_in(text: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut at = 0;
        while let Some(pos) = line[at..].find("T-") {
            let start = at + pos;
            let before_ok = start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'-');
            let digits = bytes[start + 2..].iter().take_while(|b| b.is_ascii_digit()).count();
            let end = start + 2 + digits;
            let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
            if before_ok && digits >= 3 && after_ok {
                out.push((line[start..end].to_string(), i + 1));
            }
            at = start + 2;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_found_as_words_only() {
        let found: Vec<String> =
            ids_in("T-001 and (T-012), not XT-003, not T-04, T-1234.").into_iter().map(|(id, _)| id).collect();
        assert_eq!(found, ["T-001", "T-012", "T-1234"]);
    }

    #[test]
    fn the_phrase_is_derived_from_the_counts() {
        let c = Counts { open: 3, partial: 1, blocked: 2, done: 4 };
        assert_eq!(c.phrase(), "10 entries: 3 open, 1 partial, 2 blocked, 4 done.");
        assert_eq!(c.table_row("P1"), "| P1 | 3 | 1 | 2 | 4 | 10 |");
    }
}
