//! A small record that agrees with itself, written into a fresh directory.
//! Each plant changes one thing in it, and the reader must find that thing.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

pub const INDEX: &str = "# Index

**3 entries: 1 open, 0 partial, 1 blocked, 1 done.**

| Priority | open | partial | blocked | done | total |
| --- | --- | --- | --- | --- | --- |
| P0 | 0 | 0 | 0 | 0 | 0 |
| P1 | 1 | 0 | 0 | 1 | 2 |
| P2 | 0 | 0 | 1 | 0 | 1 |
| P3 | 0 | 0 | 0 | 0 | 0 |
| **All** | 1 | 0 | 1 | 1 | 3 |

| ID | Priority | Effort | Milestone | Category | Status | Item |
| --- | --- | --- | --- | --- | --- | --- |
| [T-001](area.md) | P1 | S | M3 | defect | open | The first entry |
| [T-002](area.md) | P2 | M | M4 | feature | blocked | The second entry |
| [T-003](area.md) | P1 | S | M3 | defect | done | The third entry |
";

pub const PROGRESS: &str = "# Progress

`TODO/INDEX.md` holds 3 entries: 1 open, 0 partial, 1 blocked, 1 done.

## Work order

1. T-001.

## Questions for the operator

- **Q1.** May the client listen?
";

pub const AREA: &str = "The entries of one area.

# T-001: The first entry

**Source:** the operator,
on two lines.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** open

## Problem

It fails; `crates/x/src/lib.rs:4` says \"line 4\".

## Premise

Read: `crates/x/src/lib.rs:3`.

## Approach

Change `crates/x/src/lib.rs:2-4` and `docs/ROADMAP.md`.

## Prove

```sh
cargo test -p x
# a comment in a fence, not an entry
```

# T-002: The second entry

**Source:** GitHub #1.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

It is missing.

## Premise

Read in the report, not verified here: `lablup/bssh:src/x.rs:9`.

## Approach

Add it, after T-001.

## Prove

Run `cargo test -p x -- second`.

## Blocker

The operator's ruling on question Q1 in `TODO/PROGRESS.md`.

# T-003: The third entry

**Source:** found while measuring T-001.
**Category:** defect
**Milestone:** M3
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

It hung.

## Premise

Measured.

## Approach

Bound the wait.

## Prove

`cargo test -p x -- third`

## Done

2026-10-08, commit `0000000`: `cargo test -p x -- third` passed.
";

pub const ROADMAP: &str = "# Roadmap

## M3: Beta

- [x] Something that was done.
- T-001: the first entry.

## M4: Next

- T-002.
";

pub const SOURCE: &str = "line 1\nline 2\nline 3\nline 4\nline 5\n";

/// A fresh directory with the record, for one test.
pub struct Tree {
    pub root: PathBuf,
}

impl Tree {
    /// Each call has a directory of its own: two tests that run at once
    /// with one name must not remove each other's tree (T-286).
    pub fn new(name: &str) -> Self {
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("podssh-todo-{}-{name}-{call}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let t = Self { root };
        t.write("TODO/INDEX.md", INDEX);
        t.write("TODO/PROGRESS.md", PROGRESS);
        t.write("TODO/area.md", AREA);
        t.write("docs/ROADMAP.md", ROADMAP);
        t.write("crates/x/src/lib.rs", SOURCE);
        // The package that the Proves name, with a test target (T-361).
        t.write("crates/x/Cargo.toml", "[package]\nname = \"x\"\n");
        t.write("crates/x/tests/third.rs", "#[test]\nfn third() {}\n");
        t.write("README.md", "# x\n\nThe work order is in `TODO/PROGRESS.md` (T-001 first).\n");
        t
    }

    pub fn write(&self, rel: &str, text: &str) {
        let path = self.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.root.join(rel)).unwrap()
    }

    /// Replace `old` with `new` in one file; the plant must apply.
    pub fn plant(&self, rel: &str, old: &str, new: &str) {
        let text = self.read(rel);
        assert!(text.contains(old), "the plant does not apply to {rel}: {old:?}");
        self.write(rel, &text.replacen(old, new, 1));
    }

    pub fn problems(&self) -> Vec<String> {
        podssh_todo::check::check(&self.root, None).problems.iter().map(|p| p.to_string()).collect()
    }

    pub fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
