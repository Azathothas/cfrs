//! `--base REV` against a real repository (T-277): a commit made without a
//! remap leaves citations that the check against `HEAD` cannot see, as the
//! tree has no change then; against the commit's parent the check finds
//! them, and `remap --base` moves them. With no git on PATH (the build
//! image), the tests say so and pass: the Windows job of CI runs them.

mod common;

use std::path::Path;
use std::process::Command;

use common::{Tree, SOURCE};

const LIB: &str = "crates/x/src/lib.rs";

/// git with no global or system configuration, so that no hook, signing
/// key or line-end rule of this machine reaches the test's repository.
fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", root.join("no-such-config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "podssh-todo test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "podssh-todo test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?}: {status}");
}

fn have_git() -> bool {
    let found = Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success());
    if !found {
        eprintln!("git is not on PATH: this test needs it, and did not run");
    }
    found
}

/// A tree of the record in a repository of its own, with one commit.
fn committed(name: &str) -> Tree {
    let t = Tree::new(name);
    git(t.path(), &["init", "-q"]);
    git(t.path(), &["add", "-A"]);
    git(t.path(), &["commit", "-q", "-m", "the record"]);
    t
}

fn run(args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = podssh_todo::run(&args, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

/// The lines of the check's report that ask for the remap of LIB.
fn asks(err: &str, command: &str) -> usize {
    err.lines().filter(|l| l.contains(&format!("run `{command} {LIB}`"))).count()
}

#[test]
fn a_commit_made_without_a_remap_is_found_against_its_parent() {
    if !have_git() {
        return;
    }
    let t = committed("base-commit");
    let root = t.path().to_str().unwrap();
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    git(t.path(), &["commit", "-q", "-a", "-m", "an edit with no remap"]);

    // Against HEAD the tree has no change, so no citation left behind shows.
    let (_, _, err) = run(&["check", "--root", root]);
    assert_eq!(asks(&err, "cargo todo remap"), 0, "{err}");
    // Against the commit's parent, each of the three.
    let (code, _, err) = run(&["check", "--root", root, "--base", "HEAD~1"]);
    assert_eq!(code, 1, "{err}");
    assert_eq!(asks(&err, "cargo todo remap --base HEAD~1"), 3, "{err}");

    // remap --base moves them, and the check against the parent agrees.
    let (code, out, err) = run(&["remap", "--root", root, "--base", "HEAD~1", LIB]);
    assert_eq!(code, 0, "{out}{err}");
    let area = t.read("TODO/area.md");
    assert!(area.contains("`crates/x/src/lib.rs:3-5`"), "{area}");
    let (code, out, err) = run(&["check", "--root", root, "--base", "HEAD~1"]);
    assert_eq!(code, 0, "{out}{err}");
}

#[test]
fn a_base_that_git_cannot_read_fails_the_check() {
    if !have_git() {
        return;
    }
    let t = committed("base-unread");
    let root = t.path().to_str().unwrap();
    let (code, _, err) = run(&["check", "--root", root]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["check", "--root", root, "--base", "no-such-revision"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--base: git cannot compare the tree with `no-such-revision`"), "{err}");
    // A revision that would reach git as an option is refused.
    let (code, _, err) = run(&["check", "--root", root, "--base", "--output=x"]);
    assert_eq!(code, 64, "{err}");
}
