//! The targets of a done entry's Prove (T-361): each `-p CRATE` of a
//! `cargo test` command is a package of the tree, of the workspace, of
//! `fuzz/` or of `vendor/`, and each `--test NAME` a target of one of them,
//! a file of its `tests/` or a `[[test]]` of its manifest; each `scripts/`
//! path exists. A done Prove is what ran when its entry closed, so a target
//! that moved since is named, with where it went, in the entry's
//! `## Correction`, and a target that the Correction names is taken.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The packages of the tree, by name: each one's directory and the names of
/// its `[[test]]` targets.
#[derive(Debug, Default)]
pub struct Packages {
    by_name: BTreeMap<String, (PathBuf, Vec<String>)>,
}

impl Packages {
    /// The manifests of `crates/*`, `fuzz/`, `vendor/*` and `vendor/*/*`.
    pub fn of(root: &Path) -> Packages {
        let mut manifests = vec![root.join("fuzz/Cargo.toml")];
        for dir in ["crates", "vendor"] {
            for first in children(&root.join(dir)) {
                manifests.push(first.join("Cargo.toml"));
                if dir == "vendor" {
                    manifests.extend(children(&first).into_iter().map(|d| d.join("Cargo.toml")));
                }
            }
        }
        let mut packages = Packages::default();
        for manifest in manifests {
            let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
            let (name, tests) = read_manifest(&text);
            if let (Some(name), Some(dir)) = (name, manifest.parent()) {
                packages.by_name.insert(name, (dir.to_path_buf(), tests));
            }
        }
        packages
    }

    fn has_test(&self, package: &str, test: &str) -> bool {
        let Some((dir, named)) = self.by_name.get(package) else { return false };
        named.iter().any(|n| n == test)
            || dir.join("tests").join(format!("{test}.rs")).is_file()
            || dir.join("tests").join(test).join("main.rs").is_file()
    }
}

fn children(dir: &Path) -> Vec<PathBuf> {
    let Ok(read) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<PathBuf> = read.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    out.sort();
    out
}

/// The `name` of `[package]`, and the name of each `[[test]]`.
fn read_manifest(text: &str) -> (Option<String>, Vec<String>) {
    let (mut section, mut name, mut tests) = (String::new(), None, Vec::new());
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        let Some(value) = line.strip_prefix("name").map(str::trim_start).and_then(|r| r.strip_prefix('=')) else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match section.as_str() {
            "[package]" if name.is_none() => name = Some(value),
            "[[test]]" => tests.push(value),
            _ => {}
        }
    }
    (name, tests)
}

/// The packages and the test targets of each `cargo test` command in
/// `text`: `-p`/`--package` and `--test`, up to a `--`.
fn targets(text: &str) -> Vec<(usize, Vec<String>, Vec<String>)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let words: Vec<&str> =
            line.split(|c: char| c.is_whitespace() || c == '`' || c == ';').filter(|w| !w.is_empty()).collect();
        let mut at = 0;
        while let Some(start) = (at..words.len()).find(|&k| words[k] == "cargo") {
            let mut k = start + 1;
            if words.get(k).is_some_and(|w| w.starts_with('+')) {
                k += 1;
            }
            if words.get(k) != Some(&"test") {
                at = start + 1;
                continue;
            }
            let (mut packages, mut tests) = (Vec::new(), Vec::new());
            k += 1;
            while k < words.len() && words[k] != "--" && words[k] != "cargo" && words[k] != "&&" && words[k] != "||" {
                let word = words[k];
                match word {
                    "-p" | "--package" => packages.extend(words.get(k + 1).map(|w| w.to_string())),
                    "--test" => tests.extend(words.get(k + 1).map(|w| w.to_string())),
                    _ => {
                        if let Some(v) = word.strip_prefix("--package=").or_else(|| word.strip_prefix("-p")) {
                            if !v.is_empty() {
                                packages.push(v.to_string());
                            }
                        }
                        if let Some(v) = word.strip_prefix("--test=") {
                            tests.push(v.to_string());
                        }
                    }
                }
                k += 1;
            }
            out.push((i, packages, tests));
            at = k;
        }
    }
    out
}

/// Each `scripts/` path of `text`, its line.
fn scripts(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(at) = rest.find("scripts/") {
            let tail = &rest[at..];
            let len = tail.find(|c: char| !(c.is_ascii_alphanumeric() || "_./-".contains(c))).unwrap_or(tail.len());
            let path = tail[..len].trim_end_matches(['.', '/']);
            // A path of another tree (`.tmp/x/scripts/...`) is not this one's.
            let ours = at == 0 || !rest[..at].ends_with(|c: char| c.is_ascii_alphanumeric() || "_./-".contains(c));
            if ours && path.len() > "scripts/".len() {
                out.push((i, path.to_string()));
            }
            rest = &tail[len.max(1)..];
        }
    }
    out
}

/// What of `prove` (a section's body, at `line`) does not exist, each with
/// its line: a package, a test target or a script; none that `correction`
/// names.
pub fn missing(root: &Path, packages: &Packages, prove: &str, line: usize, correction: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, named, tests) in targets(prove) {
        let known: Vec<&String> = named.iter().filter(|p| packages.by_name.contains_key(*p)).collect();
        for package in named.iter().filter(|p| !packages.by_name.contains_key(*p) && !correction.contains(p.as_str())) {
            out.push((line + 1 + i, format!("the package {package}, which the tree does not hold")));
        }
        for test in tests.iter().filter(|t| !correction.contains(t.as_str())) {
            let found = if known.is_empty() && named.is_empty() {
                packages.by_name.keys().any(|p| packages.has_test(p, test))
            } else {
                known.iter().any(|p| packages.has_test(p, test))
            };
            if !found && !(known.is_empty() && !named.is_empty()) {
                out.push((line + 1 + i, format!("the test target {test}, which no package of its command has")));
            }
        }
    }
    for (i, path) in scripts(prove) {
        if !root.join(&path).exists() && !correction.contains(path.as_str()) {
            out.push((line + 1 + i, format!("{path}, which does not exist")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_commands_give_their_packages_and_targets() {
        let found =
            targets("x\ncargo test -p a --test b -- --ignored\n`cargo +1.89 test --package=c --test=d`; cargo test");
        assert_eq!(found[0], (1, vec!["a".into()], vec!["b".into()]));
        assert_eq!(found[1], (2, vec!["c".into()], vec!["d".into()]));
        assert_eq!(found[2], (2, vec![], vec![]));
    }

    #[test]
    fn a_script_s_path_is_read_and_another_tree_s_is_not() {
        let found = scripts("sh scripts/dev.sh check, then `scripts/plant.sh`; .tmp/x/scripts/y.sh");
        assert_eq!(found, [(0, "scripts/dev.sh".into()), (0, "scripts/plant.sh".into())]);
    }

    #[test]
    fn a_manifest_gives_its_name_and_its_test_targets() {
        let (name, tests) =
            read_manifest("[package]\nname = \"podssh-x\"\n[dependencies]\nname = \"no\"\n[[test]]\nname = \"t1\"\n");
        assert_eq!(name.as_deref(), Some("podssh-x"));
        assert_eq!(tests, ["t1"]);
    }
}
