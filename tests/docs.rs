//! Rules for the documents of the repository.

/// The release notes made before the rule of issue 126.
const PREDATES_RULE: &[&str] = &[
    "v0.3.0-beta.1.md",
    "v0.3.0-beta.2.md",
    "v0.3.0-beta.3.md",
    "v0.3.0-beta.4.md",
    "v0.3.0-beta.5.md",
    "v0.3.0-beta.6.md",
];

/// The release notes of `dir` that break the rule of issue 126, and the
/// number of notes checked.
fn notes_without_breaking(dir: &std::path::Path) -> (Vec<String>, usize) {
    let mut bad = Vec::new();
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with('v')
            || !name.ends_with(".md")
            || PREDATES_RULE.contains(&name.as_str())
        {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let at = |h: &str| lines.iter().position(|l| *l == h);
        checked += 1;
        let Some(breaking) = at("## Breaking") else {
            bad.push(format!("{name}: no ## Breaking"));
            continue;
        };
        if at("## Check a download").is_some_and(|check| check > breaking) {
            bad.push(format!("{name}: ## Breaking is before ## Check a download"));
        }
        if at("## Changes for a tester").is_some_and(|changes| breaking > changes) {
            bad.push(format!("{name}: ## Breaking is after the changes"));
        }
    }
    (bad, checked)
}

/// Issue 126: each release note after v0.3.0-beta.6 has a heading
/// "## Breaking", after "## Check a download" and before "## Changes for a
/// tester". `release.yml` checks the same before a release. #216: each
/// note is checked (a stable note too), except the list PREDATES_RULE.
#[test]
fn each_new_release_note_has_a_breaking_section() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/releases");
    let (bad, checked) = notes_without_breaking(&dir);
    assert!(
        checked > 0,
        "no release note after v0.3.0-beta.6 was checked"
    );
    assert!(bad.is_empty(), "{bad:#?}");
}

/// #216: a stable note (no -beta) is checked, not skipped.
#[test]
fn a_stable_release_note_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("v0.3.0.md"), "# v0.3.0\n\nno heading\n").unwrap();
    std::fs::write(dir.path().join("v0.3.0-beta.1.md"), "old\n").unwrap();
    let (bad, checked) = notes_without_breaking(dir.path());
    assert_eq!(checked, 1);
    assert_eq!(bad, ["v0.3.0.md: no ## Breaking"]);
}

/// Each repository path in backticks in the documents exists (podssh: a
/// document named scripts in the wrong directory).
#[test]
fn each_path_in_the_documents_exists() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let documents = [
        "README.md",
        "SECURITY.md",
        "docs/maintenance.md",
        "docs/protocol.md",
        "docs/virtual-network.md",
        "docs/target-environment.md",
        "docs/decisions.md",
        "docs/development.md",
    ];
    let prefixes = [
        "scripts/", "docs/", "src/", "tests/", "crates/", ".github/", "fuzz/",
    ];
    let mut missing = Vec::new();
    let mut seen = 0;
    for document in documents {
        let text = std::fs::read_to_string(root.join(document)).unwrap();
        for (i, part) in text.split('`').enumerate() {
            // The odd parts are in backticks.
            if i % 2 == 0 || !prefixes.iter().any(|p| part.starts_with(p)) {
                continue;
            }
            let path = part.trim_end_matches(['.', ',', ':']);
            let plain = path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c));
            // A template (vX.Y.Z) or a path with arguments is not a path.
            if !plain || path.contains("X.Y.Z") {
                continue;
            }
            seen += 1;
            if !root.join(path).exists() {
                missing.push(format!("{document}: {path}"));
            }
        }
    }
    assert!(seen > 20, "the test found only {seen} paths");
    assert!(missing.is_empty(), "missing paths: {missing:#?}");
}

/// The known gaps of SECURITY.md say what is true now: no "not done yet"
/// for work that is done, and no "yet" for a platform that the project
/// does not build for.
#[test]
fn the_security_gaps_have_no_stale_yet() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("SECURITY.md")).unwrap();
    let gaps = &text[text.find("## Known gaps").expect("a Known gaps section")..];
    let flat = gaps.split_whitespace().collect::<Vec<_>>().join(" ");
    for stale in ["not done yet", "for them yet", "Windows or macOS yet"] {
        assert!(!flat.contains(stale), "SECURITY.md: {stale:?}");
    }
    assert!(root.join("fuzz").is_dir(), "SECURITY.md names fuzz/");
}

/// Issue 176: a flag of `podnet warp` is not a global flag of podnet. The
/// README called the flags of WarpArgs "global".
#[test]
fn the_readme_does_not_call_warp_flags_global() {
    let readme =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    for line in readme.lines() {
        if line.contains("(global") && line.contains("PODNET_WARP_") {
            panic!("a flag of podnet warp is called global: {line}");
        }
    }
    // A global flag before the command of podnet is refused for a warp flag.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_podnet"))
        .args(["--cc", "cubic", "warp", "status"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

/// The python block of the README section "Ephemeral hosts".
fn readme_notebook_cell() -> String {
    let readme =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    let section = readme
        .split("### Ephemeral hosts")
        .nth(1)
        .expect("the README has the section");
    let block = section
        .split("```python\n")
        .nth(1)
        .and_then(|b| b.split("```").next())
        .expect("the section has a python block");
    block.to_string()
}

/// Issue 192: the notebook is valid nbformat 4 with no outputs, and its
/// code cell is the cell of the README.
#[test]
fn the_notebook_is_the_cell_of_the_readme() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/notebooks/install.ipynb"
    ))
    .unwrap();
    let nb: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(nb["nbformat"], 4);
    let code = nb["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cell_type"] == "code")
        .expect("a code cell");
    assert_eq!(code["outputs"], serde_json::json!([]));
    let source: String = code["source"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert_eq!(source.trim_end(), readme_notebook_cell().trim_end());
    // The cell compiles, when python3 is here.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("cell.py");
    std::fs::write(&file, &source).unwrap();
    if let Ok(out) = std::process::Command::new("python3")
        .args(["-I", "-m", "py_compile"])
        .arg(&file)
        .output()
    {
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// #223: the crate podnet-netns ships the license text of the project.
#[test]
fn podnet_netns_ships_the_license() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let main = std::fs::read(root.join("LICENSE")).unwrap();
    let pod = std::fs::read(root.join("crates/podnet-netns/LICENSE"))
        .expect("crates/podnet-netns/LICENSE");
    assert_eq!(main, pod, "crates/podnet-netns/LICENSE is the root LICENSE");
}

/// #212: a relative link of the README is a 404 on the crate page, so
/// each link of the README is a full URL or an anchor of the README.
#[test]
fn the_readme_has_no_relative_link() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "crates/podnet-netns/README.md"] {
        let text = std::fs::read_to_string(root.join(name)).unwrap();
        let mut bad = Vec::new();
        for part in text.split("](").skip(1) {
            let target = part.split(')').next().unwrap_or("");
            let ok = target.starts_with("https://")
                || target.starts_with("http://")
                || target.starts_with('#')
                || target.starts_with("mailto:");
            if !ok {
                bad.push(target.to_string());
            }
        }
        assert!(bad.is_empty(), "{name}: relative links: {bad:?}");
    }
}

/// #256: the section "UDP in the stream" of the podnet-netns README comes
/// after the list of the seccomp backend, not inside it.
#[test]
fn the_seccomp_list_of_podnet_netns_is_one_list() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("crates/podnet-netns/README.md")).unwrap();
    let needs = text
        .find("Needs: seccomp")
        .expect("the Needs line of seccomp");
    let udp = text.find("### UDP in the stream").expect("the UDP heading");
    assert!(needs < udp, "the UDP heading splits the seccomp list");
}

/// #257: each command whose help has --detach is named in the sentence
/// of the README about --detach.
#[test]
fn the_readme_names_each_command_with_detach() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("README.md")).unwrap();
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let at = flat
        .find("`--detach` works with")
        .expect("the --detach sentence");
    let sentence = &flat[at..at + flat[at..].find(". ").unwrap()];
    for command in [
        "tunnel",
        "serve",
        "share",
        "demo",
        "connect",
        "warp proxy",
        "warp forward",
        "warp tun",
        "relay node",
        "net proxy",
        "net switch",
    ] {
        let args: Vec<&str> = command.split(' ').chain(["--help"]).collect();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_podnet"))
            .args(&args)
            .output()
            .unwrap();
        let help = String::from_utf8_lossy(&out.stdout);
        if help.contains("--detach") {
            assert!(
                sentence.contains(&format!("`{command}`")),
                "{command} is not in: {sentence}"
            );
        }
    }
}

/// #258: each release tag that the README, the notebook or a help text
/// names has a release note: a tag in an example is not invented.
#[test]
fn each_tag_in_the_documents_has_a_release_note() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for name in ["README.md", "notebooks/install.ipynb", "src/main.rs"] {
        let text = std::fs::read_to_string(root.join(name)).unwrap();
        for part in text.split("v0.3.0-beta.").skip(1) {
            let n: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            if n.is_empty() {
                continue;
            }
            let note = root.join(format!("docs/releases/v0.3.0-beta.{n}.md"));
            if !note.exists() {
                missing.push(format!("{name}: v0.3.0-beta.{n}"));
            }
        }
    }
    assert!(missing.is_empty(), "tags with no release note: {missing:?}");
}
