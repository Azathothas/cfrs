//! Rules for the documents of the repository.

/// Issue 126: each release note after v0.3.0-beta.6 has a heading
/// "## Breaking", after "## Check a download" and before "## Changes for a
/// tester". `release.yml` checks the same before a release.
#[test]
fn each_new_release_note_has_a_breaking_section() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/releases");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some(n) = name
            .strip_prefix("v0.3.0-beta.")
            .and_then(|r| r.strip_suffix(".md"))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if n <= 6 {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let at = |h: &str| lines.iter().position(|l| *l == h);
        let breaking = at("## Breaking").unwrap_or_else(|| panic!("{name}: no ## Breaking"));
        if let Some(check) = at("## Check a download") {
            assert!(
                check < breaking,
                "{name}: ## Breaking is before ## Check a download"
            );
        }
        if let Some(changes) = at("## Changes for a tester") {
            assert!(
                breaking < changes,
                "{name}: ## Breaking is after the changes"
            );
        }
        checked += 1;
    }
    let _ = checked;
}

/// Issue 176: a flag of `cfrs warp` is not a global flag of cfrs. The
/// README called the flags of WarpArgs "global".
#[test]
fn the_readme_does_not_call_warp_flags_global() {
    let readme =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    for line in readme.lines() {
        if line.contains("(global") && line.contains("CFRS_WARP_") {
            panic!("a flag of cfrs warp is called global: {line}");
        }
    }
    // A global flag before the command of cfrs is refused for a warp flag.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cfrs"))
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
