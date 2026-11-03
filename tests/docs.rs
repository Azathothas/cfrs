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
