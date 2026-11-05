//! The record of this repository agrees with itself. This is the reader that
//! CI runs; `cargo todo check` prints the same problems.

#[test]
fn the_record_of_this_repository_agrees() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let report = podnet_todo::check::check(&root, None);
    let problems: Vec<String> = report.problems.iter().map(|p| p.to_string()).collect();
    assert!(
        problems.is_empty(),
        "{} problems in TODO/:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// The packages that a done Prove can name come from the workspace of this
/// repository: the root package, each member and `fuzz/`. The checker
/// names no package, so the test names only its own.
#[test]
fn the_packages_of_this_repository_are_read() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let packages = podnet_todo::prove::Packages::of(&root);
    let names: Vec<&str> = packages.names().collect();
    assert!(names.contains(&env!("CARGO_PKG_NAME")), "{names:?}");
    assert!(
        names.len() >= 4,
        "the root, the members and fuzz/: {names:?}"
    );
}
