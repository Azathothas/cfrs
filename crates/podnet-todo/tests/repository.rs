//! The record of this repository agrees with itself. This is the reader that
//! the gate runs; `cargo run -p podssh-todo -- check` prints the same
//! problems.

#[test]
fn the_record_of_this_repository_agrees() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let report = podssh_todo::check::check(&root, None);
    let problems: Vec<String> = report.problems.iter().map(|p| p.to_string()).collect();
    assert!(problems.is_empty(), "{} problems in TODO/:\n{}", problems.len(), problems.join("\n"));
}
