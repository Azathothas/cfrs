// The commit that `--version` prints. The release workflow sets
// PODNET_BUILD_COMMIT; a local build prints "unknown".
fn main() {
    println!("cargo:rerun-if-env-changed=PODNET_BUILD_COMMIT");
    let commit = std::env::var("PODNET_BUILD_COMMIT").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=PODNET_BUILD_COMMIT={commit}");
}
