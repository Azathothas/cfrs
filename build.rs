// The commit that `--version` prints, and the target triple that
// `cfrs update` downloads. The release workflow sets CFRS_BUILD_COMMIT; a
// local build prints "unknown".
fn main() {
    println!("cargo:rerun-if-env-changed=CFRS_BUILD_COMMIT");
    let commit = std::env::var("CFRS_BUILD_COMMIT").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=CFRS_BUILD_COMMIT={commit}");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=CFRS_BUILD_TARGET={target}");
}
