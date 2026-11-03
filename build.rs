// The commit that `--version` prints, and the target triple that
// `cfrs update` downloads. The release workflow sets CFRS_BUILD_COMMIT; a
// local build prints "unknown".
fn main() {
    println!("cargo:rerun-if-env-changed=CFRS_BUILD_COMMIT");
    let commit = std::env::var("CFRS_BUILD_COMMIT").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=CFRS_BUILD_COMMIT={commit}");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=CFRS_BUILD_TARGET={target}");
    // The date of the manual (issue 181): SOURCE_DATE_EPOCH, else the date
    // of the commit. Both are the same for each build of a commit, so a
    // rebuild gives the same binary.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let date = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(civil_date)
        .or_else(commit_date)
        .unwrap_or_default();
    println!("cargo:rustc-env=CFRS_BUILD_DATE={date}");
}

/// YYYY-MM-DD of a Unix time (the algorithm of Howard Hinnant).
fn civil_date(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The date of the commit of HEAD, when git can tell it.
fn commit_date() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-c", "safe.directory=*", "log", "-1", "--format=%cs"])
        .output()
        .ok()?;
    let date = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && date.len() == 10).then_some(date)
}
