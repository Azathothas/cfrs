//! Issue 270: `podnet update` writes the new binary with mode 0755, also with
//! the umask 077. The umask is a setting of the process, so this test has
//! its own test binary and no other test runs beside it.

use std::os::unix::fs::PermissionsExt as _;

#[test]
fn the_new_binary_has_mode_0755_with_a_restrictive_umask() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("podnet");
    std::fs::write(&path, "#!/bin/sh\necho 'podnet 0.3.0-beta.4 (old)'\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let new = b"#!/bin/sh\necho 'podnet 0.3.0-beta.5 (new)'\n";
    // SAFETY: umask has no memory effect; this binary has one test.
    let old = unsafe { libc::umask(0o077) };
    let result = podnet::update::install(&path, new, "v0.3.0-beta.5");
    unsafe { libc::umask(old) };
    result.unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
}
