//! Tests of scripts/install.sh (issues 174, 175, 169, 166, 165).
//!
//! Each test runs the script with `sh` and a PATH of its own: links to the
//! real tools that the script needs, and fake `uname`, downloaders and
//! `cosign`. A fake downloader copies the files of a fake release (a
//! directory) by the last part of the URL, so no network is used.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The real tools that the script calls.
const TOOLS: &[&str] = &[
    "sh",
    "cat",
    "sed",
    "awk",
    "tr",
    "mkdir",
    "rm",
    "cp",
    "mv",
    "chmod",
    "sha256sum",
    "cut",
    "head",
    "id",
    "mktemp",
    "dirname",
    "basename",
    "grep",
    "printf",
    "sleep",
    "ls",
    "touch",
    "env",
    "test",
    "[",
    "expr",
    "wc",
    "stat",
    "tail",
    "kill",
];

struct Lab {
    root: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("cfrs-install-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["bin", "release", "dest"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        for tool in TOOLS {
            if let Some(real) = which(tool) {
                let _ = std::os::unix::fs::symlink(real, root.join("bin").join(tool));
            }
        }
        let lab = Lab { root };
        lab.script(
            "uname",
            "case \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac",
        );
        lab.release("v9.9.9", "cfrs 9.9.9 (test)");
        lab
    }

    fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn dest(&self) -> PathBuf {
        self.root.join("dest")
    }

    /// A fake tool in the PATH of the script.
    fn script(&self, name: &str, body: &str) {
        let path = self.bin().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A fake release: a cfrs that prints `version`, and its SHA256SUMS.
    fn release(&self, _tag: &str, version: &str) {
        let rel = self.root.join("release");
        let bin = rel.join("cfrs-x86_64-unknown-linux-musl");
        std::fs::write(&bin, format!("#!/bin/sh\necho '{version}'\n")).unwrap();
        let sum = sha256_hex(&std::fs::read(&bin).unwrap());
        std::fs::write(
            rel.join("SHA256SUMS"),
            format!("{sum}  cfrs-x86_64-unknown-linux-musl\n"),
        )
        .unwrap();
    }

    /// A fake curl that serves the release by the last part of the URL.
    fn curl(&self) {
        self.script(
            "curl",
            &format!(
                "out=''; url=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done\nf={rel}/$(basename \"$url\")\n[ -f \"$f\" ] || exit 22\ncp \"$f\" \"$out\"",
                rel = self.root.join("release").display()
            ),
        );
    }

    /// A fake busybox: `wget -q -O OUT URL`, `--list` (with ssl_client when
    /// `tls`).
    fn busybox(&self, tls: bool) {
        self.script(
            "busybox",
            &format!(
                "case \"$1\" in\n--list) echo wget; {tls}; exit 0 ;;\nwget) shift; [ \"$1\" = --help ] && {{ echo 'BusyBox v1.36 multi-call binary'; exit 0; }}\n  out=''; url=''\n  while [ $# -gt 0 ]; do case \"$1\" in -O) out=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done\n  f={rel}/$(basename \"$url\"); [ -f \"$f\" ] || exit 1; cp \"$f\" \"$out\" ;;\nesac",
                tls = if tls { "echo ssl_client" } else { "true" },
                rel = self.root.join("release").display()
            ),
        );
    }

    /// A fake curl with this body after the parse of `-o OUT` and the URL
    /// (`$f` is the file of the release for the URL).
    fn curl_with(&self, body: &str) {
        self.script(
            "curl",
            &format!(
                "out=''; url=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2 ;; -H) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done\necho \"$url\" >> {log}\nf={rel}/$(basename \"$url\")\n{body}",
                rel = self.root.join("release").display(),
                log = self.root.join("curl.log").display(),
            ),
        );
    }

    fn curl_log(&self) -> String {
        std::fs::read_to_string(self.root.join("curl.log")).unwrap_or_default()
    }

    fn run(&self, extra: &[(&str, &str)]) -> Output {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install.sh");
        let mut cmd = Command::new(self.bin().join("sh"));
        cmd.arg(&script)
            .env_clear()
            .env("PATH", self.bin())
            .env("HOME", &self.root)
            .env("CFRS_VERSION", "v9.9.9")
            .env("CFRS_INSTALL_DIR", self.dest())
            .env("NO_COLOR", "1");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn which(tool: &str) -> Option<PathBuf> {
    for dir in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let p = Path::new(dir).join(tool);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn curl_installs_the_release() {
    let lab = Lab::new("curl");
    lab.curl();
    let out = lab.run(&[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("downloader: curl"), "{t}");
    assert!(t.contains("cfrs 9.9.9 (test)"), "{t}");
    assert!(lab.dest().join("cfrs").exists());
}

// Issue 174: busybox wget goes after each other downloader.
#[test]
fn busybox_is_last_in_the_default_order() {
    let lab = Lab::new("bblast");
    lab.curl();
    lab.busybox(true);
    let t = text(&lab.run(&[]));
    assert!(t.contains("downloader: curl"), "{t}");
    assert!(!t.contains("does not check TLS"), "{t}");
}

// Issue 174: busybox with TLS is used, with the warning.
#[test]
fn busybox_with_tls_warns() {
    let lab = Lab::new("bbwarn");
    lab.busybox(true);
    let out = lab.run(&[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("downloader: busybox"), "{t}");
    assert!(t.contains("does not check TLS certificates"), "{t}");
    assert!(t.contains("does not protect you"), "{t}");
}

// Issue 174: a busybox with no TLS would send https as plain HTTP.
#[test]
fn busybox_without_tls_is_not_selected() {
    let lab = Lab::new("bbnotls");
    lab.busybox(false);
    let out = lab.run(&[]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("no downloader"), "{t}");
    assert!(!lab.dest().join("cfrs").exists());
}

// Issue 174: a wget that is the busybox applet (Alpine) is busybox.
#[test]
fn wget_that_is_busybox_is_treated_as_busybox() {
    let lab = Lab::new("bbwget");
    lab.busybox(true);
    lab.script(
        "wget",
        &format!("exec {} wget \"$@\"", lab.bin().join("busybox").display()),
    );
    let out = lab.run(&[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("downloader: wget-busybox"), "{t}");
    assert!(t.contains("does not check TLS certificates"), "{t}");
}

// Issue 174: with cosign, the warning says that the signature protects.
#[test]
fn busybox_with_cosign_names_the_signature() {
    let lab = Lab::new("bbcosign");
    lab.busybox(true);
    lab.script("cosign", "exit 0");
    std::fs::write(lab.root.join("release/SHA256SUMS.sigstore.json"), "{}").unwrap();
    let t = text(&lab.run(&[]));
    assert!(t.contains("cosign checks the signature"), "{t}");
}

const SERVE: &str = "[ -f \"$f\" ] || exit 22\ncp \"$f\" \"$out\"";

// Issue 169: a bad CFRS_DOWNLOADER names the variable.
#[test]
fn bad_downloader_names_the_variable() {
    let lab = Lab::new("baddl");
    lab.curl();
    let out = lab.run(&[("CFRS_DOWNLOADER", "nosuch")]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("CFRS_DOWNLOADER=nosuch: not found"), "{t}");
}

// Issues 169 and 175: a binary that does not run keeps the old one.
#[test]
fn a_binary_that_does_not_run_keeps_the_old_one() {
    let lab = Lab::new("norun");
    lab.curl();
    let rel = lab.root.join("release");
    let bin = rel.join("cfrs-x86_64-unknown-linux-musl");
    std::fs::write(&bin, "#!/bin/sh\nexit 1\n").unwrap();
    let sum = sha256_hex(&std::fs::read(&bin).unwrap());
    std::fs::write(
        rel.join("SHA256SUMS"),
        format!("{sum}  cfrs-x86_64-unknown-linux-musl\n"),
    )
    .unwrap();
    let old = lab.dest().join("cfrs");
    std::fs::write(&old, "old binary").unwrap();
    let out = lab.run(&[]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("does not run on this machine"), "{t}");
    assert!(!t.contains("installed"), "{t}");
    assert_eq!(std::fs::read_to_string(&old).unwrap(), "old binary");
    let left: Vec<_> = std::fs::read_dir(lab.dest())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, vec![std::ffi::OsString::from("cfrs")], "{left:?}");
}

// Issue 175: a cut download is a download error, not a SHA256 mismatch;
// a missing file is "no FILE in TAG".
#[test]
fn a_cut_download_is_a_download_error() {
    let lab = Lab::new("cut");
    lab.curl_with("case \"$url\" in *musl) head -c 5 \"$f\" > \"$out\"; exit 56 ;; esac\n[ -f \"$f\" ] || exit 22\ncp \"$f\" \"$out\"");
    let t = text(&lab.run(&[]));
    assert!(
        t.contains("the download of cfrs-x86_64-unknown-linux-musl failed (exit 56"),
        "{t}"
    );
    assert!(!t.contains("SHA256 of"), "{t}");

    let lab = Lab::new("missing");
    lab.curl_with(SERVE);
    std::fs::remove_file(lab.root.join("release/cfrs-x86_64-unknown-linux-musl")).unwrap();
    let t = text(&lab.run(&[]));
    assert!(
        t.contains("no cfrs-x86_64-unknown-linux-musl in v9.9.9"),
        "{t}"
    );
}

// Issue 166: latest reads releases.atom when the API refuses.
#[test]
fn latest_falls_back_to_releases_atom() {
    let lab = Lab::new("atom");
    lab.curl_with(SERVE);
    std::fs::write(
        lab.root.join("release/releases.atom"),
        "<feed><entry><link rel=\"alternate\" type=\"text/html\" href=\"https://github.com/Azathothas/cfrs/releases/tag/v9.9.9\"/></entry>\n<entry><link href=\"https://github.com/Azathothas/cfrs/releases/tag/v9.9.8\"/></entry></feed>\n",
    )
    .unwrap();
    let out = lab.run(&[("CFRS_VERSION", "latest")]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("reading releases.atom"), "{t}");
    assert!(t.contains("release: v9.9.9"), "{t}");
    assert!(
        lab.curl_log().contains("api.github.com"),
        "{}",
        lab.curl_log()
    );
}

// Issue 175: a bad directory fails before a download; a relative
// directory is shown as an absolute path.
#[test]
fn the_directory_is_checked_first_and_made_absolute() {
    let lab = Lab::new("dir");
    lab.curl_with(SERVE);
    let out = lab.run(&[("CFRS_INSTALL_DIR", "/proc/nope")]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("not a writable directory"), "{t}");
    assert_eq!(lab.curl_log(), "", "a download before the check");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install.sh");
    let out = Command::new(lab.bin().join("sh"))
        .arg(&script)
        .current_dir(&lab.root)
        .env_clear()
        .env("PATH", lab.bin())
        .env("HOME", &lab.root)
        .env("CFRS_VERSION", "v9.9.9")
        .env("CFRS_INSTALL_DIR", "rel/bin")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let abs = std::fs::canonicalize(lab.root.join("rel/bin")).unwrap();
    assert!(
        t.contains(&format!("installed {}/cfrs", abs.display())),
        "{t}"
    );
    assert!(
        t.contains(&format!("export PATH=\"{}:", abs.display())),
        "{t}"
    );
}

// Issue 175: the output of a failed cosign is shown.
#[test]
fn a_failed_cosign_shows_its_output() {
    let lab = Lab::new("cosignfail");
    lab.curl_with(SERVE);
    lab.script("cosign", "echo 'tuf refresh failed' >&2; exit 1");
    std::fs::write(lab.root.join("release/SHA256SUMS.sigstore.json"), "{}").unwrap();
    let out = lab.run(&[]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("tuf refresh failed"), "{t}");
    assert!(t.contains("signature of SHA256SUMS is not valid"), "{t}");
}

// Issue 175: TERM stops the script, and its temporary directory goes.
#[test]
fn term_stops_the_script_and_cleans_up() {
    let lab = Lab::new("term");
    lab.curl_with("kill -TERM $PPID\nexit 1");
    let tmp = lab.root.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let out = lab.run(&[("TMPDIR", tmp.to_str().unwrap())]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(143), "{t}");
    let left: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
    assert!(!lab.dest().join("cfrs").exists());
}

// Issue 165: the documented form fails when the downloader is missing (a
// pipe to sh exits 0).
#[test]
fn the_assignment_form_fails_with_no_downloader() {
    let lab = Lab::new("form");
    let out = Command::new(lab.bin().join("sh"))
        .args([
            "-c",
            "s=$(curl -fsSL https://example.invalid/install.sh) && sh -c \"$s\"",
        ])
        .env_clear()
        .env("PATH", lab.bin())
        .output()
        .unwrap();
    assert!(!out.status.success());
}
