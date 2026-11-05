//! The roots that podnet trusts for each TLS connection that it opens as a
//! client: the quick-tunnel API, DNS over HTTPS, the WARP API, the fetch of
//! the public URL, the edge, and HTTPS origins. They are the roots of
//! `pod-tls` (PodUtils/podcrates) in one context of the process
//! ([`context`]), with podnet's settings and ring as its provider.
//!
//! The order:
//!
//! 1. A file given with `--ca-file`, else the file in `SSL_CERT_FILE`. The file
//!    is used alone: podnet adds no other root to it.
//! 2. Else all of these: `podnet-ca.pem` beside the binary, the first readable
//!    bundle of [`pod_tls::SYSTEM_BUNDLES`], and the Mozilla roots compiled
//!    into podnet (webpki-roots [`pod_tls::ROOTS_VERSION`]).
//!
//! The edge also trusts the Cloudflare roots of `cf-edge-roots.pem`. podnet has
//! no option that accepts each certificate for these connections; only an
//! origin can turn off the check (`noTLSVerify`, `--no-tls-verify`).
//!
//! When a certificate is expired or not valid yet, [`pod_tls::clock_hint`]
//! gives the clock of the host, because a wrong clock is a frequent cause on
//! a small host or in a container.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use pod_tls::{CaFile, Context, Settings, Words};

/// The variable that names a file of roots, as in OpenSSL.
pub const CA_FILE_VARIABLE: &str = "SSL_CERT_FILE";
/// The name of the file of roots beside the binary.
pub const BESIDE_BINARY: &str = "podnet-ca.pem";
/// The first date when a root of `cf-edge-roots.pem` stops being valid.
pub const EDGE_ROOTS_FIRST_END: &str = "2029-08-15";

static CA_FILE: OnceLock<PathBuf> = OnceLock::new();

/// Use `path` as the only file of roots (`--ca-file`). Call it before the
/// first connection; a later call has no effect.
pub fn set_ca_file(path: PathBuf) {
    let _ = CA_FILE.set(path);
}

/// The TLS of this process: its roots, read one time, and its client
/// configurations, on ring.
pub fn context() -> &'static Arc<Context> {
    static CONTEXT: OnceLock<Arc<Context>> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let mut words = Words::new("podnet");
        words.replace_roots = format!("--ca-file FILE or {CA_FILE_VARIABLE}");
        words.add_roots = Some(format!("{BESIDE_BINARY} beside the binary"));
        let mut settings = Settings::new(words);
        settings.ca_file = CA_FILE
            .get()
            .map(|path| CaFile::new("--ca-file", path.clone()))
            .or_else(|| {
                std::env::var_os(CA_FILE_VARIABLE)
                    .filter(|v| !v.is_empty())
                    .map(|v| CaFile::new(CA_FILE_VARIABLE, v))
            });
        settings.extra_bundle = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(BESIDE_BINARY)));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(Context::new(provider, settings))
    })
}

/// The seconds of `time` since the Unix epoch, negative before it, for
/// [`pod_core::clock::http_date`].
pub fn unix_secs(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The roots of pod-tls are the version of webpki-roots in Cargo.lock.
    #[test]
    fn the_roots_version_is_the_one_of_cargo_lock() {
        let lock = include_str!("../Cargo.lock");
        let versions: Vec<&str> = lock
            .split("[[package]]")
            .filter(|p| p.contains("name = \"webpki-roots\""))
            .filter_map(|p| p.lines().find_map(|l| l.strip_prefix("version = \"")))
            .map(|v| v.trim_end_matches('"'))
            .collect();
        assert!(
            versions.contains(&pod_tls::ROOTS_VERSION),
            "webpki-roots in Cargo.lock: {versions:?}"
        );
        let newest = versions
            .iter()
            .filter(|v| v.starts_with("1."))
            .max()
            .unwrap();
        assert_eq!(*newest, pod_tls::ROOTS_VERSION);
    }

    /// The constant is the first notAfter of the edge roots, and it is
    /// in the future.
    #[test]
    fn the_first_end_of_the_edge_roots() {
        let mut dates = pod_tls::not_after_dates(crate::cloudflare::CF_EDGE_ROOTS_PEM).unwrap();
        assert!(dates.len() >= 3, "{dates:?}");
        dates.sort();
        assert_eq!(dates[0], EDGE_ROOTS_FIRST_END, "{dates:?}");
        let today = pod_core::clock::http_date(unix_secs(std::time::SystemTime::now()));
        let year: i32 = today[12..16].parse().unwrap();
        let end: i32 = EDGE_ROOTS_FIRST_END[..4].parse().unwrap();
        assert!(end >= year, "an edge root ends on {EDGE_ROOTS_FIRST_END}");
    }

    /// Only these files may set a certificate verifier of their own: the
    /// origin option noTLSVerify (util/tls.rs, net.rs), the MASQUE key pin
    /// (warp/session.rs, which always compares the key), and the doctor
    /// (doctor.rs: it records the chain, gives the decision to webpki, and
    /// closes each session after the handshake with no data).
    #[test]
    fn no_other_code_sets_its_own_verifier() {
        const ALLOWED: &[&str] = &[
            "src/doctor.rs",
            "src/net.rs",
            "src/util/tls.rs",
            "src/warp/session.rs",
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut stack = vec![root.join("src"), root.join("crates/podnet-netns/src")];
        let mut found = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let marker = ["dangerous", "()"].concat();
                if text.contains(&marker)
                    || text.contains(&["impl ServerCert", "Verifier for"].concat())
                {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    found.push(rel);
                }
            }
        }
        found.sort();
        for file in &found {
            assert!(
                ALLOWED.contains(&file.as_str()),
                "{file} sets its own certificate verifier"
            );
        }
        assert_eq!(found.len(), ALLOWED.len(), "{found:?}");
    }
}
