//! The roots that cfrs trusts for each TLS connection that it opens as a
//! client: the quick-tunnel API, DNS over HTTPS, the WARP API, the fetch of
//! the public URL, the edge, and HTTPS origins.
//!
//! The order:
//!
//! 1. A file given with `--ca-file`, else the file in `SSL_CERT_FILE`. The file
//!    is used alone: cfrs adds no other root to it.
//! 2. Else all of these: `cfrs-ca.pem` beside the binary, the first readable
//!    bundle of [`SYSTEM_BUNDLES`], and the Mozilla roots compiled into cfrs
//!    (webpki-roots [`ROOTS_CRATE_VERSION`]).
//!
//! The edge also trusts the Cloudflare roots of `cf-edge-roots.pem`. cfrs has
//! no option that accepts each certificate for these connections; only an
//! origin can turn off the check (`noTLSVerify`, `--no-tls-verify`).
//!
//! When a certificate is expired or not valid yet, [`clock_hint`] gives the
//! clock of the host, because a wrong clock is a frequent cause on a small
//! host or in a container.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use rustls::RootCertStore;

/// The variable that names a file of roots, as in OpenSSL.
pub const CA_FILE_VARIABLE: &str = "SSL_CERT_FILE";
/// The name of the file of roots beside the binary.
pub const BESIDE_BINARY: &str = "cfrs-ca.pem";
/// The system bundles, in the order cfrs tries them. cfrs uses the first
/// that it can read.
pub const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
];
/// The version of webpki-roots (in Cargo.lock) whose roots are compiled in.
pub const ROOTS_CRATE_VERSION: &str = "1.0.11";
/// The first date when a root of `cf-edge-roots.pem` stops being valid.
pub const EDGE_ROOTS_FIRST_END: &str = "2029-08-15";

static CA_FILE: OnceLock<PathBuf> = OnceLock::new();
static ROOTS: OnceLock<Result<Arc<Roots>, String>> = OnceLock::new();

/// Use `path` as the only file of roots (`--ca-file`). Call it before the
/// first connection; a later call has no effect.
pub fn set_ca_file(path: PathBuf) {
    let _ = CA_FILE.set(path);
}

/// The roots, and where they came from.
#[derive(Debug)]
pub struct Roots {
    pub store: Arc<RootCertStore>,
    /// For example `SSL_CERT_FILE /etc/corp.pem (2 roots)`.
    pub sources: Vec<String>,
}

/// The roots of this process. They are read one time.
pub fn roots() -> Result<Arc<Roots>> {
    ROOTS
        .get_or_init(|| {
            let explicit = CA_FILE.get().map(|p| ("--ca-file", p.clone())).or_else(|| {
                std::env::var_os(CA_FILE_VARIABLE)
                    .filter(|v| !v.is_empty())
                    .map(|v| (CA_FILE_VARIABLE, PathBuf::from(v)))
            });
            let beside = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join(BESIDE_BINARY)));
            load(explicit, beside.as_deref(), SYSTEM_BUNDLES)
                .map(Arc::new)
                .map_err(|e| format!("{e:#}"))
        })
        .clone()
        .map_err(|e| anyhow::anyhow!(e))
}

/// Read the roots. `explicit` is the file of `--ca-file` or `SSL_CERT_FILE`,
/// with the name of its source.
pub fn load(
    explicit: Option<(&str, PathBuf)>,
    beside: Option<&Path>,
    bundles: &[&str],
) -> Result<Roots> {
    let mut store = RootCertStore::empty();
    let mut sources = Vec::new();
    if let Some((source, path)) = explicit {
        let n =
            add_file(&mut store, &path).with_context(|| format!("{source} {}", path.display()))?;
        if n == 0 {
            bail!("{source} {}: the file has no certificate", path.display());
        }
        sources.push(format!("{source} {} ({n} roots)", path.display()));
        return Ok(Roots {
            store: Arc::new(store),
            sources,
        });
    }
    if let Some(path) = beside.filter(|p| p.is_file()) {
        let n = add_file(&mut store, path).with_context(|| format!("{}", path.display()))?;
        sources.push(format!("{} ({n} roots)", path.display()));
    }
    for bundle in bundles {
        let path = Path::new(bundle);
        if let Ok(n) = add_file(&mut store, path) {
            if n > 0 {
                sources.push(format!("{bundle} ({n} roots)"));
                break;
            }
        }
    }
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    sources.push(format!(
        "webpki-roots {ROOTS_CRATE_VERSION} ({} roots)",
        webpki_roots::TLS_SERVER_ROOTS.len()
    ));
    Ok(Roots {
        store: Arc::new(store),
        sources,
    })
}

/// Add the certificates of the PEM file `path`. A certificate that rustls
/// cannot use as a root is skipped; a file that cannot be read or parsed is
/// an error. Gives the number of roots added.
fn add_file(store: &mut RootCertStore, path: &Path) -> Result<usize> {
    let pem = std::fs::read(path).context("reading the file")?;
    let mut added = 0;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.context("parsing the PEM")?;
        if store.add(cert).is_ok() {
            added += 1;
        }
    }
    Ok(added)
}

/// A rustls client configuration with [`roots`] and the extra roots
/// `extra` (the Cloudflare edge roots for the edge), and the ALPN `alpn`.
pub fn client_config(extra: &[&[u8]], alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    crate::init_crypto();
    let roots = roots()?;
    let store = if extra.is_empty() {
        (*roots.store).clone()
    } else {
        let mut store = (*roots.store).clone();
        for pem in extra {
            for cert in CertificateDer::pem_slice_iter(pem) {
                let _ = store.add(cert.context("parsing the embedded roots")?);
            }
        }
        store
    };
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// For an error of an expired certificate, or of one that is not valid yet:
/// a line that gives the clock of this host. Else `None`.
pub fn clock_hint(err: &anyhow::Error) -> Option<String> {
    let text = format!("{err:#} {err:?}").to_ascii_lowercase();
    let about_time = [
        "certificate expired",
        "expired certificate",
        "notvalidyet",
        "not valid yet",
        "expired",
    ]
    .iter()
    .any(|needle| text.contains(needle))
        && text.contains("cert");
    about_time.then(|| {
        format!(
            "certificates are checked against the clock of this host, which reads {}",
            imf_fixdate(SystemTime::now())
        )
    })
}

/// `time` as an HTTP date (IMF-fixdate), for example
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn imf_fixdate(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|e| -(e.duration().as_secs() as i64));
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The date of day `days` after 1970-01-01 (the algorithm of H. Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The notAfter dates (`YYYY-MM-DD`) of the certificates of a PEM text.
pub fn not_after_dates(pem: &[u8]) -> Result<Vec<String>> {
    let mut dates = Vec::new();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.context("parsing the PEM")?;
        dates.push(not_after(cert.as_ref()).context("reading the validity")?);
    }
    Ok(dates)
}

/// The notAfter of a DER certificate: Certificate -> TBSCertificate ->
/// (version, serial, signature, issuer, validity).
fn not_after(der: &[u8]) -> Result<String> {
    fn tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
        let (&tag, rest) = data.split_first().context("no tag")?;
        let (&first, rest) = rest.split_first().context("no length")?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                bail!("bad length");
            }
            let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
            (len, &rest[n..])
        };
        if rest.len() < len {
            bail!("short value");
        }
        Ok((tag, &rest[..len], &rest[len..]))
    }
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    let (tag, _, after) = tlv(rest)?;
    if tag == 0xa0 {
        rest = after; // the explicit version
    }
    for _ in 0..3 {
        rest = tlv(rest)?.2; // serial, signature, issuer
    }
    let (_, validity, _) = tlv(rest)?;
    let (_, _, after_start) = tlv(validity)?;
    let (tag, end, _) = tlv(after_start)?;
    let end = std::str::from_utf8(end)?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: u32 = end[..2].parse()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &end[2..])
        }
        0x18 => (end[..4].parse()?, &end[4..]),
        _ => bail!("the time has tag {tag:#x}"),
    };
    Ok(format!("{year:04}-{}-{}", &rest[..2], &rest[2..4]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dates_of_imf_fixdate() {
        let at =
            |secs: u64| imf_fixdate(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs));
        assert_eq!(at(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(at(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(at(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(at(2_208_988_800), "Sun, 01 Jan 2040 00:00:00 GMT");
    }

    /// The constant is the version of webpki-roots in Cargo.lock.
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
            versions.contains(&ROOTS_CRATE_VERSION),
            "webpki-roots in Cargo.lock: {versions:?}"
        );
        let newest = versions
            .iter()
            .filter(|v| v.starts_with("1."))
            .max()
            .unwrap();
        assert_eq!(*newest, ROOTS_CRATE_VERSION);
    }

    /// The constant is the first notAfter of the edge roots, and it is
    /// in the future.
    #[test]
    fn the_first_end_of_the_edge_roots() {
        let mut dates = not_after_dates(crate::cloudflare::CF_EDGE_ROOTS_PEM).unwrap();
        assert!(dates.len() >= 3, "{dates:?}");
        dates.sort();
        assert_eq!(dates[0], EDGE_ROOTS_FIRST_END, "{dates:?}");
        let today = imf_fixdate(SystemTime::now());
        let year: i32 = today[12..16].parse().unwrap();
        let end: i32 = EDGE_ROOTS_FIRST_END[..4].parse().unwrap();
        assert!(end >= year, "an edge root ends on {EDGE_ROOTS_FIRST_END}");
    }

    #[test]
    fn an_explicit_file_is_used_alone() {
        let dir = tempfile::tempdir().unwrap();
        let ca = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&ca).unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, cert.pem()).unwrap();

        let roots = load(Some(("SSL_CERT_FILE", path.clone())), None, SYSTEM_BUNDLES).unwrap();
        assert_eq!(roots.store.len(), 1);
        assert!(roots.sources[0].starts_with("SSL_CERT_FILE"));

        let all = load(None, Some(&path), &[]).unwrap();
        assert_eq!(
            all.store.len(),
            1 + webpki_roots::TLS_SERVER_ROOTS.len(),
            "{:?}",
            all.sources
        );

        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let err = load(Some(("--ca-file", empty)), None, &[]).unwrap_err();
        assert!(err.to_string().contains("has no certificate"), "{err}");
    }

    /// Only these files may set a certificate verifier of their own: the
    /// origin option noTLSVerify (util/tls.rs, net.rs) and the MASQUE key pin
    /// (warp/session.rs, which always compares the key).
    #[test]
    fn no_other_code_sets_its_own_verifier() {
        const ALLOWED: &[&str] = &["src/util/tls.rs", "src/net.rs", "src/warp/session.rs"];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut stack = vec![root.join("src"), root.join("crates/pod-netns/src")];
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

    #[test]
    fn the_clock_hint_names_the_host_date() {
        let err = anyhow::anyhow!("invalid peer certificate: Expired").context("TLS handshake");
        let hint = clock_hint(&err).unwrap();
        assert!(
            hint.contains("which reads ") && hint.ends_with(" GMT"),
            "{hint}"
        );
        assert!(clock_hint(&anyhow::anyhow!("connection refused")).is_none());
    }
}
