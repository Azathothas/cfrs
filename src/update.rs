//! `cfrs update`: replace this binary with the binary of a release, after
//! these checks:
//!
//! 1. `SHA256SUMS.sigstore.json` (the cosign bundle) holds a certificate
//!    that chains to the Fulcio roots of Sigstore (`src/sigstore-fulcio.pem`)
//!    at the time of its log entry, for code signing.
//! 2. The certificate names `release.yml` of this repository at the tag of
//!    the release (`refs/tags/vX`), and the issuer of GitHub Actions.
//! 3. The signature of the bundle is valid over `SHA256SUMS`, with the key
//!    of the certificate, and the digest of the bundle is the SHA-256 of
//!    `SHA256SUMS`.
//! 4. The SHA-256 of the downloaded binary is its line in `SHA256SUMS`.
//! 5. The new binary runs and prints the version of the release.
//!
//! cfrs does not check the inclusion proof of the transparency log (Rekor).
//! All downloads use the TLS roots of [`crate::trust`] and the proxy of
//! [`crate::egress`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use base64::Engine;
use serde::Deserialize;

/// The repository of the releases.
pub const REPOSITORY: &str = "Azathothas/cfrs";
/// The issuer of the GitHub Actions tokens.
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The Fulcio intermediate and root certificates of Sigstore (the public
/// instance), from the trusted root of sigstore/root-signing.
pub const FULCIO_PEM: &[u8] = include_bytes!("sigstore-fulcio.pem");
/// The target triple of this binary.
pub const TARGET: &str = env!("CFRS_BUILD_TARGET");

/// The release asset for the target `target`: the static musl binary of the
/// same architecture (a release ships no glibc binary, and a static binary
/// runs on a glibc host too).
pub fn asset_target(target: &str) -> String {
    target
        .replace("-gnueabihf", "-musleabihf")
        .replace("-gnueabi", "-musleabi")
        .replace("-gnu", "-musl")
}

/// One release of the GitHub API.
#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

impl Release {
    fn asset(&self, name: &str) -> Result<&Asset> {
        self.assets
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("the release {} has no file {name}", self.tag_name))
    }
}

/// The identity that the certificate of `tag` must name.
pub fn identity(tag: &str) -> String {
    format!("https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}")
}

/// The largest release binary that `cfrs update` downloads. The binaries are
/// about 14 MB; [`crate::fetch::MAX_BODY`] (16 MiB) is too near.
pub const MAX_BINARY: usize = 128 << 20;

/// GET `url` with a body of at most `max_body` bytes, and follow up to 5
/// redirects.
async fn get(url: &str, timeout: Duration, max_body: usize) -> Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..6 {
        let response = crate::fetch::Request::new("GET", url.clone())
            .header("Accept", "application/octet-stream, application/json")
            .timeout(timeout)
            .max_body(max_body)
            .send()
            .await?;
        match response.status {
            200 => return Ok(response.body),
            301 | 302 | 303 | 307 | 308 => {
                url = response
                    .header("location")
                    .context("a redirect with no Location")?
                    .to_string();
                if !url.starts_with("https://") {
                    bail!("a redirect away from HTTPS");
                }
            }
            status => bail!("GET {}: HTTP {status}", url.split('?').next().unwrap_or("")),
        }
    }
    bail!("too many redirects")
}

/// The releases, newest first.
pub async fn releases() -> Result<Vec<Release>> {
    let body = get(
        &format!("https://api.github.com/repos/{REPOSITORY}/releases?per_page=30"),
        Duration::from_secs(30),
        crate::fetch::MAX_BODY,
    )
    .await
    .context("reading the list of releases")?;
    serde_json::from_slice(&body).context("decoding the list of releases")
}

/// The release to install: `tag`, or the newest release. A prerelease is
/// taken only with `tag`, or when this binary is a prerelease.
pub fn choose<'a>(
    releases: &'a [Release],
    tag: Option<&str>,
    current: &str,
) -> Result<&'a Release> {
    if let Some(tag) = tag {
        return releases
            .iter()
            .find(|r| r.tag_name == tag && !r.draft)
            .with_context(|| format!("no release has the tag {tag}"));
    }
    let pre = current.contains('-');
    releases
        .iter()
        .find(|r| !r.draft && (pre || !r.prerelease))
        .context("no release found")
}

/// The fields of the cosign bundle that cfrs checks.
#[derive(Debug, Deserialize)]
struct Bundle {
    #[serde(rename = "verificationMaterial")]
    material: Material,
    #[serde(rename = "messageSignature")]
    signature: MessageSignature,
}

#[derive(Debug, Deserialize)]
struct Material {
    certificate: Option<RawBytes>,
    #[serde(rename = "x509CertificateChain")]
    chain: Option<Chain>,
    #[serde(rename = "tlogEntries", default)]
    tlog: Vec<TlogEntry>,
}

#[derive(Debug, Deserialize)]
struct Chain {
    certificates: Vec<RawBytes>,
}

#[derive(Debug, Deserialize)]
struct RawBytes {
    #[serde(rename = "rawBytes")]
    raw: String,
}

#[derive(Debug, Deserialize)]
struct TlogEntry {
    #[serde(rename = "integratedTime")]
    integrated_time: String,
}

#[derive(Debug, Deserialize)]
struct MessageSignature {
    #[serde(rename = "messageDigest")]
    digest: MessageDigest,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct MessageDigest {
    algorithm: String,
    digest: String,
}

fn b64(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .context("bad base64")
}

/// Check the cosign bundle `bundle` over `sums`, for the tag `tag`. See the
/// checks 1 to 3 of the module.
pub fn verify_bundle(bundle: &[u8], sums: &[u8], tag: &str) -> Result<()> {
    use ring::digest::{digest, SHA256};
    let bundle: Bundle = serde_json::from_slice(bundle).context("decoding the cosign bundle")?;
    let leaf = match (&bundle.material.certificate, &bundle.material.chain) {
        (Some(cert), _) => b64(&cert.raw)?,
        (None, Some(chain)) => b64(&chain.certificates.first().context("an empty chain")?.raw)?,
        (None, None) => bail!("the bundle has no certificate"),
    };
    let time = bundle
        .material
        .tlog
        .first()
        .context("the bundle has no log entry")?
        .integrated_time
        .parse::<u64>()
        .context("the time of the log entry")?;

    // 1. The chain to the Fulcio roots, at the time of the log entry.
    use rustls::pki_types::pem::PemObject;
    let mut pems = rustls::pki_types::CertificateDer::pem_slice_iter(FULCIO_PEM)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("the embedded Fulcio roots")?;
    let root = pems.pop().context("no Fulcio root")?;
    let anchor = webpki::anchor_from_trusted_cert(&root)
        .context("the Fulcio root")?
        .to_owned();
    let leaf_der = rustls::pki_types::CertificateDer::from(leaf.clone());
    let end =
        webpki::EndEntityCert::try_from(&leaf_der).context("the certificate of the bundle")?;
    const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    end.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &pems,
        rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(time)),
        webpki::KeyUsage::required(CODE_SIGNING),
        None,
        None,
    )
    .map_err(|e| anyhow::anyhow!("the certificate does not chain to Fulcio: {e:?}"))?;

    // 2. The identity and the issuer.
    let (_, cert) =
        x509_parser::parse_x509_certificate(&leaf).context("parsing the certificate")?;
    let want = identity(tag);
    let mut uris = Vec::new();
    let mut issuer = None;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::URI(uri) = name {
                        uris.push(uri.to_string());
                    }
                }
            }
            _ => {
                let oid = ext.oid.to_id_string();
                if oid == "1.3.6.1.4.1.57264.1.1" {
                    issuer = Some(String::from_utf8_lossy(ext.value).into_owned());
                } else if oid == "1.3.6.1.4.1.57264.1.8" && issuer.is_none() {
                    // A DER UTF8String: tag, length, text.
                    issuer = ext
                        .value
                        .get(2..)
                        .map(|v| String::from_utf8_lossy(v).into_owned());
                }
            }
        }
    }
    if !uris.contains(&want) {
        bail!("the certificate names {uris:?}, not {want}");
    }
    if issuer.as_deref() != Some(ISSUER) {
        bail!("the certificate has the issuer {issuer:?}, not {ISSUER}");
    }

    // 3. The digest and the signature over SHA256SUMS.
    if bundle.signature.digest.algorithm != "SHA2_256" {
        bail!(
            "the bundle digest is {}, not SHA2_256",
            bundle.signature.digest.algorithm
        );
    }
    if b64(&bundle.signature.digest.digest)? != digest(&SHA256, sums).as_ref() {
        bail!("the digest of the bundle is not the SHA-256 of SHA256SUMS");
    }
    let key = cert.public_key().subject_public_key.data.to_vec();
    let signature = b64(&bundle.signature.signature)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, key)
        .verify(sums, &signature)
        .map_err(|_| anyhow::anyhow!("the signature over SHA256SUMS is not valid"))?;
    Ok(())
}

/// The SHA-256 of `name` in `sums` (the lines of `sha256sum`).
pub fn sum_of(sums: &[u8], name: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(sums).context("SHA256SUMS is not text")?;
    for line in text.lines() {
        if let Some((hex, file)) = line.split_once("  ") {
            if file.trim_start_matches('*') == name {
                return (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
                    .collect::<std::result::Result<Vec<u8>, _>>()
                    .context("a bad hash in SHA256SUMS");
            }
        }
    }
    bail!("SHA256SUMS has no line for {name}")
}

/// What `cfrs update` did.
#[derive(Debug)]
pub enum Outcome {
    UpToDate(String),
    Available {
        current: String,
        tag: String,
    },
    Updated {
        from: String,
        to: String,
        path: PathBuf,
    },
}

/// Update this binary (`check`: only say what is available).
pub async fn run(tag: Option<&str>, check: bool) -> Result<Outcome> {
    let current = format!("v{}", env!("CARGO_PKG_VERSION"));
    let releases = releases().await?;
    let release = choose(&releases, tag, &current)?;
    if tag.is_none() && release.tag_name == current {
        return Ok(Outcome::UpToDate(current));
    }
    if check {
        return Ok(Outcome::Available {
            current,
            tag: release.tag_name.clone(),
        });
    }
    let name = format!("cfrs-{}", asset_target(TARGET));
    let binary_url = release.asset(&name)?.browser_download_url.clone();
    let sums_url = release.asset("SHA256SUMS")?.browser_download_url.clone();
    let bundle_url = release
        .asset("SHA256SUMS.sigstore.json")?
        .browser_download_url
        .clone();
    let sums = get(&sums_url, Duration::from_secs(60), crate::fetch::MAX_BODY)
        .await
        .context("SHA256SUMS")?;
    let bundle = get(&bundle_url, Duration::from_secs(60), crate::fetch::MAX_BODY)
        .await
        .context("SHA256SUMS.sigstore.json")?;
    verify_bundle(&bundle, &sums, &release.tag_name)
        .with_context(|| format!("checking the signature of {}", release.tag_name))?;
    let want = sum_of(&sums, &name)?;
    let binary = get(&binary_url, Duration::from_secs(300), MAX_BINARY)
        .await
        .context(name.clone())?;
    let got = ring::digest::digest(&ring::digest::SHA256, &binary);
    if got.as_ref() != want.as_slice() {
        bail!("the SHA-256 of {name} is not its line in SHA256SUMS");
    }
    let path = std::env::current_exe()
        .context("finding this binary")?
        .canonicalize()
        .context("finding this binary")?;
    install(&path, &binary, &release.tag_name)?;
    Ok(Outcome::Updated {
        from: current,
        to: release.tag_name.clone(),
        path,
    })
}

/// How long the new binary may take to print its version.
pub const TRIAL_LIMIT: Duration = Duration::from_secs(10);

/// The kept binary beside `path`: `cfrs.prev` for `cfrs`.
pub fn previous_of(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".prev");
    path.with_file_name(name)
}

/// Run `path --version` with no stdin, for at most `limit`. It must exit 0,
/// and its first line must start with `want`. A text file that is busy
/// (ETXTBSY, just after the write) is tried again.
pub fn trial(path: &Path, want: &str, limit: Duration) -> Result<()> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    const TEXT_BUSY: i32 = 26;
    let mut tries = 0;
    let mut child = loop {
        match Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => break child,
            Err(err) if err.raw_os_error() == Some(TEXT_BUSY) && tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(err).with_context(|| format!("running {}", path.display())),
        }
    };
    // Read stdout in a thread, so a long answer cannot block the child.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.by_ref().take(64 * 1024).read_to_end(&mut out);
        out
    });
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{} did not answer --version in {} s",
                path.display(),
                limit.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        bail!("{} --version exits with {status}", path.display());
    }
    let text = String::from_utf8_lossy(&out);
    let first = text.lines().next().unwrap_or("");
    if !first.starts_with(want) {
        bail!("{} prints {:?}, not {want}…", path.display(), first.trim());
    }
    Ok(())
}

/// Sync the directory, so a rename stays after a power loss.
fn sync_dir(dir: &Path) {
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
}

/// Keep a copy of `path` as `previous`: a hard link, or a copy when a link
/// is not possible, put in place with a rename.
fn keep(path: &Path, previous: &Path) -> Result<()> {
    let tmp = previous.with_file_name(format!(".cfrs-prev-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(path, &tmp).is_err() {
        std::fs::copy(path, &tmp)
            .with_context(|| format!("keeping a copy of {}", path.display()))?;
    }
    std::fs::rename(&tmp, previous).with_context(|| format!("writing {}", previous.display()))
}

/// Put `binary` in place of `path`: a new file beside it (mode 0755), which
/// must pass [`trial`] for `tag`; then the binary before is kept as
/// [`previous_of`], and a rename puts the new file in place.
pub fn install(path: &Path, binary: &[u8], tag: &str) -> Result<()> {
    install_with(path, binary, tag, TRIAL_LIMIT)
}

fn install_with(path: &Path, binary: &[u8], tag: &str, limit: Duration) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().context("the binary has no directory")?;
    let tmp = dir.join(format!(".cfrs-update-{}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&tmp)
            .with_context(|| format!("writing in {} (no write permission?)", dir.display()))?;
        file.write_all(binary)?;
        file.sync_all()?;
        drop(file);
        let want = format!("cfrs {} ", tag.trim_start_matches('v'));
        trial(&tmp, &want, limit).context("the new binary")?;
        keep(path, &previous_of(path))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        sync_dir(dir);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Put the kept binary ([`previous_of`]) back in place of `path`, with no
/// network. The kept binary must pass [`trial`] first. The binary that was
/// in place becomes the kept binary, so a second rollback goes forward
/// again. Gives the first line of `--version` of the binary now in place.
pub fn rollback(path: &Path) -> Result<String> {
    rollback_with(path, TRIAL_LIMIT)
}

fn rollback_with(path: &Path, limit: Duration) -> Result<String> {
    let previous = previous_of(path);
    if !previous.exists() {
        bail!(
            "no kept binary at {}: cfrs update keeps one from 0.3.0-beta.5 on",
            previous.display()
        );
    }
    trial(&previous, "cfrs ", limit).context("the kept binary")?;
    let dir = path.parent().context("the binary has no directory")?;
    let held = dir.join(format!(".cfrs-rollback-{}", std::process::id()));
    let _ = std::fs::remove_file(&held);
    if std::fs::hard_link(path, &held).is_err() {
        std::fs::copy(path, &held).with_context(|| format!("keeping {}", path.display()))?;
    }
    std::fs::rename(&previous, path).with_context(|| format!("replacing {}", path.display()))?;
    std::fs::rename(&held, &previous).with_context(|| format!("writing {}", previous.display()))?;
    sync_dir(dir);
    let out = std::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell script in the place of a cfrs binary.
    fn fake(version_line: &str, extra: &str) -> Vec<u8> {
        format!("#!/bin/sh\n{extra}\necho '{version_line}'\n").into_bytes()
    }

    fn put(path: &Path, body: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn version_of(path: &Path) -> String {
        let out = std::process::Command::new(path)
            .arg("--version")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// An update keeps the binary before as cfrs.prev; a rollback puts it
    /// back, and a second rollback goes forward again.
    #[test]
    fn install_keeps_the_binary_before_and_rollback_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfrs");
        put(&path, &fake("cfrs 0.3.0-beta.4 (old)", ""));
        install(&path, &fake("cfrs 0.3.0-beta.5 (new)", ""), "v0.3.0-beta.5").unwrap();
        assert_eq!(version_of(&path), "cfrs 0.3.0-beta.5 (new)");
        assert_eq!(version_of(&previous_of(&path)), "cfrs 0.3.0-beta.4 (old)");
        assert_eq!(rollback(&path).unwrap(), "cfrs 0.3.0-beta.4 (old)");
        assert_eq!(version_of(&previous_of(&path)), "cfrs 0.3.0-beta.5 (new)");
        assert_eq!(rollback(&path).unwrap(), "cfrs 0.3.0-beta.5 (new)");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "no temporary file stays: {names:?}");
    }

    /// The trial refuses a binary that exits with an error, that prints
    /// another version, or that does not answer in time. The binary in
    /// place does not change, and no file stays.
    #[test]
    fn a_bad_new_binary_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfrs");
        put(&path, &fake("cfrs 0.3.0-beta.4 (old)", ""));
        let cases = [
            fake("cfrs 0.3.0-beta.5 (new)", "exit 3"),
            fake("cfrs 0.3.0-beta.5 (new)", "")
                .into_iter()
                .chain(b"exit 1\n".iter().copied())
                .collect(),
            fake("cfrs 0.2.0 (other)", ""),
            fake("cfrs 0.3.0-beta.5 (new)", "sleep 30"),
        ];
        for body in cases {
            let err = install_with(&path, &body, "v0.3.0-beta.5", Duration::from_millis(500))
                .expect_err("a bad binary is refused");
            assert!(format!("{err:#}").contains("new binary"), "{err:#}");
            assert_eq!(version_of(&path), "cfrs 0.3.0-beta.4 (old)");
            assert!(!previous_of(&path).exists());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    /// A rollback with no kept binary, or with a kept binary that fails its
    /// trial, changes nothing.
    #[test]
    fn rollback_needs_a_kept_binary_that_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfrs");
        put(&path, &fake("cfrs 0.3.0-beta.5 (new)", ""));
        assert!(format!("{:#}", rollback(&path).unwrap_err()).contains("no kept binary"));
        put(
            &previous_of(&path),
            &fake("cfrs 0.3.0-beta.4 (old)", "exit 2"),
        );
        assert!(rollback_with(&path, Duration::from_millis(500)).is_err());
        assert_eq!(version_of(&path), "cfrs 0.3.0-beta.5 (new)");
    }

    const SUMS: &[u8] = include_bytes!("../tests/data/v0.3.0-beta.1.SHA256SUMS");
    const BUNDLE: &[u8] = include_bytes!("../tests/data/v0.3.0-beta.1.SHA256SUMS.sigstore.json");

    /// The real files of v0.3.0-beta.1: the bundle passes for its tag, and
    /// fails for another tag, for a changed SHA256SUMS and for a changed
    /// signature.
    #[test]
    fn the_bundle_of_a_release() {
        verify_bundle(BUNDLE, SUMS, "v0.3.0-beta.1").unwrap();

        let err = verify_bundle(BUNDLE, SUMS, "v0.3.0-beta.2")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not https://github.com/Azathothas/cfrs/.github/workflows/release.yml@refs/tags/v0.3.0-beta.2"), "{err}");

        let mut changed = SUMS.to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        let err = verify_bundle(BUNDLE, &changed, "v0.3.0-beta.1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest"), "{err}");

        let text = std::str::from_utf8(BUNDLE).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let sig = v["messageSignature"]["signature"].as_str().unwrap();
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(sig)
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let bad = text.replace(sig, &base64::engine::general_purpose::STANDARD.encode(raw));
        let err = verify_bundle(bad.as_bytes(), SUMS, "v0.3.0-beta.1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("signature"), "{err}");
    }

    #[test]
    fn a_glibc_build_takes_the_musl_asset() {
        assert_eq!(
            asset_target("x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            asset_target("armv7-unknown-linux-gnueabihf"),
            "armv7-unknown-linux-musleabihf"
        );
        assert_eq!(
            asset_target("riscv64gc-unknown-linux-musl"),
            "riscv64gc-unknown-linux-musl"
        );
    }

    #[test]
    fn a_line_of_sha256sums() {
        let sum = sum_of(SUMS, "cfrs-x86_64-unknown-linux-musl").unwrap();
        assert_eq!(sum.len(), 32);
        assert!(sum_of(SUMS, "cfrs-sparc-unknown-linux-musl").is_err());
    }

    #[test]
    fn the_choice_of_a_release() {
        let r = |tag: &str, pre: bool| Release {
            tag_name: tag.into(),
            prerelease: pre,
            draft: false,
            assets: Vec::new(),
        };
        let list = vec![
            r("v0.4.0-beta.1", true),
            r("v0.3.0", false),
            r("v0.3.0-beta.1", true),
        ];
        assert_eq!(choose(&list, None, "v0.3.0").unwrap().tag_name, "v0.3.0");
        assert_eq!(
            choose(&list, None, "v0.3.0-beta.1").unwrap().tag_name,
            "v0.4.0-beta.1"
        );
        assert_eq!(
            choose(&list, Some("v0.3.0-beta.1"), "v0.3.0")
                .unwrap()
                .tag_name,
            "v0.3.0-beta.1"
        );
        assert!(choose(&list, Some("v9"), "v0.3.0").is_err());
    }
}
