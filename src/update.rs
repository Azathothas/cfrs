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

/// GET `url`, and follow up to 5 redirects.
async fn get(url: &str, timeout: Duration) -> Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..6 {
        let response = crate::fetch::Request::new("GET", url.clone())
            .header("Accept", "application/octet-stream, application/json")
            .timeout(timeout)
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
    let sums = get(&sums_url, Duration::from_secs(60))
        .await
        .context("SHA256SUMS")?;
    let bundle = get(&bundle_url, Duration::from_secs(60))
        .await
        .context("SHA256SUMS.sigstore.json")?;
    verify_bundle(&bundle, &sums, &release.tag_name)
        .with_context(|| format!("checking the signature of {}", release.tag_name))?;
    let want = sum_of(&sums, &name)?;
    let binary = get(&binary_url, Duration::from_secs(300))
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

/// Put `binary` in place of `path`: a new file beside it (mode 0755), which
/// must run and print the version of `tag`, then a rename.
pub fn install(path: &Path, binary: &[u8], tag: &str) -> Result<()> {
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
        let out = std::process::Command::new(&tmp)
            .arg("--version")
            .output()
            .context("running the new binary")?;
        let version = String::from_utf8_lossy(&out.stdout);
        let want = format!("cfrs {} ", tag.trim_start_matches('v'));
        if !version.starts_with(&want) {
            bail!("the new binary prints {:?}, not {want}…", version.trim());
        }
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
