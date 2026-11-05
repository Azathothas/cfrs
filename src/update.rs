//! `podnet update`: replace this binary with the binary of a release, after
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
//! podnet does not check the inclusion proof of the transparency log (Rekor).
//! All downloads use the TLS roots of [`crate::trust`] and the proxy of
//! [`crate::egress`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use base64::Engine;
use serde::Deserialize;

/// The repository of the releases.
pub const REPOSITORY: &str = "PodUtils/podnet";
/// The issuer of the GitHub Actions tokens.
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The Fulcio intermediate and root certificates of Sigstore (the public
/// instance), from the trusted root of sigstore/root-signing.
pub const FULCIO_PEM: &[u8] = include_bytes!("sigstore-fulcio.pem");
/// The target triple of this binary.
pub const TARGET: &str = env!("PODNET_BUILD_TARGET");

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
    /// The release of `tag` with no request to the GitHub API (issue 166):
    /// the URLs of its files follow from the tag. The checks of the
    /// signature and of SHA-256 do not change.
    pub fn pinned(tag: &str) -> Release {
        let asset = |name: String| Asset {
            browser_download_url: format!(
                "https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
            ),
            name,
        };
        Release {
            tag_name: tag.to_string(),
            prerelease: tag.contains('-'),
            draft: false,
            assets: vec![
                asset(format!("podnet-{}", asset_target(TARGET))),
                asset("SHA256SUMS".into()),
                asset("SHA256SUMS.sigstore.json".into()),
            ],
        }
    }

    fn asset(&self, name: &str) -> Result<&Asset> {
        self.assets
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("the release {} has no file {name}", self.tag_name))
    }
}

/// The identity that the certificate of `tag` must name.
pub fn identity(tag: &str) -> String {
    identity_in(REPOSITORY, tag)
}

/// The identity of `tag` of the repository `repository`.
pub fn identity_in(repository: &str, tag: &str) -> String {
    format!("https://github.com/{repository}/.github/workflows/release.yml@refs/tags/{tag}")
}

/// The largest release binary that `podnet update` downloads. The binaries are
/// about 14 MB; [`crate::fetch::MAX_BODY`] (16 MiB) is too near.
pub const MAX_BINARY: usize = 128 << 20;

/// An HTTP status other than 200 and a redirect.
#[derive(Debug)]
pub struct HttpStatus(pub u16);

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}", self.0)
    }
}

impl std::error::Error for HttpStatus {}

/// GET `url` with a body of at most `max_body` bytes, and follow up to 5
/// redirects.
async fn get(url: &str, timeout: Duration, max_body: usize) -> Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..6 {
        let request = crate::fetch::Request::new("GET", url.clone())
            .header("Accept", "application/octet-stream, application/json")
            .timeout(timeout)
            .max_body(max_body);
        let response = crate::fetch::send(request).await?;
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
            status => {
                return Err(anyhow::Error::new(HttpStatus(status))
                    .context(format!("GET {}", url.split('?').next().unwrap_or(""))))
            }
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

/// True when `tag` can be a release tag: 1 to 64 characters of
/// `0-9 A-Z a-z . + -`, the first `v` or a digit, and no `..`. Issue 227: a
/// tag goes into the URLs of the files and into the identity of the
/// signature, so a `/` or a `..` must not pass.
pub fn valid_tag(tag: &str) -> bool {
    (1..=64).contains(&tag.len())
        && tag.starts_with(|c: char| c == 'v' || c.is_ascii_digit())
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        && !tag.contains("..")
}

/// The tags of a releases.atom feed, newest first. A text that is not a
/// [`valid_tag`] is skipped.
pub fn atom_tags(feed: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for part in feed.split("/releases/tag/").skip(1) {
        let tag: String = part
            .chars()
            .take_while(|c| !matches!(c, '"' | '<' | '\'' | ' '))
            .collect();
        if valid_tag(&tag) && !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    tags
}

/// The newest tag of releases.atom that `current` takes: a prerelease
/// (a tag with `-`) only when this binary is a prerelease, as [`choose`].
pub fn newest_in_atom(feed: &str, current: &str) -> Option<String> {
    let pre = current.contains('-');
    atom_tags(feed)
        .into_iter()
        .filter(|tag| pre || !tag.contains('-'))
        .max_by(|a, b| version_order(a, b))
}

/// The order of two tags as versions (`v0.3.0-beta.10` after
/// `v0.3.0-beta.9`; a release after its prereleases). The GitHub API and
/// the feed do not give the newest first: the API lists by tag name, so
/// `v0.3.0-beta.10` came after `v0.3.0-beta.7`, and an update took
/// `v0.3.0-beta.9` as the newest.
pub fn version_order(a: &str, b: &str) -> std::cmp::Ordering {
    fn key(tag: &str) -> (Vec<u64>, bool, Vec<(u64, String)>) {
        let tag = tag.trim_start_matches('v');
        let (core, pre) = match tag.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (tag, None),
        };
        let core = core.split('.').map(|n| n.parse().unwrap_or(0)).collect();
        // A numeric part compares as a number, a word as text.
        let parts = pre
            .map(|p| {
                p.split('.')
                    .map(|x| match x.parse::<u64>() {
                        Ok(n) => (n, String::new()),
                        Err(_) => (0, x.to_string()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        (core, pre.is_none(), parts)
    }
    let (ca, sa, pa) = key(a);
    let (cb, sb, pb) = key(b);
    ca.cmp(&cb).then(sa.cmp(&sb)).then_with(|| {
        let word = |v: &Vec<(u64, String)>| v.iter().map(|(_, w)| w.clone()).collect::<Vec<_>>();
        word(&pa).cmp(&word(&pb)).then(pa.cmp(&pb))
    })
}

/// The newest release: the GitHub API, else releases.atom (issue 166: the
/// API answers 403 on a shared address; the feed has no quota).
async fn newest(current: &str) -> Result<Release> {
    let api = match releases().await {
        Ok(list) => return Ok(choose(&list, None, current)?.clone()),
        Err(err) => err,
    };
    tracing::info!(error = %format!("{api:#}"), "the GitHub API did not answer; reading releases.atom");
    let feed = get(
        &format!("https://github.com/{REPOSITORY}/releases.atom"),
        Duration::from_secs(30),
        crate::fetch::MAX_BODY,
    )
    .await
    .map_err(|atom| anyhow::anyhow!("{api:#}; releases.atom: {atom:#}"))
    .context("reading the list of releases")?;
    let tag = newest_in_atom(&String::from_utf8_lossy(&feed), current)
        .context("releases.atom has no release")?;
    Ok(Release::pinned(&tag))
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
        .filter(|r| !r.draft && (pre || !r.prerelease) && valid_tag(&r.tag_name))
        .max_by(|a, b| version_order(&a.tag_name, &b.tag_name))
        .context("no release found")
}

/// The fields of the cosign bundle that podnet checks.
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
    verify_bundle_for(bundle, sums, &identity(tag))
}

/// [`verify_bundle`] for the certificate identity `want`.
pub fn verify_bundle_for(bundle: &[u8], sums: &[u8], want: &str) -> Result<()> {
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
    let want = want.to_string();
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

/// What `podnet update` did.
#[derive(Debug)]
pub enum Outcome {
    UpToDate(String),
    /// `--version` names the version of this binary (issue 197).
    Same(String),
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

/// The step before a download: nothing to do, only a report, or an install.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    UpToDate,
    Same,
    Available,
    Install,
}

/// What to do with the release `tag` (issue 197: `--version` of the
/// version of this binary does nothing, unless `force`; issue 275: also
/// with no `--version`, `force` installs the version of this binary again).
pub fn plan(tag: &str, current: &str, pinned: bool, check: bool, force: bool) -> Plan {
    if tag == current && !force {
        return if pinned { Plan::Same } else { Plan::UpToDate };
    }
    // With no --version, an older release is not an update: podnet never
    // goes back on its own (--version goes back on purpose). `force` does
    // not change this.
    if !pinned
        && !(force && tag == current)
        && version_order(tag, current) != std::cmp::Ordering::Greater
    {
        return Plan::UpToDate;
    }
    if check {
        Plan::Available
    } else {
        Plan::Install
    }
}

/// The warning when PODNET_REPO is set (issue 168): the repository of
/// `podnet update` is fixed, because it names the signer of the binary.
pub fn ignored_repo_warning(value: Option<std::ffi::OsString>) -> Option<String> {
    let value = value?;
    (value.to_string_lossy() != REPOSITORY).then(|| {
        format!(
            "PODNET_REPO={} is for scripts/install.sh; podnet update uses {REPOSITORY}",
            value.to_string_lossy()
        )
    })
}

/// Update this binary (`check`: only say what is available; `force`:
/// install the version of this binary again).
pub async fn run(tag: Option<&str>, check: bool, force: bool) -> Result<Outcome> {
    if let Some(warning) = ignored_repo_warning(std::env::var_os("PODNET_REPO")) {
        tracing::warn!("{warning}");
    }
    let current = format!("v{}", env!("CARGO_PKG_VERSION"));
    if let Some(tag) = tag.filter(|tag| !valid_tag(tag)) {
        bail!("not a release tag: {tag:?}");
    }
    // Issue 166: a pinned tag needs no list of the releases.
    let release = match tag {
        Some(tag) => Release::pinned(tag),
        None => newest(&current).await?,
    };
    let step = plan(&release.tag_name, &current, tag.is_some(), check, force);
    let name = format!("podnet-{}", asset_target(TARGET));
    let sums_url = release.asset("SHA256SUMS")?.browser_download_url.clone();
    let sums = match step {
        Plan::UpToDate => return Ok(Outcome::UpToDate(current)),
        Plan::Same => return Ok(Outcome::Same(current)),
        // A pinned tag: SHA256SUMS shows that the release exists.
        Plan::Available if tag.is_none() => None,
        Plan::Available | Plan::Install => Some(
            get(&sums_url, Duration::from_secs(60), crate::fetch::MAX_BODY)
                .await
                .map_err(|err| {
                    let missing = err
                        .chain()
                        .any(|e| matches!(e.downcast_ref::<HttpStatus>(), Some(HttpStatus(404))));
                    if missing {
                        anyhow::anyhow!("no release has the tag {}", release.tag_name)
                    } else {
                        err.context("SHA256SUMS")
                    }
                })?,
        ),
    };
    if step == Plan::Available {
        return Ok(Outcome::Available {
            current,
            tag: release.tag_name.clone(),
        });
    }
    let sums = sums.expect("fetched for an install");
    let binary_url = release.asset(&name)?.browser_download_url.clone();
    let bundle_url = release
        .asset("SHA256SUMS.sigstore.json")?
        .browser_download_url
        .clone();
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

/// The kept binary beside `path`: `podnet.prev` for `podnet`.
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
    let tmp = previous.with_file_name(format!(".podnet-prev-{}", std::process::id()));
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

/// The identity of a file: its device and its inode.
type FileId = (u64, u64);

/// Check that `path` is still the file `id` of the trial: a regular file
/// (not a symlink) of this user that other users cannot write (issue 236).
/// A check by the path leaves a short window before the rename; a process
/// that can write the directory can also rename its own file over the
/// binary, so the check is for a file of this user in a shared directory.
fn same_file(path: &Path, id: FileId) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let uid = unsafe { libc::geteuid() };
    if !meta.file_type().is_file()
        || (meta.dev(), meta.ino()) != id
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
    {
        bail!(
            "{} changed after its trial run; it is not installed",
            path.display()
        );
    }
    Ok(())
}

/// The identity of the file at `path` (not of a symlink target).
fn file_id(path: &Path) -> Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(test)]
thread_local! {
    /// A test hook: it runs after the trial and before the rename.
    static AFTER_TRIAL: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn after_trial(path: &Path) {
    if let Some(hook) = AFTER_TRIAL.with(|h| h.get()) {
        hook(path);
    }
}

#[cfg(not(test))]
fn after_trial(_path: &Path) {}

fn install_with(path: &Path, binary: &[u8], tag: &str, limit: Duration) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let dir = path.parent().context("the binary has no directory")?;
    let tmp = dir.join(format!(".podnet-update-{}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&tmp)
            .with_context(|| format!("writing in {} (no write permission?)", dir.display()))?;
        file.write_all(binary)?;
        // Issue 270: the umask masks the mode of the open; 0755 also with
        // a restrictive umask.
        file.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        file.sync_all()?;
        let meta = file.metadata()?;
        let id = (meta.dev(), meta.ino());
        drop(file);
        let want = format!("podnet {} ", tag.trim_start_matches('v'));
        trial(&tmp, &want, limit).context("the new binary")?;
        after_trial(&tmp);
        same_file(&tmp, id).context("the new binary")?;
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
            "no kept binary at {}: podnet update keeps one from 0.3.0-beta.5 on",
            previous.display()
        );
    }
    let id = file_id(&previous)?;
    trial(&previous, "podnet ", limit).context("the kept binary")?;
    after_trial(&previous);
    same_file(&previous, id).context("the kept binary")?;
    let dir = path.parent().context("the binary has no directory")?;
    let held = dir.join(format!(".podnet-rollback-{}", std::process::id()));
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

    /// A shell script in the place of a podnet binary.
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

    /// An update keeps the binary before as podnet.prev; a rollback puts it
    /// back, and a second rollback goes forward again.
    #[test]
    fn install_keeps_the_binary_before_and_rollback_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("podnet");
        put(&path, &fake("podnet 0.3.0-beta.4 (old)", ""));
        install(
            &path,
            &fake("podnet 0.3.0-beta.5 (new)", ""),
            "v0.3.0-beta.5",
        )
        .unwrap();
        assert_eq!(version_of(&path), "podnet 0.3.0-beta.5 (new)");
        assert_eq!(version_of(&previous_of(&path)), "podnet 0.3.0-beta.4 (old)");
        assert_eq!(rollback(&path).unwrap(), "podnet 0.3.0-beta.4 (old)");
        assert_eq!(version_of(&previous_of(&path)), "podnet 0.3.0-beta.5 (new)");
        assert_eq!(rollback(&path).unwrap(), "podnet 0.3.0-beta.5 (new)");
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
        let path = dir.path().join("podnet");
        put(&path, &fake("podnet 0.3.0-beta.4 (old)", ""));
        let cases = [
            fake("podnet 0.3.0-beta.5 (new)", "exit 3"),
            fake("podnet 0.3.0-beta.5 (new)", "")
                .into_iter()
                .chain(b"exit 1\n".iter().copied())
                .collect(),
            fake("podnet 0.2.0 (other)", ""),
            fake("podnet 0.3.0-beta.5 (new)", "sleep 30"),
        ];
        for body in cases {
            let err = install_with(&path, &body, "v0.3.0-beta.5", Duration::from_millis(500))
                .expect_err("a bad binary is refused");
            assert!(format!("{err:#}").contains("new binary"), "{err:#}");
            assert_eq!(version_of(&path), "podnet 0.3.0-beta.4 (old)");
            assert!(!previous_of(&path).exists());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    /// Issue 236: a file that is replaced after the trial run is not
    /// installed, and the binary in place does not change.
    #[test]
    fn a_file_swapped_after_the_trial_is_not_installed() {
        fn swap(path: &Path) {
            let other = path.with_file_name("swapped");
            put(&other, &fake("podnet 0.3.0-beta.5 (swapped)", ""));
            std::fs::rename(&other, path).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("podnet");
        put(&path, &fake("podnet 0.3.0-beta.4 (old)", ""));
        AFTER_TRIAL.with(|h| h.set(Some(swap)));
        let err = install(
            &path,
            &fake("podnet 0.3.0-beta.5 (new)", ""),
            "v0.3.0-beta.5",
        )
        .expect_err("a swapped file is refused");
        AFTER_TRIAL.with(|h| h.set(None));
        assert!(
            format!("{err:#}").contains("changed after its trial"),
            "{err:#}"
        );
        assert_eq!(version_of(&path), "podnet 0.3.0-beta.4 (old)");
        assert!(!previous_of(&path).exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // The kept binary of a rollback is checked the same way.
        put(&previous_of(&path), &fake("podnet 0.3.0-beta.3 (kept)", ""));
        AFTER_TRIAL.with(|h| h.set(Some(swap)));
        let err = rollback(&path).expect_err("a swapped kept binary is refused");
        AFTER_TRIAL.with(|h| h.set(None));
        assert!(
            format!("{err:#}").contains("changed after its trial"),
            "{err:#}"
        );
        assert_eq!(version_of(&path), "podnet 0.3.0-beta.4 (old)");
    }

    /// A rollback with no kept binary, or with a kept binary that fails its
    /// trial, changes nothing.
    #[test]
    fn rollback_needs_a_kept_binary_that_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("podnet");
        put(&path, &fake("podnet 0.3.0-beta.5 (new)", ""));
        assert!(format!("{:#}", rollback(&path).unwrap_err()).contains("no kept binary"));
        put(
            &previous_of(&path),
            &fake("podnet 0.3.0-beta.4 (old)", "exit 2"),
        );
        assert!(rollback_with(&path, Duration::from_millis(500)).is_err());
        assert_eq!(version_of(&path), "podnet 0.3.0-beta.5 (new)");
    }

    /// The repository of the releases up to v0.3.0-beta.12 (the fixture).
    const OLD: &str = "Azathothas/cfrs";
    const SUMS: &[u8] = include_bytes!("../tests/data/v0.3.0-beta.1.SHA256SUMS");
    const BUNDLE: &[u8] = include_bytes!("../tests/data/v0.3.0-beta.1.SHA256SUMS.sigstore.json");

    /// The real files of v0.3.0-beta.1: the bundle passes for its tag, and
    /// fails for another tag, for a changed SHA256SUMS and for a changed
    /// signature.
    #[test]
    fn the_bundle_of_a_release() {
        verify_bundle_for(BUNDLE, SUMS, &identity_in(OLD, "v0.3.0-beta.1")).unwrap();

        let err = verify_bundle_for(BUNDLE, SUMS, &identity_in(OLD, "v0.3.0-beta.2"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not https://github.com/Azathothas/cfrs/.github/workflows/release.yml@refs/tags/v0.3.0-beta.2"), "{err}");

        let mut changed = SUMS.to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        let err = verify_bundle_for(BUNDLE, &changed, &identity_in(OLD, "v0.3.0-beta.1"))
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
        let err = verify_bundle_for(bad.as_bytes(), SUMS, &identity_in(OLD, "v0.3.0-beta.1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("signature"), "{err}");

        // The identity of this repository refuses a release of the old one.
        let err = verify_bundle(BUNDLE, SUMS, "v0.3.0-beta.1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not https://github.com/PodUtils/podnet/.github"),
            "{err}"
        );
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

    // Issue 166: the files of a pinned tag, with no API.
    #[test]
    fn a_pinned_release_has_the_three_files() {
        let r = Release::pinned("v0.3.0-beta.9");
        assert!(r.prerelease);
        let urls: Vec<&str> = r
            .assets
            .iter()
            .map(|a| a.browser_download_url.as_str())
            .collect();
        assert_eq!(urls.len(), 3);
        for url in urls {
            assert!(
                url.starts_with(
                    "https://github.com/PodUtils/podnet/releases/download/v0.3.0-beta.9/"
                ),
                "{url}"
            );
        }
        assert!(r.asset("SHA256SUMS.sigstore.json").is_ok());
        assert!(r.asset(&format!("podnet-{}", asset_target(TARGET))).is_ok());
    }

    // Issue 227: a tag with a path is not a tag.
    #[test]
    fn atom_tags_refuses_a_path_in_a_tag() {
        let feed = r#"<link href="https://github.com/PodUtils/podnet/releases/tag/v0.3.0-beta.9/../../x"/>
<link href="https://github.com/PodUtils/podnet/releases/tag/v0.3.0-beta.8"/>"#;
        assert_eq!(atom_tags(feed), ["v0.3.0-beta.8"]);
        assert_eq!(
            newest_in_atom(feed, "v0.3.0-beta.1").as_deref(),
            Some("v0.3.0-beta.8")
        );
    }

    // Issue 227: the form of a tag.
    #[test]
    fn a_tag_must_be_a_tag() {
        for good in ["v0.3.0-beta.9", "v1.0.0", "0.3.0", "v1.0.0+build.1"] {
            assert!(valid_tag(good), "{good}");
        }
        let long = format!("v{}", "1".repeat(64));
        for bad in [
            "",
            "v1/../x",
            "v1..2",
            "../v1",
            "x1.0",
            "v1 2",
            "v1%2f",
            "v1?x",
            long.as_str(),
        ] {
            assert!(!valid_tag(bad), "{bad}");
        }
        let r = |tag: &str| Release {
            tag_name: tag.into(),
            prerelease: false,
            draft: false,
            assets: Vec::new(),
        };
        let list = vec![r("v9.0.0/../x"), r("v1.0.0")];
        assert_eq!(choose(&list, None, "v0.1.0").unwrap().tag_name, "v1.0.0");
    }

    // Issue 166: the newest tag of releases.atom.
    #[test]
    fn the_newest_tag_of_releases_atom() {
        let feed = r#"<feed><entry><id>tag:github.com,2008:Repository/1/v0.4.0-beta.1</id>
<link rel="alternate" type="text/html" href="https://github.com/PodUtils/podnet/releases/tag/v0.4.0-beta.1"/></entry>
<entry><link rel="alternate" href="https://github.com/PodUtils/podnet/releases/tag/v0.3.0"/></entry></feed>"#;
        assert_eq!(atom_tags(feed), ["v0.4.0-beta.1", "v0.3.0"]);
        assert_eq!(
            newest_in_atom(feed, "v0.3.0-beta.9").as_deref(),
            Some("v0.4.0-beta.1")
        );
        assert_eq!(newest_in_atom(feed, "v0.2.0").as_deref(), Some("v0.3.0"));
        assert_eq!(newest_in_atom("<feed/>", "v0.2.0"), None);
    }

    // The API lists by tag name: beta.10 after beta.7. The newest is the
    // highest version, and a release is after its prereleases.
    #[test]
    fn the_newest_is_the_highest_version() {
        use std::cmp::Ordering::*;
        assert_eq!(version_order("v0.3.0-beta.10", "v0.3.0-beta.9"), Greater);
        assert_eq!(version_order("v0.3.0", "v0.3.0-beta.10"), Greater);
        assert_eq!(version_order("v0.3.0-rc.1", "v0.3.0-beta.10"), Greater);
        assert_eq!(version_order("v0.4.0-beta.1", "v0.3.0"), Greater);
        assert_eq!(version_order("v0.3.0-beta.9", "v0.3.0-beta.9"), Equal);
        let r = |tag: &str| Release {
            tag_name: tag.into(),
            prerelease: tag.contains('-'),
            draft: false,
            assets: Vec::new(),
        };
        let list = vec![
            r("v0.3.0-beta.9"),
            r("v0.3.0-beta.8"),
            r("v0.3.0-beta.7"),
            r("v0.3.0-beta.10"),
        ];
        assert_eq!(
            choose(&list, None, "v0.3.0-beta.10").unwrap().tag_name,
            "v0.3.0-beta.10"
        );
        let feed =
            "<a href=\"/releases/tag/v0.3.0-beta.9\"/><a href=\"/releases/tag/v0.3.0-beta.10\"/>";
        assert_eq!(
            newest_in_atom(feed, "v0.3.0-beta.9").as_deref(),
            Some("v0.3.0-beta.10")
        );
    }

    // Issue 197: the version of this binary is not installed again, except
    // with force.
    #[test]
    fn the_same_tag_is_not_installed_again() {
        assert_eq!(plan("v1", "v1", false, false, false), Plan::UpToDate);
        assert_eq!(plan("v1", "v1", true, false, false), Plan::Same);
        assert_eq!(plan("v1", "v1", true, true, false), Plan::Same);
        assert_eq!(plan("v1", "v1", true, false, true), Plan::Install);
        // Issue 275: --force with no --version installs the same version
        // again, and --check says that it is available. No downgrade.
        assert_eq!(plan("v1", "v1", false, false, true), Plan::Install);
        assert_eq!(plan("v1", "v1", false, true, true), Plan::Available);
        assert_eq!(plan("v0", "v1", false, false, true), Plan::UpToDate);
        assert_eq!(plan("v2", "v1", true, true, false), Plan::Available);
        assert_eq!(plan("v2", "v1", false, false, false), Plan::Install);
        // No downgrade with no --version; on purpose with it.
        assert_eq!(
            plan("v0.3.0-beta.9", "v0.3.0-beta.10", false, true, false),
            Plan::UpToDate
        );
        assert_eq!(
            plan("v0.3.0-beta.9", "v0.3.0-beta.10", true, true, false),
            Plan::Available
        );
    }

    // Issue 168: PODNET_REPO is not used, and a warning says so.
    #[test]
    fn podnet_repo_is_reported_as_ignored() {
        assert_eq!(ignored_repo_warning(None), None);
        assert_eq!(ignored_repo_warning(Some(REPOSITORY.into())), None);
        let w = ignored_repo_warning(Some("me/fork".into())).unwrap();
        assert!(
            w.contains("PODNET_REPO=me/fork") && w.contains(REPOSITORY),
            "{w}"
        );
    }
}
