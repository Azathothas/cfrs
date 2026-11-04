//! The hosts of a relay deployment, and the cache files of the relay
//! (adapted from podssh `pool.rs` and `cache.rs`).
//!
//! * The pool: the relay publishes its hosts in `/relays.json`. cfrs reads
//!   it after a mint (rarely: a token lasts hours), and keeps it in
//!   `relay-pool-HOST.json` in the state directory. Until a pool is cached,
//!   the alternates of the default relay come from [`SEED`].
//! * The token: a minted token is kept in `relay-token-HOST.json`, so the
//!   next process (or a restart of `--detach`) does not mint again.
//!
//! A token goes only to the hosts of the deployment of the primary host:
//! the other hosts under its parent domain ([`same_deployment`]). Each cache
//! file is private (mode 0600). A file that is a symbolic link, of another
//! user, readable by others or larger than [`MAX_FILE`] is not used.

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};

/// The host of the default relay.
pub const DEFAULT_HOST: &str = "tcp.ssh.relay.ajam.dev";

/// Hosts of the pool of the default relay, in different regions (the seed
/// of podssh). A cached pool replaces them. Each one reached TCP 7844 of
/// the edge (`/trace?target=198.41.192.167:7844`, 2026-11-04: the 37 hosts
/// of the pool, road `vpc`).
pub const SEED: &[&str] = &[
    "tcp-us-east-1.ssh.relay.ajam.dev",
    "tcp-eu-west-3.ssh.relay.ajam.dev",
    "tcp-ap-southeast-1.ssh.relay.ajam.dev",
    "tcp-azure-westeurope.ssh.relay.ajam.dev",
    "tcp-us-central1.ssh.relay.ajam.dev",
    "tcp-ap-south-1.ssh.relay.ajam.dev",
];

/// The most alternates that one connect tries after the primary host.
pub const MAX_ALTERNATES: usize = 3;

/// A cached pool older than this is still used, and read again at the next
/// mint.
pub const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

/// The largest `/relays.json` that cfrs reads.
pub const MAX_BODY: usize = 256 * 1024;

/// The largest cache file that cfrs reads.
pub const MAX_FILE: u64 = 64 * 1024;

/// Whether `host` is another host of the deployment of `primary`: a host
/// under its parent domain (for `tcp.ssh.relay.ajam.dev`, a host under
/// `ssh.relay.ajam.dev`). A parent with no dot (a top-level domain) and an
/// IP address never match.
pub fn same_deployment(primary: &str, host: &str) -> bool {
    let primary = primary.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if primary.parse::<std::net::IpAddr>().is_ok() || !valid_host(&host) {
        return false;
    }
    let Some((_, parent)) = primary.split_once('.') else {
        return false;
    };
    parent.contains('.') && host != primary && host.ends_with(&format!(".{parent}"))
}

/// A DNS name of letters, digits, `-` and `.`, with no empty label.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The `pool[].host` names of a `/relays.json` body, in its order (the
/// relay ranks them for the client), kept only when they belong to the
/// deployment of `primary`.
pub fn parse_pool(body: &[u8], primary: &str) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Doc {
        pool: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        host: String,
    }
    let doc: Doc = serde_json::from_slice(body).context("the pool is not the expected JSON")?;
    let mut hosts: Vec<String> = Vec::new();
    for entry in doc.pool {
        let host = entry.host.trim().to_ascii_lowercase();
        if same_deployment(primary, &host) && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() {
        bail!("the pool lists no host of the deployment of {primary}");
    }
    Ok(hosts)
}

/// The alternates of `primary`, best first: the hosts of `cached`, else
/// (for the default relay only) [`SEED`]. At most [`MAX_ALTERNATES`].
pub fn alternates_of(primary: &str, cached: Option<Vec<String>>) -> Vec<String> {
    let hosts: Vec<String> = match cached {
        Some(hosts) if !hosts.is_empty() => hosts,
        _ if primary.eq_ignore_ascii_case(DEFAULT_HOST) => {
            SEED.iter().map(|s| s.to_string()).collect()
        }
        _ => Vec::new(),
    };
    hosts
        .into_iter()
        .filter(|h| same_deployment(primary, h))
        .take(MAX_ALTERNATES)
        .collect()
}

#[derive(Serialize, Deserialize)]
struct CachedPool {
    /// Milliseconds since the epoch.
    fetched: u64,
    hosts: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct CachedToken {
    token: String,
    /// Milliseconds since the epoch.
    expires: u64,
}

/// `host` as a part of a file name.
fn safe_name(host: &str) -> String {
    host.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' => c.to_ascii_lowercase(),
            _ => '_',
        })
        .collect()
}

fn pool_file(primary: &str) -> String {
    format!("relay-pool-{}.json", safe_name(primary))
}

fn token_file(primary: &str) -> String {
    format!("relay-token-{}.json", safe_name(primary))
}

fn millis(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The text of the private file `path`, or `None` when it is missing or
/// not safe to use.
pub fn read_private(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let uid = unsafe { libc::geteuid() };
    let why = if !meta.file_type().is_file() {
        "it is not a regular file"
    } else if meta.uid() != uid {
        "it belongs to another user"
    } else if meta.mode() & 0o077 != 0 {
        "other users can read or write it"
    } else if meta.len() > MAX_FILE {
        "it is too large"
    } else {
        return std::fs::read_to_string(path).ok();
    };
    tracing::warn!(path = %path.display(), "cfrs does not use the cache file: {why}");
    None
}

/// Write `text` to `path` with mode 0600 (a new file, then a rename).
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("writing {}", temp.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", temp.display()))?;
    drop(file);
    std::fs::rename(&temp, path).with_context(|| format!("writing {}", path.display()))
}

/// The cache directory to read: an existing state directory (none is made).
fn read_dir() -> Option<PathBuf> {
    let candidates = crate::state::candidates(&|key| std::env::var_os(key))?;
    candidates
        .into_iter()
        .map(|(_, dir)| dir)
        .find(|dir| dir.is_dir())
}

/// The pool cached for `primary` in `dir`, and whether it is stale at `now`.
pub fn load_pool_in(dir: &Path, primary: &str, now: SystemTime) -> Option<(Vec<String>, bool)> {
    let text = read_private(&dir.join(pool_file(primary)))?;
    let cached: CachedPool = serde_json::from_str(&text).ok()?;
    let age = millis(now).saturating_sub(cached.fetched);
    Some((cached.hosts, age > STALE_AFTER.as_millis() as u64))
}

/// Keep `hosts` as the pool of `primary` in `dir`.
pub fn store_pool_in(dir: &Path, primary: &str, hosts: &[String], now: SystemTime) -> Result<()> {
    let text = serde_json::to_string(&CachedPool {
        fetched: millis(now),
        hosts: hosts.to_vec(),
    })?;
    write_private(&dir.join(pool_file(primary)), &text)
}

/// The token cached for `primary` in `dir`, with its expiry.
pub fn load_token_in(dir: &Path, primary: &str) -> Option<(String, SystemTime)> {
    let text = read_private(&dir.join(token_file(primary)))?;
    let cached: CachedToken = serde_json::from_str(&text).ok()?;
    if cached.token.is_empty() {
        return None;
    }
    Some((
        cached.token,
        UNIX_EPOCH + Duration::from_millis(cached.expires),
    ))
}

/// Keep `token` for `primary` in `dir`.
pub fn store_token_in(dir: &Path, primary: &str, token: &str, expires: SystemTime) -> Result<()> {
    let text = serde_json::to_string(&CachedToken {
        token: token.to_string(),
        expires: millis(expires),
    })?;
    write_private(&dir.join(token_file(primary)), &text)
}

/// The pool cached for `primary` in the state directory.
pub fn load_pool(primary: &str) -> Option<(Vec<String>, bool)> {
    load_pool_in(&read_dir()?, primary, SystemTime::now())
}

/// The token cached for `primary` in the state directory.
pub fn load_token(primary: &str) -> Option<(String, SystemTime)> {
    load_token_in(&read_dir()?, primary)
}

/// Keep the pool of `primary` in the state directory (none with
/// `CFRS_STATE_DIR=none`). A failure is logged only.
pub fn store_pool(primary: &str, hosts: &[String]) {
    if let Ok(Some(dir)) = crate::state::state_dir() {
        if let Err(err) = store_pool_in(&dir, primary, hosts, SystemTime::now()) {
            tracing::debug!(error = %format!("{err:#}"), "the relay pool is not cached");
        }
    }
}

/// Keep the token of `primary` in the state directory (none with
/// `CFRS_STATE_DIR=none`). A failure is logged only.
pub fn store_token(primary: &str, token: &str, expires: SystemTime) {
    if let Ok(Some(dir)) = crate::state::state_dir() {
        if let Err(err) = store_token_in(&dir, primary, token, expires) {
            tracing::debug!(error = %format!("{err:#}"), "the relay token is not cached");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_of_one_deployment() {
        let p = DEFAULT_HOST;
        assert!(same_deployment(p, "tcp-us-east-1.ssh.relay.ajam.dev"));
        assert!(same_deployment(p, "TCP-EU-WEST-3.ssh.relay.ajam.dev"));
        assert!(!same_deployment(p, p), "not the primary itself");
        assert!(!same_deployment(p, "evil.example"));
        assert!(!same_deployment(p, "ssh.relay.ajam.dev.evil.example"));
        assert!(!same_deployment(p, "xssh.relay.ajam.dev"));
        assert!(!same_deployment(p, "a..ssh.relay.ajam.dev"));
        assert!(!same_deployment(p, "a b.ssh.relay.ajam.dev"));
        assert!(
            !same_deployment("relay.dev", "other.dev"),
            "a top-level parent"
        );
        assert!(!same_deployment("127.0.0.1", "x.0.0.1"), "an IP address");
    }

    #[test]
    fn the_pool_keeps_the_hosts_of_the_deployment_in_order() {
        let body = br#"{"pool":[
            {"host":"tcp-azure-westus2.ssh.relay.ajam.dev"},
            {"host":"tcp.ssh.relay.ajam.dev"},
            {"host":"evil.example"},
            {"host":"tcp-ca-central-1.ssh.relay.ajam.dev"},
            {"host":"tcp-azure-westus2.ssh.relay.ajam.dev"}
        ]}"#;
        assert_eq!(
            parse_pool(body, DEFAULT_HOST).unwrap(),
            [
                "tcp-azure-westus2.ssh.relay.ajam.dev",
                "tcp-ca-central-1.ssh.relay.ajam.dev"
            ]
        );
        assert!(parse_pool(br#"{"pool":[{"host":"evil.example"}]}"#, DEFAULT_HOST).is_err());
        assert!(parse_pool(b"<html>", DEFAULT_HOST).is_err());
    }

    #[test]
    fn the_alternates_come_from_the_cache_else_the_seed() {
        let seed = alternates_of(DEFAULT_HOST, None);
        assert_eq!(seed.len(), MAX_ALTERNATES);
        assert_eq!(seed[0], SEED[0]);
        let cached = vec!["tcp-x.ssh.relay.ajam.dev".to_string()];
        assert_eq!(alternates_of(DEFAULT_HOST, Some(cached.clone())), cached);
        // Another relay has no seed; its cache is used.
        assert!(alternates_of("relay.example.org", None).is_empty());
        let other = vec!["b.example.org".to_string(), "evil.example".to_string()];
        assert_eq!(
            alternates_of("relay.example.org", Some(other)),
            ["b.example.org"]
        );
    }

    #[test]
    fn the_cache_files_are_private_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let hosts = vec!["tcp-x.ssh.relay.ajam.dev".to_string()];
        store_pool_in(dir.path(), DEFAULT_HOST, &hosts, now).unwrap();
        assert_eq!(
            load_pool_in(dir.path(), DEFAULT_HOST, now),
            Some((hosts.clone(), false))
        );
        let later = now + STALE_AFTER + Duration::from_secs(1);
        assert_eq!(
            load_pool_in(dir.path(), DEFAULT_HOST, later),
            Some((hosts, true))
        );

        let expires = UNIX_EPOCH + Duration::from_millis(millis(now) + 3_600_000);
        store_token_in(dir.path(), DEFAULT_HOST, "ephm1.t", expires).unwrap();
        let path = dir.path().join(token_file(DEFAULT_HOST));
        let mode = std::fs::metadata(&path).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            load_token_in(dir.path(), DEFAULT_HOST),
            Some(("ephm1.t".to_string(), expires))
        );

        // A file that others can read is not used.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_token_in(dir.path(), DEFAULT_HOST), None);
        // A symbolic link is not used.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join(token_file("tcp-y.ssh.relay.ajam.dev"));
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(load_token_in(dir.path(), "tcp-y.ssh.relay.ajam.dev"), None);
        // A large file is not used.
        std::fs::write(&path, vec![b' '; MAX_FILE as usize + 1]).unwrap();
        assert_eq!(load_token_in(dir.path(), DEFAULT_HOST), None);
    }

    #[test]
    fn a_host_is_a_safe_file_name() {
        assert_eq!(safe_name("127.0.0.1"), "127.0.0.1");
        assert_eq!(safe_name("a/../b"), "a_.._b");
    }
}
