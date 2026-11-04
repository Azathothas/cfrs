//! Configuration: credentials, transport, ingress and reconnect policy.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;
use uuid::Uuid;

use crate::ingress::{Ingress, Service};

/// How to authenticate the tunnel with the edge. `Debug` hides the token and
/// the secret.
#[derive(Clone)]
pub enum Credentials {
    /// Anonymous `trycloudflare.com` quick tunnel (provisioned on start).
    Quick,
    /// Named tunnel token: base64 of `{"a":account,"t":tunnel_id,"s":secret}`.
    Token(String),
    /// A cloudflared credentials JSON file.
    File(PathBuf),
    /// The three fields already decoded.
    Explicit {
        account_tag: String,
        tunnel_id: Uuid,
        secret: Vec<u8>,
    },
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::Quick => f.write_str("Quick"),
            Credentials::Token(_) => f.write_str("Token(<hidden>)"),
            Credentials::File(path) => f.debug_tuple("File").field(path).finish(),
            Credentials::Explicit {
                account_tag,
                tunnel_id,
                ..
            } => f
                .debug_struct("Explicit")
                .field("account_tag", account_tag)
                .field("tunnel_id", tunnel_id)
                .field("secret", &"<hidden>")
                .finish(),
        }
    }
}

#[derive(Deserialize)]
struct TokenJson {
    a: String,
    t: String,
    s: String,
}

#[derive(Deserialize)]
struct CredentialsJson {
    #[serde(rename = "AccountTag", alias = "account_tag")]
    account_tag: String,
    #[serde(rename = "TunnelID", alias = "tunnel_id")]
    tunnel_id: String,
    #[serde(rename = "TunnelSecret", alias = "tunnel_secret")]
    tunnel_secret: String,
}

/// Decode a named-tunnel token. Cloudflare emits standard base64 of the JSON
/// envelope; the secret inside is base64 as well.
pub fn parse_token(token: &str) -> Result<Credentials> {
    let token = token.trim();
    let raw = decode_b64(token).context("token is not valid base64")?;
    let parsed: TokenJson = serde_json::from_slice(&raw).context("the token payload")?;
    let secret = decode_b64(&parsed.s)?;
    let tunnel_id = Uuid::parse_str(&parsed.t).context("token tunnel id is not a UUID")?;
    Ok(Credentials::Explicit {
        account_tag: parsed.a,
        tunnel_id,
        secret,
    })
}

/// Load a cloudflared credentials file.
pub fn parse_credentials_file(path: &std::path::Path) -> Result<Credentials> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading credentials file {}", path.display()))?;
    // The error of serde names a missing field, or the place of bad JSON.
    let parsed: CredentialsJson = serde_json::from_str(&text)
        .with_context(|| format!("credentials file {}", path.display()))?;
    let secret = decode_b64(&parsed.tunnel_secret).with_context(|| {
        format!(
            "credentials file {}: TunnelSecret is not base64",
            path.display()
        )
    })?;
    let tunnel_id = Uuid::parse_str(&parsed.tunnel_id).with_context(|| {
        format!(
            "credentials file {}: TunnelID is not a UUID",
            path.display()
        )
    })?;
    Ok(Credentials::Explicit {
        account_tag: parsed.account_tag,
        tunnel_id,
        secret,
    })
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .map_err(|e| anyhow::anyhow!("base64: {e}"))
}

/// Edge transport. QUIC is implemented; HTTP/2 is accepted for compatibility
/// but currently returns a clear error at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Auto,
    Quic,
    Http2,
}

impl Protocol {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Protocol::Auto),
            "quic" => Ok(Protocol::Quic),
            "http2" | "h2" => Ok(Protocol::Http2),
            other => bail!("unknown protocol {other:?}; expected auto, quic or http2"),
        }
    }

    /// The transport actually used. `auto` prefers QUIC.
    pub fn resolved(self) -> Protocol {
        match self {
            Protocol::Auto => Protocol::Quic,
            other => other,
        }
    }
}

/// How the connection to the tunnel edge is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Transport {
    /// Dial the edge directly on port 7844. Fast, and what `cloudflared` does.
    Direct,
    /// Carry the edge connection inside a WARP MASQUE tunnel on TCP 443, so the
    /// host never has to reach port 7844 at all.
    Warp,
    /// Decide from the host: direct when the edge answers on 7844, WARP when it
    /// does not. The default, so a quick tunnel works on an egress that permits
    /// only 443 without the caller having to know which network it is on.
    #[default]
    Auto,
    /// Carry the HTTP/2 leg in a WebSocket to a relay on TCP 443, which opens
    /// TCP to the edge (`crate::ws_relay`). For a host whose proxy carries
    /// only port 443 and no WARP.
    Relay,
}

impl Transport {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Transport::Auto),
            "direct" => Ok(Transport::Direct),
            "warp" | "masque" | "warp+masque" => Ok(Transport::Warp),
            "relay" => Ok(Transport::Relay),
            other => bail!("unknown transport {other:?}; expected auto, direct, warp or relay"),
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Transport::Auto => "auto",
            Transport::Direct => "direct",
            Transport::Warp => "warp",
            Transport::Relay => "relay",
        })
    }
}

/// Reconnect behaviour when the edge drops a connection.
///
/// A leg tries again after each network error, with no limit by default:
/// after a network loss of any length, the tunnel serves again. The delay
/// doubles from `initial` to `max`, plus 0 to 25 % at random, so that the
/// legs do not reconnect at the same time. A refusal of the edge with
/// `should_retry = false` stops the leg; its `retry_after` replaces the
/// delay. The count of attempts starts again when a connection stays up
/// for `stable`.
#[derive(Clone, Debug)]
pub struct ReconnectPolicy {
    pub max_attempts: u32,
    pub initial: Duration,
    pub max: Duration,
    pub stable: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: u32::MAX,
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            stable: Duration::from_secs(60),
        }
    }
}

/// What a leg does after a failed attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// Try again after this delay.
    Retry(Duration),
    /// Stop the leg, for this reason.
    Stop(String),
}

/// The longest `retry_after` that cfrs obeys.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

impl ReconnectPolicy {
    /// The delay before attempt `attempt` (from 1), with no jitter.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(20);
        let secs = self.initial.as_secs().saturating_mul(1u64 << shift);
        Duration::from_secs(secs.min(self.max.as_secs()))
    }

    /// The delay before attempt `attempt`, plus 0 to 25 % at random.
    pub fn backoff_with_jitter(&self, attempt: u32) -> Duration {
        let base = self.backoff(attempt);
        let mut byte = [0u8; 2];
        let _ = getrandom::fill(&mut byte);
        let fraction = u16::from_le_bytes(byte) as u32 % 2501; // 0..=25.00 %
        base + base * fraction / 10_000
    }

    /// What to do after attempt `attempt` failed with `err`.
    pub fn next(&self, attempt: u32, err: &anyhow::Error) -> Next {
        if let Some(refused) = err
            .chain()
            .find_map(|e| e.downcast_ref::<crate::cloudflare::rpc::Refused>())
        {
            if !refused.should_retry {
                return Next::Stop(format!(
                    "the edge refused the registration and asks for no retry: {}",
                    refused.cause
                ));
            }
            if !refused.retry_after.is_zero() {
                return Next::Retry(
                    refused
                        .retry_after
                        .clamp(Duration::from_secs(1), MAX_RETRY_AFTER),
                );
            }
        }
        if attempt >= self.max_attempts {
            return Next::Stop(format!("{} attempts failed; the last: {err:#}", attempt));
        }
        Next::Retry(self.backoff_with_jitter(attempt + 1))
    }
}

/// Everything needed to run a tunnel.
#[derive(Clone, Debug)]
pub struct Config {
    pub service_url: String,
    pub user_agent: String,
    pub credentials: Credentials,
    pub protocol: Protocol,
    pub transport: Transport,
    /// Where to keep the WARP device and its MASQUE key so a later run resumes
    /// it instead of registering a second device. `None` registers fresh each
    /// time, which is what a one-shot caller wants.
    pub warp_identity: Option<PathBuf>,
    pub ha_connections: u8,
    pub reconnect: ReconnectPolicy,
    pub ingress: Ingress,
    pub verify: bool,
    /// How the next edge leg starts (`--leg-failover`).
    pub failover: crate::race::Failover,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            service_url: crate::quicktunnel::DEFAULT_QUICK_SERVICE.to_string(),
            user_agent: format!("cfrs/{}", env!("CARGO_PKG_VERSION")),
            credentials: Credentials::Quick,
            protocol: Protocol::Auto,
            transport: Transport::default(),
            warp_identity: None,
            ha_connections: 2,
            reconnect: ReconnectPolicy::default(),
            ingress: Ingress::default(),
            verify: false,
            failover: crate::race::Failover::Staggered(crate::race::LEG_STAGGER),
        }
    }
}

impl Config {
    /// A single catch-all HTTP service.
    pub fn with_service(service: Service) -> Self {
        Config {
            ingress: Ingress::default().catch_all(service),
            ..Config::default()
        }
    }
}

// ── cloudflared-compatible config file ──────────────────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    tunnel: Option<String>,
    #[serde(default, rename = "credentials-file")]
    credentials_file: Option<PathBuf>,
    #[serde(default)]
    ingress: Vec<crate::ingress::RawIngress>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default, rename = "ha-connections")]
    ha_connections: Option<u8>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "hello-world")]
    hello_world: Option<bool>,
}

/// The top-level keys of a cloudflared config.yml. cfrs reads `tunnel`,
/// `credentials-file`, `token`, `ingress`, `url`, `hello-world`, `protocol`
/// and `ha-connections`, and ignores the others. A key outside this list is a typo: an error.
pub const CLOUDFLARED_KEYS: &[&str] = &[
    "tunnel",
    "credentials-file",
    "ingress",
    "protocol",
    "ha-connections",
    "originRequest",
    "warp-routing",
    "loglevel",
    "transport-loglevel",
    "logfile",
    "log-directory",
    "metrics",
    "no-autoupdate",
    "autoupdate-freq",
    "edge-ip-version",
    "edge-bind-address",
    "region",
    "retries",
    "grace-period",
    "pidfile",
    "post-quantum",
    "management-diagnostics",
    "tag",
    "url",
    "hello-world",
    "origincert",
    "token",
];

/// The keys of an ingress rule.
pub const RULE_KEYS: &[&str] = &["hostname", "path", "service", "originRequest"];

/// The keys of `originRequest` that cloudflared knows. cfrs reads
/// `noTLSVerify`, `httpHostHeader`, `connectTimeout`, `tlsTimeout`,
/// `keepAliveTimeout`, `disableChunkedEncoding` and its own
/// `stripAcceptEncoding`, and ignores the others.
pub const ORIGIN_REQUEST_KEYS: &[&str] = &[
    "connectTimeout",
    "tlsTimeout",
    "tcpKeepAlive",
    "noHappyEyeballs",
    "keepAliveConnections",
    "keepAliveTimeout",
    "httpHostHeader",
    "originServerName",
    "matchSNItoHost",
    "caPool",
    "noTLSVerify",
    "disableChunkedEncoding",
    "bastionMode",
    "proxyAddress",
    "proxyPort",
    "proxyType",
    "ipRules",
    "http2Origin",
    "access",
    "stripAcceptEncoding",
];

/// An error for each key of `map` that is not in `known`. `place` names
/// the map: "a cloudflared config", "ingress rule 2".
fn check_keys(
    file: &std::path::Path,
    map: &serde_json::Map<String, serde_json::Value>,
    known: &[&'static str],
    place: &str,
) -> Result<()> {
    for key in map.keys() {
        if !known.contains(&key.as_str()) {
            let hint = nearest_key(key, known)
                .map(|k| format!("; did you mean {k}?"))
                .unwrap_or_default();
            bail!(
                "{}: the key {key:?} is not a key of {place}{hint}",
                file.display()
            );
        }
    }
    Ok(())
}

/// Check the keys of each ingress rule and of each `originRequest`
/// (issue 170: `hostnam:` made a catch-all rule). The top-level
/// `originRequest` is the default of each rule; the key of a rule wins.
fn check_and_merge_rules(file: &std::path::Path, value: &mut serde_json::Value) -> Result<()> {
    let Some(map) = value.as_object_mut() else {
        return Ok(());
    };
    let defaults = match map.get("originRequest") {
        None | Some(serde_json::Value::Null) => serde_json::Map::new(),
        Some(serde_json::Value::Object(o)) => {
            check_keys(file, o, ORIGIN_REQUEST_KEYS, "originRequest")?;
            check_origin_values(file, o, "originRequest")?;
            o.clone()
        }
        Some(_) => bail!("{}: originRequest: give a map of keys", file.display()),
    };
    let Some(ingress) = map.get_mut("ingress") else {
        return Ok(());
    };
    let Some(rules) = ingress.as_array_mut() else {
        if ingress.is_null() {
            return Ok(());
        }
        bail!(
            "{}: ingress: give a list of rules, for example `- service: http://127.0.0.1:8080`",
            file.display()
        );
    };
    for (i, rule) in rules.iter_mut().enumerate() {
        let place = format!("ingress rule {}", i + 1);
        let Some(rule) = rule.as_object_mut() else {
            bail!("{}: {place}: give a map of keys", file.display());
        };
        check_keys(file, rule, RULE_KEYS, &place)?;
        match rule.get("service") {
            None | Some(serde_json::Value::Null) => {
                bail!(
                    "{}: {place}: service: is missing, for example `service: http://127.0.0.1:8080`",
                    file.display()
                )
            }
            Some(serde_json::Value::String(_)) => {}
            Some(_) => bail!("{}: {place}: service: give a string", file.display()),
        }
        for key in ["hostname", "path"] {
            if let Some(value) = rule.get(key) {
                if !value.is_string() && !value.is_null() {
                    bail!("{}: {place}: {key}: give a string", file.display());
                }
            }
        }
        // Issue 269: cloudflared reads path: as a regular expression; cfrs
        // reads it as a literal prefix. A path that looks like a regular
        // expression is an error, not a rule that never matches.
        if let Some(path) = rule.get("path").and_then(|v| v.as_str()) {
            if let Some(c) = path.chars().find(|c| REGEX_CHARS.contains(*c)) {
                bail!(
                    "{}: {place}: path: {path:?} has {c:?}; path is a literal prefix in cfrs, a regular expression is not supported (for example `path: /api/`)",
                    file.display()
                );
            }
        }
        let mut origin = match rule.remove("originRequest") {
            None | Some(serde_json::Value::Null) => serde_json::Map::new(),
            Some(serde_json::Value::Object(o)) => {
                check_keys(
                    file,
                    &o,
                    ORIGIN_REQUEST_KEYS,
                    &format!("{place}, originRequest"),
                )?;
                check_origin_values(file, &o, &format!("{place}, originRequest"))?;
                o
            }
            Some(_) => bail!(
                "{}: {place}: originRequest: give a map of keys",
                file.display()
            ),
        };
        for (key, default) in &defaults {
            origin.entry(key.clone()).or_insert_with(|| default.clone());
        }
        if !origin.is_empty() {
            rule.insert("originRequest".into(), serde_json::Value::Object(origin));
        }
    }
    Ok(())
}

/// The characters of a regular expression that a literal path prefix does
/// not have.
const REGEX_CHARS: &str = "^$*+?()[]{}|\\";

/// The types of the values of `originRequest` that cfrs reads (issue 172):
/// a time needs a unit, a flag is true or false.
fn check_origin_values(
    file: &std::path::Path,
    map: &serde_json::Map<String, serde_json::Value>,
    place: &str,
) -> Result<()> {
    for (key, value) in map {
        match key.as_str() {
            "connectTimeout" | "tlsTimeout" | "keepAliveTimeout" | "tcpKeepAlive" => {
                if value.is_number() {
                    bail!(
                        "{}: {place}: {key}: {value} needs a unit, for example {value}s",
                        file.display()
                    );
                }
                if !value.is_string() {
                    bail!(
                        "{}: {place}: {key}: give a time, for example 30s",
                        file.display()
                    );
                }
            }
            "noTLSVerify" | "disableChunkedEncoding" | "stripAcceptEncoding" => {
                if !value.is_boolean() {
                    bail!("{}: {place}: {key}: give true or false", file.display());
                }
            }
            "httpHostHeader" if !value.is_string() => {
                bail!("{}: {place}: {key}: give a string", file.display());
            }
            _ => {}
        }
    }
    Ok(())
}

/// The types of the top-level values that cfrs reads (issue 172).
fn check_top_values(file: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    let map = match value {
        serde_json::Value::Null => bail!(
            "{}: the file has no keys (it needs ingress:, for example `ingress:` and `  - service: http://127.0.0.1:8080`)",
            file.display()
        ),
        serde_json::Value::Object(map) => map,
        _ => bail!(
            "{}: the config must be a mapping of keys (for example ingress:), not a list or a value",
            file.display()
        ),
    };
    for key in ["tunnel", "credentials-file", "protocol", "token", "url"] {
        if let Some(v) = map.get(key) {
            if !v.is_string() && !v.is_null() {
                bail!("{}: {key}: give a string", file.display());
            }
        }
    }
    if let Some(v) = map.get("hello-world") {
        if !v.is_boolean() && !v.is_null() {
            bail!("{}: hello-world: give true or false", file.display());
        }
    }
    if let Some(v) = map.get("ha-connections") {
        if !v.is_u64() {
            bail!(
                "{}: ha-connections: give a number from 1 to 8",
                file.display()
            );
        }
    }
    Ok(())
}

/// The nearest key of `known` (by edit distance), for an error.
fn nearest_key(key: &str, known: &[&'static str]) -> Option<&'static str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut row: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut prev = row[0];
            row[0] = i + 1;
            for (j, cb) in b.iter().enumerate() {
                let cur = row[j + 1];
                row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
                prev = cur;
            }
        }
        row[b.len()]
    }
    known
        .iter()
        .map(|k| (distance(key, k), *k))
        .min()
        // Issue 172: a short key is near each short key; "a" is not "tag".
        .filter(|(d, _)| *d <= (key.chars().count() / 3).max(1) && *d < key.chars().count())
        .map(|(_, k)| k)
}

/// Load a cloudflared-style YAML config.
///
/// * With `credentials-file:`, the file gives the credentials, and
///   `tunnel:` is the name or the UUID of the tunnel, as in cloudflared. A
///   UUID must be the TunnelID of the file.
/// * With `tunnel:` only, it is a named-tunnel token.
/// * With `token:`, the value is the named-tunnel token. `credentials-file:`
///   is then an error. A `tunnel:` must then be the tunnel id of the token.
/// * With none of the three, cfrs starts a quick tunnel, and says so.
/// * A key that cloudflared does not know is an error: at the top level,
///   in an ingress rule and in `originRequest`.
/// * The top-level `originRequest` is the default of each rule.
/// * The last ingress rule must match each request (no hostname, no path).
pub fn load_file(path: &std::path::Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let mut value =
        crate::yaml::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
    check_top_values(path, &value)?;
    if let Some(map) = value.as_object() {
        check_keys(path, map, CLOUDFLARED_KEYS, "a cloudflared config")?;
    }
    check_and_merge_rules(path, &mut value)?;
    let raw: RawConfig =
        serde_json::from_value(value).with_context(|| format!("parsing {}", path.display()))?;

    let mut config = Config::default();
    if !raw.ingress.is_empty() {
        if let Some(last) = raw.ingress.last() {
            if last.hostname.is_some() || last.path.is_some() {
                bail!(
                    "{}: the last ingress rule must match each request (no hostname and no path), for example `- service: http_status:404`",
                    path.display()
                );
            }
        }
        config.ingress = crate::ingress::ingress_from_raw(raw.ingress)?;
    }
    // Issue 269: url: and hello-world: of cloudflared give one catch-all
    // rule when the file has no ingress rules.
    let hello = raw.hello_world == Some(true);
    match (&raw.url, hello) {
        (Some(_), true) => bail!(
            "{}: url: and hello-world: both give the origin; give one",
            path.display()
        ),
        (Some(_), false) | (None, true) if !config.ingress.is_empty() => bail!(
            "{}: {} and ingress: both give the origin; give one",
            path.display(),
            if hello { "hello-world:" } else { "url:" }
        ),
        (Some(url), false) => {
            let service = crate::ingress::Service::parse(url)
                .with_context(|| format!("{}: url: {url}", path.display()))?;
            config.ingress = crate::ingress::Ingress::default().catch_all(service);
        }
        (None, true) => {
            config.ingress =
                crate::ingress::Ingress::default().catch_all(crate::ingress::Service::HelloWorld);
        }
        (None, false) => {}
    }
    if let Some(token) = &raw.token {
        // Issue 269: a token of the file is the named tunnel, not a quick
        // tunnel.
        crate::report::hide(token);
        if raw.credentials_file.is_some() {
            bail!(
                "{}: token: and credentials-file: both give the credentials; give one",
                path.display()
            );
        }
        let credentials = parse_token(token)
            .with_context(|| format!("{}: token: is not a tunnel token", path.display()))?;
        if let (Some(tunnel), Credentials::Explicit { tunnel_id, .. }) = (&raw.tunnel, &credentials)
        {
            if Uuid::parse_str(tunnel.trim()).ok() != Some(*tunnel_id) {
                bail!(
                    "{}: tunnel: {tunnel} is not the tunnel id of token: ({tunnel_id}); remove tunnel: or correct it",
                    path.display()
                );
            }
        }
        config.credentials = credentials;
    } else {
        credentials_of_file(path, raw.tunnel, raw.credentials_file, &mut config)?;
    }
    if let Some(protocol) = raw.protocol {
        config.protocol = Protocol::parse(&protocol)?;
    }
    if let Some(ha) = raw.ha_connections {
        if !(1..=8).contains(&ha) {
            bail!(
                "{}: ha-connections: {ha} is not from 1 to 8",
                path.display()
            );
        }
        config.ha_connections = ha;
    }
    Ok(config)
}

/// The credentials of `tunnel:` and `credentials-file:` of a config file.
fn credentials_of_file(
    path: &std::path::Path,
    tunnel: Option<String>,
    credentials_file: Option<PathBuf>,
    config: &mut Config,
) -> Result<()> {
    match (tunnel, credentials_file) {
        (tunnel, Some(file)) => {
            let credentials = parse_credentials_file(&file)?;
            if let (Some(tunnel), Credentials::Explicit { tunnel_id, .. }) = (&tunnel, &credentials)
            {
                if let Ok(uuid) = Uuid::parse_str(tunnel.trim()) {
                    if uuid != *tunnel_id {
                        bail!(
                            "{}: tunnel: {uuid} is not the TunnelID of {} ({tunnel_id})",
                            path.display(),
                            file.display()
                        );
                    }
                }
            }
            config.credentials = credentials;
        }
        (Some(tunnel), None) => {
            if Uuid::parse_str(tunnel.trim()).is_ok() || !tunnel.trim().starts_with("ey") {
                bail!(
                    "{}: tunnel: names a tunnel ({tunnel}); give its credentials-file:, or a tunnel token",
                    path.display()
                );
            }
            config.credentials = parse_token(&tunnel)?;
        }
        (None, None) => {
            tracing::info!(
                "{} has no tunnel:, no credentials-file: and no token:; cfrs starts a quick tunnel",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_next_step_follows_the_flags_of_the_edge() {
        use crate::cloudflare::rpc::Refused;
        let policy = ReconnectPolicy::default();
        let refused = |should_retry, secs| {
            anyhow::Error::new(Refused {
                cause: "Unauthorized: tunnel not found".into(),
                should_retry,
                retry_after: Duration::from_secs(secs),
            })
            .context("registering")
        };
        let text = format!("{:#}", refused(false, 0));
        assert!(text.contains("cfrs speaks cloudflared 2026.10.7"), "{text}");
        match policy.next(1, &refused(false, 0)) {
            Next::Stop(reason) => assert!(reason.contains("tunnel not found"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            policy.next(1, &refused(true, 5)),
            Next::Retry(Duration::from_secs(5))
        );
        assert_eq!(
            policy.next(1, &refused(true, 9999)),
            Next::Retry(MAX_RETRY_AFTER)
        );
        // A network error is retried with no limit, with 0-25 % jitter.
        let net = anyhow::anyhow!("connection refused");
        for attempt in [1, 5, 1000, u32::MAX - 1] {
            let Next::Retry(d) = policy.next(attempt, &net) else {
                panic!("attempt {attempt} stopped");
            };
            let base = policy.backoff(attempt.saturating_add(1));
            assert!(d >= base && d <= base + base / 4, "{d:?} for {base:?}");
        }
        assert_eq!(policy.backoff(1000), Duration::from_secs(30));
        let capped = ReconnectPolicy {
            max_attempts: 3,
            ..policy
        };
        assert!(matches!(capped.next(3, &net), Next::Stop(_)));
    }

    /// The cloudflared forms of tunnel: and credentials-file:, a typo in a
    /// key, and a last rule that is not a catch-all.
    #[test]
    fn load_file_follows_cloudflared() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("creds.json");
        std::fs::write(
            &creds,
            r#"{"AccountTag":"0123456789abcdef","TunnelID":"ffd86bd5-1bff-456b-8c2c-75a014cdc4c8","TunnelSecret":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}"#,
        )
        .unwrap();
        let path = dir.path().join("config.yml");
        let load = |text: String| {
            std::fs::write(&path, text).unwrap();
            load_file(&path).map_err(|e| format!("{e:#}"))
        };
        let c = creds.display();
        let catch_all = "ingress:\n  - service: http://127.0.0.1:1\n";

        // A UUID, or a name, with credentials-file:.
        for tunnel in ["ffd86bd5-1bff-456b-8c2c-75a014cdc4c8", "my-tunnel"] {
            let config = load(format!(
                "tunnel: {tunnel}\ncredentials-file: {c}\n{catch_all}"
            ))
            .unwrap();
            assert!(matches!(config.credentials, Credentials::Explicit { .. }));
        }
        let err = load(format!(
            "tunnel: 00000000-1bff-456b-8c2c-75a014cdc4c8\ncredentials-file: {c}\n{catch_all}"
        ))
        .unwrap_err();
        assert!(err.contains("is not the TunnelID"), "{err}");

        let err = load(format!("tunnel: my-tunnel\n{catch_all}")).unwrap_err();
        assert!(err.contains("give its credentials-file:"), "{err}");

        let err = load(format!("credentails-file: {c}\n{catch_all}")).unwrap_err();
        assert!(
            err.contains("\"credentails-file\" is not a key")
                && err.contains("did you mean credentials-file?"),
            "{err}"
        );

        let err = load(format!(
            "credentials-file: {c}\ningress:\n  - hostname: a.example.com\n    service: http://127.0.0.1:1\n"
        ))
        .unwrap_err();
        assert!(
            err.contains("the last ingress rule must match each request"),
            "{err}"
        );

        // Keys of cloudflared that cfrs does not use are accepted.
        load(format!("credentials-file: {c}\nmetrics: localhost:2000\nno-autoupdate: true\nwarp-routing:\n  enabled: true\n{catch_all}")).unwrap();
    }

    #[test]
    fn load_file_reads_a_cloudflared_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            "protocol: http2\nha-connections: 3\nloglevel: info # not read\ningress:\n  - hostname: a.example.com\n    service: http://127.0.0.1:8000\n    originRequest:\n      noTLSVerify: true\n  - service: http_status:404\n",
        )
        .unwrap();
        let config = load_file(&path).unwrap();
        assert_eq!(config.ha_connections, 3);
        assert!(matches!(config.protocol, Protocol::Http2));
        assert_eq!(config.ingress.rules.len(), 2);
        assert_eq!(
            config.ingress.rules[0].hostname.as_deref(),
            Some("a.example.com")
        );
        assert!(config.ingress.rules[0].origin.no_tls_verify);

        std::fs::write(&path, "ingress:\n  - service: a\n    service: b\n").unwrap();
        let err = format!("{:#}", load_file(&path).unwrap_err());
        assert!(
            err.contains("line 3: the key \"service\" is given two times"),
            "{err}"
        );
    }

    // Issue 269: token: of a file gives the named tunnel, not a quick tunnel.
    #[test]
    fn a_token_key_makes_a_named_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let load = |text: String| {
            std::fs::write(&path, text).unwrap();
            load_file(&path).map_err(|e| format!("{e:#}"))
        };
        let id = "ffd86bd5-1bff-456b-8c2c-75a014cdc4c8";
        let token = crate::cloudflare::http2::base64_encode(
            format!(r#"{{"a":"0123456789abcdef","t":"{id}","s":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}}"#)
                .as_bytes(),
        );
        let catch_all = "ingress:\n  - service: http://127.0.0.1:1\n";
        for head in [
            format!("token: {token}\n"),
            format!("tunnel: {id}\ntoken: {token}\n"),
        ] {
            let config = load(format!("{head}{catch_all}")).unwrap();
            match config.credentials {
                Credentials::Explicit { tunnel_id, .. } => assert_eq!(tunnel_id.to_string(), id),
                other => panic!("{other:?}"),
            }
        }
        let err = load(format!("token: not-a-token\n{catch_all}")).unwrap_err();
        assert!(err.contains("token: is not a tunnel token"), "{err}");
        let err = load(format!(
            "tunnel: 00000000-1bff-456b-8c2c-75a014cdc4c8\ntoken: {token}\n{catch_all}"
        ))
        .unwrap_err();
        assert!(err.contains("is not the tunnel id of token:"), "{err}");
        let err = load(format!(
            "token: {token}\ncredentials-file: /nonexistent.json\n{catch_all}"
        ))
        .unwrap_err();
        assert!(err.contains("give one"), "{err}");
        let err = load(format!("token: 5\n{catch_all}")).unwrap_err();
        assert!(err.contains("token: give a string"), "{err}");
    }

    // Issue 269: url: and hello-world: give a catch-all rule; with ingress:
    // they are an error. A path that looks like a regular expression is an
    // error.
    #[test]
    fn url_and_hello_world_make_a_catch_all_rule() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            load_file(&path).map_err(|e| format!("{e:#}"))
        };
        let config = load("url: http://127.0.0.1:8080\n").unwrap();
        assert_eq!(config.ingress.rules.len(), 1);
        assert!(matches!(
            config.ingress.rules[0].service,
            crate::ingress::Service::Http(_)
        ));
        let config = load("hello-world: true\n").unwrap();
        assert!(matches!(
            config.ingress.rules[0].service,
            crate::ingress::Service::HelloWorld
        ));
        let config = load("hello-world: false\nloglevel: info\n").unwrap();
        assert!(config.ingress.is_empty());
        let err =
            load("url: http://127.0.0.1:1\ningress:\n  - service: http_status:404\n").unwrap_err();
        assert!(
            err.contains("url: and ingress: both give the origin"),
            "{err}"
        );
        let err = load("hello-world: true\ningress:\n  - service: http_status:404\n").unwrap_err();
        assert!(err.contains("hello-world: and ingress:"), "{err}");
        let err = load("url: http://127.0.0.1:1\nhello-world: true\n").unwrap_err();
        assert!(err.contains("give one"), "{err}");
        let err = load("hello-world: yes please\n").unwrap_err();
        assert!(err.contains("hello-world: give true or false"), "{err}");

        let err = load(
            "ingress:\n  - path: ^/api/.*$\n    service: http://127.0.0.1:1\n  - service: http_status:404\n",
        )
        .unwrap_err();
        assert!(err.contains("ingress rule 1: path:"), "{err}");
        assert!(err.contains("literal prefix"), "{err}");
        load("ingress:\n  - path: /api/v1.2/\n    service: http://127.0.0.1:1\n  - service: http_status:404\n")
            .unwrap();
    }

    // Issue 170: a misspelt key of a rule or of originRequest is an error.
    #[test]
    fn a_misspelt_rule_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            load_file(&path).map_err(|e| format!("{e:#}"))
        };
        let err = load(
            "ingress:\n  - hostnam: a.example.com\n    service: http://127.0.0.1:1\n  - service: http_status:404\n",
        )
        .unwrap_err();
        assert!(err.contains("ingress rule 1"), "{err}");
        assert!(err.contains("did you mean hostname?"), "{err}");

        let err = load(
            "ingress:\n  - service: http://127.0.0.1:1\n    originRequest:\n      noTLSVerfy: true\n",
        )
        .unwrap_err();
        assert!(err.contains("ingress rule 1, originRequest"), "{err}");
        assert!(err.contains("did you mean noTLSVerify?"), "{err}");

        let err = load("originRequest:\n  bogusKey: 1\ningress:\n  - service: http_status:404\n")
            .unwrap_err();
        assert!(err.contains("not a key of originRequest"), "{err}");

        // Keys of cloudflared that cfrs does not read still load.
        load("ingress:\n  - service: http://127.0.0.1:1\n    originRequest:\n      tcpKeepAlive: 30s\n      caPool: /x.pem\n").unwrap();
    }

    // Issue 170: the top-level originRequest is the default of each rule.
    #[test]
    fn a_top_level_origin_request_is_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            "originRequest:\n  noTLSVerify: true\n  httpHostHeader: top\ningress:\n  - hostname: a.example.com\n    service: https://127.0.0.1:1\n    originRequest:\n      httpHostHeader: rule\n  - service: https://127.0.0.1:2\n",
        )
        .unwrap();
        let config = load_file(&path).unwrap();
        let rules = &config.ingress.rules;
        assert!(rules[0].origin.no_tls_verify);
        assert!(rules[1].origin.no_tls_verify);
        assert_eq!(rules[0].origin.http_host_header.as_deref(), Some("rule"));
        assert_eq!(rules[1].origin.http_host_header.as_deref(), Some("top"));
    }

    // Issue 172: clear errors for a list, a BOM, an empty file, bad types,
    // a short key and a rule with no service.
    #[test]
    fn config_errors_are_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            load_file(&path).map(|_| ()).map_err(|e| format!("{e:#}"))
        };
        let err = load("- a\n- b\n").unwrap_err();
        assert!(err.contains("must be a mapping"), "{err}");
        load("\u{feff}ingress:\n  - service: http_status:404\n").unwrap();
        let err = load("# nothing\n").unwrap_err();
        assert!(err.contains("has no keys"), "{err}");
        let err = load("ingress: 5\n").unwrap_err();
        assert!(err.contains("ingress: give a list"), "{err}");
        let err = load(
            "ingress:\n  - service: http_status:404\n    originRequest:\n      connectTimeout: 5\n",
        )
        .unwrap_err();
        assert!(err.contains("connectTimeout: 5 needs a unit"), "{err}");
        let err = load("ingress:\n  - hostname: a.example.com\n  - service: http_status:404\n")
            .unwrap_err();
        assert!(err.contains("ingress rule 1: service: is missing"), "{err}");
        let err = load("a: 1\n").unwrap_err();
        assert!(!err.contains("did you mean"), "{err}");
        let err = load("tunel: x\n").unwrap_err();
        assert!(err.contains("did you mean tunnel?"), "{err}");
        let err = load("credentails-file: x\n").unwrap_err();
        assert!(err.contains("did you mean credentials-file?"), "{err}");
    }

    // Issue 172: a credentials file with no TunnelID names the field.
    #[test]
    fn a_credentials_file_error_names_the_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        std::fs::write(&path, r#"{"AccountTag":"a","TunnelSecret":"AAAA"}"#).unwrap();
        let err = format!("{:#}", parse_credentials_file(&path).unwrap_err());
        assert!(err.contains("TunnelID"), "{err}");
        assert!(!err.contains("not JSON"), "{err}");
    }

    // Issue 171: a file value out of range is an error, not a silent clamp.
    #[test]
    fn ha_connections_of_a_file_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "ha-connections: 9\n").unwrap();
        let err = format!("{:#}", load_file(&path).unwrap_err());
        assert!(err.contains("not from 1 to 8"), "{err}");
    }

    #[test]
    fn transport_names_round_trip() {
        for (text, want) in [
            ("auto", Transport::Auto),
            ("direct", Transport::Direct),
            ("warp", Transport::Warp),
            ("masque", Transport::Warp),
            ("WARP+MASQUE", Transport::Warp),
            ("  Direct ", Transport::Direct),
            ("relay", Transport::Relay),
        ] {
            assert_eq!(Transport::parse(text.trim()).unwrap(), want, "{text:?}");
        }
    }

    #[test]
    fn an_unknown_transport_names_the_alternatives() {
        let err = Transport::parse("carrier-pigeon").unwrap_err().to_string();
        assert!(err.contains("auto"), "{err}");
        assert!(err.contains("direct"), "{err}");
        assert!(err.contains("warp"), "{err}");
    }

    #[test]
    fn the_default_transport_is_auto() {
        // The point of the default is that a quick tunnel works on a host whose
        // egress permits only 443 without the caller passing a flag.
        assert_eq!(Transport::default(), Transport::Auto);
        assert_eq!(Transport::default().to_string(), "auto");
    }
}
