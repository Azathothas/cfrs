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
    let parsed: TokenJson = serde_json::from_slice(&raw).context("token payload is not JSON")?;
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
    let parsed: CredentialsJson =
        serde_json::from_str(&text).context("credentials file is not JSON")?;
    let secret = decode_b64(&parsed.tunnel_secret).context("TunnelSecret is not base64")?;
    let tunnel_id = Uuid::parse_str(&parsed.tunnel_id).context("TunnelID is not a UUID")?;
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
}

/// The top-level keys of a cloudflared config.yml. cfrs reads `tunnel`,
/// `credentials-file`, `ingress`, `protocol` and `ha-connections`, and
/// ignores the others. A key outside this list is a typo: an error.
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

/// The nearest key of [`CLOUDFLARED_KEYS`] (by edit distance), for an error.
fn nearest_key(key: &str) -> Option<&'static str> {
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
    CLOUDFLARED_KEYS
        .iter()
        .map(|k| (distance(key, k), *k))
        .min()
        .filter(|(d, _)| *d <= 3)
        .map(|(_, k)| k)
}

/// Load a cloudflared-style YAML config.
///
/// * With `credentials-file:`, the file gives the credentials, and
///   `tunnel:` is the name or the UUID of the tunnel, as in cloudflared. A
///   UUID must be the TunnelID of the file.
/// * With `tunnel:` only, it is a named-tunnel token.
/// * With neither, cfrs starts a quick tunnel, and says so.
/// * A top-level key that cloudflared does not know is an error.
/// * The last ingress rule must match each request (no hostname, no path).
pub fn load_file(path: &std::path::Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let value = crate::yaml::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
    if let Some(map) = value.as_object() {
        for key in map.keys() {
            if !CLOUDFLARED_KEYS.contains(&key.as_str()) {
                let hint = nearest_key(key)
                    .map(|k| format!("; did you mean {k}?"))
                    .unwrap_or_default();
                bail!(
                    "{}: the key {key:?} is not a key of a cloudflared config{hint}",
                    path.display()
                );
            }
        }
    }
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
    match (raw.tunnel, raw.credentials_file) {
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
                "{} has no tunnel: and no credentials-file:; cfrs starts a quick tunnel",
                path.display()
            );
        }
    }
    if let Some(protocol) = raw.protocol {
        config.protocol = Protocol::parse(&protocol)?;
    }
    if let Some(ha) = raw.ha_connections {
        config.ha_connections = ha.clamp(1, 8);
    }
    Ok(config)
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
