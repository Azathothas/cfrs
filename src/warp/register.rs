//! Anonymous Cloudflare WARP registration.
//!
//! Two calls, both credential-free on the first one:
//!
//! 1. `POST /{version}/reg` — create a device. The body carries a throwaway
//!    X25519 public key so the service accepts it; the matching private half is
//!    discarded because MASQUE does not use it.
//! 2. `PATCH /{version}/reg/{id}` — enrol a P-256 public key (X.509 SPKI, base64)
//!    and switch the device from `wireguard` to `masque`. This is what makes the
//!    returned `config.peers[0].endpoint` point at the MASQUE front door and what
//!    lets the TLS client certificate authenticate the tunnel.
//!
//! Nothing here shells out to `wgcf`, `warp-cli` or `cloudflared`: the two HTTP
//! calls and the key generation are the whole of it.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::egress::Proxy;

/// API host. Reachable on TCP 443, which is the point of this module.
pub const API_BASE: &str = "https://api.cloudflareclient.com";

/// A second name of the same API (podssh): cfrs tries it after a dial, TLS
/// or 5xx failure of the first. It resolved on 2026-11-02 to other
/// Cloudflare addresses. A proxy allowlist can have one name and not the
/// other.
pub const API_SECOND: &str = "https://api.devices.cloudflare.com";

/// The environment variable with the one API base to use
/// (`https://HOST[:PORT]`).
pub const API_VARIABLE: &str = "CFRS_WARP_API";

/// The API bases to try, in order: [`API_VARIABLE`] alone when it is set,
/// else [`API_BASE`] and [`API_SECOND`].
pub fn api_bases(value: Option<&str>) -> Result<Vec<String>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(vec![API_BASE.to_string(), API_SECOND.to_string()]);
    };
    let value = value.trim_end_matches('/');
    let rest = value
        .strip_prefix("https://")
        .or_else(|| {
            value
                .strip_prefix("http://")
                .filter(|r| r.starts_with("127.0.0.1:") || r.starts_with("localhost:"))
        })
        .with_context(|| {
            format!("{API_VARIABLE}={value:?}: use https://HOST[:PORT] (http:// for a loopback host only)")
        })?;
    if rest.is_empty() || rest.contains(['/', '?', '@', '#']) {
        bail!("{API_VARIABLE}={value:?}: use https://HOST[:PORT], with no path");
    }
    Ok(vec![value.to_string()])
}

/// Send `request` (made for [`API_BASE`]) to each API base in turn, until
/// one answers with a status under 500. The error names each base.
async fn send_api(request: crate::fetch::Request) -> Result<crate::fetch::Response> {
    let bases = api_bases(std::env::var(API_VARIABLE).ok().as_deref())
        .map_err(|e| crate::exit::fault(crate::exit::Fault::Config, e))?;
    send_api_to(request, &bases).await
}

/// [`send_api`] with the bases `bases`.
async fn send_api_to(
    request: crate::fetch::Request,
    bases: &[String],
) -> Result<crate::fetch::Response> {
    let path = request
        .url
        .strip_prefix(API_BASE)
        .unwrap_or(&request.url)
        .to_string();
    let mut failures = Vec::new();
    let count = bases.len();
    for (i, base) in bases.iter().enumerate() {
        let mut attempt = request.clone();
        attempt.url = format!("{base}{path}");
        match attempt.send().await {
            Ok(response) if response.status < 500 || i + 1 == count => return Ok(response),
            Ok(response) => failures.push(format!("{base}: HTTP {}", response.status)),
            Err(err) if i + 1 == count => {
                return Err(err.context(if failures.is_empty() {
                    format!("the WARP API at {base}")
                } else {
                    format!("the WARP API at {base} (before: {})", failures.join("; "))
                }))
            }
            Err(err) => failures.push(format!("{base}: {err:#}")),
        }
        tracing::info!(failed = %failures.last().map(String::as_str).unwrap_or(""), "the WARP API: cfrs tries the next host");
    }
    unreachable!("the last base returns")
}

/// API version segment. It must agree with the build number in
/// [`CLIENT_VERSION`]; the service rejects a mismatched pair.
pub const API_VERSION: &str = "v0a5641";

/// `CF-Client-Version` header value.
pub const CLIENT_VERSION: &str = "a-6.38.9-5641";

/// `User-Agent` the Android client sends, and the one the service expects.
pub const USER_AGENT: &str = "WARP for Android";

/// SNI the MASQUE front door presents.
pub const MASQUE_SNI: &str = "consumer-masque.cloudflareclient.com";

/// Default MASQUE port. 443 everywhere; the API may advertise others.
pub const MASQUE_PORT: u16 = 443;

/// The `:authority` of the CONNECT-IP request. Only the host matters; Cloudflare
/// uses it as a routing hint, not a real endpoint.
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

/// The device as the API reports it.
///
/// `Serialize` is not for the wire (the API only takes the two bodies below);
/// it exists so a caller can persist a registered device and resume it without
/// registering a second one. `Debug` hides the token.
#[derive(Clone, Deserialize, Serialize)]
pub struct Device {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub tunnel_type: String,
    pub account: Account,
    pub config: DeviceConfig,
    /// Only present on the `POST /reg` response.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub warp_enabled: bool,
    #[serde(default)]
    pub waitlist_enabled: bool,
    #[serde(default)]
    pub policy: Policy,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("key", &self.key)
            .field("key_type", &self.key_type)
            .field("tunnel_type", &self.tunnel_type)
            .field("account", &self.account)
            .field("config", &self.config)
            .field("token", &"<hidden>")
            .field("warp_enabled", &self.warp_enabled)
            .field("waitlist_enabled", &self.waitlist_enabled)
            .field("policy", &self.policy)
            .finish()
    }
}

/// `Debug` hides the license key.
#[derive(Clone, Deserialize, Serialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub license: String,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("account_type", &self.account_type)
            .field("license", &"<hidden>")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub interface: Interface,
    #[serde(default)]
    pub services: Services,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Peer {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Endpoint {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Interface {
    #[serde(default)]
    pub addresses: Addresses,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Addresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Services {
    #[serde(default)]
    pub http_proxy: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Policy {
    #[serde(default)]
    pub tunnel_protocol: String,
    #[serde(default)]
    pub post_quantum: String,
}

/// The `POST /reg` body. All values are strings, matching the Android client.
#[derive(Debug, Serialize)]
struct RegistrationRequest {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    model: String,
    serial_number: String,
    os_version: String,
    key_type: String,
    tunnel_type: String,
    locale: String,
}

/// The `PATCH /reg/{id}` body that enrols a MASQUE key.
#[derive(Debug, Serialize)]
struct EnrolRequest {
    key: String,
    key_type: String,
    tunnel_type: String,
    /// The name of the device in the dashboard (issue 141). Absent by
    /// default: the body is as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

/// The name, the model and the locale that a new device declares (issue
/// 141). The default gives the bytes of before: model `PC`, locale
/// `en_US`, no name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceHints {
    pub name: Option<String>,
    pub model: Option<String>,
    pub locale: Option<String>,
}

/// The variables of [`DeviceHints`].
pub const DEVICE_NAME_VARIABLE: &str = "CFRS_WARP_DEVICE_NAME";
pub const DEVICE_MODEL_VARIABLE: &str = "CFRS_WARP_DEVICE_MODEL";
pub const DEVICE_LOCALE_VARIABLE: &str = "CFRS_WARP_DEVICE_LOCALE";

static HINTS: std::sync::OnceLock<DeviceHints> = std::sync::OnceLock::new();

impl DeviceHints {
    /// The hints of the variables.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self {
            name: var(DEVICE_NAME_VARIABLE),
            model: var(DEVICE_MODEL_VARIABLE),
            locale: var(DEVICE_LOCALE_VARIABLE),
        }
    }

    /// A name of 1 to 64 printable characters, a model of 1 to 32, a
    /// locale as `ll_CC`.
    pub fn check(&self) -> Result<()> {
        let printable = |s: &str| s.chars().all(|c| !c.is_control());
        if let Some(name) = &self.name {
            if name.is_empty() || name.chars().count() > 64 || !printable(name) {
                bail!("the device name has 1 to 64 printable characters: {name:?}");
            }
        }
        if let Some(model) = &self.model {
            if model.is_empty() || model.chars().count() > 32 || !printable(model) {
                bail!("the device model has 1 to 32 printable characters: {model:?}");
            }
        }
        if let Some(locale) = &self.locale {
            let b = locale.as_bytes();
            let ok = b.len() == 5
                && b[..2].iter().all(u8::is_ascii_lowercase)
                && b[2] == b'_'
                && b[3..].iter().all(u8::is_ascii_uppercase);
            if !ok {
                bail!("the device locale is as en_US: {locale:?}");
            }
        }
        Ok(())
    }

    /// Set the hints of this process (the flags). A later call does
    /// nothing.
    pub fn set(self) -> Result<()> {
        self.check()?;
        let _ = HINTS.set(self);
        Ok(())
    }

    /// The hints of this process: the flags, else the variables.
    pub fn current() -> Self {
        HINTS.get().cloned().unwrap_or_else(Self::from_env)
    }
}

fn now_rfc3339_millis() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// `YYYY-MM-DD HH:MM UTC` of Unix seconds.
pub(crate) fn utc_minutes(secs: u64) -> String {
    let (y, mo, d, h, mi, _) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} UTC")
}

/// Convert Unix seconds to a civil UTC date, so the crate needs no time library.
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h as u32, mi as u32, s as u32)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS entropy unavailable");
    out
}

fn random_hex(n: usize) -> String {
    let mut out = String::with_capacity(n * 2);
    let bytes = random_bytes::<32>();
    for b in bytes.iter().take(n) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// A request of the WARP API, with the headers of the official client.
fn request(
    method: &'static str,
    path: &str,
    bearer: Option<&str>,
    proxy: Option<&Proxy>,
) -> crate::fetch::Request {
    let mut request = crate::fetch::Request::new(method, format!("{API_BASE}/{API_VERSION}{path}"))
        .header("User-Agent", USER_AGENT)
        .header("CF-Client-Version", CLIENT_VERSION)
        .header("Content-Type", "application/json; charset=UTF-8")
        .timeout(std::time::Duration::from_secs(30))
        .via(proxy.cloned());
    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    request
}

/// The send of an API request: see [`send_api`].
trait SendApi {
    async fn send_api(self) -> Result<crate::fetch::Response>;
}

impl SendApi for crate::fetch::Request {
    async fn send_api(self) -> Result<crate::fetch::Response> {
        send_api(self).await
    }
}

fn with_json<T: Serialize>(
    request: crate::fetch::Request,
    body: &T,
) -> Result<crate::fetch::Request> {
    Ok(request.json(&serde_json::to_value(body).context("encoding the WARP API body")?))
}

/// The device of an answer. A body that cannot be decoded is not shown: the
/// answer of `POST /reg` holds the token.
fn check(resp: crate::fetch::Response) -> Result<Device> {
    if !resp.is_success() {
        bail!("WARP API answered HTTP {}: {}", resp.status, resp.text());
    }
    serde_json::from_slice(&resp.body)
        .with_context(|| format!("decoding the WARP API answer ({} bytes)", resp.body.len()))
}

/// Create an anonymous device. Returns the device plus its bearer token, which
/// is needed for the enrolment call and for later account queries.
pub async fn create_device(proxy: Option<&Proxy>) -> Result<Device> {
    // A throwaway X25519 public key. The API validates its shape, not that
    // anybody holds the private half, and MASQUE never uses it.
    create_device_with_key(&b64(&random_bytes::<32>()), proxy).await
}

/// Register a WireGuard device with the X25519 public key `key` (base64).
/// `warp export` (issue 148) keeps the private half.
pub async fn create_device_with_key(key: &str, proxy: Option<&Proxy>) -> Result<Device> {
    let hints = DeviceHints::current();
    hints.check()?;
    let body = RegistrationRequest {
        key: key.to_string(),
        install_id: String::new(),
        fcm_token: String::new(),
        tos: now_rfc3339_millis(),
        model: hints.model.unwrap_or_else(|| "PC".into()),
        serial_number: random_hex(8),
        os_version: String::new(),
        key_type: "curve25519".into(),
        tunnel_type: "wireguard".into(),
        locale: hints.locale.unwrap_or_else(|| "en_US".into()),
    };
    let resp = with_json(request("POST", "/reg", None, proxy), &body)?
        .send_api()
        .await
        .context("POST /reg")?;
    if let Some(err) = registration_error(resp.status, resp.header("retry-after"), &resp.text()) {
        return Err(err);
    }
    check(resp)
}

/// The error of a refused registration (issue 187): a 429 (error 1015)
/// names the remedy and the Retry-After. None for another status.
pub fn registration_error(
    status: u16,
    retry_after: Option<&str>,
    body: &str,
) -> Option<anyhow::Error> {
    if status != 429 && !body.contains("1015") {
        return None;
    }
    let wait = retry_after
        .and_then(crate::quicktunnel::parse_retry_after)
        .map(|d| format!("; the service asks to wait {} s", d.as_secs()))
        .unwrap_or_default();
    Some(
        anyhow::Error::new(ApiError {
            status,
            body: body.chars().take(200).collect(),
        })
        .context(format!(
            "the WARP service limits new devices for each address (HTTP {status}, error 1015){wait}; reuse a saved identity (--identity FILE, the default warp.json) in place of a new device, or wait"
        )),
    )
}

/// Enrol a MASQUE identity: upload the P-256 public key (X.509 SPKI, base64) and
/// switch the device to the `masque` tunnel type.
pub async fn enrol_masque(
    device_id: &str,
    token: &str,
    spki_b64: &str,
    proxy: Option<&Proxy>,
) -> Result<Device> {
    let body = EnrolRequest {
        key: spki_b64.to_string(),
        key_type: "secp256r1".into(),
        tunnel_type: "masque".into(),
        name: DeviceHints::current().name,
    };
    let resp = with_json(
        request("PATCH", &format!("/reg/{device_id}"), Some(token), proxy),
        &body,
    )?
    .send_api()
    .await
    .context("PATCH /reg/{id}")?;
    check(resp)
}

/// Read the device record again (`GET /reg/{id}`).
pub async fn get_device(device_id: &str, token: &str, proxy: Option<&Proxy>) -> Result<Device> {
    let resp = request("GET", &format!("/reg/{device_id}"), Some(token), proxy)
        .send_api()
        .await
        .context("GET /reg/{id}")?;
    check(resp)
}

/// Read the account of the device (`GET /reg/{id}/account`). The answer has
/// the account type, the WARP+ state and the data quota.
pub async fn get_account(
    device_id: &str,
    token: &str,
    proxy: Option<&Proxy>,
) -> Result<serde_json::Value> {
    let resp = request(
        "GET",
        &format!("/reg/{device_id}/account"),
        Some(token),
        proxy,
    )
    .send_api()
    .await
    .context("GET /reg/{id}/account")?;
    json_body(resp)
}

/// Hide the license key in an account record (`GET /reg/{id}/account`):
/// each key named `license`, at any depth, with a non-empty string value
/// becomes `"<hidden>"`. `cfrs warp status --json` prints the record.
pub fn redact_account(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key.eq_ignore_ascii_case("license") {
                    if item.as_str().is_some_and(|s| !s.is_empty()) {
                        *item = serde_json::Value::String("<hidden>".into());
                    }
                } else {
                    redact_account(item);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_account),
        _ => {}
    }
}

/// Attach a WARP+ license key to the device (`PUT /reg/{id}/account`).
pub async fn set_license(
    device_id: &str,
    token: &str,
    license: &str,
    proxy: Option<&Proxy>,
) -> Result<serde_json::Value> {
    let resp = request(
        "PUT",
        &format!("/reg/{device_id}/account"),
        Some(token),
        proxy,
    )
    .json(&serde_json::json!({ "license": license }))
    .send_api()
    .await
    .context("PUT /reg/{id}/account")?;
    json_body(resp)
}

/// Remove the device from the WARP service (`DELETE /reg/{id}`).
pub async fn delete_device(device_id: &str, token: &str, proxy: Option<&Proxy>) -> Result<()> {
    let resp = request("DELETE", &format!("/reg/{device_id}"), Some(token), proxy)
        .send_api()
        .await
        .context("DELETE /reg/{id}")?;
    if !resp.is_success() {
        bail!("WARP API answered HTTP {}: {}", resp.status, resp.text());
    }
    Ok(())
}

/// A WARP API answer that is not a success: its HTTP status and body.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub body: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WARP API answered HTTP {}: {}", self.status, self.body)
    }
}

impl std::error::Error for ApiError {}

/// The HTTP status of a WARP API answer in the chain of `err`.
pub fn api_status(err: &anyhow::Error) -> Option<u16> {
    err.chain()
        .find_map(|e| e.downcast_ref::<ApiError>())
        .map(|e| e.status)
}

fn json_body(resp: crate::fetch::Response) -> Result<serde_json::Value> {
    if !resp.is_success() {
        return Err(ApiError {
            status: resp.status,
            body: resp.text(),
        }
        .into());
    }
    serde_json::from_slice(&resp.body)
        .with_context(|| format!("decoding the WARP API answer ({} bytes)", resp.body.len()))
}

impl Device {
    /// IPv4 address the tunnel assigned, without any prefix length.
    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let raw = self.config.interface.addresses.v4.trim();
        let raw = raw.split('/').next().unwrap_or(raw);
        raw.parse().ok()
    }

    /// IPv6 address the tunnel assigned, without any prefix length.
    pub fn ipv6(&self) -> Option<std::net::Ipv6Addr> {
        let raw = self.config.interface.addresses.v6.trim();
        let raw = raw.split('/').next().unwrap_or(raw);
        raw.parse().ok()
    }

    /// The MASQUE front door, as an address to dial.
    pub fn masque_endpoint(&self) -> Option<std::net::SocketAddr> {
        let peer = self.config.peers.first()?;
        let v4 = peer.endpoint.v4.split(':').next().unwrap_or("").trim();
        if let Ok(ip) = v4.parse::<std::net::Ipv4Addr>() {
            return Some(std::net::SocketAddr::new(ip.into(), MASQUE_PORT));
        }
        let v6 = peer.endpoint.v6.trim().trim_start_matches('[');
        let v6 = v6.split(']').next().unwrap_or(v6);
        if let Ok(ip) = v6.parse::<std::net::Ipv6Addr>() {
            return Some(std::net::SocketAddr::new(ip.into(), MASQUE_PORT));
        }
        None
    }

    /// The addresses of the MASQUE front door to try, in order (issue 124):
    /// the IPv4 address of the first peer, then its IPv6 address. Both
    /// have the key of the first peer.
    pub fn masque_endpoints(&self) -> Vec<std::net::SocketAddr> {
        let Some(peer) = self.config.peers.first() else {
            return Vec::new();
        };
        if self.config.peers.len() > 1 {
            // Issue 133: other peers have other keys; only the first is used.
            tracing::debug!(
                peers = self.config.peers.len(),
                "the device record has more than one peer"
            );
        }
        let mut out = Vec::new();
        let v4 = peer.endpoint.v4.split(':').next().unwrap_or("").trim();
        if let Ok(ip) = v4.parse::<std::net::Ipv4Addr>() {
            out.push(std::net::SocketAddr::new(ip.into(), MASQUE_PORT));
        }
        let v6 = peer.endpoint.v6.trim().trim_start_matches('[');
        let v6 = v6.split(']').next().unwrap_or(v6);
        if let Ok(ip) = v6.parse::<std::net::Ipv6Addr>() {
            out.push(std::net::SocketAddr::new(ip.into(), MASQUE_PORT));
        }
        out
    }

    /// The server's pinned public key, PEM (`PUBLIC KEY`).
    pub fn peer_public_key_pem(&self) -> Option<&str> {
        self.config
            .peers
            .first()
            .map(|p| p.public_key.as_str())
            .filter(|k| k.contains("BEGIN PUBLIC KEY"))
    }

    /// The `client_id`, whose first three base64 bytes are the WireGuard
    /// "reserved" tag. Kept because the WireGuard mode needs it.
    pub fn reserved(&self) -> Option<[u8; 3]> {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.config.client_id.as_bytes())
            .ok()?;
        if raw.len() < 3 {
            return None;
        }
        Some([raw[0], raw[1], raw[2]])
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_license_key_is_hidden_in_the_account_record() {
        let mut account = serde_json::json!({
            "account_type": "limited",
            "license": "abcd1234-efgh5678-ijkl9012",
            "nested": [{"license": "x1y2z3"}],
            "empty": {"license": ""},
            "warp_plus": true
        });
        redact_account(&mut account);
        let text = account.to_string();
        assert!(
            !text.contains("abcd1234") && !text.contains("x1y2z3"),
            "{text}"
        );
        assert_eq!(account["license"], "<hidden>");
        assert_eq!(account["nested"][0]["license"], "<hidden>");
        assert_eq!(account["empty"]["license"], "");
        assert_eq!(account["account_type"], "limited");
    }

    use super::*;

    #[test]
    fn the_api_bases() {
        assert_eq!(api_bases(None).unwrap(), [API_BASE, API_SECOND]);
        assert_eq!(api_bases(Some(" ")).unwrap(), [API_BASE, API_SECOND]);
        assert_eq!(
            api_bases(Some("https://api.devices.cloudflare.com/")).unwrap(),
            [API_SECOND]
        );
        assert_eq!(
            api_bases(Some("http://127.0.0.1:8080")).unwrap(),
            ["http://127.0.0.1:8080"]
        );
        for bad in [
            "http://api.cloudflareclient.com",
            "api.cloudflareclient.com",
            "https://api.cloudflareclient.com/v0",
            "https://",
        ] {
            assert!(api_bases(Some(bad)).is_err(), "{bad}");
        }
    }

    /// An API on loopback that answers each request with `status`.
    async fn answering(status: u16) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let text = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}"
                );
                let _ = socket.write_all(text.as_bytes()).await;
            }
        });
        base
    }

    /// The second base answers after a dial failure or a 5xx of the first;
    /// a 4xx of the first is its answer.
    #[tokio::test]
    async fn the_second_api_host_answers_after_a_failure() {
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_base = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let good = answering(200).await;
        let busy = answering(503).await;
        let refused = answering(403).await;
        let request = || {
            crate::fetch::Request::new("GET", format!("{API_BASE}/{API_VERSION}/reg/x"))
                .timeout(std::time::Duration::from_secs(5))
                .via(None)
        };
        let answer = send_api_to(request(), &[dead_base.clone(), good.clone()])
            .await
            .unwrap();
        assert_eq!(answer.status, 200);
        let answer = send_api_to(request(), &[busy.clone(), good.clone()])
            .await
            .unwrap();
        assert_eq!(answer.status, 200);
        let answer = send_api_to(request(), &[refused, good.clone()])
            .await
            .unwrap();
        assert_eq!(answer.status, 403, "a 4xx is an answer");
        let answer = send_api_to(request(), &[good.clone(), busy.clone()])
            .await
            .unwrap();
        assert_eq!(answer.status, 200);
        let err = send_api_to(request(), &[busy, dead_base])
            .await
            .expect_err("each base failed");
        assert!(format!("{err:#}").contains("HTTP 503"), "{err:#}");
    }

    // Issue 187: a 429 of the registration names the remedy.
    #[test]
    fn a_429_on_registration_names_the_remedy() {
        let err = registration_error(429, Some("120"), "error code: 1015").unwrap();
        let text = format!("{err:#}");
        assert!(text.contains("reuse a saved identity"), "{text}");
        assert!(text.contains("wait 120 s"), "{text}");
        assert_eq!(api_status(&err), Some(429));
        assert!(registration_error(400, None, "bad key").is_none());
    }

    // Issue 141: the hints are checked; the default body is as before.
    #[test]
    fn the_device_hints() {
        assert!(DeviceHints::default().check().is_ok());
        let ok = DeviceHints {
            name: Some("ci-runner-7".into()),
            model: Some("Linux".into()),
            locale: Some("de_DE".into()),
        };
        assert!(ok.check().is_ok());
        for bad in [
            DeviceHints {
                name: Some(String::new()),
                ..Default::default()
            },
            DeviceHints {
                name: Some("x".repeat(65)),
                ..Default::default()
            },
            DeviceHints {
                name: Some("a\nb".into()),
                ..Default::default()
            },
            DeviceHints {
                model: Some("m".repeat(33)),
                ..Default::default()
            },
            DeviceHints {
                locale: Some("english".into()),
                ..Default::default()
            },
            DeviceHints {
                locale: Some("EN_us".into()),
                ..Default::default()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        let body = serde_json::to_value(EnrolRequest {
            key: "k".into(),
            key_type: "secp256r1".into(),
            tunnel_type: "masque".into(),
            name: None,
        })
        .unwrap();
        assert!(body.get("name").is_none(), "{body}");
    }

    #[test]
    fn civil_dates_are_right() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2026-10-31T00:00:00Z
        assert_eq!(civil_from_unix(1_793_404_800), (2026, 10, 31, 0, 0, 0));
    }

    #[test]
    fn timestamp_shape() {
        let ts = now_rfc3339_millis();
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
    }

    #[test]
    fn endpoint_parsing_strips_the_zero_port() {
        let device: Device = serde_json::from_str(
            r#"{"id":"x","account":{"id":"a"},"config":{"peers":[{"public_key":"k",
                "endpoint":{"v4":"162.159.198.2:0","v6":"[2606:4700:103::2]:0"}}],
                "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::1"}}}}"#,
        )
        .unwrap();
        assert_eq!(
            device.masque_endpoint(),
            Some("162.159.198.2:443".parse().unwrap())
        );
        // Issue 124: both addresses of the peer, IPv4 first.
        assert_eq!(
            device.masque_endpoints(),
            [
                "162.159.198.2:443".parse().unwrap(),
                "[2606:4700:103::2]:443".parse().unwrap()
            ]
        );
        assert_eq!(device.ipv4(), Some("172.16.0.2".parse().unwrap()));
        assert_eq!(device.ipv6(), Some("2606:4700:110::1".parse().unwrap()));
    }
}
