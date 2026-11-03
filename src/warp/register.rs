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
    let body = RegistrationRequest {
        // A throwaway X25519 public key. The API validates its shape, not that
        // anybody holds the private half, and MASQUE never uses it.
        key: b64(&random_bytes::<32>()),
        install_id: String::new(),
        fcm_token: String::new(),
        tos: now_rfc3339_millis(),
        model: "PC".into(),
        serial_number: random_hex(8),
        os_version: String::new(),
        key_type: "curve25519".into(),
        tunnel_type: "wireguard".into(),
        locale: "en_US".into(),
    };
    let resp = with_json(request("POST", "/reg", None, proxy), &body)?
        .send()
        .await
        .context("POST /reg")?;
    check(resp)
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
    };
    let resp = with_json(
        request("PATCH", &format!("/reg/{device_id}"), Some(token), proxy),
        &body,
    )?
    .send()
    .await
    .context("PATCH /reg/{id}")?;
    check(resp)
}

/// Read the device record again (`GET /reg/{id}`).
pub async fn get_device(device_id: &str, token: &str, proxy: Option<&Proxy>) -> Result<Device> {
    let resp = request("GET", &format!("/reg/{device_id}"), Some(token), proxy)
        .send()
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
    .send()
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
    .send()
    .await
    .context("PUT /reg/{id}/account")?;
    json_body(resp)
}

/// Remove the device from the WARP service (`DELETE /reg/{id}`).
pub async fn delete_device(device_id: &str, token: &str, proxy: Option<&Proxy>) -> Result<()> {
    let resp = request("DELETE", &format!("/reg/{device_id}"), Some(token), proxy)
        .send()
        .await
        .context("DELETE /reg/{id}")?;
    if !resp.is_success() {
        bail!("WARP API answered HTTP {}: {}", resp.status, resp.text());
    }
    Ok(())
}

fn json_body(resp: crate::fetch::Response) -> Result<serde_json::Value> {
    if !resp.is_success() {
        bail!("WARP API answered HTTP {}: {}", resp.status, resp.text());
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
