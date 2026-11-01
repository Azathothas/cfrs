//! Provision an anonymous Cloudflare "quick tunnel", the way `cloudflared` does.
//!
//! # What this reproduces
//!
//! `cloudflared tunnel --url ...` calls `POST https://api.trycloudflare.com/tunnel`
//! with an empty body and **no credentials of any kind**. The response carries a
//! tunnel id, an account tag, a 32-byte secret (base64 in JSON) and the public
//! hostname. The request is plain HTTPS on port 443.
//!
//! References in the `cloudflared` source:
//!
//! * `cmd/cloudflared/tunnel/quick_tunnel.go` - `RunQuickTunnel` performs the
//!   POST; `QuickTunnelResponse` is the response shape.
//! * `cmd/cloudflared/tunnel/cmd.go` - `quick-service` defaults to
//!   `https://api.trycloudflare.com`.
//! * `quicktunnelauth` - when an email allow-list is requested the client sends
//!   `{"auth_mode":"otp"}` instead of an empty body. The allow-list itself never
//!   leaves the client; Cloudflare only learns that OTP is required.
//!
//! # What this does NOT do
//!
//! It does not open the tunnel edge connection. See [`crate::tunnel`] and
//! `docs/protocol.md`.

use serde::{Deserialize, Serialize};

/// Default provisioning endpoint, matching cloudflared's `quick-service` flag.
pub const DEFAULT_QUICK_SERVICE: &str = "https://api.trycloudflare.com";

/// The anonymous provisioning response. Only the fields cfrs uses are modelled;
/// cloudflared's `QuickTunnel` also carries `name`, which is unused here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuickTunnel {
    /// Tunnel UUID.
    pub id: String,
    /// The public hostname, e.g. `foo-bar.trycloudflare.com`.
    pub hostname: String,
    /// Hex account tag the tunnel is billed/attributed to.
    pub account_tag: String,
    /// Base64-encoded 32-byte tunnel secret. Sent to the edge verbatim by
    /// cloudflared (`connection.Credentials.TunnelSecret`), not hashed.
    pub secret: String,
}

impl QuickTunnel {
    /// The public URL for this tunnel.
    pub fn url(&self) -> String {
        format!("https://{}", self.hostname)
    }

    /// The raw secret bytes, decoded from base64.
    ///
    /// This is the value cloudflared puts on the wire as `TunnelAuth.tunnelSecret`
    /// without any hashing step, so a reimplementation must not transform it.
    pub fn secret_bytes(&self) -> Result<Vec<u8>, String> {
        decode_base64(&self.secret).ok_or_else(|| {
            format!(
                "tunnel secret is not valid base64 ({} bytes of text)",
                self.secret.len()
            )
        })
    }
}

/// Top-level envelope: `{"success":bool,"result":{...},"errors":[...]}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuickTunnelResponse {
    pub success: bool,
    #[serde(default)]
    pub result: Option<QuickTunnel>,
    #[serde(default)]
    pub errors: Vec<QuickTunnelError>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuickTunnelError {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

/// How the tunnel should be authenticated for visitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Anyone with the URL can reach the origin. Empty request body.
    Public,
    /// Visitors must pass a one-time PIN before reaching the origin.
    /// Request body is `{"auth_mode":"otp"}`.
    ///
    /// Note that the allow-list is enforced by the *client*, exactly as
    /// `cloudflared --allowed-mail` does: Cloudflare is told only that OTP is
    /// required, never which addresses are acceptable.
    Otp,
}

impl AuthMode {
    /// The request body to POST. `None` means an empty body.
    pub fn request_body(self) -> Option<&'static str> {
        match self {
            AuthMode::Public => None,
            AuthMode::Otp => Some(r#"{"auth_mode":"otp"}"#),
        }
    }
}

/// A validation failure detected before any network call is made.
#[derive(Debug)]
pub enum ProvisionError {
    /// The provisioning endpoint was not a valid absolute URL.
    BadEndpoint(String),
    /// The HTTP request itself failed.
    Http(anyhow::Error),
    /// A non-2xx HTTP status.
    Status {
        code: u16,
        body: String,
        /// The `Retry-After` of the answer.
        retry_after: Option<std::time::Duration>,
    },
    /// A 2xx response that is not valid JSON, or not a `QuickTunnelResponse`.
    Decode(String),
    /// The service returned `"success": false`.
    Service(Vec<QuickTunnelError>),
    /// `success: true` but no `result` object.
    MissingResult,
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::BadEndpoint(e) => write!(f, "invalid quick-service endpoint: {e}"),
            ProvisionError::Http(_) => write!(f, "request to the quick-tunnel service failed"),
            ProvisionError::Status {
                code,
                body,
                retry_after,
            } => {
                write!(f, "quick-tunnel service returned HTTP {code}")?;
                if let Some(wait) = retry_after {
                    write!(f, " (Retry-After: {} s)", wait.as_secs())?;
                }
                if !body.is_empty() {
                    write!(f, ": {body}")?;
                }
                if *code == 405 {
                    write!(
                        f,
                        "; a proxy that answers 405 refuses the request form: use a CONNECT proxy"
                    )?;
                }
                Ok(())
            }
            ProvisionError::Decode(e) => {
                write!(f, "could not decode the quick-tunnel response: {e}")
            }
            ProvisionError::Service(errs) => {
                let joined: Vec<String> = errs
                    .iter()
                    .map(|e| format!("{}: {}", e.code, e.message))
                    .collect();
                write!(
                    f,
                    "quick-tunnel service reported failure: {}",
                    joined.join("; ")
                )
            }
            ProvisionError::MissingResult => {
                write!(
                    f,
                    "quick-tunnel service returned success with no result object"
                )
            }
        }
    }
}

/// The cause of a failed request comes through `source`, so that its hop
/// and its text stay in the chain.
impl std::error::Error for ProvisionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProvisionError::Http(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// The user agent cloudflared-style clients send. Kept simple and honest.
pub fn user_agent() -> String {
    format!("cfrs/{} (rust)", env!("CARGO_PKG_VERSION"))
}

/// Provision a quick tunnel: `POST <endpoint>/tunnel`.
///
/// `proxy` is a proxy for this request only. With `None`, the request takes
/// the proxy choice of the process (`crate::egress::proxy_for`).
pub async fn request_quick_tunnel(
    endpoint: &str,
    auth_mode: AuthMode,
    user_agent: &str,
    timeout: std::time::Duration,
    proxy: Option<&crate::egress::Proxy>,
) -> Result<QuickTunnel, ProvisionError> {
    let url = format!("{}/tunnel", endpoint.trim_end_matches('/'));
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ProvisionError::BadEndpoint(url));
    }
    let mut request = crate::fetch::Request::new("POST", url)
        .header("Content-Type", "application/json")
        .header("User-Agent", user_agent)
        .timeout(timeout)
        .via(proxy.cloned());
    if let Some(body) = auth_mode.request_body() {
        request.body = Some(body.into());
    }
    let response = request.send().await.map_err(ProvisionError::Http)?;
    let status = response.status;
    let text = response.text();
    let retry_after = response.header("retry-after").and_then(parse_retry_after);
    match parse_quick_tunnel_response(status, &text) {
        Err(ProvisionError::Status { code, body, .. }) => Err(ProvisionError::Status {
            code,
            body,
            retry_after,
        }),
        other => other,
    }
}

/// The wait of a `Retry-After` value: a number of seconds, or an HTTP date
/// (IMF-fixdate).
pub fn parse_retry_after(value: &str) -> Option<std::time::Duration> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(std::time::Duration::from_secs(secs));
    }
    // Sun, 06 Nov 1994 08:49:37 GMT
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 || parts[5] != "GMT" {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = MONTHS.iter().position(|m| *m == parts[2])? as i64 + 1;
    let year: i64 = parts[3].parse().ok()?;
    let hms: Vec<i64> = parts[4].split(':').filter_map(|p| p.parse().ok()).collect();
    if hms.len() != 3 {
        return None;
    }
    // Days from 1970-01-01 (the algorithm of H. Hinnant).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let at = days * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(std::time::Duration::from_secs((at - now).max(0) as u64))
}

/// The longest time that [`provision`] tries.
pub const PROVISION_BUDGET: std::time::Duration = std::time::Duration::from_secs(300);
/// The most attempts of [`provision`].
pub const PROVISION_ATTEMPTS: u32 = 5;

/// [`request_quick_tunnel`] with retries: a 429, a 5xx and a transport
/// error are tried again, after `Retry-After` or else a backoff with jitter
/// (2, 4, 8, 16 s), up to [`PROVISION_ATTEMPTS`] attempts in `budget`.
/// Another 4xx fails at once. A `Retry-After` that is longer than the time
/// left fails with the wait in the error.
pub async fn provision(
    endpoint: &str,
    auth_mode: AuthMode,
    user_agent: &str,
    timeout: std::time::Duration,
    budget: std::time::Duration,
) -> Result<QuickTunnel, ProvisionError> {
    let start = std::time::Instant::now();
    let policy = crate::config::ReconnectPolicy {
        initial: std::time::Duration::from_secs(2),
        max: std::time::Duration::from_secs(16),
        ..Default::default()
    };
    let mut attempt = 0;
    loop {
        attempt += 1;
        let err = match request_quick_tunnel(endpoint, auth_mode, user_agent, timeout, None).await {
            Ok(tunnel) => return Ok(tunnel),
            Err(err) => err,
        };
        let wait = match &err {
            ProvisionError::Status {
                code, retry_after, ..
            } if *code == 429 || (500..600).contains(code) => {
                retry_after.unwrap_or_else(|| policy.backoff_with_jitter(attempt))
            }
            // A refusal of the proxy and a TLS failure do not change on a
            // retry.
            ProvisionError::Http(inner)
                if matches!(
                    crate::hop::of(inner),
                    Some(crate::hop::Hop::Proxy | crate::hop::Hop::Tls)
                ) =>
            {
                return Err(err)
            }
            ProvisionError::Http(_) => policy.backoff_with_jitter(attempt),
            _ => return Err(err),
        };
        let left = budget.saturating_sub(start.elapsed());
        if attempt >= PROVISION_ATTEMPTS || wait > left {
            if wait > left {
                tracing::warn!(
                    "the quick-tunnel service asks to wait {} s, more than the {} s left",
                    wait.as_secs(),
                    left.as_secs()
                );
            }
            return Err(err);
        }
        tracing::warn!(attempt, retry_in = ?wait, "provisioning failed: {err}; trying again");
        tokio::time::sleep(wait).await;
    }
}

/// Parse and validate a provisioning response body.
///
/// Split out from [`request_quick_tunnel`] so it can be tested against captured
/// real responses without a live service.
pub fn parse_quick_tunnel_response(status: u16, body: &str) -> Result<QuickTunnel, ProvisionError> {
    if !(200..300).contains(&status) {
        // The body of an error, for a terminal: 1 KiB at most, with no
        // control characters.
        let mut clipped = crate::report::clean(body.trim());
        if clipped.len() > 1024 {
            let mut cut = 1024;
            while !clipped.is_char_boundary(cut) {
                cut -= 1;
            }
            clipped.truncate(cut);
        }
        return Err(ProvisionError::Status {
            code: status,
            body: clipped,
            retry_after: None,
        });
    }

    // The provisioning body carries the tunnel's `secret`, `account_tag` and `id`,
    // which are the credentials the edge expects at registration. A decode
    // failure therefore has a body that is mostly credentials, and this error
    // reaches the operator's stderr and any CI log. Redact before including any
    // of it.
    let parsed: QuickTunnelResponse = serde_json::from_str(body)
        .map_err(|e| ProvisionError::Decode(format!("{e}; body was: {}", redact(body))))?;

    if !parsed.success {
        return Err(ProvisionError::Service(parsed.errors));
    }

    parsed.result.ok_or(ProvisionError::MissingResult)
}

/// Replace the credential-bearing fields of a provisioning body with a marker,
/// then clip it to something readable.
///
/// A provisioning response is mostly secret: `secret` is a 32-byte base64 blob
/// and `account_tag` identifies the account, and both are what the edge expects
/// at registration. Including the body in an error is useful for debugging a
/// malformed response, but including the credentials in a log is a leak its
/// readers cannot see. So the values are replaced rather than the whole body
/// dropped, which keeps the diagnostic and loses nothing that matters.
fn redact(body: &str) -> String {
    const REDACTED: &str = "<redacted>";
    let mut out = String::with_capacity(body.len());
    // One pass over the body, checking each key at every position. The keys are
    // few and the body is short, so matching repeatedly per key would work too,
    // but a single cursor cannot get the boundaries wrong: `copied` is always
    // bytes the scan has already accepted.
    let keys: [&str; 4] = ["secret", "account_tag", "tunnel_secret", "id"];
    let mut i = 0;
    while i < body.len() {
        let mut matched: Option<&str> = None;
        for key in keys {
            let needle = format!("\"{key}\"");
            if body[i..].starts_with(&needle) {
                matched = Some(key);
                break;
            }
        }
        let Some(key) = matched else {
            let ch = body[i..].chars().next().expect("i is a boundary");
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };
        // Copy the key and its colon, then replace the value in quotes.
        let needle_len = key.len() + 2;
        let after_key = i + needle_len;
        let Some(colon) = body[after_key..].find(':') else {
            break;
        };
        let after_colon = after_key + colon + 1;
        let Some(open) = body[after_colon..].find('"').map(|p| after_colon + p + 1) else {
            break;
        };
        let Some(close) = body[open + 1..].find('"').map(|p| open + 1 + p) else {
            break;
        };
        out.push_str(&body[i..open + 1]);
        out.push_str(REDACTED);
        i = close + 1;
    }
    truncate(&out, 200)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        // Clip on a character boundary: a raw byte cut can land inside a
        // multi-byte character and panic on the next slice.
        let mut cut = n;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &s[..cut])
    }
}

/// Minimal standard base64 decoder for the tunnel secret.
///
/// Hand-rolled rather than pulling in a dependency: the secret is standard
/// base64 with padding, and this keeps the dependency list small.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in &bytes {
        if b == b'=' {
            break;
        }
        let v = value(b)?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::redact;

    /// A body shaped like the real provisioning response, with values that are
    /// recognisable so a leak in a log is visible.
    const REAL_BODY: &str = r#"{"success":true,"result":{"id":"2983af16-7c68-4ef0-9590-e05f35a0cd7b","name":"qt-x","hostname":"foo.trycloudflare.com","account_tag":"5ab4e9dfbd435d24068829fda0077963","secret":"GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K"}}"#;

    #[test]
    fn redaction_removes_every_credential_from_the_error_text() {
        let redacted = redact(REAL_BODY);
        assert!(
            !redacted.contains("GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K"),
            "the tunnel secret must not survive redaction: {redacted}"
        );
        assert!(
            !redacted.contains("5ab4e9dfbd435d24068829fda0077963"),
            "the account tag must not survive redaction: {redacted}"
        );
        assert!(
            !redacted.contains("2983af16-7c68-4ef0-9590-e05f35a0cd7b"),
            "the tunnel id must not survive redaction: {redacted}"
        );
        assert!(
            redacted.contains("<redacted>"),
            "the redaction marker should be visible: {redacted}"
        );
    }

    #[test]
    fn redaction_keeps_the_fields_a_human_needs() {
        let redacted = redact(REAL_BODY);
        assert!(
            redacted.contains("foo.trycloudflare.com"),
            "the hostname is the part that identifies which tunnel this was: {redacted}"
        );
        assert!(
            redacted.contains(r#""secret""#),
            "the key should remain: {redacted}"
        );
    }

    #[test]
    fn redaction_survives_a_body_that_is_not_json() {
        // A hostile or intercepted endpoint can return anything. The error path
        // must not panic on it.
        for body in [
            "",
            "{",
            "not json at all",
            "{\"secret\":",
            "{\"secret\":\"unterminated",
            r#"{"secret":"a","secret":"b"}"#,
            r#"{"nested":{"account_tag":"x"},"id":"y"}"#,
        ] {
            let out = redact(body);
            assert!(
                !out.contains("unterminated") || body.len() < 40,
                "{body:?} -> {out:?}"
            );
        }
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // The original clipped at a raw byte offset, which panics when the cut
        // lands inside a multi-byte character.
        let text = "é".repeat(400);
        let out = super::truncate(&text, 200);
        assert!(out.ends_with("..."));
        assert!(out.is_char_boundary(out.len() - 3));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    use super::*;

    const OK_BODY: &str = r#"{"success":true,"result":{"id":"6ff42ae2-765d-4adf-8112-31c55c1551ef","hostname":"t.trycloudflare.com","account_tag":"0123456789abcdef","secret":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}}"#;

    /// A local endpoint that gives `answers` in order, one per connection.
    /// Gives its URL and the count of requests.
    fn scripted(
        answers: Vec<(u16, &'static str, &'static str)>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = hits.clone();
        std::thread::spawn(move || {
            let mut answers = answers.into_iter();
            for mut s in listener.incoming().flatten() {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let Some((code, extra, body)) = answers.next() else {
                    break;
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {code} X\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, hits)
    }

    fn hits(h: &std::sync::atomic::AtomicUsize) -> usize {
        h.load(std::sync::atomic::Ordering::SeqCst)
    }

    const BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
    const TO: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn a_429_waits_for_retry_after() {
        let (url, count) = scripted(vec![
            (429, "Retry-After: 1\r\n", "slow down"),
            (200, "", OK_BODY),
        ]);
        let start = std::time::Instant::now();
        let tunnel = provision(&url, AuthMode::Public, "t", TO, BUDGET)
            .await
            .unwrap();
        assert_eq!(tunnel.hostname, "t.trycloudflare.com");
        assert!(start.elapsed() >= std::time::Duration::from_secs(1));
        assert_eq!(hits(&count), 2);
    }

    #[tokio::test]
    async fn a_long_retry_after_fails_with_the_wait() {
        let (url, count) = scripted(vec![(429, "Retry-After: 9999\r\n", "error code: 1015")]);
        let err = provision(&url, AuthMode::Public, "t", TO, BUDGET)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("HTTP 429 (Retry-After: 9999 s): error code: 1015"),
            "{text}"
        );
        assert_eq!(hits(&count), 1);
    }

    #[tokio::test]
    async fn a_5xx_is_retried_and_a_403_is_not() {
        let (url, count) = scripted(vec![
            (500, "Retry-After: 0\r\n", ""),
            (502, "Retry-After: 0\r\n", ""),
            (503, "Retry-After: 0\r\n", ""),
            (200, "", OK_BODY),
        ]);
        provision(&url, AuthMode::Public, "t", TO, BUDGET)
            .await
            .unwrap();
        assert_eq!(hits(&count), 4);

        let (url, count) = scripted(vec![(403, "", "forbidden\u{1b}[2J\u{7}\rnow")]);
        let err = provision(&url, AuthMode::Public, "t", TO, BUDGET)
            .await
            .unwrap_err();
        assert_eq!(hits(&count), 1);
        let text = err.to_string();
        assert!(text.ends_with("HTTP 403: forbiddennow"), "{text:?}");
    }

    #[test]
    fn retry_after_values() {
        let secs = std::time::Duration::from_secs;
        assert_eq!(parse_retry_after("120"), Some(secs(120)));
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(std::time::Duration::ZERO)
        );
        let later = std::time::SystemTime::now() + secs(3600);
        let wait = parse_retry_after(&crate::trust::imf_fixdate(later)).unwrap();
        assert!(wait.as_secs() > 3590 && wait.as_secs() <= 3600, "{wait:?}");
        assert_eq!(parse_retry_after("soon"), None);
    }

    /// A response captured from a real `POST https://api.trycloudflare.com/tunnel`
    /// run against the live service on 2026-10-09. The values are real but the
    /// tunnel is long dead; only the shape matters to these tests.
    const REAL_RESPONSE: &str = r#"{
  "id": "c1267064-5604-4d16-9a83-66b7ed37f182",
  "name": "operator-icon-sheffield-compression",
  "hostname": "operator-icon-sheffield-compression.trycloudflare.com",
  "account_tag": "5ab4e9dfbd435d24068829fda0077963",
  "secret": "GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K",
  "success": true,
  "result": {
    "id": "c1267064-5604-4d16-9a83-66b7ed37f182",
    "name": "operator-icon-sheffield-compression",
    "hostname": "operator-icon-sheffield-compression.trycloudflare.com",
    "account_tag": "5ab4e9dfbd435d24068829fda0077963",
    "secret": "GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K"
  },
  "errors": [],
  "messages": []
}"#;

    #[test]
    fn parses_a_real_provisioning_response() {
        let tunnel = parse_quick_tunnel_response(200, REAL_RESPONSE).expect("should parse");
        assert_eq!(
            tunnel.hostname,
            "operator-icon-sheffield-compression.trycloudflare.com"
        );
        assert_eq!(
            tunnel.url(),
            "https://operator-icon-sheffield-compression.trycloudflare.com"
        );
        assert_eq!(tunnel.id, "c1267064-5604-4d16-9a83-66b7ed37f182");
        assert_eq!(
            tunnel.account_tag.len(),
            32,
            "account tag is a 32-char hex string"
        );
    }

    #[test]
    fn secret_decodes_to_the_documented_32_bytes() {
        let tunnel = parse_quick_tunnel_response(200, REAL_RESPONSE).expect("should parse");
        let bytes = tunnel.secret_bytes().expect("secret should be base64");
        // cloudflared treats this as TunnelSecret and puts it on the wire raw.
        assert_eq!(bytes.len(), 32, "tunnel secret must be 32 raw bytes");
    }

    #[test]
    fn hostname_is_a_trycloudflare_subdomain() {
        let tunnel = parse_quick_tunnel_response(200, REAL_RESPONSE).expect("should parse");
        assert!(
            tunnel.hostname.ends_with(".trycloudflare.com"),
            "quick tunnel hostnames are under trycloudflare.com: {}",
            tunnel.hostname
        );
        let label = tunnel
            .hostname
            .strip_suffix(".trycloudflare.com")
            .expect("suffix checked above");
        assert!(!label.is_empty(), "there must be a leading label");
        assert!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "the label must be ascii alphanumerics and hyphens: {label}"
        );
        assert!(
            !tunnel.hostname.contains('/'),
            "hostname must not carry a scheme or path"
        );
    }

    #[test]
    fn rejects_a_success_false_envelope() {
        let body = r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"nope"}]}"#;
        match parse_quick_tunnel_response(200, body) {
            Err(ProvisionError::Service(errs)) => {
                assert_eq!(errs.len(), 1);
                assert_eq!(errs[0].code, 1001);
                assert_eq!(errs[0].message, "nope");
            }
            other => panic!("expected Service error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_success_with_no_result() {
        let body = r#"{"success":true,"errors":[]}"#;
        match parse_quick_tunnel_response(200, body) {
            Err(ProvisionError::MissingResult) => {}
            other => panic!("expected MissingResult, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_non_2xx_status() {
        match parse_quick_tunnel_response(403, "forbidden") {
            Err(ProvisionError::Status { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Status error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_json() {
        match parse_quick_tunnel_response(200, "not json at all") {
            Err(ProvisionError::Decode(_)) => {}
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn public_mode_sends_an_empty_body_and_otp_sends_the_auth_mode() {
        assert_eq!(AuthMode::Public.request_body(), None);
        assert_eq!(AuthMode::Otp.request_body(), Some(r#"{"auth_mode":"otp"}"#));
    }

    const T: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn endpoint_must_be_an_absolute_http_url() {
        let err = request_quick_tunnel("ftp://example.com", AuthMode::Public, "t", T, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::BadEndpoint(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn trailing_slash_on_the_endpoint_is_not_doubled() {
        let err = request_quick_tunnel("not-a-url/", AuthMode::Public, "t", T, None)
            .await
            .unwrap_err();
        match err {
            ProvisionError::BadEndpoint(url) => {
                assert!(url.ends_with("/tunnel"), "unexpected url {url}");
                assert!(!url.contains("//tunnel"), "double slash in {url}");
            }
            other => panic!("expected BadEndpoint, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_closed_proxy_is_a_transport_failure() {
        let proxy = crate::egress::Proxy::parse("127.0.0.1:1").unwrap();
        let err = request_quick_tunnel(
            "https://api.trycloudflare.com",
            AuthMode::Public,
            "t",
            T,
            Some(&proxy),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ProvisionError::Http(_) | ProvisionError::Status { .. }),
            "expected a transport failure, got {err:?}"
        );
    }
}
