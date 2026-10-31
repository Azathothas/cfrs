//! Outbound connections through an HTTP `CONNECT` proxy.
//!
//! A sealed host often permits exactly one egress: an HTTP proxy that answers
//! `CONNECT host:port` on an allowed address. Every protocol above TCP then
//! runs unchanged inside that pipe, including TLS to the WARP MASQUE front
//! door. [`Proxy::from_env`] reads the usual variables and [`Proxy::connect`]
//! returns a stream positioned after the proxy's response.
//!
//! The proxy is used for the dials that need it: the WARP registration API,
//! the DNS-over-HTTPS lookup, and the MASQUE front door. The tunnel edge is
//! reached inside the WARP session, so it never needs a host socket.

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::net::BoxedIo;

/// Largest `CONNECT` response header block accepted. A well-behaved proxy
/// answers in under 300 bytes; anything larger is a misconfiguration or an
/// attempt to make the caller allocate without bound.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// An HTTP proxy that supports `CONNECT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    url: String,
    host: String,
    port: u16,
    auth: Option<(String, String)>,
}

impl Proxy {
    /// Read the proxy from the environment. Order matches curl: `HTTPS_PROXY`,
    /// then `https_proxy`, then `ALL_PROXY`, then `all_proxy`. Returns `None`
    /// when no variable is set.
    pub fn from_env() -> Option<Self> {
        for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            if let Ok(spec) = std::env::var(key) {
                if spec.trim().is_empty() {
                    continue;
                }
                match Self::parse(&spec) {
                    Ok(proxy) => return Some(proxy),
                    Err(err) => {
                        tracing::warn!(%key, error = %err, "ignoring unparsable proxy variable");
                    }
                }
            }
        }
        None
    }

    /// Parse `http://[user:pass@]host:port`. A missing port means 8080, the
    /// same default curl uses for `http_proxy`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty proxy URL");
        }
        let (scheme, rest) = match spec.split_once("://") {
            Some((scheme, rest)) => (scheme, rest),
            None => ("http", spec),
        };
        if !scheme.eq_ignore_ascii_case("http") {
            bail!("only http:// proxies are supported, not {scheme}://");
        }
        let rest = rest.trim_end_matches('/');
        let (auth, authority) = match rest.rsplit_once('@') {
            Some((auth, authority)) => (Some(auth), authority),
            None => (None, rest),
        };
        let (host, port) = split_host_port(authority)?;
        let auth = match auth {
            Some(auth) => {
                let (user, pass) = auth
                    .split_once(':')
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .unwrap_or_else(|| (auth.to_string(), String::new()));
                Some((percent_decode(&user), percent_decode(&pass)))
            }
            None => None,
        };
        Ok(Self {
            url: spec.to_string(),
            host,
            port,
            auth,
        })
    }

    /// The original URL, for libraries that take one (for example `reqwest`).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The proxy's own address. Connecting here is direct, never proxied.
    pub fn address(&self) -> (&str, u16) {
        (&self.host, self.port)
    }

    /// Open a `CONNECT` tunnel to `host:port` and return the stream.
    ///
    /// The returned stream carries the target's protocol verbatim. Nothing is
    /// read or written after the proxy's `200` line except by the caller.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> Result<BoxedIo> {
        let mut stream =
            tokio::time::timeout(timeout, TcpStream::connect((self.host.as_str(), self.port)))
                .await
                .with_context(|| format!("connecting to the proxy {}:{}", self.host, self.port))?
                .with_context(|| format!("connecting to the proxy {}:{}", self.host, self.port))?;
        stream.set_nodelay(true).ok();

        let mut request = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n"
        );
        if let Some((user, pass)) = &self.auth {
            let raw = format!("{user}:{pass}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
        }
        request.push_str("\r\n");

        tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
            .await
            .context("writing the CONNECT request")?
            .context("writing the CONNECT request")?;

        let head = read_head(&mut stream, timeout).await?;
        let status = parse_status(&head)?;
        if !(200..300).contains(&status) {
            bail!("proxy refused CONNECT {host}:{port} with HTTP {status}");
        }
        Ok(Box::new(stream))
    }
}

/// Split `host:port`, `[v6]:port` or a bare host. A missing port is 8080.
fn split_host_port(authority: &str) -> Result<(String, u16)> {
    if authority.is_empty() {
        bail!("proxy URL has no host");
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("proxy IPv6 address is missing its closing bracket")?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().context("proxy port is not a number")?,
            None => 8080,
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => Ok((
            host.to_string(),
            port.parse().context("proxy port is not a number")?,
        )),
        _ => Ok((authority.to_string(), 8080)),
    }
}

/// Decode `%XX` escapes. A malformed escape is left as written.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Read bytes until the blank line that ends the response head.
async fn read_head(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    loop {
        let n = tokio::time::timeout(timeout, stream.read(&mut chunk))
            .await
            .context("reading the CONNECT response")?
            .context("reading the CONNECT response")?;
        if n == 0 {
            bail!("the proxy closed the connection before answering CONNECT");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADER_BYTES {
            bail!("the proxy response header exceeds {MAX_HEADER_BYTES} bytes");
        }
    }
}

/// Parse `HTTP/1.1 200 Connection established`.
fn parse_status(head: &[u8]) -> Result<u16> {
    let text = String::from_utf8_lossy(head);
    let line = text
        .lines()
        .next()
        .context("the proxy sent an empty response")?;
    let mut parts = line.split_whitespace();
    let version = parts.next().context("missing HTTP version")?;
    if !version.starts_with("HTTP/") {
        bail!("the proxy did not answer with HTTP: {line}");
    }
    let code = parts.next().context("missing HTTP status code")?;
    code.parse::<u16>()
        .with_context(|| format!("the proxy status is not a number: {line}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_url() {
        let p = Proxy::parse("http://user:p%40ss@10.0.0.1:3128").unwrap();
        assert_eq!(p.address(), ("10.0.0.1", 3128));
        assert_eq!(p.auth, Some(("user".into(), "p@ss".into())));
    }

    #[test]
    fn a_missing_port_defaults_to_8080() {
        let p = Proxy::parse("http://proxy.example").unwrap();
        assert_eq!(p.address(), ("proxy.example", 8080));
    }

    #[test]
    fn parses_a_bracketed_ipv6_authority() {
        let p = Proxy::parse("http://[::1]:9000").unwrap();
        assert_eq!(p.address(), ("::1", 9000));
    }

    #[test]
    fn rejects_a_non_http_scheme() {
        assert!(Proxy::parse("socks5://127.0.0.1:1080").is_err());
    }

    #[test]
    fn status_parsing_accepts_the_canonical_line() {
        assert_eq!(
            parse_status(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap(),
            200
        );
        assert_eq!(
            parse_status(b"HTTP/1.0 407 Proxy Auth\r\n\r\n").unwrap(),
            407
        );
    }

    #[test]
    fn status_parsing_rejects_a_non_http_reply() {
        assert!(parse_status(b"SSH-2.0-OpenSSH\r\n").is_err());
    }
}
