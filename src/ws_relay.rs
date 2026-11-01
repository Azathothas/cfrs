//! The HTTP/2 edge leg through a WebSocket-to-TCP relay
//! (`--transport relay`).
//!
//! Some hosts reach the internet only through an HTTPS proxy on port 443,
//! and the proxy does not carry port 7844 of the edge. A relay on port 443
//! (a Cloudflare Worker, for example `tcp.ssh.relay.ajam.dev`) takes a
//! WebSocket at `/connect/{ip}/{port}` and opens TCP to that address. cfrs
//! sends the TLS of the HTTP/2 leg (SNI `h2.cftunnel.com`, the edge roots)
//! in the WebSocket, so the relay sees only TLS bytes. The tunnel token does
//! not go to the relay.
//!
//! The token of the relay comes from [`TOKEN_VARIABLE`], or cfrs mints one with
//! `POST /v1/mint`. It goes only in the `X-Relay-Token` header (not in the
//! URL), and no log or error has it.
//!
//! Limits of the relay that apply to an edge connection:
//!
//! * TCP only: no QUIC leg.
//! * IPv4 only: the relay has no IPv6 egress.
//! * A session ends after 180 s with no payload. The PING of the HTTP/2
//!   leg (each 30 s) is payload.
//! * A session ends at 64 MiB (both directions) or after 12 h. The tunnel
//!   then connects a replacement, as for each lost connection.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _, Result};
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

use crate::net::BoxedIo;

/// The relay of `--transport relay` when no other is given.
pub const DEFAULT_RELAY: &str = "https://tcp.ssh.relay.ajam.dev";
/// The environment variable with the relay URL.
pub const RELAY_VARIABLE: &str = "CFRS_RELAY";
/// The environment variable with a token for the relay.
pub const TOKEN_VARIABLE: &str = "CFRS_RELAY_TOKEN";
/// A minted token is minted again when it has less time than this.
const MINT_MARGIN: Duration = Duration::from_secs(10 * 60);
/// The largest WebSocket message and frame that cfrs takes from the relay.
const MAX_MESSAGE: usize = 16 << 20;
/// The buffer between the WebSocket pump and the HTTP/2 leg.
const PIPE_BUFFER: usize = 256 * 1024;

static RELAY: OnceLock<Relay> = OnceLock::new();

/// Use `relay` for each HTTP/2 edge connection of this process.
pub fn set(relay: Relay) {
    let _ = RELAY.set(relay);
}

/// The relay of this process, when `--transport relay` is in use.
pub fn active() -> Option<&'static Relay> {
    RELAY.get()
}

/// A WebSocket-to-TCP relay.
pub struct Relay {
    tls: bool,
    host: String,
    port: u16,
    fixed: Option<String>,
    minted: tokio::sync::Mutex<Option<Minted>>,
}

struct Minted {
    token: String,
    expires: SystemTime,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("url", &self.url())
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Why the relay refused a WebSocket.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// The token is absent, wrong or expired: a new token can help.
    Token,
    /// Anything else, with the text for the error.
    Other(String),
}

impl Relay {
    /// A relay at `url` (`https://host[:port]`; `wss://` is the same). Plain
    /// `http://` or `ws://` is taken only for a loopback host (tests).
    /// `token` is used as it is; with no token, cfrs mints one.
    pub fn new(url: &str, token: Option<String>) -> Result<Self> {
        let url = url.trim().trim_end_matches('/');
        let (tls, rest) = if let Some(rest) = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("wss://"))
        {
            (true, rest)
        } else if let Some(rest) = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("ws://"))
        {
            (false, rest)
        } else {
            bail!("the relay URL {url:?} does not start with https://");
        };
        if rest.contains('/') || rest.contains('?') || rest.contains('@') || rest.is_empty() {
            bail!("the relay URL {url:?} must be only a scheme and a host, for example {DEFAULT_RELAY}");
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host.to_string(),
                port.parse::<u16>()
                    .with_context(|| format!("the port of the relay URL {url:?}"))?,
            ),
            _ => (rest.to_string(), if tls { 443 } else { 80 }),
        };
        if !tls && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
            bail!("the relay URL {url:?} must use https:// (plain http:// is for a loopback relay only)");
        }
        Ok(Self {
            tls,
            host,
            port,
            fixed: token.filter(|t| !t.trim().is_empty()),
            minted: tokio::sync::Mutex::new(None),
        })
    }

    /// The relay of `url`, else of [`RELAY_VARIABLE`], else [`DEFAULT_RELAY`],
    /// with the token of [`TOKEN_VARIABLE`].
    pub fn from_env(url: Option<&str>) -> Result<Self> {
        let from_env = std::env::var(RELAY_VARIABLE)
            .ok()
            .filter(|v| !v.trim().is_empty());
        let url = url.map(str::to_string).or(from_env);
        Self::new(
            url.as_deref().unwrap_or(DEFAULT_RELAY),
            std::env::var(TOKEN_VARIABLE).ok(),
        )
    }

    /// The base URL, with no token.
    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }

    /// A token: the fixed token, a minted token that has time left, or a new
    /// minted token (`fresh` mints one in each case).
    async fn token(&self, fresh: bool) -> Result<String> {
        if let Some(token) = &self.fixed {
            return Ok(token.clone());
        }
        let mut minted = self.minted.lock().await;
        let usable = minted.as_ref().filter(|m| {
            !fresh
                && m.expires
                    .duration_since(SystemTime::now())
                    .is_ok_and(|left| left > MINT_MARGIN)
        });
        if let Some(m) = usable {
            return Ok(m.token.clone());
        }
        let new = self.mint().await?;
        let token = new.token.clone();
        *minted = Some(new);
        Ok(token)
    }

    async fn mint(&self) -> Result<Minted> {
        let url = format!("{}/v1/mint", self.url());
        let response = crate::fetch::Request::new("POST", url)
            .json(&serde_json::json!({}))
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .context("minting a relay token")?;
        match response.status {
            200 => {}
            429 => bail!(
                "the relay refused a new token (429); try again after {} s",
                response.header("retry-after").unwrap_or("60")
            ),
            503 => bail!("the relay gives no tokens (503); set {TOKEN_VARIABLE}"),
            status => bail!("minting a relay token: HTTP {status}"),
        }
        let body: serde_json::Value = response.json().context("the mint answer")?;
        let token = body
            .get("token")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .context("the mint answer has no token")?
            .to_string();
        let expires = body
            .get("expires")
            .and_then(|e| e.as_u64())
            .map(|ms| UNIX_EPOCH + Duration::from_millis(ms))
            .unwrap_or_else(|| SystemTime::now() + Duration::from_secs(3600));
        Ok(Minted { token, expires })
    }

    /// A byte stream to `target` through the relay. A refused token is
    /// minted again one time.
    pub async fn connect(&self, target: SocketAddr, timeout: Duration) -> Result<BoxedIo> {
        if target.is_ipv6() {
            bail!("the relay has no IPv6 egress; {target} is IPv6");
        }
        let token = self.token(false).await?;
        match self.open(target, &token, timeout).await? {
            Ok(io) => Ok(io),
            Err(Refusal::Token) if self.fixed.is_none() => {
                let token = self.token(true).await?;
                match self.open(target, &token, timeout).await? {
                    Ok(io) => Ok(io),
                    Err(Refusal::Token) => bail!("the relay refused a new token (403)"),
                    Err(Refusal::Other(text)) => bail!("{text}"),
                }
            }
            Err(Refusal::Token) => bail!("the relay refused the token of {TOKEN_VARIABLE} (403)"),
            Err(Refusal::Other(text)) => bail!("{text}"),
        }
    }

    async fn open(
        &self,
        target: SocketAddr,
        token: &str,
        timeout: Duration,
    ) -> Result<std::result::Result<BoxedIo, Refusal>> {
        let io = crate::egress::dial(&self.host, self.port, None, timeout)
            .await
            .with_context(|| format!("TCP to the relay {}", self.url()))?;
        let io: BoxedIo = if self.tls {
            // HTTP/1.1 only: a WebSocket upgrade does not go over HTTP/2.
            let config = crate::trust::client_config(&[], &[b"http/1.1"])?;
            let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .context("the relay host is not a valid TLS name")?;
            let tls = tokio::time::timeout(
                timeout,
                tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect(name, io),
            )
            .await
            .map_err(|_| anyhow::anyhow!("TLS to the relay: no answer in {} s", timeout.as_secs()))?
            .with_context(|| format!("TLS to the relay {}", self.url()))?;
            Box::new(tls)
        } else {
            io
        };
        let scheme = if self.tls { "wss" } else { "ws" };
        let url = format!(
            "{scheme}://{}:{}/connect/{}/{}",
            self.host,
            self.port,
            target.ip(),
            target.port()
        );
        let mut request = url
            .into_client_request()
            .context("the WebSocket request to the relay")?;
        request.headers_mut().insert(
            "x-relay-token",
            http::HeaderValue::from_str(token).context("the relay token is not a header value")?,
        );
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let handshake = tokio_tungstenite::client_async_with_config(request, io, Some(config));
        let ws = match tokio::time::timeout(timeout, handshake).await {
            Err(_) => bail!(
                "the WebSocket to the relay: no answer in {} s",
                timeout.as_secs()
            ),
            Ok(Ok((ws, _response))) => ws,
            Ok(Err(tungstenite::Error::Http(response))) => {
                let status = response.status().as_u16();
                let body = response
                    .body()
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .to_string();
                return Ok(Err(refusal(status, &body, target)));
            }
            Ok(Err(err)) => {
                return Err(err)
                    .with_context(|| format!("the WebSocket to the relay {}", self.url()))
            }
        };
        let (ours, theirs) = tokio::io::duplex(PIPE_BUFFER);
        tokio::spawn(async move {
            if let Err(err) =
                crate::ws::bridge(ws, Box::new(theirs), &crate::metrics::Metrics::new()).await
            {
                tracing::debug!(error = %format!("{err:#}"), "the relay WebSocket ended");
            }
        });
        Ok(Ok(Box::new(ours)))
    }
}

/// Classify a refused upgrade. The text never has the token.
fn refusal(status: u16, body: &str, target: SocketAddr) -> Refusal {
    let body = body.trim();
    let excerpt: String = body.chars().take(200).collect();
    match status {
        403 if body.contains("ALLOW list") => Refusal::Other(format!(
            "the relay does not allow {target} (403, policy): {excerpt}"
        )),
        401 | 403 => Refusal::Token,
        429 => Refusal::Other(format!("the relay is busy (429): {excerpt}")),
        502 => Refusal::Other(format!(
            "the relay could not open TCP to {target} (502): {excerpt}"
        )),
        status => Refusal::Other(format!(
            "the relay answered HTTP {status} to the WebSocket: {excerpt}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_urls() {
        let relay = Relay::new("https://tcp.ssh.relay.ajam.dev/", None).unwrap();
        assert_eq!(relay.url(), "https://tcp.ssh.relay.ajam.dev");
        assert_eq!((relay.port, relay.tls), (443, true));
        let relay = Relay::new("wss://relay.example:8443", Some("t".into())).unwrap();
        assert_eq!(relay.url(), "https://relay.example:8443");
        assert_eq!(
            Relay::new("http://127.0.0.1:9", None).unwrap().url(),
            "http://127.0.0.1:9"
        );
        for bad in [
            "http://relay.example",
            "relay.example",
            "https://relay.example/connect",
            "https://user@relay.example",
            "https://",
            "https://relay.example:x",
        ] {
            assert!(Relay::new(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_token_is_not_in_debug_or_url() {
        let relay = Relay::new(DEFAULT_RELAY, Some("ephm1.secret".into())).unwrap();
        assert!(!format!("{relay:?}").contains("secret"));
        assert!(!relay.url().contains("secret"));
    }

    #[test]
    fn refusals() {
        let target: SocketAddr = "198.41.192.7:7844".parse().unwrap();
        assert_eq!(
            refusal(403, "missing or wrong token", target),
            Refusal::Token
        );
        assert!(matches!(
            refusal(403, "198.41.192.7 is not in the ALLOW list", target),
            Refusal::Other(text) if text.contains("policy")
        ));
        assert!(matches!(refusal(502, "", target), Refusal::Other(text) if text.contains("502")));
    }

    /// A relay on loopback in the test: it takes the WebSocket at
    /// /connect/IP/PORT with the right token, opens TCP to an echo server,
    /// and copies the bytes. 1 MiB goes there and back. A wrong token is
    /// refused with 403 first, and the client mints no token (it is fixed).
    #[tokio::test]
    #[allow(clippy::result_large_err)] // the callback type of tungstenite
    async fn bytes_go_through_a_local_relay() {
        use futures::{SinkExt as _, StreamExt as _};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = socket.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let expected = format!("/connect/{}/{}", echo_addr.ip(), echo_addr.port());
        tokio::spawn(async move {
            while let Ok((socket, _)) = relay.accept().await {
                let expected = expected.clone();
                tokio::spawn(async move {
                    let mut good = false;
                    let check = |request: &tungstenite::handshake::server::Request,
                                 response: tungstenite::handshake::server::Response| {
                        let token = request
                            .headers()
                            .get("x-relay-token")
                            .and_then(|v| v.to_str().ok());
                        if request.uri().path() != expected || token != Some("good") {
                            let mut refused = tungstenite::handshake::server::ErrorResponse::new(
                                Some("missing or wrong token".to_string()),
                            );
                            *refused.status_mut() = http::StatusCode::FORBIDDEN;
                            return Err(refused);
                        }
                        good = true;
                        Ok(response)
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(socket, check).await
                    else {
                        return;
                    };
                    assert!(good);
                    let mut tcp = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        tokio::select! {
                            message = ws.next() => match message {
                                Some(Ok(tungstenite::Message::Binary(bytes))) => {
                                    // An empty frame is a keepalive of the relay.
                                    let _ = ws.send(tungstenite::Message::Binary(Vec::new().into())).await;
                                    tcp.write_all(&bytes).await.unwrap();
                                }
                                _ => return,
                            },
                            n = tcp.read(&mut buf) => {
                                let n = n.unwrap();
                                if n == 0 { return; }
                                ws.send(tungstenite::Message::Binary(buf[..n].to_vec().into())).await.unwrap();
                            }
                        }
                    }
                });
            }
        });

        let url = format!("http://127.0.0.1:{}", relay_addr.port());
        let wrong = Relay::new(&url, Some("bad".into())).unwrap();
        let err = wrong
            .connect(echo_addr, Duration::from_secs(5))
            .await
            .err()
            .expect("a wrong token is refused");
        assert!(err.to_string().contains("403"), "{err:#}");
        assert!(!format!("{err:#}").contains("bad"), "{err:#}");

        let relay = Relay::new(&url, Some("good".into())).unwrap();
        let io = relay
            .connect(echo_addr, Duration::from_secs(5))
            .await
            .unwrap();
        let (mut r, mut w) = tokio::io::split(io);
        let data: Vec<u8> = (0..(1u32 << 20)).map(|i| (i * 7 % 251) as u8).collect();
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&sent).await.unwrap();
            w
        });
        let mut got = vec![0u8; data.len()];
        tokio::time::timeout(Duration::from_secs(20), r.read_exact(&mut got))
            .await
            .expect("the echo in time")
            .unwrap();
        assert!(got == data, "the bytes changed on the way");
        drop(writer.await.unwrap());
    }
}
