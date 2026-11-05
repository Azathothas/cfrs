//! The HTTP/2 edge leg through a WebSocket-to-TCP relay
//! (`--transport relay`).
//!
//! Some hosts reach the internet only through an HTTPS proxy on port 443,
//! and the proxy does not carry port 7844 of the edge. A relay on port 443
//! (a Cloudflare Worker, for example `tcp.ssh.relay.ajam.dev`) takes a
//! WebSocket at `/connect/{ip}/{port}` and opens TCP to that address. podnet
//! sends the TLS of the HTTP/2 leg (SNI `h2.cftunnel.com`, the edge roots)
//! in the WebSocket, so the relay sees only TLS bytes. The tunnel token does
//! not go to the relay.
//!
//! The token of the relay comes from [`TOKEN_VARIABLE`], or podnet mints one with
//! `POST /v1/mint`. It goes only in the `X-Relay-Token` header (not in the
//! URL), and no log or error has it.
//!
//! Limits of the relay that apply to an edge connection:
//!
//! * TCP only: no QUIC leg.
//! * IPv4 only: the relay has no IPv6 egress.
//! * The relay can end a session after 180 s with no payload (a limit of
//!   the relay, not of podnet). The PING of the HTTP/2
//!   leg (each 30 s) is payload.
//! * A session ends at 64 MiB (both directions) or after 12 h. podnet
//!   connects a replacement before that: at `SESSION_BYTES` or
//!   `SESSION_AGE` the old connection takes no new stream, and its open
//!   streams go on until they end.

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
pub const RELAY_VARIABLE: &str = "PODNET_RELAY";
/// The environment variable with a token for the relay.
pub const TOKEN_VARIABLE: &str = "PODNET_RELAY_TOKEN";
/// A minted token is minted again when it has less time than this.
const MINT_MARGIN: Duration = Duration::from_secs(10 * 60);
/// The largest WebSocket message and frame that podnet takes from the relay.
const MAX_MESSAGE: usize = 16 << 20;
/// The bytes (both directions, TLS included) after which podnet replaces an
/// edge connection through the relay. The relay ends a session at 64 MiB.
pub const SESSION_BYTES: u64 = 60 << 20;
/// The age after which podnet replaces an edge connection through the relay.
/// The relay ends a session after 12 h.
pub const SESSION_AGE: Duration = Duration::from_secs(11 * 3600 + 30 * 60);
/// The budget of one session through the relay: spent at [`SESSION_BYTES`]
/// or at [`SESSION_AGE`]. A MASQUE session through the relay is replaced
/// when it is spent (the owner ruling of 2026-11-04).
#[derive(Clone, Debug)]
pub struct RelayBudget {
    spent: std::sync::Arc<std::sync::atomic::AtomicBool>,
    opened: std::time::Instant,
    age: Duration,
}

impl RelayBudget {
    /// Count the bytes of `io` against a new budget.
    pub fn meter(io: BoxedIo) -> (BoxedIo, Self) {
        Self::meter_with(io, SESSION_BYTES, SESSION_AGE)
    }

    /// [`RelayBudget::meter`] with other limits (for the tests).
    pub fn meter_with(io: BoxedIo, bytes: u64, age: Duration) -> (BoxedIo, Self) {
        let spent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let io = crate::edge_h2::Metered::with_flag(io, bytes, spent.clone());
        let budget = Self {
            spent,
            opened: std::time::Instant::now(),
            age,
        };
        (Box::new(io), budget)
    }

    /// Whether the bytes or the time of the session are spent.
    pub fn spent(&self) -> bool {
        self.spent.load(std::sync::atomic::Ordering::Relaxed) || self.opened.elapsed() >= self.age
    }
}

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

/// One host of a relay.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Host {
    tls: bool,
    host: String,
    port: u16,
}

impl Host {
    /// Parse `https://host[:port]` (`wss://` is the same). Plain `http://`
    /// or `ws://` is taken only for a loopback host (tests).
    fn parse(url: &str) -> Result<Self> {
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
        let default = if tls { 443 } else { 80 };
        let port_of = |text: &str| {
            text.parse::<u16>()
                .with_context(|| format!("the port of the relay URL {url:?}"))
        };
        // The host is kept with no brackets; url() adds them (issue 273).
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (host, tail) = v6
                .split_once(']')
                .with_context(|| format!("the relay URL {url:?} has no ]"))?;
            let port = match tail {
                "" => default,
                _ => port_of(
                    tail.strip_prefix(':')
                        .with_context(|| format!("the relay URL {url:?} has text after the ]"))?,
                )?,
            };
            (host.to_string(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((host, _)) if host.contains(':') => bail!(
                    "write the IPv6 address of the relay URL {url:?} in brackets: https://[::1]:8443"
                ),
                Some((host, port)) => (host.to_string(), port_of(port)?),
                None => (rest.to_string(), default),
            }
        };
        if host.is_empty() {
            bail!("the relay URL {url:?} has no host");
        }
        if !tls && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
            bail!("the relay URL {url:?} must use https:// (plain http:// is for a loopback relay only)");
        }
        Ok(Self { tls, host, port })
    }

    fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            format!("{scheme}://{}", self.authority_host())
        } else {
            format!("{scheme}://{}:{}", self.authority_host(), self.port)
        }
    }

    /// The host as a URL writes it: an IPv6 address in brackets.
    fn authority_host(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

/// A WebSocket-to-TCP relay: the primary host, then the alternates of its
/// deployment (`crate::relay_pool`). A connect tries the primary first, and
/// an alternate each [`HOST_STAGGER`] or at once after a failure.
pub struct Relay {
    hosts: Vec<Host>,
    /// The alternates were given in the URL list: no pool is read for them.
    listed: bool,
    fixed: Option<String>,
    minted: tokio::sync::Mutex<Option<Minted>>,
}

/// The time before a connect tries the next relay host in parallel.
pub const HOST_STAGGER: Duration = Duration::from_secs(2);

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
    /// The policy of the deployment refuses the target: no host helps.
    Policy(String),
    /// Anything else, with the text for the error.
    Other(String),
}

impl Relay {
    /// A relay at `url` (`https://host[:port]`; `wss://` is the same). Plain
    /// `http://` or `ws://` is taken only for a loopback host (tests).
    /// `token` is used as it is; with no token, podnet mints one.
    pub fn new(url: &str, token: Option<String>) -> Result<Self> {
        let mut hosts = Vec::new();
        for item in url.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let host = Host::parse(item)?;
            if let Some(primary) = hosts.first() {
                let primary: &Host = primary;
                let same = host.host.eq_ignore_ascii_case(&primary.host)
                    || crate::relay_pool::same_deployment(&primary.host, &host.host);
                if !same {
                    bail!(
                        "the relay host {} is not of the deployment of {} (a host under its parent domain); the token goes to each host of the list",
                        host.host,
                        primary.host
                    );
                }
            }
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        if hosts.is_empty() {
            bail!("the relay URL is empty; for example {DEFAULT_RELAY}");
        }
        let listed = hosts.len() > 1;
        if !listed && hosts[0].tls && hosts[0].port == 443 {
            let cached = crate::relay_pool::load_pool(&hosts[0].host).map(|(hosts, _)| hosts);
            for alternate in crate::relay_pool::alternates_of(&hosts[0].host, cached) {
                hosts.push(Host {
                    tls: true,
                    host: alternate,
                    port: 443,
                });
            }
        }
        Ok(Self {
            hosts,
            listed,
            fixed: token.filter(|t| !t.trim().is_empty()),
            minted: tokio::sync::Mutex::new(None),
        })
    }

    /// The relay of `url` with only its own host (no alternates): for the
    /// reverse mode and for tests.
    pub fn single(url: &str, token: Option<String>) -> Result<Self> {
        let host = Host::parse(url)?;
        Ok(Self {
            hosts: vec![host],
            listed: false,
            fixed: token.filter(|t| !t.trim().is_empty()),
            minted: tokio::sync::Mutex::new(None),
        })
    }

    /// The name of the token cache of this relay: the primary host, and its
    /// port when it is not the default.
    fn cache_key(&self) -> String {
        let primary = &self.hosts[0];
        let default = if primary.tls { 443 } else { 80 };
        if primary.port == default {
            primary.host.clone()
        } else {
            format!("{}-{}", primary.host, primary.port)
        }
    }

    /// The URLs of the hosts, the primary first.
    pub fn urls(&self) -> Vec<String> {
        self.hosts.iter().map(Host::url).collect()
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

    /// The TCP port of the relay.
    pub fn port(&self) -> u16 {
        self.hosts[0].port
    }

    /// The host of the relay.
    pub fn host(&self) -> &str {
        &self.hosts[0].host
    }

    /// The base URL of the primary host, with no token.
    pub fn url(&self) -> String {
        self.hosts[0].url()
    }

    /// A token: the fixed token, a minted token that has time left (in
    /// memory, else in the cache file), or a new minted token. With
    /// `refused`, a token that is the refused one is minted again; when
    /// another attempt minted already, its token is used.
    async fn token(&self, refused: Option<&str>) -> Result<String> {
        if let Some(token) = &self.fixed {
            return Ok(token.clone());
        }
        let usable = |m: &Minted| {
            refused != Some(m.token.as_str())
                && m.expires
                    .duration_since(SystemTime::now())
                    .is_ok_and(|left| left > MINT_MARGIN)
        };
        let mut minted = self.minted.lock().await;
        if let Some(m) = minted.as_ref().filter(|m| usable(m)) {
            return Ok(m.token.clone());
        }
        if minted.is_none() {
            if let Some((token, expires)) = crate::relay_pool::load_token(&self.cache_key()) {
                let cached = Minted { token, expires };
                if usable(&cached) {
                    let token = cached.token.clone();
                    *minted = Some(cached);
                    return Ok(token);
                }
            }
        }
        let (new, at) = self.mint().await?;
        crate::relay_pool::store_token(&self.cache_key(), &new.token, new.expires);
        let token = new.token.clone();
        *minted = Some(new);
        drop(minted);
        if !self.listed {
            self.refresh_pool(at);
        }
        Ok(token)
    }

    /// Mint at the primary host, else at the next host when one does not
    /// answer. A refusal (429, 503) stops: the brake and the policy are of
    /// the deployment. Gives the host that minted.
    async fn mint(&self) -> Result<(Minted, Host)> {
        let mut failures = Vec::new();
        for host in &self.hosts {
            match mint_at(host).await {
                Ok(minted) => return Ok((minted, host.clone())),
                Err(MintError::Stop(err)) => return Err(err),
                Err(MintError::Next(err)) => {
                    tracing::debug!(relay = %host.url(), error = %format!("{err:#}"), "no mint at this relay host");
                    failures.push(format!("{}: {err:#}", host.url()));
                }
            }
        }
        bail!("minting a relay token: {}", failures.join("; "))
    }

    /// Read `/relays.json` at `at` in the background when the cached pool is
    /// missing or stale.
    fn refresh_pool(&self, at: Host) {
        let primary = self.host().to_string();
        if !self.hosts[0].tls || self.hosts[0].port != 443 {
            return;
        }
        if crate::relay_pool::load_pool(&primary).is_some_and(|(_, stale)| !stale) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            let request = crate::fetch::Request::new("GET", format!("{}/relays.json", at.url()))
                .timeout(Duration::from_secs(20))
                .max_body(crate::relay_pool::MAX_BODY);
            let hosts = match request.send().await {
                Ok(response) if response.status == 200 => {
                    crate::relay_pool::parse_pool(response.text().as_bytes(), &primary)
                }
                Ok(response) => Err(anyhow::anyhow!("HTTP {}", response.status)),
                Err(err) => Err(err),
            };
            match hosts {
                Ok(hosts) => {
                    tracing::debug!(count = hosts.len(), "the relay pool is cached");
                    crate::relay_pool::store_pool(&primary, &hosts);
                }
                Err(err) => {
                    tracing::debug!(error = %format!("{err:#}"), "no relay pool")
                }
            }
        });
    }

    /// A byte stream to `target` through the relay: the primary host
    /// first, then the alternates (staggered). A refused token is minted
    /// again one time. A refusal that another host does not change (a
    /// refused fixed token, the policy of the deployment) stops the hosts
    /// that did not start yet.
    pub async fn connect(&self, target: SocketAddr, timeout: Duration) -> Result<BoxedIo> {
        if target.is_ipv6() {
            bail!("the relay has no IPv6 egress; {target} is IPv6");
        }
        if self.hosts.len() == 1 {
            return self
                .connect_at(&self.hosts[0], target, timeout)
                .await
                .map_err(|e| e.0);
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        let stop = &stop;
        let attempts: Vec<futures::future::BoxFuture<'_, Result<BoxedIo>>> = self
            .hosts
            .iter()
            .map(|host| {
                let attempt = async move {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        bail!("not tried: a relay host before it refused for the deployment");
                    }
                    match self.connect_at(host, target, timeout).await {
                        Ok(io) => Ok(io),
                        Err(HostError(err, again)) => {
                            if !again {
                                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(err.context(format!("the relay host {}", host.url())))
                        }
                    }
                };
                Box::pin(attempt) as futures::future::BoxFuture<'_, Result<BoxedIo>>
            })
            .collect();
        let close = |_, io: BoxedIo| -> futures::future::BoxFuture<'static, ()> {
            Box::pin(async move { drop(io) })
        };
        match crate::race::race(
            attempts,
            crate::race::Failover::Staggered(HOST_STAGGER),
            close,
        )
        .await
        {
            Ok(won) => {
                if won.index > 0 {
                    let failed: Vec<String> =
                        won.failures.iter().map(|(_, e)| format!("{e:#}")).collect();
                    tracing::info!(
                        relay = %self.hosts[won.index].url(),
                        failed = %failed.join("; "),
                        "an alternate relay host carries the connection"
                    );
                }
                Ok(won.value)
            }
            Err(failures) => {
                let mut failures = failures.into_iter();
                let (_, first) = failures.next().expect("one host at least");
                let rest: Vec<String> = failures.map(|(_, e)| format!("{e:#}")).collect();
                if rest.is_empty() {
                    Err(first)
                } else {
                    Err(first.context(format!(
                        "each relay host failed; the others: {}",
                        rest.join("; ")
                    )))
                }
            }
        }
    }

    /// [`Self::connect`] at one host. The error says whether another host
    /// can help.
    async fn connect_at(
        &self,
        host: &Host,
        target: SocketAddr,
        timeout: Duration,
    ) -> std::result::Result<BoxedIo, HostError> {
        let token = self.token(None).await.map_err(HostError::again)?;
        match self
            .open(host, target, &token, timeout)
            .await
            .map_err(HostError::again)?
        {
            Ok(io) => Ok(io),
            Err(Refusal::Token) if self.fixed.is_none() => {
                let token = self.token(Some(&token)).await.map_err(HostError::again)?;
                match self
                    .open(host, target, &token, timeout)
                    .await
                    .map_err(HostError::again)?
                {
                    Ok(io) => Ok(io),
                    Err(Refusal::Token) => Err(HostError::stop(anyhow::anyhow!(
                        "the relay refused a new token (403)"
                    ))),
                    Err(refusal) => Err(refusal.into()),
                }
            }
            Err(Refusal::Token) => Err(HostError::stop(anyhow::anyhow!(
                "the relay refused the token of {TOKEN_VARIABLE} (403)"
            ))),
            Err(refusal) => Err(refusal.into()),
        }
    }

    async fn open(
        &self,
        host: &Host,
        target: SocketAddr,
        token: &str,
        timeout: Duration,
    ) -> Result<std::result::Result<BoxedIo, Refusal>> {
        let path = format!("/connect/{}/{}", target.ip(), target.port());
        let ws = match websocket_at(host, &path, token, timeout).await? {
            Ok(ws) => ws,
            Err((status, body)) => return Ok(Err(refusal(status, &body, target))),
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

    /// A WebSocket to `path` on the relay, with `token` in `X-Relay-Token`.
    /// A refused upgrade gives its HTTP status and body (the body never has
    /// the token).
    pub(crate) async fn websocket(
        &self,
        path: &str,
        token: &str,
        timeout: Duration,
    ) -> Result<std::result::Result<RelaySocket, (u16, String)>> {
        websocket_at(&self.hosts[0], path, token, timeout).await
    }

    /// A POST of an empty JSON object to `path` on the relay; the JSON
    /// answer, or the status and the start of the body.
    pub(crate) async fn post_json(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<std::result::Result<serde_json::Value, (u16, String)>> {
        let mut request = crate::fetch::Request::new("POST", format!("{}{path}", self.url()))
            .json(&serde_json::json!({}))
            .timeout(Duration::from_secs(20));
        if let Some(token) = token {
            request = request.header("X-Relay-Token", token);
        }
        let response = request.send().await?;
        if response.status != 200 {
            let retry = response.header("retry-after").map(str::to_string);
            let mut text: String = response.text().chars().take(200).collect();
            if let Some(retry) = retry {
                text.push_str(&format!(" (retry after {retry} s)"));
            }
            return Ok(Err((response.status, text)));
        }
        Ok(Ok(response.json()?))
    }
}

/// A WebSocket to `path` on `host`, with `token` in `X-Relay-Token`. A
/// refused upgrade gives its HTTP status and body (the body never has the
/// token).
async fn websocket_at(
    host: &Host,
    path: &str,
    token: &str,
    timeout: Duration,
) -> Result<std::result::Result<RelaySocket, (u16, String)>> {
    let io = crate::egress::dial(&host.host, host.port, None, timeout)
        .await
        .with_context(|| format!("TCP to the relay {}", host.url()))?;
    let io: BoxedIo = if host.tls {
        // HTTP/1.1 only: a WebSocket upgrade does not go over HTTP/2.
        let config = crate::trust::client_config(&[], &[b"http/1.1"])?;
        let name = rustls::pki_types::ServerName::try_from(host.host.clone())
            .context("the relay host is not a valid TLS name")?;
        let tls = tokio::time::timeout(
            timeout,
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect(name, io),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TLS to the relay: no answer in {} s", timeout.as_secs()))?
        .with_context(|| format!("TLS to the relay {}", host.url()))?;
        Box::new(tls)
    } else {
        io
    };
    let scheme = if host.tls { "wss" } else { "ws" };
    let url = format!("{scheme}://{}:{}{path}", host.authority_host(), host.port);
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
    match tokio::time::timeout(timeout, handshake).await {
        Err(_) => bail!(
            "the WebSocket to the relay: no answer in {} s",
            timeout.as_secs()
        ),
        Ok(Ok((ws, _response))) => Ok(Ok(ws)),
        Ok(Err(tungstenite::Error::Http(response))) => {
            let status = response.status().as_u16();
            let body = response
                .body()
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
                .to_string();
            Ok(Err((status, body)))
        }
        Ok(Err(err)) => {
            Err(err).with_context(|| format!("the WebSocket to the relay {}", host.url()))
        }
    }
}

/// A failure at one relay host, and whether another host can help.
struct HostError(anyhow::Error, bool);

impl HostError {
    fn again(err: anyhow::Error) -> Self {
        Self(err, true)
    }

    fn stop(err: anyhow::Error) -> Self {
        Self(err, false)
    }
}

impl From<Refusal> for HostError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Token => Self::stop(anyhow::anyhow!("the relay refused the token (403)")),
            Refusal::Policy(text) => Self::stop(anyhow::anyhow!("{text}")),
            Refusal::Other(text) => Self::again(anyhow::anyhow!("{text}")),
        }
    }
}

/// Why a mint failed: `Next` when another host can answer.
enum MintError {
    Next(anyhow::Error),
    Stop(anyhow::Error),
}

async fn mint_at(host: &Host) -> std::result::Result<Minted, MintError> {
    let url = format!("{}/v1/mint", host.url());
    let response = crate::fetch::Request::new("POST", url)
        .json(&serde_json::json!({}))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .context("minting a relay token")
        .map_err(MintError::Next)?;
    match response.status {
        200 => {}
        429 => {
            return Err(MintError::Stop(anyhow::anyhow!(
                "the relay refused a new token (429); try again after {} s",
                response.header("retry-after").unwrap_or("60")
            )))
        }
        503 => {
            return Err(MintError::Stop(anyhow::anyhow!(
                "the relay gives no tokens (503); set {TOKEN_VARIABLE}"
            )))
        }
        status => {
            return Err(MintError::Next(anyhow::anyhow!(
                "minting a relay token: HTTP {status}"
            )))
        }
    }
    let body: serde_json::Value = response
        .json()
        .context("the mint answer")
        .map_err(MintError::Next)?;
    let token = body
        .get("token")
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .context("the mint answer has no token")
        .map_err(MintError::Next)?
        .to_string();
    let expires = body
        .get("expires")
        .and_then(|e| e.as_u64())
        .map(|ms| UNIX_EPOCH + Duration::from_millis(ms))
        .unwrap_or_else(|| SystemTime::now() + Duration::from_secs(3600));
    Ok(Minted { token, expires })
}

/// A WebSocket to the relay.
pub(crate) type RelaySocket = tokio_tungstenite::WebSocketStream<BoxedIo>;

/// Classify a refused upgrade. The text never has the token.
fn refusal(status: u16, body: &str, target: SocketAddr) -> Refusal {
    let body = body.trim();
    let excerpt: String = body.chars().take(200).collect();
    match status {
        403 if body.contains("ALLOW list") => Refusal::Policy(format!(
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

    /// The budget of a MASQUE session through the relay: spent at its
    /// bytes (both directions) or at its age.
    #[tokio::test]
    async fn a_relay_budget_is_spent_at_its_bytes_or_its_age() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let (mut io, budget) =
            RelayBudget::meter_with(Box::new(near), 10, Duration::from_secs(3600));
        io.write_all(b"12345").await.unwrap();
        far.write_all(b"1234").await.unwrap();
        let mut got = [0u8; 4];
        io.read_exact(&mut got).await.unwrap();
        assert!(!budget.spent(), "9 of 10 bytes");
        io.write_all(b"x").await.unwrap();
        assert!(budget.spent());
        let (_io, aged) =
            RelayBudget::meter_with(Box::new(tokio::io::duplex(8).0), 1 << 20, Duration::ZERO);
        assert!(aged.spent(), "the age is spent");
    }

    #[test]
    fn relay_urls() {
        let relay = Relay::new("https://tcp.ssh.relay.ajam.dev/", None).unwrap();
        assert_eq!(relay.url(), "https://tcp.ssh.relay.ajam.dev");
        assert_eq!((relay.port(), relay.hosts[0].tls), (443, true));
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
            "https://::1",
            "https://[::1",
            "https://[::1]x",
            "http://[2001:db8::1]",
        ] {
            assert!(Relay::new(bad, None).is_err(), "{bad}");
        }
    }

    /// Issue 273: an IPv6 relay host in brackets keeps its port.
    #[test]
    fn an_ipv6_relay_host_keeps_its_port() {
        let relay = Relay::new("https://[::1]:8443", None).unwrap();
        assert_eq!((relay.host(), relay.port()), ("::1", 8443));
        assert_eq!(relay.url(), "https://[::1]:8443");
        let relay = Relay::new("http://[::1]:8080", None).unwrap();
        assert_eq!((relay.host(), relay.port()), ("::1", 8080));
        let relay = Relay::new("https://[2001:db8::1]", None).unwrap();
        assert_eq!((relay.host(), relay.port()), ("2001:db8::1", 443));
        assert_eq!(relay.url(), "https://[2001:db8::1]");
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
            Refusal::Policy(text) if text.contains("policy")
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
        crate::test_host::need_loopback!();
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

        // A list: the first host does not answer, the next one carries the
        // connection.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let list = format!("http://127.0.0.1:{dead_port},{url}");
        let relay = Relay::new(&list, Some("good".into())).unwrap();
        assert_eq!(relay.urls().len(), 2);
        let mut io = relay
            .connect(echo_addr, Duration::from_secs(5))
            .await
            .expect("the second host carries the connection");
        io.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), io.read_exact(&mut back))
            .await
            .expect("the echo in time")
            .unwrap();
        assert_eq!(&back, b"ping");

        // A refused fixed token stops the list: no other host helps.
        let wrong = Relay::new(&format!("{url},{url}/"), Some("bad".into())).unwrap();
        assert_eq!(wrong.urls().len(), 1, "the same host once");
    }

    /// The hosts of a list are of one deployment: the token goes to each.
    #[test]
    fn a_list_of_relays_is_one_deployment() {
        let relay = Relay::new(
            "https://tcp.ssh.relay.ajam.dev,https://tcp-eu-west-3.ssh.relay.ajam.dev",
            None,
        )
        .unwrap();
        assert_eq!(
            relay.urls(),
            [
                "https://tcp.ssh.relay.ajam.dev",
                "https://tcp-eu-west-3.ssh.relay.ajam.dev"
            ]
        );
        assert_eq!(relay.url(), "https://tcp.ssh.relay.ajam.dev");
        let err = Relay::new("https://tcp.ssh.relay.ajam.dev,https://evil.example", None)
            .expect_err("another deployment is refused");
        assert!(format!("{err:#}").contains("deployment"), "{err:#}");
        assert!(Relay::new(" , ", None).is_err());
        // One host of another relay has no alternates of the seed.
        let one = Relay::single("https://relay.example.org", None).unwrap();
        assert_eq!(one.urls(), ["https://relay.example.org"]);
    }
}
