//! Each outbound TCP connection of cfrs: directly, or through a proxy.
//!
//! [`dial`] is the one path. It takes the proxy of [`ProxyChoice`]:
//!
//! * `--proxy URL` (or [`set_choice`] with [`ProxyChoice::Via`]);
//! * `--no-proxy` ([`ProxyChoice::Direct`]);
//! * else the variables, in the order of curl: `HTTPS_PROXY`, `https_proxy`,
//!   `ALL_PROXY`, `all_proxy`.
//!
//! `NO_PROXY` (or `no_proxy`) names the targets that do not use the proxy,
//! with the rules of [`NoProxy`]. A proxy can be HTTP (`CONNECT`) or SOCKS5
//! (`socks5://` resolves the name on this host, `socks5h://` gives the name
//! to the proxy). A direct dial resolves the name with the chain of
//! [`crate::resolve`], tries each address of the name, and starts
//! the next attempt [`ATTEMPT_DELAY`] after the one before (RFC 8305), so an
//! address with no route does not hold the dial.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
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

/// The time between the start of two attempts of a direct dial (RFC 8305).
pub const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// The variables of the proxy, in the order that cfrs reads them.
pub const PROXY_VARIABLES: &[&str] = &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];
/// The variables of the list of targets that do not use the proxy.
pub const NO_PROXY_VARIABLES: &[&str] = &["NO_PROXY", "no_proxy"];

/// The protocol of a proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// An HTTP proxy that answers `CONNECT`.
    Http,
    /// A SOCKS5 proxy. With `remote_dns`, the proxy resolves the name
    /// (`socks5h://`); else this host resolves it (`socks5://`).
    Socks5 { remote_dns: bool },
}

/// How cfrs reaches the proxy (issue 129).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// TCP to the host and the port of the proxy.
    Tcp,
    /// A unix socket: `socks5h+unix:/path` or `socks5h://unix:/path`.
    Unix(std::path::PathBuf),
    /// The stdin and the stdout of a command (`sh -c`), one process for
    /// each connection, as the ProxyCommand of SSH: `http+exec:COMMAND`.
    /// Only from `--proxy` and `CFRS_PROXY`.
    Exec(String),
}

/// A proxy for TCP connections.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    kind: ProxyKind,
    host: String,
    port: u16,
    auth: Option<(String, String)>,
    via: Carrier,
}

/// The Debug form shows no credentials: they go to logs and reports.
impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("via", &self.via_text())
            .field(
                "credentials",
                &if self.auth.is_some() {
                    "<hidden>"
                } else {
                    "none"
                },
            )
            .finish()
    }
}

/// `scheme://host:port`, with no credentials: the form for a message. A
/// command shows its first word only (it can hold a secret).
impl std::fmt::Display for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.via != Carrier::Tcp {
            return write!(f, "{}+{}", self.scheme(), self.via_text());
        }
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        write!(f, "{}://{host}:{}", self.scheme(), self.port)
    }
}

impl Proxy {
    /// The host of the proxy (no port, no credentials). Empty for a proxy
    /// on a unix socket or a command.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// How cfrs reaches the proxy.
    pub fn carrier(&self) -> &Carrier {
        &self.via
    }

    fn via_text(&self) -> String {
        match &self.via {
            Carrier::Tcp => "tcp".into(),
            Carrier::Unix(path) => format!("unix:{}", path.display()),
            Carrier::Exec(command) => format!(
                "exec:{} ...",
                command.split_whitespace().next().unwrap_or_default()
            ),
        }
    }

    /// Parse the value of `--proxy` or `CFRS_PROXY`: [`parse`](Self::parse),
    /// and also `SCHEME+exec:COMMAND` (issue 129). A command in the proxy
    /// variables of other tools is refused: a variable must not start a
    /// program.
    pub fn parse_trusted(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if let Some((scheme, command)) = spec.split_once("+exec:") {
            if command.trim().is_empty() {
                bail!("{scheme}+exec: has no command");
            }
            let mut proxy = Self::parse(&format!("{scheme}://exec.invalid"))?;
            proxy.host.clear();
            proxy.port = 0;
            proxy.via = Carrier::Exec(command.trim().to_string());
            return Ok(proxy);
        }
        Self::parse(spec)
    }

    /// Read the proxy from the variables of [`PROXY_VARIABLES`]. Returns
    /// `None` when no variable is set. A value that cannot be parsed is
    /// skipped with a warning.
    pub fn from_env() -> Option<Self> {
        for key in PROXY_VARIABLES {
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

    /// Parse `[scheme://][user[:password]@]host[:port]`. The schemes are
    /// `http` (the default; port 8080 when missing, as in curl), `socks5`
    /// and `socks5h` (port 1080 when missing). The user and the password are
    /// percent-decoded; a bad escape is an error.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty proxy URL");
        }
        // Issue 129: a proxy on a unix socket.
        let unix = spec
            .split_once("+unix:")
            .or_else(|| spec.split_once("://unix:"));
        if let Some((scheme, path)) = unix.filter(|(s, _)| !s.contains('/')) {
            if !path.starts_with('/') {
                bail!("the unix socket of a proxy is an absolute path: {scheme}+unix:/PATH");
            }
            let mut proxy = Self::parse(&format!("{scheme}://unix.invalid"))?;
            proxy.host.clear();
            proxy.port = 0;
            proxy.via = Carrier::Unix(path.into());
            return Ok(proxy);
        }
        if spec.contains("+exec:") {
            bail!("a proxy command (+exec:) is only taken from --proxy or CFRS_PROXY");
        }
        let (scheme, rest) = match spec.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => ("http".to_string(), spec),
        };
        let (kind, default_port) = match scheme.as_str() {
            "http" => (ProxyKind::Http, 8080),
            "socks5" => (ProxyKind::Socks5 { remote_dns: false }, 1080),
            "socks5h" => (ProxyKind::Socks5 { remote_dns: true }, 1080),
            "https" => bail!(
                "https:// proxies (TLS to the proxy) are not supported; use http:// or socks5h://"
            ),
            "socks4" | "socks4a" => {
                bail!("SOCKS4 is not supported: it has no IPv6 and no password; use socks5h://")
            }
            other => bail!("the proxy scheme {other}:// is not supported; use http://, socks5:// or socks5h://"),
        };
        let rest = rest.trim_end_matches('/');
        if rest.contains(['/', '?', '#']) {
            bail!("a proxy URL has no path, query or fragment");
        }
        let (auth, authority) = match rest.rsplit_once('@') {
            Some((auth, authority)) => (Some(auth), authority),
            None => (None, rest),
        };
        let (host, port) = split_host_port(authority, default_port)?;
        let auth = match auth {
            Some(auth) => {
                let (user, pass) = auth.split_once(':').unwrap_or((auth, ""));
                let user = percent_decode(user).context("the user of the proxy URL")?;
                let pass = percent_decode(pass).context("the password of the proxy URL")?;
                if let ProxyKind::Socks5 { .. } = kind {
                    if user.is_empty() || user.len() > 255 || pass.is_empty() || pass.len() > 255 {
                        bail!(
                            "a SOCKS5 user and password must each have 1 to 255 bytes (RFC 1929)"
                        );
                    }
                }
                Some((user, pass))
            }
            None => None,
        };
        Ok(Self {
            kind,
            host,
            port,
            auth,
            via: Carrier::Tcp,
        })
    }

    /// Open the byte stream to the proxy.
    async fn open(&self, timeout: Duration) -> Result<BoxedIo> {
        match &self.via {
            Carrier::Tcp => Ok(Box::new(dial_direct(&self.host, self.port, timeout).await?)),
            Carrier::Unix(path) => {
                let stream = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path))
                    .await
                    .map_err(|_| anyhow::anyhow!("no connect in {} s", timeout.as_secs()))??;
                Ok(Box::new(stream))
            }
            Carrier::Exec(command) => Ok(Box::new(ChildIo::spawn(command)?)),
        }
    }

    /// The protocol of the proxy.
    pub fn kind(&self) -> ProxyKind {
        self.kind
    }

    /// `http`, `socks5` or `socks5h`.
    pub fn scheme(&self) -> &'static str {
        match self.kind {
            ProxyKind::Http => "http",
            ProxyKind::Socks5 { remote_dns: false } => "socks5",
            ProxyKind::Socks5 { remote_dns: true } => "socks5h",
        }
    }

    /// The proxy's own address. Connecting here is direct, never proxied.
    pub fn address(&self) -> (&str, u16) {
        (&self.host, self.port)
    }

    /// True when the proxy URL holds a user and a password.
    pub fn has_credentials(&self) -> bool {
        self.auth.is_some()
    }

    /// Open a connection to `host:port` through the proxy, and return the
    /// stream after the answer of the proxy.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> Result<BoxedIo> {
        let work = async {
            let mut stream = self
                .open(timeout)
                .await
                .with_context(|| format!("connecting to the proxy {self}"))?;
            match self.kind {
                ProxyKind::Http => {
                    let basic = self.auth.as_ref().map(|(user, pass)| {
                        let raw = format!("{user}:{pass}");
                        format!(
                            "Basic {}",
                            base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
                        )
                    });
                    if let Some(challenge) = self
                        .http_connect(&mut stream, host, port, timeout, basic)
                        .await?
                    {
                        // A Digest proxy (issue 83): answer the challenge on
                        // a new connection.
                        let (user, pass) =
                            self.auth.as_ref().expect("a challenge needs credentials");
                        let authority = authority_of(host, port);
                        let value = crate::proxy_auth::authorization(
                            &challenge,
                            user,
                            pass,
                            "CONNECT",
                            &authority,
                            &crate::proxy_auth::cnonce(),
                            1,
                        );
                        stream = self
                            .open(timeout)
                            .await
                            .with_context(|| format!("connecting to the proxy {self} again"))?;
                        if self
                            .http_connect(&mut stream, host, port, timeout, Some(value))
                            .await?
                            .is_some()
                        {
                            bail!("the proxy {self} refused the Digest answer (407)");
                        }
                    }
                }
                ProxyKind::Socks5 { remote_dns } => {
                    self.socks5_connect(&mut stream, host, port, remote_dns, timeout)
                        .await?
                }
            }
            Ok::<BoxedIo, anyhow::Error>(stream)
        };
        work.await
            .with_context(|| format!("{host}:{port} through the proxy {self}"))
            .map_err(|e| crate::hop::at(crate::hop::Hop::Proxy, e))
    }

    /// One CONNECT with `authorization` (the value of
    /// `Proxy-Authorization`). Gives the Digest challenge of a 407 when the
    /// first try was not Digest and credentials are there.
    async fn http_connect(
        &self,
        stream: &mut BoxedIo,
        host: &str,
        port: u16,
        timeout: Duration,
        authorization: Option<String>,
    ) -> Result<Option<crate::proxy_auth::Challenge>> {
        let authority = authority_of(host, port);
        let digest_tried = authorization
            .as_deref()
            .is_some_and(|a| a.starts_with("Digest "));
        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
        );
        if let Some(value) = &authorization {
            request.push_str(&format!("Proxy-Authorization: {value}\r\n"));
        }
        request.push_str("\r\n");
        tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
            .await
            .context("writing the CONNECT request: timed out")?
            .context("writing the CONNECT request")?;

        let head = read_head(stream, timeout).await?;
        let status = parse_status(&head)?;
        if status == 407 && self.auth.is_some() && !digest_tried {
            let text = String::from_utf8_lossy(&head).to_string();
            let challenge = text.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("proxy-authenticate")
                    .then(|| crate::proxy_auth::parse_challenge(value))
                    .flatten()
            });
            if challenge.is_some() {
                return Ok(challenge);
            }
        }
        if status == 407 {
            return Err(Refusal {
                status,
                text: explain_407(&head, self.auth.is_some()),
            }
            .into());
        }
        if !(200..300).contains(&status) {
            let reason = reply_reason(stream, &head).await;
            return Err(Refusal {
                status,
                text: format!("the proxy refused CONNECT with HTTP {status}{reason}"),
            }
            .into());
        }
        Ok(None)
    }

    async fn socks5_connect(
        &self,
        stream: &mut BoxedIo,
        host: &str,
        port: u16,
        remote_dns: bool,
        timeout: Duration,
    ) -> Result<()> {
        let work = async {
            // The greeting: no authentication, and user and password when the
            // URL has them.
            let greeting: &[u8] = if self.auth.is_some() {
                &[5, 2, 0, 2]
            } else {
                &[5, 1, 0]
            };
            stream.write_all(greeting).await?;
            let mut choice = [0u8; 2];
            stream.read_exact(&mut choice).await?;
            if choice[0] != 5 {
                bail!("the proxy did not answer as SOCKS5");
            }
            match choice[1] {
                0 => {}
                2 => {
                    let (user, pass) = self.auth.as_ref().context(
                        "the proxy asks for a user and a password, and the URL has none",
                    )?;
                    let mut req = vec![1, user.len() as u8];
                    req.extend_from_slice(user.as_bytes());
                    req.push(pass.len() as u8);
                    req.extend_from_slice(pass.as_bytes());
                    stream.write_all(&req).await?;
                    let mut status = [0u8; 2];
                    stream.read_exact(&mut status).await?;
                    if status[1] != 0 {
                        bail!(
                            "the proxy refused the user and the password (SOCKS5 status {})",
                            status[1]
                        );
                    }
                }
                0xff => {
                    bail!(
                    "the proxy accepts none of the methods that cfrs offers (no authentication{})",
                    if self.auth.is_some() { ", user and password" } else { "" }
                )
                }
                other => bail!("the proxy chose the method {other}, which cfrs did not offer"),
            }

            let mut req = vec![5, 1, 0];
            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => {
                    req.push(1);
                    req.extend_from_slice(&ip.octets());
                }
                Ok(IpAddr::V6(ip)) => {
                    req.push(4);
                    req.extend_from_slice(&ip.octets());
                }
                Err(_) if remote_dns => {
                    if host.len() > 255 {
                        bail!("the name {host} is longer than 255 bytes");
                    }
                    req.push(3);
                    req.push(host.len() as u8);
                    req.extend_from_slice(host.as_bytes());
                }
                Err(_) => {
                    let ip = tokio::net::lookup_host((host, port))
                        .await
                        .with_context(|| format!("resolving {host} for socks5:// (use socks5h:// to let the proxy resolve it)"))?
                        .next()
                        .with_context(|| format!("{host} has no address"))?
                        .ip();
                    match ip {
                        IpAddr::V4(ip) => {
                            req.push(1);
                            req.extend_from_slice(&ip.octets());
                        }
                        IpAddr::V6(ip) => {
                            req.push(4);
                            req.extend_from_slice(&ip.octets());
                        }
                    }
                }
            }
            req.extend_from_slice(&port.to_be_bytes());
            stream.write_all(&req).await?;

            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).await?;
            if reply[0] != 5 {
                bail!("the proxy did not answer the SOCKS5 CONNECT");
            }
            if reply[1] != 0 {
                return Err(Refusal {
                    status: 0,
                    text: format!(
                        "the proxy refused the SOCKS5 CONNECT: {}",
                        socks5_reply(reply[1])
                    ),
                }
                .into());
            }
            let skip = match reply[3] {
                1 => 4,
                4 => 16,
                3 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await?;
                    len[0] as usize
                }
                other => bail!("the SOCKS5 reply has the address type {other}"),
            };
            let mut bound = vec![0u8; skip + 2];
            stream.read_exact(&mut bound).await?;
            Ok(())
        };
        tokio::time::timeout(timeout, work)
            .await
            .context("the SOCKS5 exchange timed out")?
    }
}

/// A proxy answered and refused the connection: an HTTP status that is not
/// 2xx (`status`), or a SOCKS5 refusal (`status` 0). A lost connection is
/// not a refusal.
#[derive(Debug)]
pub struct Refusal {
    pub status: u16,
    pub text: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Refusal {}

/// The refusal of a proxy in the chain of `err`, if there is one.
pub fn refusal(err: &anyhow::Error) -> Option<&Refusal> {
    err.chain().find_map(|e| e.downcast_ref::<Refusal>())
}

/// The reason of a refusal: the reason phrase of the status line, and the
/// first line of the body (for example "not on the egress allowlist"),
/// with no control characters. Reads at most 512 bytes of the body, for
/// at most 2 s.
async fn reply_reason(stream: &mut BoxedIo, head: &[u8]) -> String {
    let text = String::from_utf8_lossy(head);
    let phrase = text
        .lines()
        .next()
        .and_then(|l| l.splitn(3, ' ').nth(2))
        .unwrap_or("")
        .trim()
        .to_string();
    let length = text.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())?
    });
    let mut body = Vec::new();
    let want = length.unwrap_or(512).min(512);
    let mut chunk = [0u8; 512];
    while body.len() < want {
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => body.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    body.truncate(want);
    let first = String::from_utf8_lossy(&body)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();
    let mut parts = Vec::new();
    for part in [phrase, first] {
        let part = crate::report::clean(&part);
        if !part.is_empty() && !parts.contains(&part) {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(": {}", parts.join(": "))
    }
}

fn socks5_reply(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "not allowed by the rules of the proxy",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown reply code",
    }
}

/// The text for a `407` answer: the schemes in the `Proxy-Authenticate`
/// headers, and what cfrs sent.
fn explain_407(head: &[u8], sent_basic: bool) -> String {
    let text = String::from_utf8_lossy(head);
    let mut schemes: Vec<String> = Vec::new();
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authenticate") {
            continue;
        }
        for scheme in auth_schemes(value) {
            if !schemes.iter().any(|s| s.eq_ignore_ascii_case(&scheme)) {
                schemes.push(scheme);
            }
        }
    }
    let asks = if schemes.is_empty() {
        "it names no scheme (no Proxy-Authenticate header)".to_string()
    } else {
        format!("it asks for {}", schemes.join(" or "))
    };
    let sent = if sent_basic {
        "cfrs sent Basic with the user and the password of the proxy URL"
    } else {
        "cfrs sent no credentials (put user:password@ in the proxy URL)"
    };
    let only_basic = schemes.iter().any(|s| s.eq_ignore_ascii_case("basic"));
    let advice = if schemes.is_empty() || only_basic {
        ""
    } else {
        "; cfrs supports Basic only: ask for a Basic account, or use a local proxy that speaks the scheme (for example cntlm for NTLM)"
    };
    format!("the proxy requires authentication (HTTP 407): {asks}; {sent}{advice}")
}

/// The scheme names of a `Proxy-Authenticate` value. One header can hold
/// several challenges: `NTLM, Negotiate, Basic realm="a, b"`.
fn auth_schemes(value: &str) -> Vec<String> {
    let mut schemes = Vec::new();
    let mut in_quotes = false;
    let mut token = String::new();
    let mut at_start = true;
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '\\' {
                chars.next();
            } else if c == '"' {
                in_quotes = false;
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            ',' => {
                if at_start && !token.is_empty() {
                    schemes.push(std::mem::take(&mut token));
                }
                token.clear();
                at_start = true;
            }
            ' ' | '\t' => {
                if at_start && !token.is_empty() {
                    schemes.push(std::mem::take(&mut token));
                    at_start = false;
                }
            }
            '=' => {
                // A parameter (`realm=...`) of the challenge before.
                token.clear();
                at_start = false;
            }
            c if at_start => token.push(c),
            _ => {}
        }
    }
    if at_start && !token.is_empty() {
        schemes.push(token);
    }
    schemes
}

/// The targets that do not use the proxy: the value of `NO_PROXY`, entries
/// separated by commas or spaces.
///
/// * `*` matches each target.
/// * `example.com` and `.example.com` match `example.com` and each name
///   under it.
/// * An IP address matches that address; `10.0.0.0/8` matches the network.
/// * An entry with `:port` matches that port only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoProxy {
    entries: Vec<NoProxyEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NoProxyEntry {
    All,
    Name {
        name: String,
        port: Option<u16>,
    },
    Net {
        ip: IpAddr,
        prefix: u8,
        port: Option<u16>,
    },
}

impl NoProxy {
    /// Read `NO_PROXY`, else `no_proxy`.
    pub fn from_env() -> Self {
        NO_PROXY_VARIABLES
            .iter()
            .find_map(|key| std::env::var(key).ok().filter(|v| !v.trim().is_empty()))
            .map(|v| Self::parse(&v))
            .unwrap_or_default()
    }

    /// Parse a list. An entry that cannot be read is skipped with a warning.
    pub fn parse(list: &str) -> Self {
        let mut entries = Vec::new();
        for raw in list
            .split([',', ' ', '\t'])
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            match parse_no_proxy_entry(raw) {
                Some(entry) => entries.push(entry),
                None => {
                    tracing::warn!(entry = %raw, "ignoring a NO_PROXY entry that cannot be read")
                }
            }
        }
        Self { entries }
    }

    /// True when `host:port` does not use the proxy.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let ip = host.parse::<IpAddr>().ok();
        self.entries.iter().any(|entry| match entry {
            NoProxyEntry::All => true,
            NoProxyEntry::Name { name, port: p } => {
                p.is_none_or(|p| p == port)
                    && (host == *name || host.ends_with(&format!(".{name}")))
            }
            NoProxyEntry::Net {
                ip: net,
                prefix,
                port: p,
            } => p.is_none_or(|p| p == port) && ip.is_some_and(|ip| in_net(ip, *net, *prefix)),
        })
    }
}

fn parse_no_proxy_entry(raw: &str) -> Option<NoProxyEntry> {
    if raw == "*" {
        return Some(NoProxyEntry::All);
    }
    let raw = raw.to_ascii_lowercase();
    // `[v6]:port`, `v4:port`, `name:port`; a bare IPv6 address has no port.
    let (body, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        (addr.to_string(), port)
    } else if raw.matches(':').count() == 1 && !raw.contains('/') {
        let (body, p) = raw.rsplit_once(':')?;
        (body.to_string(), Some(p.parse().ok()?))
    } else {
        (raw.clone(), None)
    };
    if let Some((addr, prefix)) = body.split_once('/') {
        let ip: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        return (prefix <= max).then_some(NoProxyEntry::Net { ip, prefix, port });
    }
    if let Ok(ip) = body.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return Some(NoProxyEntry::Net { ip, prefix, port });
    }
    let name = body
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.');
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    Some(NoProxyEntry::Name {
        name: name.to_string(),
        port,
    })
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// `host:port`, or `[host]:port` for an IPv6 address.
fn authority_of(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The proxy of the tool configs of this host (issue 83), read one time:
/// used when no proxy variable is set.
fn detected_proxy() -> Option<Proxy> {
    static DETECTED: OnceLock<Option<Proxy>> = OnceLock::new();
    DETECTED
        .get_or_init(|| {
            let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
            let (spec, path) = crate::proxy_auth::detect(home.as_deref())?;
            match Proxy::parse(&spec) {
                Ok(proxy) => {
                    tracing::info!(proxy = %proxy, from = %path.display(), "no proxy variable; the proxy of a tool config is used (--no-proxy turns it off)");
                    Some(proxy)
                }
                Err(err) => {
                    tracing::warn!(from = %path.display(), error = %err, "a tool config names a proxy that cannot be parsed");
                    None
                }
            }
        })
        .clone()
}

/// How cfrs reaches the network.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxyChoice {
    /// The proxy of the variables, if one is set (the default).
    #[default]
    FromEnvironment,
    /// No proxy (`--no-proxy`).
    Direct,
    /// This proxy (`--proxy URL`).
    Via(Proxy),
}

static CHOICE: OnceLock<ProxyChoice> = OnceLock::new();

/// Set the choice of this process. Call it before the first connection; a
/// later call has no effect.
pub fn set_choice(choice: ProxyChoice) {
    let _ = CHOICE.set(choice);
}

/// The choice of this process.
pub fn choice() -> ProxyChoice {
    CHOICE.get().cloned().unwrap_or_default()
}

/// The proxy for `host:port`, after `NO_PROXY`, or `None` for a direct
/// connection.
pub fn proxy_for(host: &str, port: u16) -> Option<Proxy> {
    let proxy = match choice() {
        ProxyChoice::Direct => return None,
        ProxyChoice::Via(proxy) => proxy,
        ProxyChoice::FromEnvironment => Proxy::from_env().or_else(detected_proxy)?,
    };
    (!NoProxy::from_env().matches(host, port)).then_some(proxy)
}

/// Connect to `host:port`: through `via` when it is given, else through the
/// proxy of [`proxy_for`], else directly.
pub async fn dial(
    host: &str,
    port: u16,
    via: Option<&Proxy>,
    timeout: Duration,
) -> Result<BoxedIo> {
    let proxy = match via {
        Some(proxy) => Some(proxy.clone()),
        None => proxy_for(host, port),
    };
    match proxy {
        Some(proxy) => proxy.connect(host, port, timeout).await,
        None => Ok(Box::new(dial_direct(host, port, timeout).await?)),
    }
}

/// Connect to `host:port` with no proxy: each address of the name, with
/// [`ATTEMPT_DELAY`] between the starts.
pub async fn dial_direct(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = tokio::time::timeout(timeout, crate::resolve::resolve(host))
        .await
        .with_context(|| format!("resolving {host}: no answer in {} s", timeout.as_secs()))
        .and_then(|r| r)
        .map_err(|e| crate::hop::at(crate::hop::Hop::Dns, e))?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    let (_, stream) = dial_addrs(&interleave(addrs), timeout)
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    Ok(stream)
}

/// The errors of a dial to more than one address, one entry for each
/// text (issue 95: the doctor showed 20 errors on one line):
/// `198.41.192.7:7844: refused` or `20 addresses (198.41.192.7:7844,
/// 198.41.192.27:7844, ...): Permission denied (os error 13)`.
pub fn group_errors(errors: &[(SocketAddr, String)]) -> String {
    let mut groups: Vec<(&str, Vec<SocketAddr>)> = Vec::new();
    for (addr, text) in errors {
        match groups.iter_mut().find(|(t, _)| *t == text.as_str()) {
            Some((_, addrs)) => addrs.push(*addr),
            None => groups.push((text, vec![*addr])),
        }
    }
    groups
        .iter()
        .map(|(text, addrs)| match addrs.as_slice() {
            [one] => format!("{one}: {text}"),
            many => {
                let shown: Vec<String> = many.iter().take(2).map(|a| a.to_string()).collect();
                let more = if many.len() > 2 { ", ..." } else { "" };
                format!(
                    "{} addresses ({}{more}): {text}",
                    many.len(),
                    shown.join(", ")
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Alternate IPv6 and IPv4 addresses, the first family first (RFC 8305).
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addrs.first().copied() else {
        return addrs;
    };
    let (same, other): (Vec<_>, Vec<_>) = addrs
        .into_iter()
        .partition(|a| a.is_ipv6() == first.is_ipv6());
    let mut out = Vec::with_capacity(same.len() + other.len());
    let (mut a, mut b) = (same.into_iter(), other.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
    out
}

/// Connect to the first of `addrs` that answers. The attempts start
/// [`ATTEMPT_DELAY`] apart, or at once when the attempt before fails. Gives
/// the index of the address and the stream.
pub async fn dial_addrs(addrs: &[SocketAddr], timeout: Duration) -> Result<(usize, TcpStream)> {
    use futures::stream::{FuturesUnordered, StreamExt};
    if addrs.is_empty() {
        bail!("no address to connect to");
    }
    let work = async {
        let attempt = |i: usize| {
            let addr = addrs[i];
            async move { (i, TcpStream::connect(addr).await) }
        };
        let mut pending = FuturesUnordered::new();
        let mut next = 0;
        let mut errors = Vec::new();
        loop {
            if next < addrs.len() && (pending.is_empty() || next == 0) {
                pending.push(attempt(next));
                next += 1;
            }
            let delay = tokio::time::sleep(ATTEMPT_DELAY);
            tokio::select! {
                Some((i, result)) = pending.next() => match result {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        return Ok((i, stream));
                    }
                    Err(err) => {
                        // Issue 126: EMFILE names the limit.
                        let text = crate::rlimit::hint(&err).unwrap_or_else(|| err.to_string());
                        errors.push((addrs[i], text));
                        if pending.is_empty() && next >= addrs.len() {
                            bail!("{}", group_errors(&errors));
                        }
                    }
                },
                _ = delay, if next < addrs.len() => {
                    pending.push(attempt(next));
                    next += 1;
                }
            }
        }
    };
    tokio::time::timeout(timeout, work)
        .await
        .with_context(|| format!("no address answered in {} s", timeout.as_secs()))?
}

/// The stdin and the stdout of a command as one byte stream (issue 129).
/// The command runs with `sh -c`; its stderr is the stderr of cfrs. The
/// end of the stream closes its stdin; a drop kills it.
pub struct ChildIo {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: tokio::process::ChildStdout,
}

impl ChildIo {
    pub fn spawn(command: &str) -> Result<Self> {
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("starting the proxy command (sh -c)")?;
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .context("the stdout of the proxy command")?;
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    /// The exit status, when the command has ended.
    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }
}

impl tokio::io::AsyncRead for ChildIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ChildIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.stdin.as_mut() {
            Some(stdin) => std::pin::Pin::new(stdin).poll_write(cx, data),
            None => std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.stdin.as_mut() {
            Some(stdin) => std::pin::Pin::new(stdin).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.stdin = None;
        std::task::Poll::Ready(Ok(()))
    }
}

/// Split `host:port`, `[v6]:port` or a bare host. Refuse a host with a
/// character that has no place in a host name.
fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if authority.is_empty() {
        bail!("proxy URL has no host");
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("proxy IPv6 address is missing its closing bracket")?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().context("proxy port is not a number")?,
            None if tail.is_empty() => default_port,
            None => bail!("text after the IPv6 address of the proxy"),
        };
        host.parse::<std::net::Ipv6Addr>()
            .context("the proxy host in brackets is not an IPv6 address")?;
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_string(),
                port.parse().context("proxy port is not a number")?,
            ),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        bail!("proxy URL has no host");
    }
    if host
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "[]@/?#\\%".contains(c))
        && !host.contains(':')
    {
        bail!("the proxy host has a character that a host name cannot have");
    }
    if port == 0 {
        bail!("the proxy port is 0");
    }
    Ok((host, port))
}

/// Decode `%XX` escapes. A bad escape, or bytes that are not UTF-8, are an
/// error: a changed password gives a 407 with no cause.
fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).and_then(|b| hex_val(*b)),
                bytes.get(i + 2).and_then(|b| hex_val(*b)),
            ) else {
                bail!("a bad percent escape at byte {i}");
            };
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).context("the decoded text is not UTF-8")
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
async fn read_head(stream: &mut BoxedIo, timeout: Duration) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    // One byte at a time: no byte after the head is taken from the caller.
    loop {
        let n = tokio::time::timeout(timeout, stream.read(&mut byte))
            .await
            .context("reading the CONNECT response: timed out")?
            .context("reading the CONNECT response")?;
        if n == 0 {
            bail!("the proxy closed the connection before answering CONNECT");
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADER_BYTES {
            bail!("the proxy response header exceeds {MAX_HEADER_BYTES} bytes");
        }
    }
}

/// Parse `HTTP/1.1 200 Connection established`.
pub(crate) fn parse_status(head: &[u8]) -> Result<u16> {
    let text = String::from_utf8_lossy(head);
    let line = text
        .lines()
        .next()
        .context("the proxy sent an empty response")?;
    let mut parts = line.split_whitespace();
    let version = parts.next().context("missing HTTP version")?;
    if !version.starts_with("HTTP/") {
        bail!("the proxy did not answer with HTTP");
    }
    let code = parts.next().context("missing HTTP status code")?;
    code.parse::<u16>()
        .context("the proxy status is not a number")
}

#[cfg(test)]
mod tests {
    /// Issue 83: a proxy that asks for Digest. The first CONNECT (Basic)
    /// gets 407 with a challenge; the second connection carries the Digest
    /// answer, and the proxy checks it.
    #[tokio::test]
    async fn a_digest_proxy_takes_the_answer() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let read_head = |mut s: tokio::net::TcpStream| async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    s.read_exact(&mut b).await.unwrap();
                    head.push(b[0]);
                }
                (s, String::from_utf8(head).unwrap())
            };
            let (first, _) = listener.accept().await.unwrap();
            let (mut first, head) = read_head(first).await;
            assert!(head.contains("Proxy-Authorization: Basic "), "{head}");
            first
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm=\"cfrs-test\", nonce=\"abc123\", qop=\"auth\", algorithm=MD5\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            drop(first);
            let (second, _) = listener.accept().await.unwrap();
            let (mut second, head) = read_head(second).await;
            let line = head
                .lines()
                .find(|l| l.starts_with("Proxy-Authorization: Digest "))
                .expect("a Digest answer")
                .to_string();
            let field = |name: &str| {
                let start = line.find(&format!("{name}=")).unwrap() + name.len() + 1;
                let rest = &line[start..];
                let rest = rest.trim_start_matches('"');
                rest[..rest.find(['"', ',']).unwrap_or(rest.len())].to_string()
            };
            let challenge = crate::proxy_auth::parse_challenge(
                "Digest realm=\"cfrs-test\", nonce=\"abc123\", qop=\"auth\", algorithm=MD5",
            )
            .unwrap();
            let want = crate::proxy_auth::authorization(
                &challenge,
                "user",
                "pa:ss",
                "CONNECT",
                "example.test:443",
                &field("cnonce"),
                1,
            );
            assert_eq!(&line["Proxy-Authorization: ".len()..], want);
            second
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            second.write_all(b"through").await.unwrap();
        });
        let proxy = super::Proxy::parse(&format!("http://user:pa%3Ass@{addr}")).unwrap();
        let mut io = proxy
            .connect("example.test", 443, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        let mut got = [0u8; 7];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"through");
        server.await.unwrap();
    }

    use super::*;

    // Issue 129: a proxy on a unix socket, or at a command.
    #[test]
    fn the_carriers_parse() {
        for spec in ["socks5h+unix:/run/w.sock", "socks5h://unix:/run/w.sock"] {
            let p = Proxy::parse(spec).unwrap();
            assert_eq!(p.carrier(), &Carrier::Unix("/run/w.sock".into()), "{spec}");
            assert_eq!(p.kind(), ProxyKind::Socks5 { remote_dns: true });
            assert_eq!(p.to_string(), "socks5h+unix:/run/w.sock");
        }
        assert!(Proxy::parse("http+unix:relative.sock").is_err());
        let spec = "http+exec:ssh -i /secret/key gw nc 127.0.0.1 3128";
        assert!(
            Proxy::parse(spec).is_err(),
            "a variable does not start a command"
        );
        let p = Proxy::parse_trusted(spec).unwrap();
        assert_eq!(p.kind(), ProxyKind::Http);
        assert!(matches!(p.carrier(), Carrier::Exec(c) if c.starts_with("ssh -i")));
        assert_eq!(p.to_string(), "http+exec:ssh ...");
        assert!(!format!("{p:?}").contains("secret"));
        assert!(Proxy::parse_trusted("http+exec:  ").is_err());
    }

    /// An HTTP CONNECT proxy on a unix socket that answers 200 and echoes.
    async fn unix_connect_echo(path: std::path::PathBuf) {
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        head.push(b[0]);
                    }
                    assert!(head.starts_with(b"CONNECT echo.test:7 HTTP/1.1"));
                    s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }

    async fn round_trip(proxy: &Proxy) -> Vec<u8> {
        let mut io = proxy
            .connect("echo.test", 7, Duration::from_secs(5))
            .await
            .unwrap();
        io.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        back.to_vec()
    }

    #[tokio::test]
    async fn a_proxy_on_a_unix_socket_carries_a_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sock");
        unix_connect_echo(path.clone()).await;
        let proxy = Proxy::parse(&format!("http+unix:{}", path.display())).unwrap();
        assert_eq!(round_trip(&proxy).await, b"ping");
    }

    // Issue 129: the proxy is at the stdin and the stdout of a command: a
    // shell script reads the CONNECT, answers 200, then echoes.
    #[tokio::test]
    async fn a_proxy_command_carries_a_connection() {
        let script = r#"http+exec:while IFS= read -r l; do [ "$l" = "$(printf '\r')" ] && break; done; printf 'HTTP/1.1 200 OK\r\n\r\n'; exec cat"#;
        let proxy = Proxy::parse_trusted(script).unwrap();
        assert_eq!(round_trip(&proxy).await, b"ping");
        let proxy = Proxy::parse_trusted("http+exec:exit 3").unwrap();
        let Err(err) = proxy.connect("echo.test", 7, Duration::from_secs(5)).await else {
            panic!("a command that exits is no proxy");
        };
        assert_eq!(
            crate::hop::of(&err),
            Some(crate::hop::Hop::Proxy),
            "{err:#}"
        );
    }

    #[test]
    fn the_same_error_of_many_addresses_is_one_entry() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let denied = "Permission denied (os error 13)".to_string();
        let mut errors: Vec<(SocketAddr, String)> = (1..=20)
            .map(|i| (a(&format!("198.41.192.{i}:7844")), denied.clone()))
            .collect();
        errors.push((a("1.2.3.4:7844"), "refused".into()));
        assert_eq!(
            group_errors(&errors),
            "20 addresses (198.41.192.1:7844, 198.41.192.2:7844, ...): \
             Permission denied (os error 13); 1.2.3.4:7844: refused"
        );
        assert_eq!(
            group_errors(&errors[..1]),
            format!("198.41.192.1:7844: {denied}")
        );
    }

    #[test]
    fn parses_a_full_url() {
        let p = Proxy::parse("http://user:p%40ss@10.0.0.1:3128").unwrap();
        assert_eq!(p.address(), ("10.0.0.1", 3128));
        assert_eq!(p.auth, Some(("user".into(), "p@ss".into())));
        assert_eq!(p.to_string(), "http://10.0.0.1:3128");
    }

    #[test]
    fn debug_and_display_hold_no_password() {
        let p = Proxy::parse("http://u:secret@h:3128").unwrap();
        let debug = format!("{p:?}");
        assert!(
            !debug.contains("secret") && debug.contains("<hidden>"),
            "{debug}"
        );
        assert!(!p.to_string().contains("secret"));
        let s = Proxy::parse("socks5h://u:secret@h").unwrap();
        assert!(!format!("{s:?}").contains("secret"));
        assert_eq!(s.to_string(), "socks5h://h:1080");
    }

    #[test]
    fn the_default_ports() {
        assert_eq!(
            Proxy::parse("http://proxy.example").unwrap().address(),
            ("proxy.example", 8080)
        );
        assert_eq!(
            Proxy::parse("proxy.example:3128").unwrap().address(),
            ("proxy.example", 3128)
        );
        assert_eq!(
            Proxy::parse("socks5://127.0.0.1").unwrap().address(),
            ("127.0.0.1", 1080)
        );
    }

    #[test]
    fn parses_a_bracketed_ipv6_authority() {
        let p = Proxy::parse("http://[::1]:9000").unwrap();
        assert_eq!(p.address(), ("::1", 9000));
        assert_eq!(p.to_string(), "http://[::1]:9000");
    }

    #[test]
    fn the_schemes() {
        assert_eq!(
            Proxy::parse("socks5://127.0.0.1:1080").unwrap().kind(),
            ProxyKind::Socks5 { remote_dns: false }
        );
        assert_eq!(
            Proxy::parse("SOCKS5H://127.0.0.1:1080").unwrap().kind(),
            ProxyKind::Socks5 { remote_dns: true }
        );
        for (spec, want) in [
            ("socks4://h:1080", "SOCKS4 is not supported"),
            ("https://h:443", "https:// proxies"),
            ("ftp://h:21", "ftp:// is not supported"),
        ] {
            let err = Proxy::parse(spec).unwrap_err().to_string();
            assert!(err.contains(want), "{spec}: {err}");
        }
    }

    #[test]
    fn bad_urls_are_refused() {
        for spec in [
            "http://u:p%4@h:1",
            "http://u:p%zz@h:1",
            "http://u:%ff%fe@h:1",
            "http://h:1/path",
            "http://h:notaport",
            "http://h:0",
            "http://[::1",
            "http://h st:1",
            "socks5://:p@h:1",
        ] {
            assert!(Proxy::parse(spec).is_err(), "{spec} was accepted");
        }
        // An escaped colon stays in the user.
        let p = Proxy::parse("http://a%3Ab:c@h:1").unwrap();
        assert_eq!(p.auth, Some(("a:b".into(), "c".into())));
    }

    #[test]
    fn no_proxy_rules() {
        let list = NoProxy::parse("127.0.0.1, .example.com,internal:8443 10.0.0.0/8,[::1],*.corp");
        assert!(list.matches("127.0.0.1", 80));
        assert!(!list.matches("127.0.0.2", 80));
        assert!(list.matches("example.com", 443));
        assert!(list.matches("api.example.com", 443));
        assert!(!list.matches("badexample.com", 443));
        assert!(list.matches("internal", 8443));
        assert!(!list.matches("internal", 443));
        assert!(list.matches("10.20.30.40", 1));
        assert!(!list.matches("11.0.0.1", 1));
        assert!(list.matches("::1", 1));
        assert!(list.matches("[::1]", 1));
        assert!(list.matches("a.corp", 1));
        assert!(NoProxy::parse("*").matches("anything", 1));
        assert!(!NoProxy::default().matches("anything", 1));
    }

    #[test]
    fn a_407_names_the_schemes() {
        let head = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM, Negotiate\r\nproxy-authenticate: Basic realm=\"a, b\", Digest realm=\"x\", qop=\"auth\"\r\n\r\n";
        let text = explain_407(head, true);
        assert!(
            text.contains("it asks for NTLM or Negotiate or Basic or Digest"),
            "{text}"
        );
        assert!(text.contains("cfrs sent Basic"), "{text}");
        let text = explain_407(
            b"HTTP/1.1 407 x\r\nProxy-Authenticate: NTLM, Negotiate\r\n\r\n",
            false,
        );
        assert!(
            text.contains("NTLM or Negotiate") && text.contains("cfrs supports Basic only"),
            "{text}"
        );
        assert!(text.contains("sent no credentials"), "{text}");
    }

    #[test]
    fn status_parsing() {
        assert_eq!(
            parse_status(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap(),
            200
        );
        assert_eq!(
            parse_status(b"HTTP/1.0 407 Proxy Auth\r\n\r\n").unwrap(),
            407
        );
        assert!(parse_status(b"SSH-2.0-OpenSSH\r\n").is_err());
    }

    #[test]
    fn interleave_alternates_the_families() {
        let a: Vec<SocketAddr> = ["[::1]:1", "[::2]:1", "1.1.1.1:1", "2.2.2.2:1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let got: Vec<String> = interleave(a).iter().map(|a| a.to_string()).collect();
        assert_eq!(got, ["[::1]:1", "1.1.1.1:1", "[::2]:1", "2.2.2.2:1"]);
    }
}
