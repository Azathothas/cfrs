//! The reverse mode of the WebSocket relay (issue 88): inbound access to a
//! host that has outbound HTTPS only.
//!
//! * `cfrs relay pair` asks the relay for a pair (`POST /v1/pair`): a name,
//!   a node token, a connect token and a stop token. cfrs keeps the pair in
//!   a file of mode 0600 and prints the connect token for the operator.
//! * `cfrs relay node` holds the WebSocket `/v1/node/NAME`. For each
//!   `open {id}`, it connects to the local target and answers `ready {id}`
//!   or `reject {id, reason}`. Each binary frame is the 32 hex characters of
//!   the session id and at most 64 KiB of bytes. A lost socket is opened
//!   again with a backoff (1 s to 30 s, with jitter). A close for cause
//!   (the pair expired, the operator stopped it, a refused token) stops the
//!   node: a new pair is necessary.
//! * `cfrs relay connect NAME` opens `/v1/connect/NAME` for the operator,
//!   waits for `ready`, and then copies raw bytes: stdin and stdout (for an
//!   SSH `ProxyCommand`), or each connection of a local listener.
//!
//! The relay authenticates tokens, not persons: give the connect token only
//! over a channel that you trust.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _, Result};
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::exit::{fault, Fault};
use crate::ws_relay::Relay;

/// The environment variable with the connect token of the operator.
pub const CONNECT_TOKEN_VARIABLE: &str = "CFRS_RELAY_CONNECT_TOKEN";
/// The most bytes in one data frame.
const FRAME: usize = 64 * 1024;
/// The length of a session id: 32 lowercase hex characters.
const ID_LEN: usize = 32;
/// The interval of the WebSocket pings (the relay drops a quiet socket).
const PING_EVERY: Duration = Duration::from_secs(20);
/// The time for a WebSocket handshake, and for a local connect (the relay
/// reaps a session with no `ready` after 15 s).
const TIMEOUT: Duration = Duration::from_secs(20);
const LOCAL_CONNECT: Duration = Duration::from_secs(10);

/// A pair of the relay.
#[derive(Clone, Serialize, Deserialize)]
pub struct Pair {
    pub name: String,
    pub node_token: String,
    pub connect_token: String,
    #[serde(default)]
    pub stop_token: String,
    /// Milliseconds since the epoch.
    pub expires: u64,
    /// The base URL of the relay.
    pub relay: String,
}

impl std::fmt::Debug for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pair")
            .field("name", &self.name)
            .field("expires", &self.expires)
            .field("relay", &self.relay)
            .field("tokens", &"<redacted>")
            .finish()
    }
}

impl Pair {
    /// The time that is left; zero when the pair expired.
    pub fn left(&self) -> Duration {
        let end = UNIX_EPOCH + Duration::from_millis(self.expires);
        end.duration_since(SystemTime::now()).unwrap_or_default()
    }
}

/// A name of a pair is safe for a file name and a URL path.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("{name:?} is not a pair name (letters, digits, - and _)");
    }
    Ok(())
}

/// Ask the relay for a new pair. A name collision (409) is asked again
/// once: names are random.
pub async fn pair(relay: &Relay) -> Result<Pair> {
    for _ in 0..2 {
        match relay.post_json("/v1/pair", None).await? {
            Ok(body) => {
                let text = |key: &str| {
                    body.get(key)
                        .and_then(|v| v.as_str())
                        .filter(|v| !v.is_empty())
                        .map(str::to_string)
                        .with_context(|| format!("the pair answer has no {key}"))
                };
                let pair = Pair {
                    name: text("name")?,
                    node_token: text("node_token")?,
                    connect_token: text("connect_token")?,
                    stop_token: text("stop_token").unwrap_or_default(),
                    expires: body
                        .get("expires")
                        .and_then(|v| v.as_u64())
                        .context("the pair answer has no expires")?,
                    relay: relay.url(),
                };
                check_name(&pair.name)?;
                return Ok(pair);
            }
            Err((409, _)) => continue,
            Err((status, text)) => bail!("the relay refused a pair: HTTP {status}: {text}"),
        }
    }
    bail!("the relay gave a name that is in use two times (409)")
}

/// The directory of the pairs: `relay` in the state directory.
pub fn pairs_dir() -> Result<PathBuf> {
    let dir = crate::state::state_dir()?
        .context("no state directory (set XDG_STATE_HOME or HOME)")?
        .join("relay");
    Ok(dir)
}

/// Write `pair` to `dir/NAME.json` with mode 0600 (the directory 0700).
pub fn save(pair: &Pair, dir: &Path) -> Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    check_name(&pair.name)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.json", pair.name));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(serde_json::to_string_pretty(pair)?.as_bytes())?;
    Ok(path)
}

/// Read the pair `name` from `dir`; with no name, the pair that has the
/// most time left.
pub fn load(dir: &Path, name: Option<&str>) -> Result<Pair> {
    let read = |path: &Path| -> Result<Pair> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("{} is not a pair", path.display()))
    };
    if let Some(name) = name {
        check_name(name)?;
        return read(&dir.join(format!("{name}.json")));
    }
    let mut best: Option<Pair> = None;
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("no pair in {} (cfrs relay pair)", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(pair) = read(&path) {
            if best.as_ref().is_none_or(|b| pair.expires > b.expires) {
                best = Some(pair);
            }
        }
    }
    best.with_context(|| format!("no pair in {} (cfrs relay pair)", dir.display()))
}

/// Stop the node of `pair` and its sessions at the relay
/// (`POST /v1/stop/NAME` with the stop token).
pub async fn stop(relay: &Relay, pair: &Pair) -> Result<()> {
    if pair.stop_token.is_empty() {
        bail!("the pair {} has no stop token", pair.name);
    }
    let path = format!("/v1/stop/{}", pair.name);
    match relay.post_json(&path, Some(&pair.stop_token)).await? {
        Ok(_) => Ok(()),
        Err((status, text)) => bail!(
            "the relay did not stop {}: HTTP {status}: {text}",
            pair.name
        ),
    }
}

/// The local service of a node.
#[derive(Clone, Debug)]
pub enum Target {
    /// `host:port` (a name is resolved for each session).
    Tcp(String),
    /// `unix:/path`.
    Unix(PathBuf),
}

impl Target {
    /// `host:port`, `tcp://host:port` or `unix:/path`.
    pub fn parse(text: &str) -> Result<Self> {
        if let Some(path) = text.strip_prefix("unix:") {
            let path = path.trim_start_matches("//");
            if path.is_empty() {
                bail!("--to unix: has no path");
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        let rest = text.strip_prefix("tcp://").unwrap_or(text);
        match rest.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
                Ok(Self::Tcp(rest.to_string()))
            }
            _ => bail!("--to {text:?} is not host:port or unix:/path"),
        }
    }

    async fn connect(&self) -> Result<Box<dyn LocalIo>> {
        Ok(match self {
            Self::Tcp(addr) => Box::new(tokio::net::TcpStream::connect(addr).await?),
            Self::Unix(path) => Box::new(tokio::net::UnixStream::connect(path).await?),
        })
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

trait LocalIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> LocalIo for T {}

/// How one node socket ended.
#[derive(Debug, PartialEq, Eq)]
enum NodeEnd {
    /// Open the socket again.
    Again(String),
    /// Do not open it again: a new pair is necessary.
    Stop(String),
}

/// Run the node of `pair` until the relay ends the pair. A lost socket is
/// opened again with a backoff.
pub async fn node(relay: &Relay, pair: &Pair, target: &Target) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    loop {
        if pair.left().is_zero() {
            return Err(fault(
                Fault::Config,
                anyhow::anyhow!(
                    "the pair {} expired; make a new pair (cfrs relay pair)",
                    pair.name
                ),
            ));
        }
        let started = Instant::now();
        let end = match node_once(relay, pair, target).await {
            Ok(end) => end,
            Err(err) => NodeEnd::Again(format!("{err:#}")),
        };
        match end {
            NodeEnd::Stop(reason) => {
                return Err(fault(
                    Fault::Config,
                    anyhow::anyhow!("the relay ended the node {}: {reason}", pair.name),
                ))
            }
            NodeEnd::Again(reason) => {
                if started.elapsed() > Duration::from_secs(60) {
                    backoff = Duration::from_secs(1);
                }
                let mut byte = [0u8; 2];
                let _ = getrandom::fill(&mut byte);
                let jitter = Duration::from_millis(u64::from(u16::from_le_bytes(byte) % 1000));
                tracing::warn!(
                    name = %pair.name,
                    %reason,
                    again_in = ?(backoff + jitter),
                    "the node socket ended; cfrs opens it again"
                );
                tokio::time::sleep(backoff + jitter).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// The meaning of a close of the node socket by the relay.
fn node_close(code: u16, reason: &str) -> NodeEnd {
    let text = format!("{code} {reason}");
    match code {
        // The operator stopped the name, or the pair expired.
        1001 if reason.contains("stopped") || reason.contains("expired") => NodeEnd::Stop(text),
        1008 if reason.contains("token") => NodeEnd::Stop(text),
        _ => NodeEnd::Again(text),
    }
}

/// A text control message of the node protocol.
fn control(kind: &str, id: &str, reason: Option<&str>) -> Message {
    let mut doc = serde_json::json!({ "type": kind, "id": id });
    if let Some(reason) = reason {
        doc["reason"] = reason.into();
    }
    Message::text(doc.to_string())
}

fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

async fn node_once(relay: &Relay, pair: &Pair, target: &Target) -> Result<NodeEnd> {
    let path = format!("/v1/node/{}", pair.name);
    let ws = match relay.websocket(&path, &pair.node_token, TIMEOUT).await? {
        Ok(ws) => ws,
        Err((409, _)) => {
            return Ok(NodeEnd::Again(
                "another node holds the name (409); the old socket may still close".into(),
            ))
        }
        Err((status @ (401 | 403), body)) => {
            return Ok(NodeEnd::Stop(format!(
                "the relay refused the node token ({status}): {}",
                body.chars().take(200).collect::<String>()
            )))
        }
        Err((status, body)) => {
            return Ok(NodeEnd::Again(format!(
                "HTTP {status}: {}",
                body.chars().take(200).collect::<String>()
            )))
        }
    };
    tracing::info!(name = %pair.name, %target, "the node is connected to the relay");
    crate::detach::ready(node_ready(pair, target));
    let (mut sink, mut stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
    let mut sessions: HashMap<String, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    loop {
        tokio::select! {
            message = stream.next() => match message {
                None => return Ok(NodeEnd::Again("the relay closed the socket".into())),
                Some(Err(err)) => return Ok(NodeEnd::Again(format!("{err}"))),
                Some(Ok(Message::Text(text))) => {
                    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text.as_str()) else {
                        continue;
                    };
                    let kind = doc.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    match kind {
                        "open" if valid_id(&id) => {
                            let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                            sessions.insert(id.clone(), data_tx);
                            tokio::spawn(session(target.clone(), id, data_rx, out_tx.clone()));
                        }
                        "close" => {
                            // Dropping the sender ends the session task.
                            sessions.remove(&id);
                        }
                        "hello" => tracing::debug!("hello from the relay"),
                        other => tracing::debug!(kind = other, "a control message that cfrs does not use"),
                    }
                }
                Some(Ok(Message::Binary(data))) => {
                    if data.len() <= ID_LEN {
                        continue;
                    }
                    let Ok(id) = std::str::from_utf8(&data[..ID_LEN]) else {
                        continue;
                    };
                    if let Some(tx) = sessions.get(id) {
                        if tx.send(data[ID_LEN..].to_vec()).await.is_err() {
                            sessions.remove(id);
                        }
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    return Ok(match frame {
                        Some(frame) => node_close(u16::from(frame.code), frame.reason.as_str()),
                        None => NodeEnd::Again("the relay closed the socket".into()),
                    });
                }
                Some(Ok(_)) => {}
            },
            Some(message) = out_rx.recv() => {
                if let Err(err) = sink.send(message).await {
                    return Ok(NodeEnd::Again(format!("{err}")));
                }
            }
            _ = ping.tick() => {
                if let Err(err) = sink.send(Message::Ping(Vec::new().into())).await {
                    return Ok(NodeEnd::Again(format!("{err}")));
                }
            }
        }
    }
}

/// One session of the node: connect to the target, then copy bytes until
/// one side ends.
async fn session(
    target: Target,
    id: String,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Message>,
) {
    let io = match tokio::time::timeout(LOCAL_CONNECT, target.connect()).await {
        Ok(Ok(io)) => io,
        Ok(Err(err)) => {
            let reason = format!("{target}: {err:#}");
            tracing::info!(%id, %reason, "a session is refused");
            let _ = out.send(control("reject", &id, Some(&reason))).await;
            return;
        }
        Err(_) => {
            let reason = format!("{target}: no answer in {} s", LOCAL_CONNECT.as_secs());
            let _ = out.send(control("reject", &id, Some(&reason))).await;
            return;
        }
    };
    if out.send(control("ready", &id, None)).await.is_err() {
        return;
    }
    tracing::info!(%id, %target, "a session is open");
    let (mut read, mut write) = tokio::io::split(io);
    let to_relay = {
        let out = out.clone();
        let id = id.clone();
        async move {
            let mut buf = vec![0u8; FRAME];
            loop {
                let n = match read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut frame = Vec::with_capacity(ID_LEN + n);
                frame.extend_from_slice(id.as_bytes());
                frame.extend_from_slice(&buf[..n]);
                if out.send(Message::binary(frame)).await.is_err() {
                    return;
                }
            }
            let _ = out.send(control("close", &id, None)).await;
        }
    };
    let to_local = async move {
        while let Some(data) = data_rx.recv().await {
            if write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = write.shutdown().await;
    };
    tokio::select! {
        _ = to_relay => {}
        _ = to_local => {}
    }
    tracing::info!(%id, "a session ended");
}

/// The operator side: open a session to the node `name`, wait for
/// `ready`, then copy `input` to the node and the node to `output`.
/// After the end of the input of `relay connect`, the time with no data from
/// the target after which the session ends (issue 109).
/// The ready document of a node (issue 119): the key `name` is the name of
/// the instance (`detach::ready` sets it), so the pair is `pair`, with its
/// end.
pub fn node_ready(pair: &Pair, target: &Target) -> serde_json::Value {
    serde_json::json!({
        "pair": pair.name,
        "relay": pair.relay,
        "target": target.to_string(),
        "expires": pair.expires,
        "expires_in": pair.left().as_secs(),
    })
}

/// The detached instances that serve the node of the pair `name` (issue
/// 119: `relay stop` stops them too).
pub fn instances_of_pair(records: &[crate::instances::Record], name: &str) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.command.starts_with("relay node"))
        .filter(|r| {
            r.ready
                .as_ref()
                .and_then(|d| d.get("pair"))
                .and_then(|v| v.as_str())
                .map(|p| p == name)
                .unwrap_or_else(|| r.args.iter().any(|a| a == name))
        })
        .map(|r| r.name.clone())
        .collect()
}

pub const EOF_IDLE: Duration = Duration::from_secs(5);

pub async fn connect<R, W>(
    relay: &Relay,
    name: &str,
    token: &str,
    mut input: R,
    mut output: W,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    check_name(name)?;
    let path = format!("/v1/connect/{name}");
    let ws = match relay.websocket(&path, token, TIMEOUT).await? {
        Ok(ws) => ws,
        Err((status @ (401 | 403), _)) => {
            return Err(fault(
                Fault::Config,
                anyhow::anyhow!("the relay refused the connect token for {name} ({status})"),
            ))
        }
        Err((status, body)) => {
            return Err(fault(
                Fault::Unavailable,
                anyhow::anyhow!(
                    "the relay refused the session to {name}: HTTP {status}: {}",
                    body.chars().take(200).collect::<String>()
                ),
            ))
        }
    };
    let (mut sink, mut stream) = ws.split();
    // Wait for ready.
    let ready = async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(text))) => {
                    let doc: serde_json::Value =
                        serde_json::from_str(text.as_str()).unwrap_or_default();
                    match doc.get("type").and_then(|v| v.as_str()) {
                        Some("ready") => return Ok(()),
                        Some("reject") => {
                            let reason = doc
                                .get("reason")
                                .and_then(|v| v.as_str())
                                .unwrap_or("no reason");
                            bail!("the node {name} refused the session: {reason}");
                        }
                        _ => continue,
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    let text = frame
                        .map(|f| format!("{} {}", u16::from(f.code), f.reason))
                        .unwrap_or_else(|| "no reason".into());
                    bail!("the relay closed the session to {name}: {text}");
                }
                Some(Ok(_)) => continue,
                Some(Err(err)) => bail!("the session to {name}: {err}"),
                None => bail!("the relay closed the session to {name}"),
            }
        }
    };
    tokio::time::timeout(TIMEOUT, ready)
        .await
        .map_err(|_| anyhow::anyhow!("the node {name} did not answer in {} s", TIMEOUT.as_secs()))?
        .map_err(|err| fault(Fault::Unavailable, err))?;
    tracing::debug!(%name, "the session is ready");
    let mut buf = vec![0u8; FRAME];
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let mut input_open = true;
    // Issue 109: the end of the input does not close the session at once
    // (the protocol has no half-close, and a close lost the answer of the
    // target). The session ends when the target closes, or after EOF_IDLE
    // with no data from it.
    let mut last_data = tokio::time::Instant::now();
    loop {
        tokio::select! {
            read = input.read(&mut buf), if input_open => match read {
                Ok(0) | Err(_) => {
                    input_open = false;
                    last_data = tokio::time::Instant::now();
                }
                Ok(n) => sink.send(Message::binary(buf[..n].to_vec())).await?,
            },
            _ = tokio::time::sleep_until(last_data + EOF_IDLE), if !input_open => {
                let _ = sink.send(Message::Close(None)).await;
                break;
            }
            message = stream.next() => match message {
                Some(Ok(Message::Binary(data))) => {
                    last_data = tokio::time::Instant::now();
                    if !data.is_empty() {
                        output.write_all(&data).await?;
                        output.flush().await?;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    let doc: serde_json::Value =
                        serde_json::from_str(text.as_str()).unwrap_or_default();
                    if doc.get("type").and_then(|v| v.as_str()) == Some("reject") {
                        let reason = doc.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                        bail!("the node {name} ended the session: {reason}");
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    if let Some(frame) = frame {
                        let code = u16::from(frame.code);
                        if code != 1000 && input_open {
                            bail!("the session to {name} ended: {code} {}", frame.reason);
                        }
                    }
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            _ = ping.tick() => {
                sink.send(Message::Ping(Vec::new().into())).await?;
            }
        }
    }
    let _ = output.flush().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        name: &str,
        command: &str,
        args: &[&str],
        pair: Option<&str>,
    ) -> crate::instances::Record {
        crate::instances::Record {
            name: name.into(),
            pid: 1,
            supervisor: None,
            started: 0,
            command: command.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            hash: String::new(),
            cwd: "/".into(),
            state: "ready".into(),
            ready: pair.map(|p| serde_json::json!({ "pair": p })),
            log: String::new(),
            restarts: 0,
            retry_after_s: None,
        }
    }

    // Issue 119: relay stop finds the node instances of its pair.
    #[test]
    fn the_instances_of_a_pair() {
        let records = [
            record("relay-node-a1", "relay node", &[], Some("ssh-box")),
            record(
                "relay-node-b2",
                "relay node",
                &["relay", "node", "ssh-box"],
                None,
            ),
            record("relay-node-c3", "relay node", &[], Some("other")),
            record("ssh-box", "tunnel", &["ssh-box"], None),
        ];
        assert_eq!(
            instances_of_pair(&records, "ssh-box"),
            ["relay-node-a1", "relay-node-b2"]
        );
    }

    // Issue 119: the ready document names the pair and its end.
    #[test]
    fn the_node_ready_document_names_the_pair() {
        let pair = Pair {
            name: "ssh-box".into(),
            node_token: "n".into(),
            connect_token: "c".into(),
            stop_token: String::new(),
            expires: (SystemTime::now() + Duration::from_secs(600))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            relay: "https://relay.example".into(),
        };
        let doc = node_ready(&pair, &Target::parse("127.0.0.1:22").unwrap());
        assert_eq!(doc["pair"], "ssh-box");
        assert!(doc.get("name").is_none());
        assert_eq!(doc["expires"], pair.expires);
        assert!(doc["expires_in"].as_u64().unwrap() > 590);
    }

    #[test]
    fn targets_and_names() {
        assert!(
            matches!(Target::parse("127.0.0.1:22").unwrap(), Target::Tcp(a) if a == "127.0.0.1:22")
        );
        assert!(
            matches!(Target::parse("tcp://localhost:5432").unwrap(), Target::Tcp(a) if a == "localhost:5432")
        );
        assert!(
            matches!(Target::parse("unix:///run/x.sock").unwrap(), Target::Unix(p) if p == Path::new("/run/x.sock"))
        );
        for bad in ["22", "host:", "host:x", "unix:", ":22"] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
        assert!(check_name("0123abcd").is_ok());
        for bad in ["", "../x", "a/b", "a b"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(valid_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_id("0123456789ABCDEF0123456789abcdef"));
        assert!(!valid_id("0123"));
    }

    #[test]
    fn close_codes() {
        assert!(matches!(
            node_close(1001, "operator stopped reverse relay"),
            NodeEnd::Stop(_)
        ));
        assert!(matches!(node_close(1001, "pair expired"), NodeEnd::Stop(_)));
        assert!(matches!(
            node_close(1011, "socket error"),
            NodeEnd::Again(_)
        ));
        assert!(matches!(
            node_close(1003, "unknown session id"),
            NodeEnd::Again(_)
        ));
    }

    #[test]
    fn a_pair_file_is_private_and_the_newest_is_chosen() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let pair = |name: &str, expires| Pair {
            name: name.into(),
            node_token: "n".into(),
            connect_token: "c".into(),
            stop_token: "s".into(),
            expires,
            relay: "https://relay.example".into(),
        };
        let path = save(&pair("old", 1), dir.path()).unwrap();
        save(&pair("new", 2), dir.path()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(load(dir.path(), None).unwrap().name, "new");
        assert_eq!(load(dir.path(), Some("old")).unwrap().name, "old");
        assert!(!format!("{:?}", pair("x", 1)).contains("\"n\""));
    }
}
