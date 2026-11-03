//! A local SOCKS5 and HTTP `CONNECT` proxy whose connections go through WARP.
//!
//! This is the proxy mode of the WARP client. Programs that read `ALL_PROXY`
//! or `HTTPS_PROXY` use it directly. `cfrs warp run` puts any other program
//! behind it with pod-netns.
//!
//! Names are resolved through the tunnel (DNS over UDP to 1.1.1.1), so no
//! query goes to the local resolver.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use pod_netns::listen::ProxyListen;
use pod_netns::socks::{self, ProxyHost, ProxyRequest};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::ip::{TcpConn, WarpStack};

/// The resolver that names are sent to through the tunnel.
pub const TUNNEL_RESOLVER: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53);
/// The longest time for a DNS answer through the tunnel.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest time for a TCP connect through the tunnel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The size of each read from a tunnel connection.
const CHUNK: usize = 64 * 1024;

/// A running proxy.
pub struct WarpProxy {
    /// Where the proxy accepts clients.
    pub listen: ProxyListen,
    task: JoinHandle<()>,
}

impl WarpProxy {
    /// Stop the proxy.
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// A bound listener of the proxy, before the WARP session (issue 97: a
/// bind that fails is known before cfrs waits for the network).
pub enum Bound {
    Tcp(tokio::net::TcpListener, ProxyListen),
    Unix(tokio::net::UnixListener, ProxyListen),
}

impl Bound {
    /// The address of the listener (the port that the kernel chose too).
    pub fn listen(&self) -> &ProxyListen {
        match self {
            Bound::Tcp(_, listen) | Bound::Unix(_, listen) => listen,
        }
    }
}

/// Bind `listen`: a TCP listener, or a unix socket of mode 0600.
pub async fn bind(listen: &ProxyListen) -> Result<Bound> {
    match listen {
        ProxyListen::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding tcp://{addr}"))?;
            let actual = listener.local_addr().unwrap_or(*addr);
            Ok(Bound::Tcp(listener, ProxyListen::Tcp(actual)))
        }
        ProxyListen::Unix(path) => {
            // Issue 115: a socket that answers belongs to a running proxy:
            // it is not taken. Before, it was removed, and the running
            // proxy lost its clients.
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!(
                    "unix:{} is served by another process (cfrs ps; cfrs warp down stops cfrs warp up)",
                    path.display()
                );
            }
            let _ = std::fs::remove_file(path);
            let listener = pod_netns::listen::bind_private(path)
                .with_context(|| format!("binding unix:{}", path.display()))?;
            Ok(Bound::Unix(listener, listen.clone()))
        }
    }
}

/// Bind each of `listens` on its own: the listeners that work, and the
/// error of each one that does not.
pub async fn bind_all(listens: &[ProxyListen]) -> (Vec<Bound>, Vec<(ProxyListen, anyhow::Error)>) {
    let mut bound = Vec::new();
    let mut failed = Vec::new();
    for listen in listens {
        match bind(listen).await {
            Ok(b) => bound.push(b),
            Err(err) => failed.push((listen.clone(), err)),
        }
    }
    (bound, failed)
}

/// The counters of the proxy clients of this process (issue 117).
#[derive(Default)]
pub struct Stats {
    pub active: std::sync::atomic::AtomicU64,
    pub total: std::sync::atomic::AtomicU64,
    pub refused: std::sync::atomic::AtomicU64,
}

/// The counters of this process.
pub static STATS: Stats = Stats {
    active: std::sync::atomic::AtomicU64::new(0),
    total: std::sync::atomic::AtomicU64::new(0),
    refused: std::sync::atomic::AtomicU64::new(0),
};

/// The most clients at the same time (`--max-connections`); 0 is no limit.
static MAX_CONNECTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set the most clients at the same time (issue 117); 0 is no limit.
pub fn set_max_connections(n: u64) {
    MAX_CONNECTIONS.store(n, std::sync::atomic::Ordering::Relaxed);
}

/// The interval of the health line of the proxy in the log (issue 116).
pub const HEALTH_EVERY: Duration = Duration::from_secs(600);

/// Take a place for a new client: `None` when the limit is reached.
fn admit() -> Option<Admitted> {
    use std::sync::atomic::Ordering::SeqCst;
    let limit = MAX_CONNECTIONS.load(SeqCst);
    let active = STATS.active.fetch_add(1, SeqCst) + 1;
    if limit > 0 && active > limit {
        STATS.active.fetch_sub(1, SeqCst);
        STATS.refused.fetch_add(1, SeqCst);
        return None;
    }
    STATS.total.fetch_add(1, SeqCst);
    Some(Admitted)
}

/// A place of a client; the drop frees it.
struct Admitted;

impl Drop for Admitted {
    fn drop(&mut self) {
        STATS
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Log one line about the health of the proxy each [`HEALTH_EVERY`]
/// (issue 116: `cfrs logs warp` showed nothing after the start).
pub fn health_log(live: Arc<super::Live<WarpStack>>) {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let weak = Arc::downgrade(&live);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEALTH_EVERY);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(live) = weak.upgrade() else { return };
                use std::sync::atomic::Ordering::Relaxed;
                info!(
                    clients = STATS.active.load(Relaxed),
                    since_start = STATS.total.load(Relaxed),
                    refused = STATS.refused.load(Relaxed),
                    reconnects = live.reconnects(),
                    "WARP proxy health"
                );
            }
        });
    });
}

/// A DNS forwarder (issue 117): each query that comes to `socket` goes
/// through the WARP session of `live` to [`TUNNEL_RESOLVER`], and the
/// answer goes back. For a program that sends its own DNS on UDP (a host
/// with a fake or broken resolver).
pub fn serve_dns(live: Arc<super::Live<WarpStack>>, socket: tokio::net::UdpSocket) {
    let socket = Arc::new(socket);
    if let Ok(addr) = socket.local_addr() {
        info!(%addr, "the DNS forwarder through WARP is listening");
    }
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let query = buf[..n].to_vec();
            let socket = socket.clone();
            let live = live.clone();
            tokio::spawn(async move {
                let Ok(stack) = live.get().await else { return };
                match forward_dns(&stack, &query).await {
                    Ok(answer) => {
                        let _ = socket.send_to(&answer, from).await;
                    }
                    Err(err) => {
                        debug!(error = %format!("{err:#}"), "a DNS query through WARP failed")
                    }
                }
            });
        }
    });
}

/// Send one DNS message to [`TUNNEL_RESOLVER`] through the tunnel, with the
/// resends of [`DNS_RESEND`]; the answer with the id of the query.
async fn forward_dns(stack: &WarpStack, query: &[u8]) -> Result<Vec<u8>> {
    forward_dns_to(stack, TUNNEL_RESOLVER, query).await
}

async fn forward_dns_to(stack: &WarpStack, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("not a DNS message");
    }
    let udp = stack.udp_bind().await?;
    let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
    loop {
        udp.send_to(query.to_vec(), server).await?;
        let resend = (tokio::time::Instant::now() + DNS_RESEND).min(deadline);
        loop {
            match tokio::time::timeout_at(resend, udp.recv_from(4096)).await {
                Ok(Ok((answer, from))) if from == server && answer.get(..2) == query.get(..2) => {
                    return Ok(answer)
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => return Err(err),
                Err(_) => break,
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("no DNS answer through WARP");
        }
    }
}

/// Accept proxy clients on `bound` and connect them through the WARP
/// session of `live`. Each client takes the session of the time it comes;
/// after a reconnect (issue 75), new clients take the new session.
pub fn run(live: Arc<super::Live<WarpStack>>, bound: Bound) -> WarpProxy {
    let listen = bound.listen().clone();
    // Issue 146: a listener that other hosts reach, with no credentials.
    if let ProxyListen::Tcp(addr) = &listen {
        if !addr.ip().is_loopback() && !has_credentials() {
            tracing::warn!(%addr, "the WARP proxy listens on an address that other hosts can reach, and takes each client: give --proxy-user and --proxy-password-file");
        }
    }
    let task = match bound {
        Bound::Tcp(listener, _) => tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                client(live.clone(), stream);
            }
        }),
        Bound::Unix(listener, _) => tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                client(live.clone(), stream);
            }
        }),
    };
    info!(?listen, "WARP proxy is listening");
    WarpProxy { listen, task }
}

/// Serve one client of the proxy on its own task.
fn client<S>(live: Arc<super::Live<WarpStack>>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Issue 117: over --max-connections, the client is closed at once.
    let Some(admitted) = admit() else {
        static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
            *last = Some(std::time::Instant::now());
            warn!(
                limit = MAX_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed),
                "WARP proxy: a client is refused, --max-connections is reached"
            );
        }
        return;
    };
    tokio::spawn(async move {
        let _admitted = admitted;
        // The session of now: a new one after a reconnect.
        let stack = match live.get().await {
            Ok(stack) => stack,
            Err(err) => {
                warn!(error = %format!("{err:#}"), "WARP proxy client refused");
                return;
            }
        };
        let udp = Some(stack.clone());
        let dial = move |host, port| dial(stack.clone(), host, port);
        if let Err(err) = handle_client_auth(stream, dial, udp, CREDENTIALS.get()).await {
            debug!(error = %err, "WARP proxy client failed");
        }
    });
}

/// [`bind`] and [`run`] for one listener.
pub async fn serve(live: Arc<super::Live<WarpStack>>, listen: ProxyListen) -> Result<WarpProxy> {
    Ok(run(live, bind(&listen).await?))
}

/// Read one SOCKS5 or HTTP `CONNECT` request, connect with `dial`, answer
/// the client, and copy bytes in the two directions until both ends close.
///
/// With `udp`, a SOCKS5 `UDP ASSOCIATE` request is also served: the datagrams
/// go through UDP sockets of that stack.
pub async fn handle_client<S, D, F>(stream: S, dial: D, udp: Option<Arc<WarpStack>>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: FnOnce(ProxyHost, u16) -> F,
    F: std::future::Future<Output = Result<DuplexStream>>,
{
    handle_client_auth(stream, dial, udp, None).await
}

/// The credentials that each client of the proxies of this process must
/// give (issue 146), when they are set.
static CREDENTIALS: std::sync::OnceLock<crate::proxy_auth::Credentials> =
    std::sync::OnceLock::new();

/// Set the credentials of the clients (issue 146). Call it before the first
/// client.
pub fn set_credentials(credentials: crate::proxy_auth::Credentials) {
    let _ = CREDENTIALS.set(credentials);
}

/// True when the clients must give credentials.
pub fn has_credentials() -> bool {
    CREDENTIALS.get().is_some()
}

/// The longest time for the request of a client (issue 146: a client that
/// sent nothing held its task for ever).
const REQUEST_LIMIT: Duration = Duration::from_secs(30);

/// [`handle_client`] with the credentials that the client must give.
pub async fn handle_client_auth<S, D, F>(
    stream: S,
    dial: D,
    udp: Option<Arc<WarpStack>>,
    auth: Option<&crate::proxy_auth::Credentials>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: FnOnce(ProxyHost, u16) -> F,
    F: std::future::Future<Output = Result<DuplexStream>>,
{
    let mut stream = stream;
    let mut first = [0u8; 1];
    tokio::time::timeout(REQUEST_LIMIT, stream.read_exact(&mut first))
        .await
        .map_err(|_| anyhow::anyhow!("no request in {} s", REQUEST_LIMIT.as_secs()))??;
    let is_socks = socks::looks_like_socks5(first[0]);
    let mut stream = Prefixed::new(first[0], stream);
    if !is_socks && first[0] == 0x16 {
        // A TLS ClientHello: the client takes the proxy for https://.
        bail!("a TLS client on the proxy (use http:// or socks5h:// for the proxy URL)");
    }
    let check = auth.map(|c| move |u: &str, p: &str| c.check(u, p));
    let check_ref: Option<socks::CheckUser<'_>> = check.as_ref().map(|c| c as socks::CheckUser<'_>);
    let request: ProxyRequest = if is_socks {
        let (command, request) = tokio::time::timeout(
            REQUEST_LIMIT,
            socks::socks5_read_command_auth(&mut stream, check_ref),
        )
        .await
        .map_err(|_| anyhow::anyhow!("no SOCKS5 request in {} s", REQUEST_LIMIT.as_secs()))??;
        match command {
            0x01 => request,
            0x03 => match udp {
                Some(stack) => return udp_associate(stream, stack).await,
                None => {
                    socks::socks5_reply(&mut stream, 0x07, None).await?;
                    bail!("UDP ASSOCIATE is not available");
                }
            },
            pod_netns::upstream::CMD_UDP_IN_STREAM => match udp {
                Some(stack) => return udp_in_stream(stream, stack).await,
                None => {
                    socks::socks5_reply(&mut stream, 0x07, None).await?;
                    bail!("UDP in the stream is not available");
                }
            },
            other => {
                socks::socks5_reply(&mut stream, 0x07, None).await?;
                bail!("SOCKS5 command {other} is not supported");
            }
        }
    } else {
        let (request, authorization) =
            tokio::time::timeout(REQUEST_LIMIT, socks::http_read_request_auth(&mut stream))
                .await
                .map_err(|_| {
                    anyhow::anyhow!("no HTTP request in {} s", REQUEST_LIMIT.as_secs())
                })??;
        if let Some(auth) = auth {
            if !auth.check_basic(authorization.as_deref()) {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"cfrs\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                bail!("an HTTP client with no or wrong credentials");
            }
        }
        match request {
            socks::HttpRequest::Connect(request) => request,
            socks::HttpRequest::Forward { request, head } => {
                // An http:// URL (HTTP_PROXY): send the request in origin
                // form to the origin, then copy the two directions.
                debug!(host = %request.host, port = request.port, "WARP proxy forward request");
                let mut upstream = match dial(request.host.clone(), request.port).await {
                    Ok(upstream) => upstream,
                    Err(err) => {
                        let _ = socks::http_connect_reply(&mut stream, 502, "Bad Gateway").await;
                        return Err(err);
                    }
                };
                upstream.write_all(&head).await?;
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                return Ok(());
            }
        }
    };
    debug!(host = %request.host, port = request.port, "WARP proxy request");
    let mut upstream = match dial(request.host.clone(), request.port).await {
        Ok(upstream) => upstream,
        Err(err) => {
            let message = format!("{err:#}");
            if is_socks {
                let _ =
                    socks::socks5_reply(&mut stream, socks::socks5_code_for_error(&message), None)
                        .await;
            } else {
                let _ = socks::http_connect_reply(&mut stream, 502, "Bad Gateway").await;
            }
            return Err(err);
        }
    };
    if is_socks {
        socks::socks5_reply(&mut stream, 0x00, None).await?;
    } else {
        socks::http_connect_ok(&mut stream).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    Ok(())
}

/// Serve one SOCKS5 UDP association (RFC 1928 section 7).
///
/// A local UDP socket on the loopback address receives the datagrams of the
/// client. Each datagram goes through a UDP socket of the stack. Each answer
/// gets a SOCKS5 UDP header and goes back to the client. The association ends
/// when the control connection closes.
async fn udp_associate<S>(mut control: S, stack: Arc<WarpStack>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Issue 114: a failure gets a SOCKS5 reply (general failure), not a
    // closed connection with no reply.
    let sockets = async {
        let local = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .context("a UDP socket on 127.0.0.1 for the relay (a host that refuses it can use the UDP association in the stream, command 0x83)")?;
        let tunnel = stack.udp_bind().await?;
        anyhow::Ok((Arc::new(local), tunnel))
    };
    let (local, tunnel) = match sockets.await {
        Ok(sockets) => sockets,
        Err(err) => {
            let _ = socks::socks5_reply(&mut control, 0x01, None).await;
            return Err(err);
        }
    };
    socks::socks5_reply(&mut control, 0x00, Some(local.local_addr()?)).await?;
    debug!(relay = %local.local_addr()?, "a UDP ASSOCIATE");
    let client: Arc<std::sync::Mutex<Option<SocketAddr>>> = Arc::default();

    let to_tunnel = {
        let local = local.clone();
        let tunnel = tunnel.clone();
        let stack = stack.clone();
        let client = client.clone();
        async move {
            let mut buf = vec![0u8; 65_536];
            let mut names = Names::default();
            loop {
                let Ok((n, from)) = local.recv_from(&mut buf).await else {
                    return;
                };
                *client.lock().unwrap() = Some(from);
                let Some((host, port, payload)) = socks::socks5_udp_unwrap(&buf[..n]) else {
                    continue;
                };
                let Some(ip) = names.address(&stack, host).await else {
                    continue;
                };
                let _ = tunnel
                    .send_to(payload.to_vec(), SocketAddr::new(ip, port))
                    .await;
            }
        }
    };
    let from_tunnel = {
        let local = local.clone();
        async move {
            loop {
                let Ok((data, from)) = tunnel.recv_from(65_536).await else {
                    return;
                };
                let target = *client.lock().unwrap();
                if let Some(target) = target {
                    let framed = pod_netns::upstream::wrap_udp(&data, from.ip(), from.port());
                    let _ = local.send_to(&framed, target).await;
                }
            }
        }
    };
    let control_closed = async move {
        let mut buf = [0u8; 256];
        while let Ok(n) = control.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    };
    tokio::select! {
        _ = to_tunnel => {}
        _ = from_tunnel => {}
        _ = control_closed => {}
    }
    Ok(())
}

/// Serve one UDP association in the stream (issue 84,
/// [`pod_netns::upstream::CMD_UDP_IN_STREAM`]): each datagram in each
/// direction is a frame on the control connection, so no UDP socket of the
/// host is necessary. The association ends when the connection closes.
async fn udp_in_stream<S>(mut control: S, stack: Arc<WarpStack>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use pod_netns::upstream::{read_udp_frame, wrap_udp, write_udp_frame};
    let tunnel = match stack.udp_bind().await {
        Ok(tunnel) => tunnel,
        Err(err) => {
            let _ = socks::socks5_reply(&mut control, 0x01, None).await;
            return Err(err);
        }
    };
    socks::socks5_reply(&mut control, 0x00, None).await?;
    debug!("a UDP association in the stream (no UDP socket of the host)");
    let (mut read, mut write) = tokio::io::split(control);
    let to_tunnel = {
        let tunnel = tunnel.clone();
        let stack = stack.clone();
        async move {
            let mut names = Names::default();
            while let Ok(Some(datagram)) = read_udp_frame(&mut read).await {
                let Some((host, port, payload)) = socks::socks5_udp_unwrap(&datagram) else {
                    continue;
                };
                let Some(ip) = names.address(&stack, host).await else {
                    continue;
                };
                let _ = tunnel
                    .send_to(payload.to_vec(), SocketAddr::new(ip, port))
                    .await;
            }
        }
    };
    let from_tunnel = async move {
        loop {
            let Ok((data, from)) = tunnel.recv_from(65_536).await else {
                return;
            };
            let framed = wrap_udp(&data, from.ip(), from.port());
            if write_udp_frame(&mut write, &framed).await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        _ = to_tunnel => {}
        _ = from_tunnel => {}
    }
    Ok(())
}

/// Connect to `host:port` through the tunnel. Return a local pipe end that
/// carries the connection.
pub async fn dial(stack: Arc<WarpStack>, host: ProxyHost, port: u16) -> Result<DuplexStream> {
    let addresses = match host {
        ProxyHost::Ip(ip) => vec![ip],
        ProxyHost::Domain(name) => resolve_all(&stack, &name).await?,
    };
    // IPv4 first, then IPv6 (issue 81): a name with no A record (an IPv6
    // only host) works through WARP too.
    let mut last = None;
    for ip in order(addresses) {
        match tokio::time::timeout(
            CONNECT_TIMEOUT,
            stack.tcp_connect(SocketAddr::new(ip, port)),
        )
        .await
        {
            Ok(Ok(conn)) => {
                let (local, remote) = tokio::io::duplex(4 * CHUNK);
                tokio::spawn(bridge(conn, remote));
                return Ok(local);
            }
            Ok(Err(err)) => {
                last = Some(err.context(format!("connect to {ip}:{port} through WARP")))
            }
            Err(_) => {
                last = Some(anyhow::anyhow!(
                    "connect to {ip}:{port} through WARP timed out"
                ))
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no address to connect to")))
}

/// The order of the dial: IPv4 addresses, then IPv6, each in the order of
/// the answer, with no copy.
pub fn order(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in addresses
        .iter()
        .filter(|a| a.is_ipv4())
        .chain(addresses.iter().filter(|a| a.is_ipv6()))
    {
        if !out.contains(ip) {
            out.push(*ip);
        }
    }
    out
}

/// The addresses of the names of one UDP association, so that only the
/// first datagram to a name waits for DNS (issue 114).
#[derive(Default)]
struct Names(std::collections::HashMap<String, IpAddr>);

impl Names {
    async fn address(&mut self, stack: &WarpStack, host: ProxyHost) -> Option<IpAddr> {
        match host {
            ProxyHost::Ip(ip) => Some(ip),
            ProxyHost::Domain(name) => {
                if let Some(ip) = self.0.get(&name) {
                    return Some(*ip);
                }
                match resolve(stack, &name).await {
                    Ok(ip) => {
                        if self.0.len() >= 256 {
                            self.0.clear();
                        }
                        self.0.insert(name, ip);
                        Some(ip)
                    }
                    Err(err) => {
                        debug!(%name, error = %err, "UDP name not resolved");
                        None
                    }
                }
            }
        }
    }
}

/// The interval of the resends of a DNS query (issue 114: one lost
/// datagram cost the full time limit).
const DNS_RESEND: Duration = Duration::from_millis(1200);

/// The variable that turns off the check of the data path of a new MASQUE
/// session (issue 120), for a measurement.
pub const NO_CHECK_VARIABLE: &str = "CFRS_WARP_NO_CHECK";

/// The name of the DNS query of the check of the data path.
const CHECK_NAME: &str = "cloudflare.com";

/// Check that a packet crosses a new session (issue 120): a DNS query to
/// the resolver of the tunnel gets an answer. Before, a session was "up"
/// after the HTTP/2 answer 200, and a front door that carried no data gave
/// a proxy that answered nothing. Gives the time of the answer.
pub async fn check_data_path(stack: &WarpStack, ipv4: bool) -> Result<Duration> {
    let server = if ipv4 {
        TUNNEL_RESOLVER
    } else {
        "[2606:4700:4700::1111]:53".parse().expect("an address")
    };
    check_data_path_at(stack, server).await
}

async fn check_data_path_at(stack: &WarpStack, server: SocketAddr) -> Result<Duration> {
    let start = std::time::Instant::now();
    query_at(stack, server, CHECK_NAME, pod_netns::dns::TYPE_A)
        .await
        .map_err(|e| {
            e.context(format!(
                "the MASQUE session is open, and a DNS query to {server} through it got no answer"
            ))
        })?;
    Ok(start.elapsed())
}

async fn query(stack: &WarpStack, name: &str, kind: u16) -> Result<Vec<IpAddr>> {
    query_at(stack, TUNNEL_RESOLVER, name, kind).await
}

/// Ask `server` for the `kind` records of `name`. The query is sent again
/// each [`DNS_RESEND`] until an answer with its id comes, in at most
/// [`DNS_TIMEOUT`].
async fn query_at(
    stack: &WarpStack,
    server: SocketAddr,
    name: &str,
    kind: u16,
) -> Result<Vec<IpAddr>> {
    let udp = stack.udp_bind().await?;
    let id = (std::process::id() as u16) ^ (name.len() as u16).rotate_left(7) ^ kind;
    let query = pod_netns::dns::build_query(id, name, kind)?;
    let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
    loop {
        udp.send_to(query.clone(), server).await?;
        let resend = (tokio::time::Instant::now() + DNS_RESEND).min(deadline);
        loop {
            match tokio::time::timeout_at(resend, udp.recv_from(4096)).await {
                Ok(Ok((answer, from))) => {
                    if from == server && answer.get(..2) == Some(&id.to_be_bytes()[..]) {
                        return pod_netns::dns::parse_answers(&answer);
                    }
                }
                Ok(Err(err)) => return Err(err),
                Err(_) => break,
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("no DNS answer for {name} through WARP");
        }
    }
}

/// The A and the AAAA addresses of `name`, with DNS queries through the
/// tunnel (issue 81).
pub async fn resolve_all(stack: &WarpStack, name: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = name
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return Ok(vec![ip]);
    }
    let (a, aaaa) = tokio::join!(
        query(stack, name, pod_netns::dns::TYPE_A),
        query(stack, name, pod_netns::dns::TYPE_AAAA)
    );
    let mut all: Vec<IpAddr> = a.unwrap_or_default();
    all.extend(aaaa.unwrap_or_default());
    if all.is_empty() {
        bail!("no address for {name} through WARP");
    }
    Ok(order(all))
}

/// The first address of `name` (IPv4 first), with DNS through the tunnel.
/// The AAAA query is sent only when there is no A record (issue 114:
/// before, a lost AAAA answer delayed each name by the time limit).
pub async fn resolve(stack: &WarpStack, name: &str) -> Result<IpAddr> {
    if let Ok(ip) = name
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return Ok(ip);
    }
    let a = query(stack, name, pod_netns::dns::TYPE_A).await;
    if let Some(ip) = a.as_ref().ok().and_then(|a| a.first()) {
        return Ok(*ip);
    }
    let aaaa = query(stack, name, pod_netns::dns::TYPE_AAAA).await;
    match (a, aaaa) {
        (_, Ok(aaaa)) if !aaaa.is_empty() => Ok(aaaa[0]),
        (Err(err), _) | (_, Err(err)) => {
            Err(err.context(format!("no address for {name} through WARP")))
        }
        _ => bail!("no address for {name} through WARP"),
    }
}

/// Copy bytes between a tunnel connection and a local pipe end.
async fn bridge(conn: TcpConn, pipe: DuplexStream) {
    let (mut pipe_read, mut pipe_write) = tokio::io::split(pipe);
    let conn = &conn;
    let outbound = async {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match pipe_read.read(&mut buf).await {
                Ok(0) => {
                    // Issue 125: the end of the data of the client goes to
                    // the peer as a FIN; the answer still comes back.
                    conn.shutdown().await;
                    break;
                }
                Err(_) => break,
                Ok(n) => n,
            };
            let mut sent = 0;
            while sent < n {
                match conn.send(buf[sent..n].to_vec()).await {
                    Ok(0) => tokio::time::sleep(Duration::from_millis(5)).await,
                    Ok(count) => sent += count,
                    Err(_) => return,
                }
            }
        }
    };
    let inbound = async {
        loop {
            match conn.recv(CHUNK).await {
                Ok(data) if data.is_empty() => break,
                Ok(data) => {
                    if pipe_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = pipe_write.shutdown().await;
    };
    tokio::join!(outbound, inbound);
    conn.close().await;
}

/// A stream with one byte put back in front of it.
struct Prefixed<S> {
    first: Option<u8>,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(first: u8, inner: S) -> Self {
        Self {
            first: Some(first),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(byte) = self.first.take() {
            buf.put_slice(&[byte]);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;

    /// Issue 81: IPv4 first, then IPv6, no copy; an IPv6-only answer
    /// stays.
    #[test]
    fn the_dial_order() {
        let a: IpAddr = "1.2.3.4".parse().unwrap();
        let b: IpAddr = "2606:4700::1".parse().unwrap();
        let c: IpAddr = "5.6.7.8".parse().unwrap();
        assert_eq!(order(vec![b, a, c, a]), vec![a, c, b]);
        assert_eq!(order(vec![b]), vec![b]);
    }

    #[test]
    fn the_stack_takes_the_ipv6_address_of_an_ipv4_tunnel() {
        let v6: std::net::Ipv6Addr = "2606:4700:110:8a1::2".parse().unwrap();
        let config =
            super::super::StackConfig::new("172.16.0.2".parse().unwrap()).with_ipv6(Some(v6));
        assert_eq!(config.local_v6, Some(v6));
        let only_v6 = super::super::StackConfig::new(IpAddr::V6(v6)).with_ipv6(Some(v6));
        assert_eq!(
            only_v6.local_v6, None,
            "no second address for an IPv6 tunnel"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stack over a bare device, and a DNS server on the other side of
    /// the link at 198.51.100.7:53 that drops the first `drop_first`
    /// queries and answers 192.0.2.44 to the others.
    fn stack_with_dns(drop_first: usize) -> (Arc<WarpStack>, Arc<std::sync::atomic::AtomicUsize>) {
        use crate::vnet::device::LinkDevice;
        use smoltcp::iface::{Config, Interface, SocketSet};
        use smoltcp::socket::udp;
        use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
        let device = LinkDevice::tunnel_bounded(super::super::ip::TUNNEL_MTU, 64);
        let (to_peer, from_peer) = (device.outbound(), device.inbound());
        let stack = Arc::new(WarpStack::on_device(
            device,
            super::super::ip::StackConfig::new("172.16.0.2".parse().unwrap()),
        ));
        let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (stack2, queries2) = (stack.clone(), queries.clone());
        tokio::spawn(async move {
            let mut dev = LinkDevice::tunnel(super::super::ip::TUNNEL_MTU);
            let start = std::time::Instant::now();
            let now = || smoltcp::time::Instant::from_micros(start.elapsed().as_micros() as i64);
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
            iface.update_ip_addrs(|a| {
                a.push(IpCidr::new(IpAddress::v4(198, 51, 100, 7), 24)).ok();
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(198, 51, 100, 1))
                .ok();
            let mut sockets = SocketSet::new(Vec::new());
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
            );
            socket.bind(53).unwrap();
            let handle = sockets.add(socket);
            loop {
                while let Some(packet) = to_peer.pop() {
                    dev.inbound().push(packet);
                }
                iface.poll(now(), &mut dev, &mut sockets);
                let socket = sockets.get_mut::<udp::Socket>(handle);
                while let Ok((query, meta)) = socket.recv() {
                    let n = queries2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n < drop_first {
                        continue;
                    }
                    let parsed = pod_netns::dns::ParsedQuery::parse(query).unwrap();
                    let answer = pod_netns::dns::build_response(
                        &parsed,
                        &["192.0.2.44".parse().unwrap()],
                        0,
                    );
                    socket.send_slice(&answer, meta.endpoint).unwrap();
                }
                iface.poll(now(), &mut dev, &mut sockets);
                let mut moved = false;
                while let Some(packet) = dev.outbound().pop() {
                    from_peer.push(packet);
                    moved = true;
                }
                if moved {
                    stack2.wake();
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        (stack, queries)
    }

    const PEER_DNS: &str = "198.51.100.7:53";

    // Issue 120: the check of the data path needs an answer through the
    // stack.
    #[tokio::test]
    async fn the_check_of_the_data_path_needs_an_answer() {
        let (stack, _) = stack_with_dns(0);
        assert!(check_data_path_at(&stack, PEER_DNS.parse().unwrap())
            .await
            .is_ok());
        let (silent, _) = stack_with_dns(usize::MAX);
        let err = check_data_path_at(&silent, PEER_DNS.parse().unwrap())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("got no answer"), "{err:#}");
    }

    // Issue 114: a lost DNS datagram is sent again. Before, it cost the
    // full time limit (5 s) and gave no answer.
    #[tokio::test]
    async fn a_lost_dns_query_is_sent_again() {
        let (stack, queries) = stack_with_dns(1);
        let start = std::time::Instant::now();
        let ips = query_at(
            &stack,
            PEER_DNS.parse().unwrap(),
            "example.com",
            pod_netns::dns::TYPE_A,
        )
        .await
        .unwrap();
        assert_eq!(ips, vec!["192.0.2.44".parse::<IpAddr>().unwrap()]);
        assert_eq!(queries.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(start.elapsed() < DNS_TIMEOUT, "{:?}", start.elapsed());
    }

    // Issues 112 and 114: through a UDP ASSOCIATE, a datagram to IPv6 on a
    // tunnel with no IPv6 address does not stop the stack. A datagram to
    // IPv4 after it gets its answer, and a second association works.
    #[tokio::test]
    async fn a_udp_association_survives_a_datagram_to_ipv6() {
        let (stack, _) = stack_with_dns(0);
        for round in 0..2 {
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(udp_associate(server, stack.clone()));
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0, "round {round}: {reply:?}");
            let relay = SocketAddr::new(
                IpAddr::from([reply[4], reply[5], reply[6], reply[7]]),
                u16::from_be_bytes([reply[8], reply[9]]),
            );
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let query = pod_netns::dns::build_query(0x4242, "example.com", 1).unwrap();
            let v6 =
                pod_netns::upstream::wrap_udp(&query, "2606:4700:4700::1111".parse().unwrap(), 53);
            udp.send_to(&v6, relay).await.unwrap();
            let v4 = pod_netns::upstream::wrap_udp(&query, "198.51.100.7".parse().unwrap(), 53);
            udp.send_to(&v4, relay).await.unwrap();
            let mut buf = [0u8; 1024];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
                .await
                .expect("an answer")
                .unwrap();
            assert_eq!(&buf[10..12], &[0x42, 0x42], "round {round}");
            assert!(n > 12);
            assert!(!stack.is_closed());
            drop(client);
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }

    // Issue 117: the DNS forwarder gives the answer of the server through
    // the tunnel, with the id of the query.
    #[tokio::test]
    async fn the_dns_forwarder_gives_the_answer() {
        let (stack, _) = stack_with_dns(1);
        let query = pod_netns::dns::build_query(0x7777, "example.com", 1).unwrap();
        let answer = forward_dns_to(&stack, PEER_DNS.parse().unwrap(), &query)
            .await
            .unwrap();
        assert_eq!(&answer[..2], &[0x77, 0x77]);
        assert_eq!(
            pod_netns::dns::parse_answers(&answer).unwrap(),
            vec!["192.0.2.44".parse::<IpAddr>().unwrap()]
        );
        assert!(forward_dns_to(&stack, PEER_DNS.parse().unwrap(), b"short")
            .await
            .is_err());
    }

    // Issue 117: the limit refuses the client over it, and frees the place
    // of a client that ends.
    #[test]
    fn the_connection_limit() {
        use std::sync::atomic::Ordering::SeqCst;
        set_max_connections(2);
        let a = admit();
        let b = admit();
        assert!(a.is_some() && b.is_some());
        let refused = STATS.refused.load(SeqCst);
        assert!(admit().is_none());
        assert_eq!(STATS.refused.load(SeqCst), refused + 1);
        drop(a);
        assert!(admit().is_some());
        set_max_connections(0);
    }

    // Issue 115: a unix socket that answers is not taken.
    #[tokio::test]
    async fn a_unix_socket_that_answers_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warp.sock");
        let first = tokio::net::UnixListener::bind(&path).unwrap();
        let err = match bind(&ProxyListen::Unix(path.clone())).await {
            Err(err) => err,
            Ok(_) => panic!("a live socket was taken"),
        };
        assert!(format!("{err}").contains("another process"), "{err}");
        let client = tokio::net::UnixStream::connect(&path);
        let (accepted, connected) = tokio::join!(first.accept(), client);
        assert!(accepted.is_ok() && connected.is_ok());
        drop(first);
        assert!(
            bind(&ProxyListen::Unix(path)).await.is_ok(),
            "a dead socket is taken"
        );
    }

    /// Issue 97: each listener is bound on its own. A TCP listener that the
    /// host refuses (here: a port in use, and an address that is not on
    /// this host) does not stop the unix socket, which takes clients.
    #[tokio::test]
    async fn a_refused_tcp_listener_does_not_stop_the_unix_socket() {
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warp.sock");
        let listens = vec![
            ProxyListen::Tcp(taken.local_addr().unwrap()),
            ProxyListen::Tcp("192.0.2.1:40000".parse().unwrap()),
            ProxyListen::Unix(path.clone()),
        ];
        let (bound, failed) = bind_all(&listens).await;
        assert_eq!(bound.len(), 1);
        assert_eq!(failed.len(), 2);
        assert!(format!("{:#}", failed[0].1).contains("binding tcp://"));
        let Some(Bound::Unix(listener, _)) = bound.into_iter().next() else {
            panic!("the unix socket is the listener that works");
        };
        let client = tokio::net::UnixStream::connect(&path);
        let (accepted, connected) = tokio::join!(listener.accept(), client);
        assert!(accepted.is_ok() && connected.is_ok());
        let (bound, failed) = bind_all(&listens[..2]).await;
        assert!(bound.is_empty() && failed.len() == 2);
    }

    /// A dialer that answers with an echo server and records the target.
    fn echo_dial(
        seen: Arc<std::sync::Mutex<Option<String>>>,
    ) -> impl FnOnce(ProxyHost, u16) -> std::future::Ready<Result<DuplexStream>> {
        move |host, port| {
            *seen.lock().unwrap() = Some(format!("{host}:{port}"));
            let (local, mut remote) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while let Ok(n) = remote.read(&mut buf).await {
                    if n == 0 || remote.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            std::future::ready(Ok(local))
        }
    }

    #[tokio::test]
    async fn a_socks5_client_reaches_the_dialed_target() {
        let seen = Arc::new(std::sync::Mutex::new(None));
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(handle_client(server, echo_dial(seen.clone()), None));
        // Greeting, then CONNECT example.com:443 by name.
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut head = [0u8; 10];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(head[1], 0, "SOCKS5 success");
        client.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("example.com:443"));
        drop(client);
        let _ = task.await;
    }

    async fn read_head<R: AsyncRead + Unpin>(r: &mut R) -> String {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if r.read_exact(&mut b).await.is_err() {
                break;
            }
            head.push(b[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    // Issue 146: with credentials, a SOCKS5 client needs the right user and
    // password; a client that offers no acceptable method gets 0xff.
    #[tokio::test]
    async fn a_socks5_client_gives_its_credentials() {
        let creds = crate::proxy_auth::Credentials::new("alice", "pw").unwrap();
        for (user, pass, ok) in [("alice", "pw", true), ("alice", "no", false)] {
            let seen = Arc::new(std::sync::Mutex::new(None));
            let (mut client, server) = tokio::io::duplex(1024);
            let c = creds.clone();
            let task = tokio::spawn(async move {
                handle_client_auth(server, echo_dial(seen), None, Some(&c)).await
            });
            client.write_all(&[5, 2, 0, 2]).await.unwrap();
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 2]);
            let mut auth = vec![1, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            client.write_all(&auth).await.unwrap();
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [1, if ok { 0 } else { 1 }], "{user}:{pass}");
            if ok {
                let mut request = vec![5, 1, 0, 1, 10, 0, 0, 1];
                request.extend_from_slice(&22u16.to_be_bytes());
                client.write_all(&request).await.unwrap();
                let mut head = [0u8; 10];
                client.read_exact(&mut head).await.unwrap();
                assert_eq!(head[1], 0);
            }
            drop(client);
            let result = task.await.unwrap();
            assert_eq!(result.is_ok(), ok, "{result:?}");
        }
        // No credentials offered to a server that needs them: 0xff.
        let (mut client, server) = tokio::io::duplex(1024);
        let c = creds.clone();
        let task = tokio::spawn(async move {
            handle_client_auth(server, echo_dial(Arc::default()), None, Some(&c)).await
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
        assert!(task.await.unwrap().is_err());
        // Only user and password offered to a server with no credentials:
        // 0xff. Before, the server answered 0x00.
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(handle_client(server, echo_dial(Arc::default()), None));
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
        assert!(task.await.unwrap().is_err());
    }

    // Issue 146: an HTTP client with no credentials gets 407; with Basic it
    // gets 200.
    #[tokio::test]
    async fn an_http_client_gives_its_credentials() {
        let creds = crate::proxy_auth::Credentials::new("alice", "pw").unwrap();
        for (header, want) in [
            ("", "407"),
            ("Proxy-Authorization: Basic YWxpY2U6cHc=\r\n", "200"),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            let c = creds.clone();
            let task = tokio::spawn(async move {
                handle_client_auth(server, echo_dial(Arc::default()), None, Some(&c)).await
            });
            let request =
                format!("CONNECT 10.0.0.1:22 HTTP/1.1\r\nHost: 10.0.0.1:22\r\n{header}\r\n");
            client.write_all(request.as_bytes()).await.unwrap();
            let head = read_head(&mut client).await;
            assert!(head.starts_with(&format!("HTTP/1.1 {want}")), "{head}");
            if want == "407" {
                assert!(head.contains("Proxy-Authenticate: Basic"), "{head}");
            }
            drop(client);
            let _ = task.await;
        }
    }

    // Issue 146: a client that sends nothing is closed after the limit.
    #[tokio::test(start_paused = true)]
    async fn a_silent_client_is_closed() {
        let (_client, server) = tokio::io::duplex(1024);
        let err = handle_client(server, echo_dial(Arc::default()), None)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("no request"), "{err}");
    }

    #[tokio::test]
    async fn an_http_connect_client_reaches_the_dialed_target() {
        let seen = Arc::new(std::sync::Mutex::new(None));
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(handle_client(server, echo_dial(seen.clone()), None));
        client
            .write_all(b"CONNECT 10.1.2.3:22 HTTP/1.1\r\nHost: 10.1.2.3:22\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
        client.write_all(b"x").await.unwrap();
        let mut echo = [0u8; 1];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"x");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("10.1.2.3:22"));
        drop(client);
        let _ = task.await;
    }
}
