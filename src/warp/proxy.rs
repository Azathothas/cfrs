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
const CHUNK: usize = 16 * 1024;

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

/// Accept proxy clients on `listen` and connect them through the WARP
/// session of `live`. Each client takes the session of the time it comes;
/// after a reconnect (issue 75), new clients take the new session.
pub async fn serve(live: Arc<super::Live<WarpStack>>, listen: ProxyListen) -> Result<WarpProxy> {
    let task = match &listen {
        ProxyListen::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding tcp://{addr}"))?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let live = live.clone();
                    tokio::spawn(async move {
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
                        if let Err(err) = handle_client(stream, dial, udp).await {
                            debug!(error = %err, "WARP proxy client failed");
                        }
                    });
                }
            })
        }
        ProxyListen::Unix(path) => {
            let _ = std::fs::remove_file(path);
            let listener = pod_netns::listen::bind_private(path)
                .with_context(|| format!("binding unix:{}", path.display()))?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let live = live.clone();
                    tokio::spawn(async move {
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
                        if let Err(err) = handle_client(stream, dial, udp).await {
                            debug!(error = %err, "WARP proxy client failed");
                        }
                    });
                }
            })
        }
    };
    info!(?listen, "WARP proxy is listening");
    Ok(WarpProxy { listen, task })
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
    let mut stream = stream;
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    let is_socks = socks::looks_like_socks5(first[0]);
    let mut stream = Prefixed::new(first[0], stream);
    let request: ProxyRequest = if is_socks {
        let (command, request) = socks::socks5_read_command(&mut stream).await?;
        match command {
            0x01 => request,
            0x03 => match udp {
                Some(stack) => return udp_associate(stream, stack).await,
                None => {
                    socks::socks5_reply(&mut stream, 0x07, None).await?;
                    bail!("UDP ASSOCIATE is not available");
                }
            },
            other => {
                socks::socks5_reply(&mut stream, 0x07, None).await?;
                bail!("SOCKS5 command {other} is not supported");
            }
        }
    } else {
        match socks::http_read_request(&mut stream).await? {
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
    let local = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let tunnel = stack.udp_bind().await?;
    socks::socks5_reply(&mut control, 0x00, Some(local.local_addr()?)).await?;
    let client: Arc<std::sync::Mutex<Option<SocketAddr>>> = Arc::default();

    let to_tunnel = {
        let local = local.clone();
        let tunnel = tunnel.clone();
        let stack = stack.clone();
        let client = client.clone();
        async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, from)) = local.recv_from(&mut buf).await else {
                    return;
                };
                *client.lock().unwrap() = Some(from);
                let Some((host, port, payload)) = socks::socks5_udp_unwrap(&buf[..n]) else {
                    continue;
                };
                let ip = match host {
                    ProxyHost::Ip(ip) => ip,
                    ProxyHost::Domain(name) => match resolve(&stack, &name).await {
                        Ok(ip) => ip,
                        Err(err) => {
                            debug!(%name, error = %err, "UDP name not resolved");
                            continue;
                        }
                    },
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

/// Connect to `host:port` through the tunnel. Return a local pipe end that
/// carries the connection.
pub async fn dial(stack: Arc<WarpStack>, host: ProxyHost, port: u16) -> Result<DuplexStream> {
    let ip = match host {
        ProxyHost::Ip(ip) => ip,
        ProxyHost::Domain(name) => resolve(&stack, &name).await?,
    };
    let conn = tokio::time::timeout(
        CONNECT_TIMEOUT,
        stack.tcp_connect(SocketAddr::new(ip, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect to {ip}:{port} through WARP timed out"))??;
    let (local, remote) = tokio::io::duplex(4 * CHUNK);
    tokio::spawn(bridge(conn, remote));
    Ok(local)
}

/// Resolve `name` to an IPv4 address with a DNS query through the tunnel.
pub async fn resolve(stack: &WarpStack, name: &str) -> Result<IpAddr> {
    if let Ok(ip) = name
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return Ok(ip);
    }
    let udp = stack.udp_bind().await?;
    let id = (std::process::id() as u16) ^ (name.len() as u16).rotate_left(7);
    let query = pod_netns::dns::build_query(id, name, pod_netns::dns::TYPE_A)?;
    udp.send_to(query, TUNNEL_RESOLVER).await?;
    let (answer, _) = tokio::time::timeout(DNS_TIMEOUT, udp.recv_from(4096))
        .await
        .map_err(|_| anyhow::anyhow!("no DNS answer for {name} through WARP"))??;
    let addresses = pod_netns::dns::parse_answers(&answer)?;
    match addresses.into_iter().find(IpAddr::is_ipv4) {
        Some(ip) => Ok(ip),
        None => bail!("no IPv4 address for {name}"),
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
                Ok(0) | Err(_) => break,
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
mod tests {
    use super::*;

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
