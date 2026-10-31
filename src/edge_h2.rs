//! The HTTP/2 edge transport.
//!
//! This is the TCP transport of cloudflared (`--protocol http2`). Use it where
//! UDP is blocked and the QUIC transport cannot work.
//!
//! * cfrs opens TCP to the edge (port 7844) and starts TLS with the SNI
//!   `h2.cftunnel.com` and no ALPN.
//! * On that connection the edge is the HTTP/2 client and cfrs is the HTTP/2
//!   server. The edge opens one stream for each request.
//! * The first stream has the header
//!   `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream`. Its request
//!   body and its response body carry the capnp RPC that registers the
//!   connection.
//! * A visitor request has the visitor headers as plain HTTP/2 headers. The
//!   response headers go serialized in `Cf-Cloudflared-Response-Headers`,
//!   because HTTP/2 header rules do not apply to HTTP/1 header values.
//!
//! Each visitor stream is changed into the `ConnectRequest` form of the QUIC
//! transport and given to [`crate::proxy::serve_decoded`]. Thus both
//! transports use one service layer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::cloudflare::rpc;
use crate::cloudflare::stream::{
    ConnectRequest, ConnectionType, HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY,
    HTTP_STATUS_KEY,
};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::cloudflare::http2::{
    build_origin_response, canonical_header_name, edge_tls, is_control_header, is_hop_by_hop,
    CONTROL_STREAM_HEADER, CONTROL_STREAM_VALUE, PROXY_SRC_HEADER,
};
use crate::cloudflare::{EdgeAddr, H2_SNI};
use crate::ingress::Ingress;
use crate::service::ServiceRuntime;

/// The longest time for TCP and TLS to the edge.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest time for the edge to open the control stream and for the
/// registration to complete.
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);
/// The time between two HTTP/2 PINGs to the edge.
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
/// The longest wait for the answer of a PING. No answer is a lost
/// connection: a NAT or a proxy can drop it without a close.
pub const PING_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest time that a write to the edge or to an origin may make no
/// progress. Then the stream fails, and its task and buffers are freed.
pub const WRITE_STALL: Duration = Duration::from_secs(60);
/// The longest time that a closing connection may keep its open streams.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(90);
/// The size of the pipe buffers between HTTP/2 and the service layer.
const PIPE_BUFFER: usize = 64 * 1024;
/// The header value that marks a WebSocket stream.
const WEBSOCKET_VALUE: &str = "websocket";
/// The header value that marks a configuration push.
const CONFIGURATION_VALUE: &str = "update-configuration";
/// The meta header for a response that cfrs makes itself.
const META_CLOUDFLARED: &str = r#"{"src":"cloudflared"}"#;

/// What the edge opened a stream for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamType {
    /// The registration RPC.
    Control,
    /// A configuration push.
    Configuration,
    /// A WebSocket upgrade from a visitor.
    Websocket,
    /// A raw TCP stream (private network routing).
    Tcp,
    /// A plain HTTP request from a visitor.
    Http,
}

/// Classify a stream from its request headers, in the order cloudflared uses
/// (`connection/http2.go`, `determineHTTP2Type`).
pub fn stream_type(headers: &http::HeaderMap) -> StreamType {
    let upgrade = headers
        .get(CONTROL_STREAM_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if upgrade == CONFIGURATION_VALUE {
        return StreamType::Configuration;
    }
    if upgrade == WEBSOCKET_VALUE {
        return StreamType::Websocket;
    }
    if headers
        .get(PROXY_SRC_HEADER)
        .is_some_and(|v| !v.as_bytes().is_empty())
    {
        return StreamType::Tcp;
    }
    if upgrade == CONTROL_STREAM_VALUE {
        return StreamType::Control;
    }
    StreamType::Http
}

/// Make the `ConnectRequest` of the QUIC transport from an HTTP/2 request.
pub fn connect_request(parts: &http::request::Parts, kind: StreamType) -> ConnectRequest {
    let authority = parts
        .uri
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if kind == StreamType::Tcp {
        return ConnectRequest {
            dest: authority,
            conn_type: ConnectionType::Tcp,
            metadata: Vec::new(),
        };
    }
    let scheme = parts.uri.scheme_str().unwrap_or("http");
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let mut metadata = vec![
        (HTTP_METHOD_KEY.to_string(), parts.method.to_string()),
        (HTTP_HOST_KEY.to_string(), authority.clone()),
    ];
    for (name, value) in &parts.headers {
        let name = name.as_str();
        if is_control_header(name) || is_hop_by_hop(name) || name == "host" {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        metadata.push((
            format!("{HTTP_HEADER_KEY}:{}", canonical_header_name(name)),
            value.to_string(),
        ));
    }
    let conn_type = if kind == StreamType::Websocket {
        // HTTP/2 has no hop-by-hop upgrade headers. The origin needs them.
        metadata.push((format!("{HTTP_HEADER_KEY}:Connection"), "Upgrade".into()));
        metadata.push((format!("{HTTP_HEADER_KEY}:Upgrade"), "websocket".into()));
        ConnectionType::Websocket
    } else {
        ConnectionType::Http
    };
    ConnectRequest {
        dest: format!("{scheme}://{authority}{path}"),
        conn_type,
        metadata,
    }
}

/// Change the `ConnectResponse` metadata of the service layer into an
/// HTTP/2 response status and headers for the edge.
pub fn edge_response(error: &str, metadata: &[(String, String)]) -> (u16, Vec<(String, String)>) {
    if !error.is_empty() {
        return (
            502,
            vec![(
                crate::cloudflare::http2::RESPONSE_META_HEADER.to_string(),
                META_CLOUDFLARED.to_string(),
            )],
        );
    }
    let prefix = format!("{HTTP_HEADER_KEY}:");
    let mut status = 200u16;
    let mut headers = Vec::new();
    for (key, value) in metadata {
        if key == HTTP_STATUS_KEY {
            status = value.parse().unwrap_or(502);
        } else if let Some(name) = key.strip_prefix(&prefix) {
            headers.push((name.to_string(), value.clone()));
        }
    }
    build_origin_response(status, &headers)
}

/// One registered HTTP/2 connection to the edge.
pub struct H2Leg {
    /// The edge location that accepted the registration.
    pub location: String,
    /// The RPC session. Drop it, or shut it down, to unregister.
    pub control: rpc::ControlSession,
    /// The task that accepts streams. It ends when the connection ends.
    pub serve: JoinHandle<()>,
    /// Ready when the connection takes no new stream: the edge sent GOAWAY
    /// or closed it, or a PING got no answer. The open streams go on in
    /// `serve` until they end.
    pub draining: tokio::sync::oneshot::Receiver<String>,
    /// When the leg registered.
    pub started: std::time::Instant,
}

/// The keepalive of a connection.
#[derive(Clone, Copy, Debug)]
pub struct Keepalive {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self {
            interval: PING_INTERVAL,
            timeout: PING_TIMEOUT,
        }
    }
}

/// The edge streams of one HTTP/2 connection.
pub struct Served {
    /// The control stream, when the edge opens it.
    pub control: tokio::sync::oneshot::Receiver<(
        http::Request<h2::RecvStream>,
        h2::server::SendResponse<Bytes>,
    )>,
    pub serve: JoinHandle<()>,
    pub draining: tokio::sync::oneshot::Receiver<String>,
}

/// Serve the HTTP/2 connection `io` of the edge (cfrs is the HTTP/2 server).
/// One task accepts the streams, gives the control stream to the caller,
/// and sends a PING each `keepalive.interval`.
pub async fn serve_connection<T>(
    io: T,
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
    keepalive: Keepalive,
) -> Result<Served>
where
    T: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2::server::Builder::new()
        .max_concurrent_streams(u32::MAX)
        .initial_window_size(1 << 20)
        .initial_connection_window_size(1 << 24)
        .handshake::<_, Bytes>(io)
        .await
        .context("HTTP/2 handshake with the edge")?;
    let ping = conn.ping_pong();
    let (control_tx, control_rx) = tokio::sync::oneshot::channel();
    let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<String>();
    let (lost_tx, mut lost_rx) = tokio::sync::oneshot::channel::<String>();
    if let Some(mut ping) = ping {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(keepalive.interval).await;
                match tokio::time::timeout(keepalive.timeout, ping.ping(h2::Ping::opaque())).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => {
                        let _ = lost_tx.send(format!("the PING failed: {err}"));
                        return;
                    }
                    Err(_) => {
                        let _ = lost_tx.send(format!(
                            "the edge did not answer a PING in {} s",
                            keepalive.timeout.as_secs()
                        ));
                        return;
                    }
                }
            }
        });
    }
    let serve = tokio::spawn(async move {
        let mut control_tx = Some(control_tx);
        let reason = loop {
            let next = tokio::select! {
                next = conn.accept() => next,
                lost = &mut lost_rx => {
                    // A lost connection has no streams to finish.
                    let reason = lost.unwrap_or_else(|_| "the keepalive ended".into());
                    let _ = drain_tx.send(reason);
                    return;
                }
            };
            let (request, respond) = match next {
                Some(Ok(stream)) => stream,
                Some(Err(err)) => break format!("the HTTP/2 connection failed: {err}"),
                None => break "the edge ended the HTTP/2 connection (GOAWAY)".to_string(),
            };
            let kind = stream_type(request.headers());
            if kind == StreamType::Control {
                match control_tx.take() {
                    Some(tx) => {
                        let _ = tx.send((request, respond));
                    }
                    None => warn!("the edge opened a second control stream"),
                }
                continue;
            }
            let runtime = runtime.clone();
            let ingress = ingress.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_stream(kind, request, respond, runtime, ingress).await {
                    debug!(error = %err, "HTTP/2 stream failed");
                }
            });
        };
        debug!(%reason, "the HTTP/2 edge connection takes no new stream");
        let _ = drain_tx.send(reason);
        // The open streams go on while the connection is polled.
        let closed = std::future::poll_fn(|cx| conn.poll_closed(cx));
        let _ = tokio::time::timeout(DRAIN_LIMIT, closed).await;
    });
    Ok(Served {
        control: control_rx,
        serve,
        draining: drain_rx,
    })
}

/// Dial the first edge address that answers, register, and serve streams.
pub async fn connect(
    edges: &[EdgeAddr],
    auth: &rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &rpc::ConnectionOptions,
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
) -> Result<H2Leg> {
    if edges.is_empty() {
        bail!("no edge addresses to dial");
    }
    let mut remaining: Vec<SocketAddr> = edges
        .iter()
        .take(5)
        .map(|e| SocketAddr::new(e.ip, e.port))
        .collect();
    let mut last = None;
    while !remaining.is_empty() {
        let (addr, io) = match dial(&remaining).await {
            Ok((i, io)) => (remaining.remove(i), io),
            Err(err) => {
                last = Some(err);
                break;
            }
        };
        match connect_one(
            addr,
            io,
            auth,
            tunnel_id,
            conn_index,
            options,
            runtime.clone(),
            ingress.clone(),
        )
        .await
        {
            Ok(leg) => return Ok(leg),
            Err(err) => {
                debug!(%addr, error = %err, "HTTP/2 edge attempt failed");
                last = Some(err);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no edge answered")))
}

#[allow(clippy::too_many_arguments)]
async fn connect_one(
    addr: SocketAddr,
    io: crate::net::BoxedIo,
    auth: &rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &rpc::ConnectionOptions,
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
) -> Result<H2Leg> {
    let config = edge_tls().map_err(|e| anyhow::anyhow!(e))?;
    let name = rustls_pki_types::ServerName::try_from(H2_SNI.to_string())
        .context("the HTTP/2 SNI is not a valid name")?;
    let tls = tokio::time::timeout(
        DIAL_TIMEOUT,
        tokio_rustls::TlsConnector::from(config).connect(name, io),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS with the edge at {addr} timed out"))?
    .with_context(|| format!("TLS with the edge at {addr}"))?;

    let Served {
        control: control_rx,
        serve,
        draining,
    } = serve_connection(tls, runtime, ingress, Keepalive::default())
        .await
        .with_context(|| format!("the edge at {addr}"))?;

    let (request, mut respond) = tokio::time::timeout(REGISTER_TIMEOUT, control_rx)
        .await
        .map_err(|_| anyhow::anyhow!("the edge at {addr} did not open the control stream"))?
        .map_err(|_| anyhow::anyhow!("the edge at {addr} closed before the control stream"))?;
    let send = respond
        .send_response(http::Response::new(()), false)
        .context("answering the control stream")?;
    let reader = body_reader(request.into_body());
    let writer = body_writer(send);
    let (details, control) = tokio::time::timeout(
        REGISTER_TIMEOUT,
        rpc::register_connection_on(reader, writer, auth, tunnel_id, conn_index, options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("register_connection over HTTP/2 timed out"))??;
    info!(conn_index, location = %details.location, "registered over HTTP/2");
    Ok(H2Leg {
        location: details.location,
        control,
        serve,
        draining,
        started: std::time::Instant::now(),
    })
}

/// Open TCP to one of `addrs`: through the proxy of `crate::egress`, one
/// address at a time, or directly, with the attempt delay between the
/// addresses. Gives the index of the address.
async fn dial(addrs: &[SocketAddr]) -> Result<(usize, crate::net::BoxedIo)> {
    let first = addrs[0];
    if let Some(proxy) = crate::egress::proxy_for(&first.ip().to_string(), first.port()) {
        let mut last = None;
        for (i, addr) in addrs.iter().enumerate() {
            match proxy
                .connect(&addr.ip().to_string(), addr.port(), DIAL_TIMEOUT)
                .await
            {
                Ok(io) => return Ok((i, io)),
                Err(err) => last = Some(err.context(format!("TCP to the edge at {addr}"))),
            }
        }
        return Err(last.expect("addrs is not empty"));
    }
    let (i, tcp) = crate::egress::dial_addrs(addrs, DIAL_TIMEOUT)
        .await
        .context("TCP to the edge")?;
    Ok((i, Box::new(tcp)))
}

/// Serve one stream that is not the control stream.
async fn serve_stream(
    kind: StreamType,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
) -> Result<()> {
    let (parts, body) = request.into_parts();
    if kind == StreamType::Configuration {
        return answer_configuration(body, respond).await;
    }
    let connect = connect_request(&parts, kind);
    debug!(dest = %connect.dest, ?kind, "HTTP/2 stream");

    // The service layer reads the request body and writes the framed
    // response into pipes. Two tasks move the bytes to and from HTTP/2.
    let reader = body_reader(body);
    let (to_edge, from_service) = tokio::io::duplex(PIPE_BUFFER);
    let service = tokio::spawn(crate::proxy::serve_decoded(
        runtime,
        ingress,
        connect,
        Box::pin(reader.compat()),
        Box::pin(to_edge.compat_write()),
    ));

    let mut from_service = from_service.compat();
    let (error, metadata) =
        match crate::cloudflare::stream::read_connect_response(&mut from_service).await {
            Ok(response) => response,
            Err(err) => (err.to_string(), Vec::new()),
        };
    let (status, headers) = edge_response(&error, &metadata);
    let mut response = http::Response::builder().status(status);
    for (name, value) in &headers {
        response = response.header(name.as_str(), value.as_str());
    }
    let response = response.body(()).context("building the edge response")?;
    let send = respond
        .send_response(response, false)
        .context("sending the response head")?;
    pump_to_h2(from_service.into_inner(), send).await?;
    let _ = service.await;
    Ok(())
}

/// Answer a configuration push with the version it carries.
async fn answer_configuration(
    body: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
) -> Result<()> {
    let mut reader = body_reader(body);
    let mut text = Vec::new();
    reader.read_to_end(&mut text).await?;
    let version = serde_json::from_slice::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("version").and_then(serde_json::Value::as_i64))
        .unwrap_or(-1);
    let reply = format!(r#"{{"lastAppliedVersion":{version},"err":null}}"#);
    let mut send = respond.send_response(http::Response::new(()), false)?;
    send.send_data(Bytes::from(reply), true)?;
    Ok(())
}

/// A tokio reader for an HTTP/2 request body. A task moves the data frames
/// into a pipe and gives the flow-control capacity back to the edge.
pub fn body_reader(mut body: h2::RecvStream) -> tokio::io::DuplexStream {
    let (mut writer, reader) = tokio::io::duplex(PIPE_BUFFER);
    tokio::spawn(async move {
        while let Some(frame) = body.data().await {
            let Ok(data) = frame else {
                break;
            };
            let len = data.len();
            match tokio::time::timeout(WRITE_STALL, writer.write_all(&data)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break,
                Err(_) => {
                    debug!(
                        "the origin read nothing for {} s; the stream fails",
                        WRITE_STALL.as_secs()
                    );
                    break;
                }
            }
            let _ = body.flow_control().release_capacity(len);
        }
        let _ = writer.shutdown().await;
    });
    reader
}

/// A tokio writer for an HTTP/2 response body. A task moves the bytes from a
/// pipe into data frames, in the limits of the flow-control window.
pub fn body_writer(send: h2::SendStream<Bytes>) -> tokio::io::DuplexStream {
    let (writer, reader) = tokio::io::duplex(PIPE_BUFFER);
    tokio::spawn(async move {
        if let Err(err) = pump_to_h2(reader, send).await {
            debug!(error = %err, "HTTP/2 response body ended");
        }
    });
    writer
}

/// Copy `source` to the HTTP/2 stream until end of file, then end the stream.
async fn pump_to_h2<R>(mut source: R, mut send: h2::SendStream<Bytes>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            send.send_data(Bytes::new(), true)?;
            return Ok(());
        }
        let mut offset = 0;
        while offset < n {
            send.reserve_capacity(n - offset);
            let granted = match tokio::time::timeout(
                WRITE_STALL,
                std::future::poll_fn(|cx| send.poll_capacity(cx)),
            )
            .await
            {
                Ok(granted) => granted.context("the edge closed the stream")??,
                Err(_) => {
                    send.send_reset(h2::Reason::CANCEL);
                    bail!("the edge read nothing for {} s", WRITE_STALL.as_secs());
                }
            };
            let take = granted.min(n - offset);
            if take == 0 {
                continue;
            }
            send.send_data(Bytes::copy_from_slice(&buf[offset..offset + take]), false)?;
            offset += take;
        }
    }
}

/// Keep one HTTP/2 leg registered: serve until the connection takes no new
/// stream, then connect a replacement at once (the old connection finishes
/// its open streams), and after a failure try again as `policy` says. Gives
/// the reason when the leg stops for a cause other than `shutdown`.
#[allow(clippy::too_many_arguments)]
pub async fn reactor(
    mut leg: Option<H2Leg>,
    edges: Arc<Vec<EdgeAddr>>,
    auth: rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
    metrics: crate::metrics::Metrics,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    policy: crate::config::ReconnectPolicy,
    grace: Duration,
) -> Option<String> {
    use crate::config::Next;
    let mut attempt = 0u32;
    let mut delay = Duration::ZERO;
    loop {
        if let Some(current) = leg.take() {
            let H2Leg {
                control,
                serve,
                mut draining,
                started,
                ..
            } = current;
            tokio::select! {
                _ = shutdown.changed() => {
                    control.shutdown_graceful(grace).await;
                    serve.abort();
                    return None;
                }
                reason = &mut draining => {
                    let reason = reason.unwrap_or_else(|_| "the connection task ended".into());
                    warn!(conn_index, %reason, "the HTTP/2 edge connection ends; connecting a replacement now");
                    drop(control);
                    // The old connection finishes its open streams on its own.
                    drop(serve);
                }
            }
            if started.elapsed() >= policy.stable {
                attempt = 0;
            }
            delay = Duration::ZERO;
        }
        if *shutdown.borrow() {
            return None;
        }
        if !delay.is_zero() {
            tokio::select! {
                _ = shutdown.changed() => return None,
                _ = tokio::time::sleep(delay) => {}
            }
        }
        attempt += 1;
        let mut options =
            rpc::ConnectionOptions::default_for_quick_tunnel(crate::tunnel::CLIENT_VERSION);
        options.replace_existing = true;
        match connect(
            &edges,
            &auth,
            tunnel_id,
            conn_index,
            &options,
            runtime.clone(),
            ingress.clone(),
        )
        .await
        {
            Ok(next) => {
                info!(conn_index, attempt, location = %next.location, "reconnected over HTTP/2");
                metrics.reconnect();
                metrics.connection_opened();
                leg = Some(next);
            }
            Err(err) => {
                metrics.error();
                match policy.next(attempt, &err) {
                    Next::Retry(wait) => {
                        warn!(conn_index, attempt, error = %format!("{err:#}"), retry_in = ?wait, "HTTP/2 reconnect failed");
                        delay = wait;
                    }
                    Next::Stop(reason) => {
                        tracing::error!(conn_index, %reason, "the HTTP/2 leg stops");
                        return Some(reason);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(headers: &[(&str, &str)]) -> http::request::Parts {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri("https://app.example.com/api/x?y=1");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn classifies_streams_in_cloudflared_order() {
        let p = parts(&[(CONTROL_STREAM_HEADER, CONTROL_STREAM_VALUE)]);
        assert_eq!(stream_type(&p.headers), StreamType::Control);
        let p = parts(&[(CONTROL_STREAM_HEADER, "update-configuration")]);
        assert_eq!(stream_type(&p.headers), StreamType::Configuration);
        let p = parts(&[(CONTROL_STREAM_HEADER, "websocket")]);
        assert_eq!(stream_type(&p.headers), StreamType::Websocket);
        let p = parts(&[(PROXY_SRC_HEADER, "10.0.0.1:22")]);
        assert_eq!(stream_type(&p.headers), StreamType::Tcp);
        let p = parts(&[("accept", "*/*")]);
        assert_eq!(stream_type(&p.headers), StreamType::Http);
    }

    #[test]
    fn builds_a_connect_request_like_the_quic_transport() {
        let p = parts(&[
            ("content-type", "application/json"),
            ("cf-ray", "abc"),
            ("cf-cloudflared-proxy-connection-upgrade", ""),
        ]);
        let request = connect_request(&p, StreamType::Http);
        assert_eq!(request.dest, "https://app.example.com/api/x?y=1");
        assert_eq!(request.conn_type, ConnectionType::Http);
        assert_eq!(request.meta(HTTP_METHOD_KEY), Some("POST"));
        assert_eq!(request.meta(HTTP_HOST_KEY), Some("app.example.com"));
        assert_eq!(
            request.meta("HttpHeader:Content-Type"),
            Some("application/json")
        );
        // cf-ray is a visitor header that the origin sees in cloudflared too.
        assert_eq!(request.meta("HttpHeader:Cf-Ray"), Some("abc"));
        assert!(request
            .metadata
            .iter()
            .all(|(k, _)| !k.to_ascii_lowercase().contains("cloudflared")));
    }

    #[test]
    fn a_websocket_request_gets_the_upgrade_headers() {
        let p = parts(&[
            (CONTROL_STREAM_HEADER, "websocket"),
            ("sec-websocket-key", "k"),
        ]);
        let request = connect_request(&p, StreamType::Websocket);
        assert_eq!(request.conn_type, ConnectionType::Websocket);
        assert_eq!(request.meta("HttpHeader:Upgrade"), Some("websocket"));
        assert_eq!(request.meta("HttpHeader:Connection"), Some("Upgrade"));
        assert_eq!(request.meta("HttpHeader:Sec-Websocket-Key"), Some("k"));
    }

    #[test]
    fn a_tcp_request_names_the_destination() {
        let p = parts(&[(PROXY_SRC_HEADER, "10.0.0.1:22")]);
        let request = connect_request(&p, StreamType::Tcp);
        assert_eq!(request.conn_type, ConnectionType::Tcp);
        assert_eq!(request.dest, "app.example.com");
    }

    #[test]
    fn serializes_response_headers_for_the_edge() {
        let meta = vec![
            (HTTP_STATUS_KEY.to_string(), "201".to_string()),
            ("HttpHeader:Content-Length".to_string(), "5".to_string()),
            ("HttpHeader:X-Thing".to_string(), "v".to_string()),
        ];
        let (status, headers) = edge_response("", &meta);
        assert_eq!(status, 201);
        assert!(headers
            .iter()
            .any(|(k, v)| k == "content-length" && v == "5"));
        let blob = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cf-cloudflared-response-headers"))
            .map(|(_, v)| v.clone())
            .unwrap();
        let decoded = crate::cloudflare::http2::decode_headers(&blob);
        assert!(decoded.contains(&("X-Thing".to_string(), "v".to_string())));
        let (status, _) = edge_response("origin down", &[]);
        assert_eq!(status, 502);
    }

    fn service() -> (Arc<ServiceRuntime>, Arc<Ingress>) {
        let ingress = Arc::new(Ingress::new().catch_all(crate::ingress::Service::HelloWorld));
        let runtime =
            Arc::new(ServiceRuntime::build(&ingress, crate::metrics::Metrics::new()).unwrap());
        (runtime, ingress)
    }

    /// An edge that stops answering (its HTTP/2 connection is not polled
    /// any more) is found by the PING, not by the OS.
    #[tokio::test]
    async fn a_ping_with_no_answer_ends_the_connection() {
        let (runtime, ingress) = service();
        let (edge_side, cfrs_side) = tokio::io::duplex(1 << 16);
        let keepalive = Keepalive {
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(200),
        };
        let client = tokio::spawn(h2::client::handshake(edge_side));
        let served = serve_connection(cfrs_side, runtime, ingress, keepalive)
            .await
            .unwrap();
        // The edge side keeps its connection but never polls it again.
        let _edge = client.await.unwrap().unwrap();
        let reason = tokio::time::timeout(Duration::from_secs(5), served.draining)
            .await
            .expect("the lost connection is found")
            .unwrap();
        assert!(reason.contains("did not answer a PING"), "{reason}");
    }

    /// When the edge ends the connection, the draining signal comes, and a
    /// stream that is open goes on to its end.
    #[tokio::test]
    async fn goaway_drains_and_open_streams_finish() {
        let (runtime, ingress) = service();
        let (edge_side, cfrs_side) = tokio::io::duplex(1 << 16);
        let client = tokio::spawn(h2::client::handshake(edge_side));
        let served = serve_connection(cfrs_side, runtime, ingress, Keepalive::default())
            .await
            .unwrap();
        let (mut send, connection) = client.await.unwrap().unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::builder()
            .method("GET")
            .uri("https://x.trycloudflare.com/")
            .body(())
            .unwrap();
        let (response, _) = send.send_request(request, true).unwrap();
        // No more requests from this edge connection: it sends GOAWAY when
        // its streams end.
        drop(send);
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut text = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            text.extend_from_slice(&chunk);
        }
        assert_eq!(text, b"Hello, world! (cfrs)\n");
        drop(body);
        let reason = tokio::time::timeout(Duration::from_secs(5), served.draining)
            .await
            .expect("the drain signal")
            .unwrap();
        assert!(
            reason.contains("GOAWAY") || reason.contains("failed"),
            "{reason}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(5), served.serve).await;
        driver.abort();
    }

    /// Run a real HTTP/2 connection in memory: the test is the edge (the
    /// HTTP/2 client), the code under test is the server. A visitor request
    /// goes through the hello_world service and comes back with serialized
    /// headers.
    #[tokio::test]
    async fn serves_a_visitor_request_over_http2() {
        let ingress = Arc::new(Ingress::new().catch_all(crate::ingress::Service::HelloWorld));
        let runtime =
            Arc::new(ServiceRuntime::build(&ingress, crate::metrics::Metrics::new()).unwrap());
        let (edge_side, cfrs_side) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(cfrs_side).await.unwrap();
            while let Some(Ok((request, respond))) = conn.accept().await {
                let kind = stream_type(request.headers());
                let runtime = runtime.clone();
                let ingress = ingress.clone();
                tokio::spawn(async move {
                    serve_stream(kind, request, respond, runtime, ingress)
                        .await
                        .unwrap();
                });
            }
        });
        let (mut client, connection) = h2::client::handshake(edge_side).await.unwrap();
        tokio::spawn(connection);
        let request = http::Request::builder()
            .method("GET")
            .uri("https://x.trycloudflare.com/")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response
            .headers()
            .contains_key("cf-cloudflared-response-headers"));
        let mut body = response.into_body();
        let mut text = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            text.extend_from_slice(&chunk);
        }
        assert_eq!(text, b"Hello, world! (cfrs)\n");
        drop(client);
        server.abort();
    }
}
