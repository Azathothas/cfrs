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
    let mut last = None;
    for edge in edges.iter().take(5) {
        let addr = SocketAddr::new(edge.ip, edge.port);
        match connect_one(
            addr,
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

async fn connect_one(
    addr: SocketAddr,
    auth: &rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &rpc::ConnectionOptions,
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
) -> Result<H2Leg> {
    let io = dial(addr).await?;
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

    let mut conn = h2::server::Builder::new()
        .max_concurrent_streams(u32::MAX)
        .initial_window_size(1 << 20)
        .initial_connection_window_size(1 << 24)
        .handshake::<_, Bytes>(tls)
        .await
        .with_context(|| format!("HTTP/2 handshake with the edge at {addr}"))?;

    // The connection makes progress only while `accept` is polled, so one
    // task accepts all streams. It gives the control stream to this task.
    let (control_tx, control_rx) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(async move {
        let mut control_tx = Some(control_tx);
        while let Some(next) = conn.accept().await {
            let (request, respond) = match next {
                Ok(stream) => stream,
                Err(err) => {
                    debug!(error = %err, "the HTTP/2 edge connection ended");
                    break;
                }
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
        }
    });

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
    })
}

/// Open TCP to the edge, directly or through the `HTTPS_PROXY` proxy.
async fn dial(addr: SocketAddr) -> Result<crate::net::BoxedIo> {
    if let Some(proxy) = crate::egress::Proxy::from_env() {
        return proxy
            .connect(&addr.ip().to_string(), addr.port(), DIAL_TIMEOUT)
            .await
            .with_context(|| format!("TCP to the edge at {addr} through the proxy"));
    }
    let tcp = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP to the edge at {addr} timed out"))?
        .with_context(|| format!("TCP to the edge at {addr}"))?;
    let _ = tcp.set_nodelay(true);
    Ok(Box::new(tcp))
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
            if writer.write_all(&data).await.is_err() {
                break;
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
            let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .context("the edge closed the stream")??;
            let take = granted.min(n - offset);
            if take == 0 {
                continue;
            }
            send.send_data(Bytes::copy_from_slice(&buf[offset..offset + take]), false)?;
            offset += take;
        }
    }
}

/// Keep one HTTP/2 leg registered: serve until the connection ends, then
/// connect again with back-off, until `shutdown` changes.
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
) {
    let mut attempt = 0u32;
    loop {
        if let Some(current) = leg.take() {
            attempt = 0;
            let H2Leg {
                control, mut serve, ..
            } = current;
            tokio::select! {
                _ = shutdown.changed() => {
                    control.shutdown_graceful(grace).await;
                    serve.abort();
                    return;
                }
                _ = &mut serve => {
                    warn!(conn_index, "the edge closed the HTTP/2 connection");
                    drop(control);
                }
            }
        }
        if *shutdown.borrow() {
            return;
        }
        attempt += 1;
        if attempt > policy.max_attempts {
            warn!(
                conn_index,
                "giving up after {} reconnect attempts", policy.max_attempts
            );
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(policy.backoff(attempt)) => {}
        }
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
                warn!(conn_index, attempt, error = %err, "HTTP/2 reconnect failed");
                metrics.error();
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
