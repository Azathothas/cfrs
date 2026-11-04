//! Inbound tunnel streams: parse the edge framing and dispatch to a service.
//!
//! One QUIC stream carries one request. After the `ConnectRequest` preamble the
//! stream is either HTTP (we synthesise an HTTP/1.1 request for the origin and
//! relay the response) or raw TCP (byte pump). Built-in services are axum
//! routers called directly, so multipart, directory serving and file transfer
//! work without an external process.

use crate::cloudflare::http2::{connection_named, is_hop_by_hop};
use crate::cloudflare::stream as cqstream;
use crate::cloudflare::stream::{HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY};
use anyhow::{anyhow, bail, Context, Result};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tower::ServiceExt;

use crate::gate::UNLOCK_PATH;
use crate::ingress::{Ingress, OriginOptions, Service};
use crate::metrics::Metrics;
use crate::net::{self, BoxedIo};
use crate::service::{Built, ServiceRuntime};
use crate::share::ShareControl;
use crate::util::path_and_query;

const MAX_HEAD_BYTES: usize = 32 * 1024;
/// The most header lines of an origin answer (issue 238: 64 was too few
/// for an answer with many Set-Cookie lines). MAX_HEAD_BYTES limits the
/// head too.
pub(crate) const MAX_HEADERS: usize = 256;
/// The longest line of the trailer of a chunked answer of the origin.
const MAX_TRAILER_LINE: usize = 8192;
/// The largest trailer of a chunked answer of the origin.
const MAX_TRAILER_BYTES: usize = 64 * 1024;

/// The visitor side of one edge stream: the request body (after the
/// `ConnectRequest`) for reading, the `ConnectResponse` and body for writing.
/// A QUIC stream gives these directly. The HTTP/2 transport gives adapters.
pub type EdgeReader = std::pin::Pin<Box<dyn futures::io::AsyncRead + Send>>;
pub type EdgeWriter = std::pin::Pin<Box<dyn futures::io::AsyncWrite + Send>>;

/// Handle one inbound stream. Errors are logged, never propagated to the edge.
pub async fn serve_stream(
    runtime: std::sync::Arc<ServiceRuntime>,
    ingress: std::sync::Arc<Ingress>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let mut signature = [0u8; 6];
    if let Err(err) = recv.read_exact(&mut signature).await {
        tracing::debug!(error = %err, "the edge closed a stream before its signature");
        return;
    }
    if signature == crate::cloudflare::RPC_STREAM_SIGNATURE {
        // The edge calls the connector (a configuration push). cfrs serves
        // no RPC on such a stream: reset it, so the edge gets an answer at
        // once.
        tracing::debug!("the edge opened an RPC stream; it is reset");
        let _ = recv.stop(RPC_STREAM_REFUSED.into());
        let _ = send.reset(RPC_STREAM_REFUSED.into());
        return;
    }
    let metrics = runtime.metrics().clone();
    metrics.stream_started();
    if let Err(err) = serve_inner(&runtime, &ingress, signature, send, recv).await {
        metrics.error();
        tracing::warn!(error = %format!("{err:#}"), "stream failed");
    }
    metrics.stream_finished();
}

/// The QUIC error code of a reset RPC stream.
pub const RPC_STREAM_REFUSED: u32 = 0;

async fn serve_inner(
    runtime: &ServiceRuntime,
    ingress: &Ingress,
    signature: [u8; 6],
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<()> {
    use tokio::io::AsyncReadExt as _;
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
    let recv = std::io::Cursor::new(signature).chain(recv);
    let mut reader: EdgeReader = Box::pin(recv.compat());
    let writer: EdgeWriter = Box::pin(send.compat_write());
    let request = cqstream::read_connect_request(&mut reader).await?;
    serve_request(runtime, ingress, request, reader, writer).await
}

/// Handle one request that is already decoded. The HTTP/2 transport calls
/// this with adapters for the stream.
pub async fn serve_decoded(
    runtime: std::sync::Arc<ServiceRuntime>,
    ingress: std::sync::Arc<Ingress>,
    request: cqstream::ConnectRequest,
    reader: EdgeReader,
    writer: EdgeWriter,
) {
    let metrics = runtime.metrics().clone();
    metrics.stream_started();
    if let Err(err) = serve_request(&runtime, &ingress, request, reader, writer).await {
        metrics.error();
        tracing::warn!(error = %format!("{err:#}"), "stream failed");
    }
    metrics.stream_finished();
}

async fn serve_request(
    runtime: &ServiceRuntime,
    ingress: &Ingress,
    request: cqstream::ConnectRequest,
    reader: EdgeReader,
    writer: EdgeWriter,
) -> Result<()> {
    // A failure that a visitor sees names its request in the log.
    let what = format!(
        "{} {}",
        request.meta(HTTP_METHOD_KEY).unwrap_or("-"),
        crate::report::clean(&request.dest)
    );
    serve_request_inner(runtime, ingress, request, reader, writer)
        .await
        .with_context(|| what)
}

async fn serve_request_inner(
    runtime: &ServiceRuntime,
    ingress: &Ingress,
    mut request: cqstream::ConnectRequest,
    reader: EdgeReader,
    writer: EdgeWriter,
) -> Result<()> {
    // Issue 205: the credential in front of the tunnel. A request with no
    // right Authorization gets 401 and reaches no origin; the origin does
    // not get the credential of cfrs.
    if let Some(auth) = &ingress.auth {
        if !auth.check_basic(header_value(&request, "authorization")) {
            let mut writer = writer;
            return write_simple_response_with(
                &mut writer,
                401,
                "text/plain; charset=utf-8",
                AUTH_BODY,
                &[(
                    "WWW-Authenticate".to_string(),
                    "Basic realm=\"cfrs\", charset=\"UTF-8\"".to_string(),
                )],
            )
            .await;
        }
        let name = format!("{HTTP_HEADER_KEY}:authorization");
        request
            .metadata
            .retain(|(key, _)| !key.eq_ignore_ascii_case(&name));
    }
    let host = request
        .meta(HTTP_HOST_KEY)
        .map(str::to_string)
        .or_else(|| crate::util::authority_of(&request.dest))
        .unwrap_or_default();
    let path = path_and_query(&request.dest);
    tracing::debug!(%host, %path, kind = ?request.conn_type, "inbound");

    let Some(index) = ingress.resolve_index(&host, &path) else {
        let mut writer = writer;
        return write_simple_response(
            &mut writer,
            503,
            "text/plain; charset=utf-8",
            b"cfrs: no ingress rule matched\n",
        )
        .await;
    };
    let built = runtime.get(index).context("runtime rule missing")?;

    match built {
        Built::Forward(service, options) => {
            forward_http(
                service,
                options,
                &request,
                reader,
                writer,
                runtime.metrics(),
            )
            .await
        }
        Built::Tcp(service, options) => {
            forward_tcp(
                service,
                options,
                &request,
                reader,
                writer,
                runtime.metrics(),
            )
            .await
        }
        Built::ForwardWs(target) => {
            if !is_websocket(&request) {
                let mut writer = writer;
                return write_simple_response(
                    &mut writer,
                    426,
                    "text/plain; charset=utf-8",
                    b"cfrs: this endpoint requires a WebSocket upgrade\n",
                )
                .await;
            }
            crate::ws::serve_websocket(target, &request, reader, writer, runtime.metrics()).await
        }
        Built::HelloWorld => {
            let mut writer = writer;
            write_simple_response(
                &mut writer,
                200,
                "text/plain; charset=utf-8",
                b"Hello, world! (cfrs)\n",
            )
            .await
        }
        Built::Status(code) => {
            let mut writer = writer;
            write_simple_response(&mut writer, *code, "text/plain; charset=utf-8", b"").await
        }
        Built::Metrics => {
            let text = runtime.metrics().prometheus();
            let mut writer = writer;
            write_simple_response(
                &mut writer,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                text.as_bytes(),
            )
            .await
        }
        Built::Static(router) => {
            dispatch_axum(
                router.clone(),
                &request,
                &host,
                reader,
                writer,
                runtime.metrics(),
            )
            .await
        }
        Built::Share(app) => {
            dispatch_axum(
                app.router(),
                &request,
                &host,
                reader,
                writer,
                runtime.metrics(),
            )
            .await
        }
        Built::ShareProxy {
            target,
            gate,
            control,
            stop_after,
        } => {
            share_proxy(
                target,
                gate,
                control,
                *stop_after,
                &request,
                &host,
                reader,
                writer,
                runtime.metrics(),
            )
            .await
        }
    }
}

// ── HTTP forwarding ─────────────────────────────────────────────────────────

async fn forward_http(
    service: &Service,
    options: &OriginOptions,
    request: &cqstream::ConnectRequest,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    // The QUIC leg marks a WebSocket by the connection type and may keep no
    // Upgrade header (issue 56): is_websocket checks both.
    let upgrade = is_websocket(request);
    let head = match build_request_head(request, options, upgrade) {
        Ok(head) => head,
        Err(err) => {
            write_simple_response(
                &mut writer,
                400,
                "text/plain; charset=utf-8",
                b"cfrs: the request is not valid HTTP/1.1\n",
            )
            .await?;
            return Err(err);
        }
    };
    let mut io = net::dial(service, options).await?;
    tokio::io::AsyncWriteExt::write_all(&mut io, head.as_bytes()).await?;

    if upgrade || is_chunked(request) {
        return proxy_bidi(&mut reader, &mut writer, io, metrics).await;
    }

    if let Some(len) = content_length(request) {
        if len > 0 {
            copy_futures_to_tokio_n(&mut reader, &mut io, len, metrics).await?;
        }
    }

    let (status, headers, leftover) = read_response_head(&mut io).await?;
    let resp_len = response_length(&headers)?;
    write_response_meta(&mut writer, status, &headers).await?;
    // A chunked body: the edge frames the body itself, so send only the
    // payload of the chunks. The last chunk ends the body, also when the
    // origin keeps the connection open.
    let chunked = headers_value(&headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        let mut source =
            tokio::io::BufReader::new(tokio::io::AsyncReadExt::chain(&leftover[..], &mut io));
        copy_chunked_to_futures(&mut source, &mut writer, metrics).await?;
        return futures_close(&mut writer).await;
    }
    if !leftover.is_empty() {
        futures_write_all(&mut writer, &leftover).await?;
        futures::io::AsyncWriteExt::flush(&mut writer).await?;
        metrics.add_out(leftover.len() as u64);
    }
    match resp_len {
        Some(total) => {
            let remaining = total.saturating_sub(leftover.len() as u64);
            if remaining > 0 {
                copy_tokio_to_futures_n(&mut io, &mut writer, remaining, metrics).await?;
            }
        }
        None => {
            copy_tokio_to_futures_eof(&mut io, &mut writer, metrics).await?;
        }
    }
    futures_close(&mut writer).await
}

async fn proxy_bidi(
    reader: &mut EdgeReader,
    writer: &mut EdgeWriter,
    io: BoxedIo,
    metrics: &Metrics,
) -> Result<()> {
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();

    let request_pump = async {
        let _ = copy_futures_to_tokio_eof(reader, &mut io_w, &in_metrics).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_w).await;
    };
    let response_pump = async {
        let (status, headers, leftover) = read_response_head(&mut io_r).await?;
        write_response_meta(writer, status, &headers).await?;
        if !leftover.is_empty() {
            futures_write_all(writer, &leftover).await?;
            out_metrics.add_out(leftover.len() as u64);
        }
        copy_tokio_to_futures_eof(&mut io_r, writer, &out_metrics).await?;
        futures_close(writer).await?;
        Ok::<(), anyhow::Error>(())
    };
    let (_, response) = tokio::join!(request_pump, response_pump);
    response
}

/// The body of the 401 of `--auth-user` (issue 205).
pub const AUTH_BODY: &[u8] = b"cfrs: this tunnel needs a user and a password (HTTP Basic)\n";

/// The answer of a raw TCP origin to an HTTP request (issue 199).
pub const TCP_HTTP_BODY: &[u8] = b"cfrs: a raw TCP origin carries TCP or WebSocket streams, not HTTP. Use --forward with \"cfrs connect\", or --port for an HTTP origin.\n";

async fn forward_tcp(
    service: &Service,
    options: &OriginOptions,
    request: &cqstream::ConnectRequest,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    // Issue 199: a quick tunnel gets HTTP requests. A raw byte pipe gave
    // the edge no HTTP status, and the edge answered 502.
    if request.conn_type == cqstream::ConnectionType::Http && !is_websocket(request) {
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                origin = %crate::net::origin_label(service),
                "an HTTP request came to a raw TCP origin; cfrs answers 501 (use --forward and cfrs connect)"
            );
        }
        return write_simple_response(&mut writer, 501, "text/plain; charset=utf-8", TCP_HTTP_BODY)
            .await;
    }
    let io = net::dial(service, options).await?;
    cqstream::write_connect_response(&mut writer, "", &[]).await?;
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();
    let to_origin = async {
        let _ = copy_futures_to_tokio_eof(&mut reader, &mut io_w, &in_metrics).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_w).await;
    };
    let from_origin = async {
        let _ = copy_tokio_to_futures_eof(&mut io_r, &mut writer, &out_metrics).await;
        let _ = futures_close(&mut writer).await;
    };
    tokio::join!(to_origin, from_origin);
    Ok(())
}

// ── Built-in (axum) dispatch ────────────────────────────────────────────────

async fn dispatch_axum(
    router: axum::Router,
    request: &cqstream::ConnectRequest,
    host: &str,
    reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let uri = path_and_query(&request.dest);
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    let builder = Request::builder().method(method).uri(uri);

    let mut headers = HeaderMap::new();
    let named = connection_named(
        request
            .metadata
            .iter()
            .filter(|(key, _)| {
                key.strip_prefix(&format!("{HTTP_HEADER_KEY}:"))
                    .is_some_and(|name| name.eq_ignore_ascii_case("connection"))
            })
            .map(|(_, value)| value.as_str()),
    );
    for (key, value) in &request.metadata {
        let Some(name) = key.strip_prefix(&format!("{HTTP_HEADER_KEY}:")) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower) || named.contains(&lower) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    if !headers.contains_key(axum::http::header::HOST) && !host.is_empty() {
        if let Ok(value) = HeaderValue::from_str(host) {
            headers.insert(axum::http::header::HOST, value);
        }
    }

    // The body goes through a pump (issue 92): when the service answers
    // before the end of the body (an early 413), the pump reads the rest and
    // drops it for a time, so that the stream is not reset before the edge
    // has the answer (a reset gave 502 to the visitor in place of the 413).
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(4);
    tokio::spawn(pump_body(reader, tx));
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    let body = Body::from_stream(stream);
    let mut axum_request = builder.body(body)?;
    *axum_request.headers_mut() = headers;

    let response: Response<Body> = router
        .oneshot(axum_request)
        .await
        .map_err(|e| anyhow!("service error: {e}"))?;

    write_axum_response(&mut writer, response, metrics).await
}

/// The longest time that the rest of a body is read after an early answer.
const DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Move the request body from the edge to `tx`. When the receiver is gone
/// (the service does not read more), read the rest and drop it, for at most
/// [`DRAIN_LIMIT`].
async fn pump_body(
    reader: EdgeReader,
    tx: tokio::sync::mpsc::Sender<std::io::Result<bytes::Bytes>>,
) {
    use tokio::io::AsyncReadExt as _;
    let mut reader = reader.compat();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                if tx
                    .send(Ok(bytes::Bytes::copy_from_slice(&buf[..n])))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                return;
            }
        }
    }
    let drained = tokio::time::timeout(DRAIN_LIMIT, async {
        let mut total = 0u64;
        while let Ok(n) = reader.read(&mut buf).await {
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        total
    })
    .await;
    tracing::debug!(?drained, "the rest of a request body after an early answer");
}

async fn write_axum_response(
    writer: &mut EdgeWriter,
    response: Response<Body>,
    metrics: &Metrics,
) -> Result<()> {
    let status = response.status().as_u16();
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                // A value with bytes above 127 is kept (as UTF-8, lossy):
                // to_str() refuses it, and the header was lost.
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();

    let has_len = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let has_chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });

    let body = response.into_body();
    if !has_len && !has_chunked {
        // Small built-in bodies: buffer so the edge gets a Content-Length.
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| anyhow!("reading response body: {e}"))?
            .to_bytes();
        headers.push(("Content-Length".to_string(), bytes.len().to_string()));
        write_response_meta(writer, status, &headers).await?;
        futures_write_all(writer, &bytes).await?;
        metrics.add_out(bytes.len() as u64);
    } else {
        write_response_meta(writer, status, &headers).await?;
        use futures::StreamExt;
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| anyhow!("response body: {e}"))?;
            futures_write_all(writer, &chunk).await?;
            metrics.add_out(chunk.len() as u64);
        }
    }
    futures_close(writer).await
}

// ── quickbridge proxy mode ──────────────────────────────────────────────────

/// The origin of a proxy share: `unix:/PATH` (issue 204) or `host:port`.
pub fn share_origin(target: &str) -> Service {
    match target.strip_prefix("unix:") {
        Some(path) => Service::Unix(path.into()),
        None => Service::Http(format!("http://{target}")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn share_proxy(
    target: &str,
    gate: &crate::gate::Gate,
    control: &ShareControl,
    stop_after: bool,
    request: &cqstream::ConnectRequest,
    host: &str,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let path = path_and_query(&request.dest);
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    let headers = headers_from_request(request);

    if path == UNLOCK_PATH && method.eq_ignore_ascii_case("POST") {
        let len = content_length(request).unwrap_or(0);
        if len > crate::gate::MAX_UNLOCK_BODY {
            return write_simple_response(
                &mut writer,
                413,
                "text/plain; charset=utf-8",
                b"the unlock request is too large",
            )
            .await;
        }
        let body = read_body(&mut reader, len).await?;
        // Issue 229: an unlock from another site does not use a try of the
        // PIN.
        if !crate::gate::same_site(&headers, Some(host)) {
            return write_simple_response(
                &mut writer,
                403,
                "text/plain; charset=utf-8",
                b"an unlock from another site is refused",
            )
            .await;
        }
        let fields = parse_form(&body);
        let password = fields
            .iter()
            .find(|(k, _)| k == "password")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let next = fields
            .iter()
            .find(|(k, _)| k == "next")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "/".to_string());
        return match gate.unlock(&password) {
            Some(cookie) => {
                write_simple_response_with(
                    &mut writer,
                    303,
                    "text/plain; charset=utf-8",
                    b"",
                    &[
                        (
                            "Location".to_string(),
                            crate::gate::safe_next(&next).to_string(),
                        ),
                        ("Set-Cookie".to_string(), cookie),
                    ],
                )
                .await
            }
            None => {
                let html = gate.page_html(&next, true);
                write_simple_response(
                    &mut writer,
                    403,
                    "text/html; charset=utf-8",
                    html.as_bytes(),
                )
                .await
            }
        };
    }

    if !gate.is_open(&headers) {
        let html = gate.page_html(&path, false);
        return write_simple_response(
            &mut writer,
            crate::gate::locked_status(method),
            "text/html; charset=utf-8",
            html.as_bytes(),
        )
        .await;
    }

    control.touch();
    let service = share_origin(target);
    let result = forward_http(
        &service,
        &OriginOptions::default(),
        request,
        reader,
        writer,
        metrics,
    )
    .await;
    // --stop-after: the first request that the origin answered in full
    // ends the session. A HEAD request does not count.
    if stop_after && result.is_ok() && !method.eq_ignore_ascii_case("HEAD") {
        control.request_stop();
    }
    result
}

fn headers_from_request(request: &cqstream::ConnectRequest) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (key, value) in &request.metadata {
        let Some(name) = key.strip_prefix(&format!("{HTTP_HEADER_KEY}:")) else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

async fn read_body(reader: &mut EdgeReader, len: u64) -> Result<Vec<u8>> {
    let mut body = vec![0u8; len as usize];
    if len > 0 {
        futures::io::AsyncReadExt::read_exact(reader, &mut body).await?;
    }
    Ok(body)
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    text.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Response helpers ────────────────────────────────────────────────────────

async fn write_simple_response(
    writer: &mut EdgeWriter,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write_simple_response_with(writer, status, content_type, body, &[]).await
}

async fn write_simple_response_with(
    writer: &mut EdgeWriter,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(String, String)],
) -> Result<()> {
    // Issue 271: a reply that cfrs makes (the PIN page, the unlock
    // redirect, an error) is not stored by a cache.
    let mut headers = vec![
        ("Content-Type".to_string(), content_type.to_string()),
        ("Content-Length".to_string(), body.len().to_string()),
        ("Cache-Control".to_string(), "no-store".to_string()),
    ];
    headers.extend(extra.iter().cloned());
    write_response_meta(writer, status, &headers).await?;
    if !body.is_empty() {
        futures_write_all(writer, body).await?;
    }
    futures_close(writer).await
}

/// Build the `ConnectResponse` metadata pairs. The status is a bare
/// `HttpStatus`; every header must be `HttpHeader:<Name>` or the edge drops it.
fn response_meta_pairs(status: u16, headers: &[(String, String)]) -> Vec<(String, String)> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    let mut meta: Vec<(String, String)> = Vec::with_capacity(headers.len() + 1);
    meta.push((cqstream::HTTP_STATUS_KEY.to_string(), status.to_string()));
    for (name, value) in headers {
        let key = if name == cqstream::HTTP_STATUS_KEY || name.starts_with(&prefix) {
            name.clone()
        } else {
            format!("{prefix}{name}")
        };
        meta.push((key, value.clone()));
    }
    meta
}

pub(crate) async fn write_response_meta(
    writer: &mut EdgeWriter,
    status: u16,
    headers: &[(String, String)],
) -> Result<()> {
    let meta = response_meta_pairs(status, headers);
    let refs: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    cqstream::write_connect_response(writer, "", &refs).await?;
    Ok(())
}

// ── Request head ────────────────────────────────────────────────────────────

/// The HTTP/1.1 head of the request to the origin.
///
/// The method, the target and the host come from the edge (the QUIC leg has
/// no HTTP parser before this) or from `httpHostHeader`: each one with a
/// control character, a space or a line break is an error (issue 226). A
/// header with a bad name or value is dropped. The hop-by-hop headers and
/// the headers that `Connection` names stay on their hop (issue 235), but
/// `Transfer-Encoding` stays: a chunked request body goes to the origin as
/// it is.
fn build_request_head(
    request: &cqstream::ConnectRequest,
    options: &OriginOptions,
    upgrade: bool,
) -> Result<String> {
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    if axum::http::Method::from_bytes(method.as_bytes()).is_err() {
        bail!("the request method {method:?} is not a token");
    }
    let path = request_path(&request.dest);
    if !path.bytes().all(|b| b > b' ' && b != 0x7f) {
        bail!("the request target {path:?} has a space or a control character");
    }
    let host = match &options.http_host_header {
        Some(host) => host.clone(),
        None => request.meta(HTTP_HOST_KEY).unwrap_or_default().to_string(),
    };
    if HeaderValue::from_bytes(host.as_bytes()).is_err() {
        let from = if options.http_host_header.is_some() {
            "httpHostHeader"
        } else {
            "the request"
        };
        bail!("the Host {host:?} of {from} has a control character");
    }
    let prefix = format!("{HTTP_HEADER_KEY}:");
    let headers = || {
        request
            .metadata
            .iter()
            .filter_map(|(key, value)| Some((key.strip_prefix(&prefix)?, value.as_str())))
    };
    let named = connection_named(
        headers()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| value),
    );

    let mut head = String::with_capacity(256);
    head.push_str(method);
    head.push(' ');
    head.push_str(&path);
    head.push_str(" HTTP/1.1\r\n");
    if !host.is_empty() {
        head.push_str("Host: ");
        head.push_str(&host);
        head.push_str("\r\n");
    }
    let mut saw_upgrade = false;
    for (name, value) in headers() {
        let lower = name.to_ascii_lowercase();
        if lower == "host" {
            continue;
        }
        if options.strip_accept_encoding && lower == "accept-encoding" {
            continue;
        }
        if lower == "upgrade" && upgrade {
            saw_upgrade = true;
        } else if drop_for_origin(&lower, &named) {
            continue;
        }
        if HeaderName::from_bytes(name.as_bytes()).is_err()
            || HeaderValue::from_bytes(value.as_bytes()).is_err()
        {
            tracing::warn!(header = %name.escape_debug(), "a request header is not valid HTTP; it is dropped");
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if upgrade {
        if !saw_upgrade {
            head.push_str("Upgrade: websocket\r\n");
        }
        head.push_str("Connection: Upgrade\r\n");
    } else {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    Ok(head)
}

/// Whether the request header `lower` (in lower case) stays out of the head
/// to the origin: a hop-by-hop header but `Transfer-Encoding`, or a header
/// that `Connection` names.
fn drop_for_origin(lower: &str, named: &[String]) -> bool {
    (is_hop_by_hop(lower) && lower != "transfer-encoding") || named.iter().any(|n| n == lower)
}

fn request_path(dest: &str) -> String {
    path_and_query(dest)
}

pub(crate) fn header_value<'a>(
    request: &'a cqstream::ConnectRequest,
    name: &str,
) -> Option<&'a str> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    request.metadata.iter().find_map(|(key, value)| {
        key.strip_prefix(&prefix)
            .filter(|header| header.eq_ignore_ascii_case(name))
            .map(|_| value.as_str())
    })
}

fn content_length(request: &cqstream::ConnectRequest) -> Option<u64> {
    header_value(request, "content-length").and_then(|v| v.parse().ok())
}

fn is_chunked(request: &cqstream::ConnectRequest) -> bool {
    header_value(request, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn is_upgrade(request: &cqstream::ConnectRequest) -> bool {
    header_value(request, "upgrade").is_some()
        || header_value(request, "connection")
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

/// The edge marks an upgrade by connection type, and may not keep the
/// `Upgrade`/`Connection` headers in the metadata, so check both.
fn is_websocket(request: &cqstream::ConnectRequest) -> bool {
    request.conn_type == cqstream::ConnectionType::Websocket || is_upgrade(request)
}

// ── Response head ───────────────────────────────────────────────────────────

/// The Content-Length of an origin answer, after a check of its framing
/// (issue 238). Each Content-Length value (also each item of a list) must
/// be the same number (RFC 9110 section 8.6). A Content-Length together
/// with a Transfer-Encoding that is not chunked is an error. With a chunked
/// Transfer-Encoding, the chunks frame the body (RFC 9112 section 6.3).
fn response_length(headers: &[(String, String)]) -> Result<Option<u64>> {
    let mut length = None;
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        for item in value.split(',') {
            let item = item.trim();
            let n = item
                .parse::<u64>()
                .ok()
                .filter(|_| item.bytes().all(|b| b.is_ascii_digit()))
                .with_context(|| format!("the origin answer has a bad Content-Length {item:?}"))?;
            if length.is_some_and(|l| l != n) {
                bail!("the origin answer has conflicting framing: two Content-Length values");
            }
            length = Some(n);
        }
    }
    let encodings: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .collect();
    if length.is_some() && !encodings.is_empty() {
        if encodings.iter().any(|v| v.contains("chunked")) {
            return Ok(None);
        }
        bail!("the origin answer has conflicting framing: Content-Length and Transfer-Encoding");
    }
    Ok(length)
}

async fn read_response_head<R>(io: &mut R) -> Result<(u16, Vec<(String, String)>, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        let n = tokio::io::AsyncReadExt::read(io, &mut tmp).await?;
        if n == 0 {
            bail!("origin closed before sending a response head");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD_BYTES {
            bail!("origin response head exceeds {MAX_HEAD_BYTES} bytes");
        }
        let parsed = {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&buf)? {
                httparse::Status::Complete(consumed) => {
                    let status = response.code.ok_or_else(|| anyhow!("no status code"))?;
                    let pairs = response
                        .headers
                        .iter()
                        .map(|h| {
                            (
                                h.name.to_string(),
                                String::from_utf8_lossy(h.value).into_owned(),
                            )
                        })
                        .collect::<Vec<_>>();
                    Some((status, pairs, consumed))
                }
                httparse::Status::Partial => None,
            }
        };
        if let Some((status, pairs, consumed)) = parsed {
            let leftover = buf.split_off(consumed);
            return Ok((status, pairs, leftover));
        }
    }
}

fn headers_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// ── Byte pumps ──────────────────────────────────────────────────────────────

async fn copy_futures_to_tokio_n<R, W>(
    src: &mut R,
    dst: &mut W,
    mut remaining: u64,
    metrics: &Metrics,
) -> Result<()>
where
    R: futures::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = futures::io::AsyncReadExt::read(src, &mut buf[..want]).await?;
        if n == 0 {
            bail!("edge EOF with {remaining} request bytes still expected");
        }
        tokio::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        metrics.add_in(n as u64);
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_futures_to_tokio_eof<R, W>(src: &mut R, dst: &mut W, metrics: &Metrics) -> Result<u64>
where
    R: futures::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = futures::io::AsyncReadExt::read(src, &mut buf).await?;
        if n == 0 {
            break;
        }
        tokio::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        metrics.add_in(n as u64);
        total += n as u64;
    }
    Ok(total)
}

async fn copy_tokio_to_futures_n<R, W>(
    src: &mut R,
    dst: &mut W,
    mut remaining: u64,
    metrics: &Metrics,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: futures::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = tokio::io::AsyncReadExt::read(src, &mut buf[..want]).await?;
        if n == 0 {
            bail!("origin EOF with {remaining} response bytes still expected");
        }
        futures::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        // Flush each read: a small write of the origin (an SSE event, the
        // start of a page) goes to the visitor at once.
        futures::io::AsyncWriteExt::flush(dst).await?;
        metrics.add_out(n as u64);
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_tokio_to_futures_eof<R, W>(src: &mut R, dst: &mut W, metrics: &Metrics) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: futures::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = tokio::io::AsyncReadExt::read(src, &mut buf).await?;
        if n == 0 {
            break;
        }
        futures::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        // Flush each read: a small write of the origin (an SSE event, the
        // start of a page) goes to the visitor at once.
        futures::io::AsyncWriteExt::flush(dst).await?;
        metrics.add_out(n as u64);
        total += n as u64;
    }
    Ok(total)
}

/// Decode the chunked body of `src` and write its payload to `dst`. The
/// trailer is read and dropped. A size line of more than 4096 bytes, a bad
/// size or an early end is an error.
async fn copy_chunked_to_futures<R, W>(src: &mut R, dst: &mut W, metrics: &Metrics) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: futures::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = tokio::io::AsyncReadExt::take(&mut *src, 4096)
            .read_until(b'\n', &mut line)
            .await?;
        if n == 0 || !line.ends_with(b"\n") {
            anyhow::bail!("the chunked body of the origin ends early");
        }
        let text = std::str::from_utf8(&line).context("a chunk size is not text")?;
        let hex = text.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(hex, 16)
            .with_context(|| format!("a bad chunk size {hex:?} from the origin"))?;
        if size == 0 {
            // The trailer: header lines up to an empty line, at most
            // MAX_TRAILER_LINE bytes each and MAX_TRAILER_BYTES in all
            // (issue 244). cfrs does not send the trailer on.
            let mut total = 0;
            loop {
                line.clear();
                let n = tokio::io::AsyncReadExt::take(&mut *src, MAX_TRAILER_LINE as u64)
                    .read_until(b'\n', &mut line)
                    .await?;
                if n == 0 || line == b"\r\n" || line == b"\n" {
                    return Ok(());
                }
                if !line.ends_with(b"\n") {
                    bail!(
                        "a trailer line of the origin is longer than {} KiB",
                        MAX_TRAILER_LINE / 1024
                    );
                }
                total += n;
                if total > MAX_TRAILER_BYTES {
                    bail!(
                        "the trailer of the origin is larger than {} KiB",
                        MAX_TRAILER_BYTES / 1024
                    );
                }
            }
        }
        copy_tokio_to_futures_n(src, dst, size, metrics).await?;
        line.clear();
        tokio::io::AsyncReadExt::take(&mut *src, 2)
            .read_until(b'\n', &mut line)
            .await?;
        if line != b"\r\n" && line != b"\n" {
            anyhow::bail!("a chunk of the origin has no line end after its data");
        }
    }
}

async fn futures_write_all<W>(dst: &mut W, bytes: &[u8]) -> Result<()>
where
    W: futures::io::AsyncWrite + Unpin,
{
    futures::io::AsyncWriteExt::write_all(dst, bytes).await?;
    Ok(())
}

async fn futures_close<W>(dst: &mut W) -> Result<()>
where
    W: futures::io::AsyncWrite + Unpin,
{
    futures::io::AsyncWriteExt::close(dst).await?;
    Ok(())
}

// `connect.rs` is the HTTP CONNECT client (a dial through a proxy). This
// module serves the edge streams. These re-exports keep the old paths
// (`crate::proxy::connect_tunnel` and others).
pub use crate::connect::{
    base64_encode, base64_encode_pub, connect_tunnel, connect_tunnel_with_auth, strip_scheme,
    TunnelStream,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue 92: on one QUIC connection in memory, three share uploads of
    /// 60 MB each get 200 and are on disk; a Content-Length over
    /// --max-request gets 413 before the body; the connection stays open.
    #[tokio::test(flavor = "multi_thread")]
    async fn large_share_uploads_on_one_quic_connection() {
        use crate::cloudflare::schema::ConnectionType;
        use crate::cloudflare::stream::HTTP_STATUS_KEY;
        use futures::io::AsyncWriteExt as _;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let pair = crate::cloudflare::quic::testing::local_pair().await;
        let dir = tempfile::tempdir().unwrap();
        let config = crate::share::ShareConfig::upload(dir.path());
        let token = config.token.clone();
        let ingress = Arc::new(Ingress::new().catch_all(Service::Share(config)));
        let runtime = Arc::new(ServiceRuntime::build(&ingress, Metrics::new()).unwrap());
        let client = pair.client.clone();
        let server = tokio::spawn(async move {
            while let Ok((send, recv)) = client.accept_bi().await {
                tokio::spawn(serve_stream(runtime.clone(), ingress.clone(), send, recv));
            }
        });
        const SIZE: usize = 60 * 1024 * 1024;
        let boundary = "XBOUNDARYX";
        let post = |name: &str, length: usize| cqstream::ConnectRequest {
            dest: format!("http://x.trycloudflare.com/s/{token}/upload?{name}"),
            conn_type: ConnectionType::Http,
            metadata: vec![
                (HTTP_METHOD_KEY.into(), "POST".into()),
                (HTTP_HOST_KEY.into(), "x.trycloudflare.com".into()),
                (
                    format!("{HTTP_HEADER_KEY}:Content-Type"),
                    format!("multipart/form-data; boundary={boundary}"),
                ),
                (
                    format!("{HTTP_HEADER_KEY}:Content-Length"),
                    length.to_string(),
                ),
            ],
        };
        for round in 0..3 {
            let head = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; \
                 filename=\"f{round}.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            );
            let tail = format!("\r\n--{boundary}--\r\n");
            let total = head.len() + SIZE + tail.len();
            let (send, recv) = pair.edge.open_bi().await.unwrap();
            let mut writer = send.compat_write();
            let mut reader = recv.compat();
            cqstream::write_connect_request(&mut writer, &post("a", total))
                .await
                .unwrap();
            let body = tokio::spawn(async move {
                writer.write_all(head.as_bytes()).await.unwrap();
                let chunk = vec![7u8; 64 * 1024];
                let mut left = SIZE;
                while left > 0 {
                    let n = left.min(chunk.len());
                    writer.write_all(&chunk[..n]).await.unwrap();
                    left -= n;
                }
                writer.write_all(tail.as_bytes()).await.unwrap();
                writer.close().await.unwrap();
            });
            let (error, meta) = tokio::time::timeout(
                Duration::from_secs(120),
                cqstream::read_connect_response(&mut reader),
            )
            .await
            .expect("an answer to the upload")
            .unwrap();
            assert!(error.is_empty(), "round {round}: {error}");
            assert!(
                meta.contains(&(HTTP_STATUS_KEY.to_string(), "200".to_string())),
                "round {round}: {meta:?}"
            );
            body.await.unwrap();
            let len = std::fs::metadata(dir.path().join(format!("f{round}.bin")))
                .unwrap()
                .len();
            assert_eq!(len, SIZE as u64);
        }
        // Over the limit: 413 at once, with no body sent.
        let (send, recv) = pair.edge.open_bi().await.unwrap();
        let mut writer = send.compat_write();
        let mut reader = recv.compat();
        cqstream::write_connect_request(&mut writer, &post("b", 150_000_000))
            .await
            .unwrap();
        let (_, meta) = tokio::time::timeout(
            Duration::from_secs(10),
            cqstream::read_connect_response(&mut reader),
        )
        .await
        .expect("a 413 before the body")
        .unwrap();
        assert!(
            meta.contains(&(HTTP_STATUS_KEY.to_string(), "413".to_string())),
            "{meta:?}"
        );
        // The rest of the body is read after the answer (it is not reset
        // at once, which gave 502 at the edge): 2 MiB more go through.
        let chunk = vec![1u8; 64 * 1024];
        for _ in 0..32 {
            writer
                .write_all(&chunk)
                .await
                .expect("the stream takes the rest of the body");
        }
        assert!(pair.client.close_reason().is_none());
        server.abort();
    }

    /// On a QUIC connection in memory: a stream with the RPC signature is
    /// reset at once, and a data stream after it is served (the signature
    /// that cfrs read first goes back in front of the request).
    #[tokio::test]
    async fn an_rpc_stream_is_reset_and_a_data_stream_is_served() {
        use crate::cloudflare::schema::ConnectionType;
        use std::sync::Arc;
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let pair = crate::cloudflare::quic::testing::local_pair().await;
        let ingress = Arc::new(Ingress::new().catch_all(Service::HelloWorld));
        let runtime = Arc::new(ServiceRuntime::build(&ingress, Metrics::new()).unwrap());
        let client = pair.client.clone();
        let server = tokio::spawn(async move {
            while let Ok((send, recv)) = client.accept_bi().await {
                tokio::spawn(serve_stream(runtime.clone(), ingress.clone(), send, recv));
            }
        });

        let (mut send, mut recv) = pair.edge.open_bi().await.unwrap();
        send.write_all(&crate::cloudflare::RPC_STREAM_SIGNATURE)
            .await
            .unwrap();
        send.write_all(b"01 a call").await.unwrap();
        let err = tokio::time::timeout(std::time::Duration::from_secs(5), recv.read_to_end(1024))
            .await
            .expect("an answer to the RPC stream")
            .unwrap_err();
        assert!(
            matches!(
                err,
                quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))
                    if code == quinn::VarInt::from_u32(RPC_STREAM_REFUSED)
            ),
            "{err:?}"
        );

        let (send, recv) = pair.edge.open_bi().await.unwrap();
        let mut writer = send.compat_write();
        let mut reader = recv.compat();
        let request = cqstream::ConnectRequest {
            dest: "http://x.trycloudflare.com/".into(),
            conn_type: ConnectionType::Http,
            metadata: vec![
                (HTTP_METHOD_KEY.into(), "GET".into()),
                (HTTP_HOST_KEY.into(), "x.trycloudflare.com".into()),
            ],
        };
        cqstream::write_connect_request(&mut writer, &request)
            .await
            .unwrap();
        futures::io::AsyncWriteExt::close(&mut writer)
            .await
            .unwrap();
        let (error, meta) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            cqstream::read_connect_response(&mut reader),
        )
        .await
        .expect("an answer to the data stream")
        .unwrap();
        assert_eq!(error, "");
        assert!(
            meta.iter()
                .any(|(k, v)| k == cqstream::HTTP_STATUS_KEY && v == "200"),
            "{meta:?}"
        );
        server.abort();
    }

    /// A writer that keeps the bytes until a flush, like a buffered edge
    /// stream. `committed` holds what a flush passed on.
    struct HoldUntilFlush {
        held: Vec<u8>,
        committed: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl futures::io::AsyncWrite for HoldUntilFlush {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.held.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let held = std::mem::take(&mut self.held);
            self.committed.lock().unwrap().extend_from_slice(&held);
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    /// A small write of the origin reaches the edge before the origin
    /// writes more (an SSE event), with a length and to the end of the
    /// stream.
    #[tokio::test]
    async fn small_writes_go_out_at_once() {
        for with_length in [true, false] {
            let committed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut dst = HoldUntilFlush {
                held: Vec::new(),
                committed: committed.clone(),
            };
            let (mut origin, mut src) = tokio::io::duplex(1 << 16);
            let copy = tokio::spawn(async move {
                if with_length {
                    copy_tokio_to_futures_n(&mut src, &mut dst, 20, &Metrics::new())
                        .await
                        .map(|_| ())
                } else {
                    copy_tokio_to_futures_eof(&mut src, &mut dst, &Metrics::new())
                        .await
                        .map(|_| ())
                }
            });
            tokio::io::AsyncWriteExt::write_all(&mut origin, b"data: event-1\n\n")
                .await
                .unwrap();
            let start = std::time::Instant::now();
            while committed.lock().unwrap().len() < 15 {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(2),
                    "the event was held"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            tokio::io::AsyncWriteExt::write_all(&mut origin, b"12345")
                .await
                .unwrap();
            drop(origin);
            copy.await.unwrap().unwrap();
            assert_eq!(
                committed.lock().unwrap().as_slice(),
                b"data: event-1\n\n12345"
            );
        }
    }

    /// The payload of each chunk, with no framing; an extension and a
    /// trailer are dropped; the last chunk ends the body while the origin
    /// keeps the connection open.
    /// Issue 238: an answer with more than 64 headers passes.
    #[tokio::test]
    async fn an_origin_answer_with_many_headers_passes() {
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec();
        for i in 0..100 {
            raw.extend_from_slice(format!("Set-Cookie: c{i}=v\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\nok");
        let (status, headers, leftover) = read_response_head(&mut &raw[..]).await.unwrap();
        assert_eq!(
            (status, headers.len(), leftover.as_slice()),
            (200, 101, &b"ok"[..])
        );
    }

    /// Issue 238: two different Content-Length values, or Content-Length
    /// with a Transfer-Encoding that is not chunked, are an error.
    #[test]
    fn the_framing_of_an_origin_answer_is_checked() {
        let h = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        };
        let cl = "Content-Length";
        let te = "Transfer-Encoding";
        assert_eq!(response_length(&h(&[(cl, "5")])).unwrap(), Some(5));
        assert_eq!(
            response_length(&h(&[(cl, "5"), (cl, "5")])).unwrap(),
            Some(5)
        );
        assert_eq!(response_length(&h(&[(cl, "5, 5")])).unwrap(), Some(5));
        assert_eq!(response_length(&h(&[])).unwrap(), None);
        assert_eq!(
            response_length(&h(&[(cl, "5"), (te, "chunked")])).unwrap(),
            None
        );
        for bad in [
            h(&[(cl, "5"), (cl, "6")]),
            h(&[(cl, "5, 6")]),
            h(&[(cl, "x")]),
            h(&[(cl, "+5")]),
            h(&[(cl, "5"), (te, "gzip")]),
        ] {
            assert!(response_length(&bad).is_err(), "{bad:?}");
        }
    }

    /// Issue 244: the trailer of a chunked answer has a cap, in all and
    /// for each line.
    #[tokio::test]
    async fn the_trailer_of_the_origin_has_a_cap() {
        let mut many = b"1\r\na\r\n0\r\n".to_vec();
        for _ in 0..20_000 {
            many.extend_from_slice(b"X: y\r\n");
        }
        many.extend_from_slice(b"\r\n");
        let mut long = b"0\r\n".to_vec();
        long.extend(std::iter::repeat_n(b'a', 20_000));
        long.extend_from_slice(b"\r\n\r\n");
        for (raw, want) in [(&many, "larger than 64 KiB"), (&long, "longer than 8 KiB")] {
            let mut source = tokio::io::BufReader::new(&raw[..]);
            let mut out = futures::io::Cursor::new(Vec::new());
            let err = copy_chunked_to_futures(&mut source, &mut out, &Metrics::new())
                .await
                .unwrap_err();
            assert!(err.to_string().contains(want), "{err:#}");
        }
        // A small trailer is read and dropped.
        let raw = b"1\r\na\r\n0\r\nX-Sum: 1\r\n\r\n";
        let mut source = tokio::io::BufReader::new(&raw[..]);
        let mut out = futures::io::Cursor::new(Vec::new());
        copy_chunked_to_futures(&mut source, &mut out, &Metrics::new())
            .await
            .unwrap();
        assert_eq!(out.into_inner(), b"a");
    }

    #[tokio::test]
    async fn a_chunked_body_is_decoded() {
        let (mut origin, cfrs_side) = tokio::io::duplex(1 << 16);
        let mut wire = Vec::new();
        let mut want = Vec::new();
        for i in 0..100u32 {
            let chunk = format!("{}{i:04}", "c".repeat(1000));
            wire.extend_from_slice(format!("{:x};ext=1\r\n{chunk}\r\n", chunk.len()).as_bytes());
            want.extend_from_slice(chunk.as_bytes());
        }
        wire.extend_from_slice(b"0\r\nX-Trailer: 1\r\n\r\n");
        // The origin writes, and does not close: the decoder must end at
        // the last chunk.
        let writer = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut origin, &wire)
                .await
                .unwrap();
            origin
        });
        let mut source = tokio::io::BufReader::new(cfrs_side);
        let mut out = futures::io::Cursor::new(Vec::new());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            copy_chunked_to_futures(&mut source, &mut out, &Metrics::new()),
        )
        .await
        .expect("the decoder ends at the last chunk")
        .unwrap();
        assert_eq!(out.into_inner(), want);
        drop(writer.await.unwrap());

        for bad in [
            &b"zz\r\nab\r\n0\r\n\r\n"[..],
            b"5\r\nab",
            b"2\r\nabXX0\r\n\r\n",
        ] {
            let mut source = tokio::io::BufReader::new(bad);
            let mut out = futures::io::Cursor::new(Vec::new());
            assert!(
                copy_chunked_to_futures(&mut source, &mut out, &Metrics::new())
                    .await
                    .is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
    use crate::cloudflare::stream::ConnectionType;

    fn req(dest: &str, metadata: Vec<(&str, &str)>) -> cqstream::ConnectRequest {
        cqstream::ConnectRequest {
            dest: dest.to_string(),
            conn_type: ConnectionType::Http,
            metadata: metadata
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    // Issue 205: with --auth-user, a request with no right credential gets
    // 401 and reaches no origin; the right one passes, and the origin does
    // not get the header.
    #[tokio::test]
    async fn the_credential_in_front_of_the_tunnel() {
        use tokio::io::AsyncReadExt as _;
        use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};
        // An origin that answers with the request head it got.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}",
                        head.len()
                    );
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut s, answer.as_bytes()).await;
                });
            }
        });
        let mut ingress = Ingress::new().catch_all(Service::Http(origin));
        let creds = crate::proxy_auth::Credentials::new("u", "secret").unwrap();
        ingress.auth = Some(creds.clone());
        let runtime = ServiceRuntime::build(&ingress, Metrics::new()).unwrap();
        let run = |auth: Option<String>| {
            let mut meta = vec![
                (HTTP_METHOD_KEY, "GET".to_string()),
                (HTTP_HOST_KEY, "x".to_string()),
            ];
            let header = format!("{HTTP_HEADER_KEY}:Authorization");
            let mut request = req("https://x/", vec![]);
            for (k, v) in meta.drain(..) {
                request.metadata.push((k.to_string(), v));
            }
            if let Some(a) = auth {
                request.metadata.push((header, a));
            }
            request
        };
        for (auth, want) in [
            (None, "401"),
            (Some("Basic d3Jvbmc6d3Jvbmc=".to_string()), "401"),
            (Some(creds.basic_header()), "200"),
        ] {
            let (ours, theirs) = tokio::io::duplex(1 << 16);
            let (_input, input) = tokio::io::duplex(64);
            serve_request_inner(
                &runtime,
                &ingress,
                run(auth.clone()),
                Box::pin(input.compat()),
                Box::pin(ours.compat_write()),
            )
            .await
            .unwrap();
            let mut reader = theirs.compat();
            let (_, meta) = cqstream::read_connect_response(&mut reader).await.unwrap();
            let status = meta
                .iter()
                .find(|(k, _)| k == crate::cloudflare::stream::HTTP_STATUS_KEY)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            assert_eq!(status, want, "{auth:?}");
            if want == "200" {
                let mut body = Vec::new();
                let _ = futures::io::AsyncReadExt::read_to_end(&mut reader, &mut body).await;
                let body = String::from_utf8_lossy(&body);
                assert!(
                    !body.to_ascii_lowercase().contains("authorization"),
                    "{body}"
                );
            }
        }
    }

    // Issue 204: the origin of a proxy share.
    #[test]
    fn the_origin_of_a_proxy_share() {
        assert!(
            matches!(share_origin("unix:/run/a.sock"), Service::Unix(p) if p == std::path::Path::new("/run/a.sock"))
        );
        assert!(
            matches!(share_origin("127.0.0.1:3000"), Service::Http(u) if u == "http://127.0.0.1:3000")
        );
    }

    // Issue 199: an HTTP request to a raw TCP origin gets 501, with no dial.
    #[tokio::test]
    async fn an_http_request_to_a_tcp_origin_gets_501() {
        use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service = Service::Tcp(listener.local_addr().unwrap().to_string());
        let request = req("https://x/", vec![(HTTP_HOST_KEY, "x")]);
        let (ours, theirs) = tokio::io::duplex(4096);
        let (_input, input) = tokio::io::duplex(64);
        forward_tcp(
            &service,
            &OriginOptions::default(),
            &request,
            Box::pin(input.compat()),
            Box::pin(ours.compat_write()),
            &Metrics::new(),
        )
        .await
        .unwrap();
        let mut reader = theirs.compat();
        let (error, meta) = cqstream::read_connect_response(&mut reader).await.unwrap();
        assert!(error.is_empty(), "{error}");
        assert!(
            meta.contains(&(
                crate::cloudflare::stream::HTTP_STATUS_KEY.to_string(),
                "501".to_string()
            )),
            "{meta:?}"
        );
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "the origin was dialed");
    }

    #[test]
    fn head_and_flags() {
        let request = req(
            "https://x/a",
            vec![
                (HTTP_METHOD_KEY, "POST"),
                (HTTP_HOST_KEY, "x"),
                ("HttpHeader:Content-Length", "5"),
            ],
        );
        assert_eq!(content_length(&request), Some(5));
        let head = build_request_head(&request, &OriginOptions::default(), false).unwrap();
        assert!(head.starts_with("POST /a HTTP/1.1\r\n"));
        assert!(head.contains("Connection: close\r\n"));
    }

    /// Issue 56: a WebSocket stream of the QUIC leg (connection type
    /// Websocket) with no Upgrade header still upgrades the origin.
    #[test]
    fn a_websocket_stream_with_no_upgrade_header_upgrades() {
        let mut ws = req(
            "https://x/ws",
            vec![
                (HTTP_HOST_KEY, "x"),
                ("HttpHeader:Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                ("HttpHeader:Connection", "keep-alive"),
            ],
        );
        ws.conn_type = cqstream::ConnectionType::Websocket;
        assert!(!is_upgrade(&ws) && is_websocket(&ws));
        let head = build_request_head(&ws, &OriginOptions::default(), is_websocket(&ws)).unwrap();
        assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
        assert!(head.contains("Connection: Upgrade\r\n"), "{head}");
        assert!(
            !head.contains("keep-alive") && !head.contains("Connection: close"),
            "{head}"
        );
        assert!(
            head.contains("Sec-Websocket-Key: dGhlIHNhbXBsZSBub25jZQ=="),
            "{head}"
        );
        // With an Upgrade header, it is not doubled.
        let with = req("https://x/ws", vec![("HttpHeader:Upgrade", "websocket")]);
        let head = build_request_head(&with, &OriginOptions::default(), true).unwrap();
        assert_eq!(head.matches("pgrade: websocket").count(), 1, "{head}");
    }

    /// Issue 226: a line break in a field of the edge does not reach the
    /// origin as a new header line.
    #[test]
    fn a_line_break_does_not_make_a_header_line() {
        let request = req(
            "https://x/a",
            vec![
                (HTTP_HOST_KEY, "x"),
                ("HttpHeader:X-A", "a\r\nInjected: 1"),
                ("HttpHeader:Bad Name", "b"),
                ("HttpHeader:X-Name\r\nInjected", "c"),
                ("HttpHeader:Cookie", "name=caf\u{e9}"),
            ],
        );
        let head = build_request_head(&request, &OriginOptions::default(), false).unwrap();
        assert!(!head.contains("Injected"), "{head}");
        assert!(!head.contains("Bad Name"), "{head}");
        assert!(head.contains("Cookie: name=caf\u{e9}\r\n"), "{head}");
        assert_eq!(head.matches("\r\n\r\n").count(), 1, "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");
        assert_eq!(head.matches('\n').count(), head.matches("\r\n").count());

        let bad = [
            req(
                "https://x/a",
                vec![(HTTP_METHOD_KEY, "GET /x HTTP/1.1\r\n")],
            ),
            req("https://x/a\r\nInjected: 1", vec![]),
            req("https://x/a b", vec![]),
            req("https://x/a", vec![(HTTP_HOST_KEY, "x\nInjected: 1")]),
        ];
        for request in &bad {
            assert!(
                build_request_head(request, &OriginOptions::default(), false).is_err(),
                "{request:?}"
            );
        }
        let options = OriginOptions {
            http_host_header: Some("x\r\nInjected: 1".into()),
            ..OriginOptions::default()
        };
        let err = build_request_head(&req("https://x/", vec![]), &options, false).unwrap_err();
        assert!(err.to_string().contains("httpHostHeader"), "{err}");
    }

    /// Issue 235: the hop-by-hop headers and the headers that Connection
    /// names do not go to the origin. Transfer-Encoding stays for a chunked
    /// body.
    #[test]
    fn hop_by_hop_headers_stay_on_their_hop() {
        let request = req(
            "https://x/u",
            vec![
                (HTTP_METHOD_KEY, "POST"),
                ("HttpHeader:Keep-Alive", "timeout=5"),
                ("HttpHeader:Te", "trailers"),
                ("HttpHeader:Trailer", "X-Sum"),
                ("HttpHeader:Proxy-Authorization", "Basic YTpi"),
                ("HttpHeader:Connection", "close, X-Hop"),
                ("HttpHeader:X-Hop", "1"),
                ("HttpHeader:X-Keep", "2"),
                ("HttpHeader:Transfer-Encoding", "chunked"),
            ],
        );
        let head = build_request_head(&request, &OriginOptions::default(), false).unwrap();
        for gone in [
            "Keep-Alive",
            "Te:",
            "Trailer",
            "Proxy-Authorization",
            "X-Hop",
        ] {
            assert!(!head.contains(gone), "{gone} in {head}");
        }
        assert!(head.contains("X-Keep: 2\r\n"), "{head}");
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
        assert_eq!(head.matches("Connection:").count(), 1, "{head}");
        assert!(head.contains("Connection: close\r\n"), "{head}");
        let sized = req("https://x/u", vec![("HttpHeader:Content-Length", "5")]);
        let head = build_request_head(&sized, &OriginOptions::default(), false).unwrap();
        assert!(head.contains("Content-Length: 5\r\n"), "{head}");
    }

    #[test]
    fn upgrade_and_chunked() {
        let ws = req("https://x/ws", vec![("HttpHeader:Upgrade", "websocket")]);
        assert!(is_upgrade(&ws));
        let chunked = req(
            "https://x/u",
            vec![("HttpHeader:Transfer-Encoding", "chunked")],
        );
        assert!(is_chunked(&chunked));
    }

    #[test]
    fn form_parsing() {
        let fields = parse_form(b"password=123456&next=%2Fs%2Fabc%2F&x=a+b");
        assert!(fields.contains(&("password".to_string(), "123456".to_string())));
        assert!(fields.contains(&("next".to_string(), "/s/abc/".to_string())));
        assert!(fields.contains(&("x".to_string(), "a b".to_string())));
    }

    #[test]
    fn strips_accept_encoding_on_request() {
        let request = req(
            "https://x/",
            vec![("HttpHeader:Accept-Encoding", "gzip, br")],
        );
        let head = build_request_head(&request, &OriginOptions::default(), false).unwrap();
        assert!(head.contains("Accept-Encoding: gzip, br"));

        let options = OriginOptions {
            strip_accept_encoding: true,
            ..OriginOptions::default()
        };
        let head = build_request_head(&request, &options, false).unwrap();
        assert!(!head.to_ascii_lowercase().contains("accept-encoding"));
    }

    #[test]
    fn response_meta_prefixes_headers() {
        let headers = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Set-Cookie".to_string(), "a=b".to_string()),
            ("HttpHeader:Location".to_string(), "/next".to_string()),
        ];
        let meta = response_meta_pairs(303, &headers);
        assert_eq!(meta[0], ("HttpStatus".to_string(), "303".to_string()));
        assert!(meta.contains(&(
            "HttpHeader:Content-Type".to_string(),
            "text/plain".to_string()
        )));
        assert!(meta.contains(&("HttpHeader:Set-Cookie".to_string(), "a=b".to_string())));
        assert!(meta.contains(&("HttpHeader:Location".to_string(), "/next".to_string())));
        assert!(!meta.iter().any(|(k, _)| k == "Content-Type"));
    }
}

// ── re-exports from the outbound CONNECT client ─────────────────────────────
//
