//! A small HTTP/1.1 client for the requests of cfrs: the quick-tunnel API,
//! DNS over HTTPS, the WARP API and the fetch of the public URL.
//!
//! Each request opens one connection with [`crate::egress::dial`] (so each
//! request takes the proxy, `NO_PROXY` and the attempt delay of that
//! module), adds TLS with the roots of [`crate::trust`] for `https://`, and
//! sends `Connection: close`. The body of the answer is read by
//! `Content-Length`, by chunks, or to the end of the connection, up to
//! [`MAX_BODY`] bytes, or up to the limit of [`Request::max_body`].

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::egress::Proxy;

/// The largest body of an answer.
pub const MAX_BODY: usize = 16 << 20;
/// The largest head of an answer.
const MAX_HEAD: usize = 64 << 10;

/// One request.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// The time limit of the whole request.
    pub timeout: Duration,
    /// A proxy for this request only, in place of the choice of the process.
    pub via: Option<Proxy>,
    /// The largest body of the answer.
    pub max_body: usize,
}

impl Request {
    pub fn new(method: &'static str, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(30),
            via: None,
            max_body: MAX_BODY,
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn json(mut self, value: &serde_json::Value) -> Self {
        self.body = Some(value.to_string().into_bytes());
        self.header("Content-Type", "application/json")
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn via(mut self, proxy: Option<Proxy>) -> Self {
        self.via = proxy;
        self
    }

    /// Set the largest body of the answer, in place of [`MAX_BODY`].
    pub fn max_body(mut self, max: usize) -> Self {
        self.max_body = max;
        self
    }

    /// Send the request and read the answer.
    pub async fn send(self) -> Result<Response> {
        let timeout = self.timeout;
        let what = format!("{} {}", self.method, without_query(&self.url));
        tokio::time::timeout(timeout, send(self))
            .await
            .map_err(|_| anyhow::anyhow!("{what}: no answer in {} s", timeout.as_secs()))?
            .with_context(|| what)
    }
}

/// The answer.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    /// Names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).context("decoding the JSON body")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The parts of a URL that a request needs.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    tls: bool,
    host: String,
    port: u16,
    /// The path and the query, from `/`.
    path: String,
}

fn target(url: &str) -> Result<Target> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("the URL is not http:// or https://");
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let path = path.split('#').next().unwrap_or("/").to_string();
    if authority.contains('@') {
        bail!("the URL has a user part, which cfrs does not send");
    }
    let default = if tls { 443 } else { 80 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6.split_once(']').context("no ] in the URL")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().context("the port of the URL")?,
            None => default,
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().context("the port of the URL")?),
            None => (authority.to_string(), default),
        }
    };
    if host.is_empty() {
        bail!("the URL has no host");
    }
    Ok(Target {
        tls,
        host,
        port,
        path,
    })
}

fn without_query(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

async fn send(request: Request) -> Result<Response> {
    let target = target(&request.url)?;
    let io = crate::egress::dial(
        &target.host,
        target.port,
        request.via.as_ref(),
        request.timeout,
    )
    .await?;
    if target.tls {
        let config = crate::trust::client_config(&[], &[b"http/1.1"])?;
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .context("the host of the URL is not a TLS name")?;
        let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
            .connect(name, io)
            .await
            .map_err(|e| {
                crate::hop::at(
                    crate::hop::tls_hop(&e),
                    anyhow::anyhow!(
                        "TLS with {}:{}: {}",
                        target.host,
                        target.port,
                        crate::hop::tls_text(&e)
                    ),
                )
            })?;
        exchange(tls, &target, &request).await
    } else {
        exchange(io, &target, &request).await
    }
}

async fn exchange<S>(mut io: S, target: &Target, request: &Request) -> Result<Response>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let host = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    let default = if target.tls { 443 } else { 80 };
    let host = if target.port == default {
        host
    } else {
        format!("{host}:{}", target.port)
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
        request.method, target.path
    );
    let mut has_agent = false;
    for (name, value) in &request.headers {
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            bail!("a request header has a line break");
        }
        has_agent |= name.eq_ignore_ascii_case("user-agent");
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !has_agent {
        head.push_str(&format!(
            "User-Agent: cfrs/{}\r\n",
            env!("CARGO_PKG_VERSION")
        ));
    }
    let body = request.body.as_deref().unwrap_or_default();
    if request.body.is_some() || matches!(request.method, "POST" | "PUT" | "PATCH") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    io.write_all(head.as_bytes())
        .await
        .context("sending the request")?;
    io.write_all(body).await.context("sending the body")?;
    io.flush().await.context("sending the request")?;
    read_response(&mut io, request.method == "HEAD", request.max_body).await
}

/// The most interim (1xx) answers before the answer (issue 237).
const MAX_INTERIM: usize = 5;

/// Read one answer from `io`.
async fn read_response<S: AsyncRead + Unpin>(
    io: &mut S,
    head_only: bool,
    max_body: usize,
) -> Result<Response> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let mut interim = 0;
    let (status, headers, start) = loop {
        if !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = read_some(io, &mut chunk).await?;
            if n == 0 {
                bail!("the server closed the connection before it answered");
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let mut slots = [httparse::EMPTY_HEADER; crate::proxy::MAX_HEADERS];
        let mut parsed = httparse::Response::new(&mut slots);
        match parsed.parse(&buf).context("the answer is not HTTP")? {
            httparse::Status::Complete(len) => {
                let status = parsed.code.context("the answer has no status")?;
                // 1xx answers come before the real one.
                if (100..200).contains(&status) && status != 101 {
                    interim += 1;
                    if interim > MAX_INTERIM {
                        bail!("the server sent more than {MAX_INTERIM} interim answers");
                    }
                    buf.drain(..len);
                    continue;
                }
                let headers = parsed
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_ascii_lowercase(),
                            String::from_utf8_lossy(h.value).into_owned(),
                        )
                    })
                    .collect::<Vec<_>>();
                break (status, headers, len);
            }
            httparse::Status::Partial if buf.len() > MAX_HEAD => {
                bail!("the head of the answer is larger than {MAX_HEAD} bytes")
            }
            httparse::Status::Partial => {}
        }
    };
    let mut rest = buf.split_off(start);
    let find = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.trim().to_ascii_lowercase())
    };
    let body = if head_only || status == 204 || status == 304 {
        Vec::new()
    } else if find("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        read_chunked(io, rest, max_body).await?
    } else if let Some(len) = find("content-length") {
        let len: usize = len.parse().context("the Content-Length is not a number")?;
        if len > max_body {
            bail!("the body has {len} bytes, more than {max_body}");
        }
        while rest.len() < len {
            let n = read_some(io, &mut chunk).await?;
            if n == 0 {
                bail!(
                    "the server closed the connection after {} of {len} bytes",
                    rest.len()
                );
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        rest.truncate(len);
        rest
    } else {
        loop {
            // The bytes that came with the head count too.
            if rest.len() > max_body {
                bail!("the body is larger than {max_body} bytes");
            }
            let n = read_some(io, &mut chunk).await?;
            if n == 0 {
                break rest;
            }
            rest.extend_from_slice(&chunk[..n]);
        }
    };
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Read some bytes. The end of a TLS connection with no close_notify is the
/// end of the stream: the length of the body is checked on its own.
async fn read_some<S: AsyncRead + Unpin>(io: &mut S, buf: &mut [u8]) -> Result<usize> {
    match io.read(buf).await {
        Ok(n) => Ok(n),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(err) => Err(err).context("reading the answer"),
    }
}

async fn read_chunked<S: AsyncRead + Unpin>(
    io: &mut S,
    mut buf: Vec<u8>,
    max_body: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut pos = 0;
    loop {
        // The size line.
        let line_end = loop {
            if let Some(i) = buf[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + i;
            }
            let n = read_some(io, &mut chunk).await?;
            if n == 0 {
                bail!("the chunked body ends early");
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let line = std::str::from_utf8(&buf[pos..line_end]).context("a chunk size is not text")?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .context("a chunk size is not hexadecimal")?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(body);
        }
        // A size from the server can be near usize::MAX: each sum is checked.
        let too_large = || anyhow::anyhow!("the body is larger than {max_body} bytes");
        if body.len().checked_add(size).is_none_or(|t| t > max_body) {
            return Err(too_large());
        }
        let end = pos.checked_add(size).ok_or_else(too_large)?;
        let next = end.checked_add(2).ok_or_else(too_large)?;
        while buf.len() < next {
            let n = read_some(io, &mut chunk).await?;
            if n == 0 {
                bail!("the chunked body ends early");
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        body.extend_from_slice(&buf[pos..end]);
        pos = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            target("https://api.trycloudflare.com/tunnel").unwrap(),
            Target {
                tls: true,
                host: "api.trycloudflare.com".into(),
                port: 443,
                path: "/tunnel".into()
            }
        );
        let t = target("http://[::1]:8080?x=1#frag").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("::1", 8080, "/?x=1")
        );
        assert!(target("ftp://x").is_err());
        assert!(target("https://user:pw@x/").is_err());
    }

    async fn parse(raw: &[u8]) -> Result<Response> {
        let mut io = raw;
        read_response(&mut io, false, MAX_BODY).await
    }

    #[tokio::test]
    async fn the_body_limit_is_set_for_each_request() {
        let sized = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n";
        let to_end = b"HTTP/1.1 200 OK\r\n\r\n0123456789";
        for raw in [&sized[..], &chunked[..], &to_end[..]] {
            let mut io = raw;
            assert!(read_response(&mut io, false, 9).await.is_err());
            let mut io = raw;
            let answer = read_response(&mut io, false, 10).await.unwrap();
            assert_eq!(answer.body, b"0123456789");
        }
        let request = Request::new("GET", "https://example.com/");
        assert_eq!(request.max_body, MAX_BODY);
        assert_eq!(request.max_body(1 << 30).max_body, 1 << 30);
    }

    /// Issue 238: an answer with more than 64 headers passes.
    #[tokio::test]
    async fn an_answer_with_many_headers_passes() {
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec();
        for i in 0..100 {
            raw.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\nok");
        let r = parse(&raw).await.unwrap();
        assert_eq!((r.headers.len(), r.body.as_slice()), (101, &b"ok"[..]));
    }

    /// Issue 237: a few interim answers pass; an endless row of them is
    /// an error.
    #[tokio::test]
    async fn interim_answers_have_a_limit() {
        let three = "HTTP/1.1 100 Continue\r\n\r\n".repeat(3)
            + "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse(three.as_bytes()).await.unwrap().status, 201);
        let many = "HTTP/1.1 100 Continue\r\n\r\n".repeat(10)
            + "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        let err = parse(many.as_bytes()).await.unwrap_err();
        assert!(err.to_string().contains("interim"), "{err:#}");
    }

    #[tokio::test]
    async fn a_chunk_size_that_overflows_is_an_error() {
        for size in ["ffffffffffffffff", "fffffffffffffffe", "fffffffffffffff0"] {
            let raw = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n{size}\r\n"
            );
            let err = parse(raw.as_bytes()).await.unwrap_err();
            assert!(format!("{err:#}").contains("larger than"), "{err:#}");
        }
    }

    #[tokio::test]
    async fn bodies_by_length_by_chunks_and_to_the_end() {
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA")
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        let r = parse(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
            .await
            .unwrap();
        assert_eq!((r.status, r.text().as_str()), (201, "hello world"));
        let r = parse(b"HTTP/1.0 404 Not Found\r\nX-A: b\r\n\r\nall of it")
            .await
            .unwrap();
        assert_eq!(
            (r.status, r.text().as_str(), r.header("x-a")),
            (404, "all of it", Some("b"))
        );
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort")
            .await
            .is_err());
        assert!(parse(b"SSH-2.0-x\r\n\r\n").await.is_err());
    }
}
