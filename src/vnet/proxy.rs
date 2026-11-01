//! A SOCKS5 / HTTP `CONNECT` front door into the virtual network.
//!
//! Programs that cannot be interposed — a statically linked binary, a language
//! runtime that resolves its own network stack — still honour `ALL_PROXY`.
//! [`handle_connection`] speaks the client side of SOCKS5 and HTTP `CONNECT`
//! and dials the requested endpoint through a [`NetStack`].
//!
//! A virtual endpoint only exists while something listens on it. [`forward`]
//! supplies that: it binds a virtual listener and splices every accepted
//! connection to a real destination reached through the host, so a fixed
//! virtual address can name a service that actually exists:
//!
//! ```text
//! ALL_PROXY=socks5h:///tmp/cfrsnet.socks
//! curl http://10.66.0.2:8080/        # -> 127.0.0.1:3000
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::task::JoinHandle;

use crate::vnet::addr::VirtAddr;
use crate::vnet::socks::{self, ProxyHost};
use crate::vnet::stack::NetStack;

pub use pod_netns::listen::ProxyListen;

/// A destination table for names the virtual network cannot resolve.
pub type Resolver = HashMap<String, IpAddr>;

/// Turn a parsed request into a virtual endpoint.
pub fn resolve_target(
    request: &socks::ProxyRequest,
    resolver: &Resolver,
    default_port: u16,
) -> Result<VirtAddr> {
    let port = if request.port == 0 {
        default_port
    } else {
        request.port
    };
    match &request.host {
        ProxyHost::Ip(ip) => Ok(VirtAddr::new(*ip, port)),
        ProxyHost::Domain(name) => {
            let key = name.to_ascii_lowercase();
            if let Some(ip) = resolver.get(&key) {
                return Ok(VirtAddr::new(*ip, port));
            }
            // SOCKS5' domain form is also how some clients send an address
            // literal, so a name that parses as one is used directly rather
            // than reported as unresolvable.
            if let Ok(ip) = key.trim_start_matches('[').trim_end_matches(']').parse() {
                return Ok(VirtAddr::new(ip, port));
            }
            Err(anyhow::anyhow!("no virtual address for {name:?}"))
        }
    }
}

/// Serve one proxy client: negotiate, dial `net`, and splice both directions.
///
/// The protocol is detected from the first byte (SOCKS5 begins with `0x05`),
/// so one listener serves both SOCKS5 and HTTP `CONNECT` clients.
pub use crate::vnet::stack::TcpStream;

/// How long one proxied client connection may take, end to end. A client that
/// opens a connection to the front door and then says nothing holds a task and
/// an origin socket until this expires.
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub async fn handle_connection<S>(
    stream: S,
    net: Arc<NetStack>,
    resolver: Resolver,
    default_port: u16,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let first = match reader.fill_buf().await {
        Ok(buffer) if !buffer.is_empty() => buffer[0],
        _ => return,
    };
    let is_socks = socks::looks_like_socks5(first);
    let request = if is_socks {
        match socks::socks5_read_request(&mut reader).await {
            Ok(request) => request,
            Err(_) => return,
        }
    } else if let Ok(request) = socks::http_read_connect(&mut reader).await {
        request
    } else {
        return;
    };

    let target = match resolve_target(&request, &resolver, default_port) {
        Ok(target) => target,
        Err(err) => {
            fail(&mut reader, is_socks, &err.to_string()).await;
            return;
        }
    };
    // `net.connect` returns as soon as the socket exists and the SYN is queued,
    // which is not the same as the connection being established. The client has
    // already sent its request and is waiting, so if nothing is listening it
    // waits for data that will never arrive. Refusing instead means the client
    // gets a SOCKS5 error or a 502, which it can act on.
    match net.connect(target).await {
        Ok(mut remote) => {
            if let Err((status, message)) = wait_established(&mut remote).await {
                fail_with(&mut reader, is_socks, status, &message).await;
                return;
            }
            let reply = if is_socks {
                socks::socks5_reply(&mut reader, 0x00, None).await
            } else {
                socks::http_connect_ok(&mut reader).await
            };
            if reply.is_err() {
                return;
            }
            // Bound the whole exchange. Without this a client that opens a
            // connection and then stops reading holds a task and both sockets
            // indefinitely, and there is nothing else in the process that would
            // notice.
            let _ = tokio::time::timeout(
                CLIENT_TIMEOUT,
                tokio::io::copy_bidirectional(&mut reader, &mut remote),
            )
            .await;
        }
        Err(err) => fail(&mut reader, is_socks, &err.to_string()).await,
    }
}

/// The time limit of the handshake with a virtual address. A SYN to an
/// address that nothing owns gets no answer; the client gets 504 after this.
pub const CONNECT_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait for the virtual connection to be established, or report why it
/// failed: the status for HTTP (502 refused, 504 no answer) and a message.
async fn wait_established(stream: &mut TcpStream) -> Result<(), (u16, String)> {
    let peer = stream.peer_addr();
    match tokio::time::timeout(CONNECT_LIMIT, stream.established()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err((502, format!("{peer} refused the connection: {err}"))),
        Err(_) => Err((
            504,
            format!(
                "no answer from {peer} in {} s: no virtual host has this address",
                CONNECT_LIMIT.as_secs()
            ),
        )),
    }
}

async fn fail<S>(stream: &mut S, is_socks: bool, message: &str)
where
    S: AsyncWrite + Unpin,
{
    fail_with(stream, is_socks, 502, message).await
}

/// Refuse a client: a SOCKS5 error code, or an HTTP status with the message
/// as the body.
async fn fail_with<S>(stream: &mut S, is_socks: bool, status: u16, message: &str)
where
    S: AsyncWrite + Unpin,
{
    tracing::debug!(status, message, "proxy request refused");
    if is_socks {
        let code = match status {
            504 => 0x04, // host unreachable
            _ => socks::socks5_code_for_error(message),
        };
        let _ = socks::socks5_reply(stream, code, None).await;
    } else {
        let reason = if status == 504 {
            "Gateway Timeout"
        } else {
            "Bad Gateway"
        };
        let _ = socks::http_reply_with_body(stream, status, reason, &format!("{message}\n")).await;
    }
}

/// Bind a virtual listener and splice each accepted connection to a real
/// destination. `dial` is called once per connection, so it can open a fresh
/// real socket; the test suite passes a duplex instead.
pub fn forward<F, Fut, S>(net: Arc<NetStack>, virt: VirtAddr, dial: F) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut listener = match net.listen(virt).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(%virt, error = %err, "virtual forward could not bind");
                return;
            }
        };
        tracing::info!(%virt, "virtual forward listening");
        while let Ok(mut virtual_stream) = listener.accept().await {
            let dialed = dial();
            tokio::spawn(async move {
                match dialed.await {
                    Ok(mut real) => {
                        let _ = tokio::io::copy_bidirectional(&mut virtual_stream, &mut real).await;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "virtual forward could not reach the real service");
                        // A reset is closer to the truth than a silent close.
                        virtual_stream.abort();
                    }
                }
            });
        }
    })
}

/// The running proxy: the accept loop plus every forward task.
pub struct Proxy {
    pub listen: ProxyListen,
    accepts: JoinHandle<()>,
    forwards: Vec<JoinHandle<()>>,
}

impl Proxy {
    /// Start forwarding the configured virtual endpoints.
    pub fn spawn_forwards<F, Fut, S>(&mut self, net: Arc<NetStack>, virt: VirtAddr, dial: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<S>> + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.forwards.push(forward(net, virt, dial));
    }

    /// Stop the accept loop and every forward.
    pub fn abort(self) {
        self.accepts.abort();
        for task in self.forwards {
            task.abort();
        }
    }
}

/// Bind the client-facing listener and start accepting.
pub async fn serve(
    net: Arc<NetStack>,
    listen: ProxyListen,
    resolver: Resolver,
    default_port: u16,
) -> Result<Proxy> {
    let accepts = match &listen {
        ProxyListen::Tcp(bind) => {
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            let net = net.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(handle_connection(
                        stream,
                        net.clone(),
                        resolver.clone(),
                        default_port,
                    ));
                }
            })
        }
        ProxyListen::Unix(path) => {
            #[cfg(unix)]
            {
                let listener = bind_unix(path)?;
                let net = net.clone();
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    while let Ok((stream, _)) = listener.accept().await {
                        tokio::spawn(handle_connection(
                            stream,
                            net.clone(),
                            resolver.clone(),
                            default_port,
                        ));
                    }
                })
            }
            #[cfg(not(unix))]
            {
                let _ = (net, path);
                bail!("unix sockets are not supported on this platform");
            }
        }
    };
    Ok(Proxy {
        listen,
        accepts,
        forwards: Vec::new(),
    })
}

#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    pod_netns::listen::bind_private(path)
        .with_context(|| format!("binding unix:{}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An echo server on the far end of a duplex, returned as the `dial`
    /// closure shape.
    async fn echo(stream: tokio::io::DuplexStream) {
        let (mut read, mut write) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut read, &mut write).await;
    }

    #[test]
    fn a_domain_form_literal_resolves_to_itself() {
        // Some SOCKS5 clients send an address literal as a domain name. A name
        // that parses as an address is used directly instead of being reported
        // as unresolvable, which is what a `socks5h` client can produce.
        let request = socks::ProxyRequest {
            host: ProxyHost::Domain("10.66.0.2".into()),
            port: 8080,
        };
        let target = resolve_target(&request, &Resolver::new(), 80).unwrap();
        assert_eq!(target, VirtAddr::new("10.66.0.2".parse().unwrap(), 8080));

        let named = socks::ProxyRequest {
            host: ProxyHost::Domain("web".into()),
            port: 0,
        };
        let mut resolver = Resolver::new();
        resolver.insert("web".into(), "10.66.0.9".parse().unwrap());
        let target = resolve_target(&named, &resolver, 80).unwrap();
        assert_eq!(target, VirtAddr::new("10.66.0.9".parse().unwrap(), 80));

        let unknown = socks::ProxyRequest {
            host: ProxyHost::Domain("nowhere".into()),
            port: 80,
        };
        assert!(resolve_target(&unknown, &Resolver::new(), 80).is_err());
    }

    /// One HTTP request through the proxy: the whole answer and its time.
    async fn ask(net: Arc<NetStack>, request: &[u8]) -> (String, std::time::Duration) {
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            handle_connection(server, net, Resolver::new(), 80).await;
        });
        let start = std::time::Instant::now();
        client.write_all(request).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read_to_end(&mut answer),
        )
        .await
        .expect("the proxy did not end the answer in 10 s")
        .unwrap();
        (
            String::from_utf8_lossy(&answer).into_owned(),
            start.elapsed(),
        )
    }

    /// Issue 41: a closed virtual port gets 502 with a body at once, an
    /// address that nothing owns gets 504 after CONNECT_LIMIT (not a hang),
    /// and a plain GET gets 405 with a body that names CONNECT.
    #[tokio::test]
    async fn refusals_have_a_status_and_a_body() {
        let net = Arc::new(NetStack::loopback());
        let (answer, took) = ask(net.clone(), b"CONNECT 10.66.0.2:81 HTTP/1.1\r\n\r\n").await;
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{answer}"
        );
        assert!(
            answer.contains("10.66.0.2:81 refused the connection"),
            "{answer}"
        );
        assert!(took < std::time::Duration::from_secs(1), "{took:?}");

        let (answer, took) = ask(net.clone(), b"CONNECT 10.66.0.9:80 HTTP/1.1\r\n\r\n").await;
        assert!(
            answer.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"),
            "{answer}"
        );
        assert!(answer.contains("no answer from 10.66.0.9:80"), "{answer}");
        assert!(
            took >= CONNECT_LIMIT && took < CONNECT_LIMIT * 2,
            "{took:?}"
        );

        let (answer, _) = ask(
            net.clone(),
            b"GET http://10.66.0.2:8080/ HTTP/1.1\r\nHost: 10.66.0.2\r\n\r\n",
        )
        .await;
        assert!(
            answer.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{answer}"
        );
        assert!(answer.contains("HTTP CONNECT only"), "{answer}");
    }

    #[tokio::test]
    async fn socks5_to_virtual_echo() {
        let net = Arc::new(NetStack::loopback());
        let virt: VirtAddr = "10.66.0.2:8080".parse().unwrap();
        let handle = forward(net.clone(), virt, || async {
            let (real, far) = tokio::io::duplex(4096);
            tokio::spawn(echo(far));
            Ok(real)
        });
        // Give the forward a moment to bind its virtual listener.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let (mut client, server) = tokio::io::duplex(4096);
        let proxy = {
            let net = net.clone();
            tokio::spawn(async move {
                handle_connection(server, net, Resolver::new(), 80).await;
            })
        };
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 10, 66, 0, 2, 0x1f, 0x90])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS5 CONNECT should succeed");
        client.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut back),
        )
        .await
        .expect("echo timed out")
        .unwrap();
        assert_eq!(&back, b"ping");
        drop(client);
        let _ = proxy.await;
        handle.abort();
    }

    #[tokio::test]
    async fn names_resolve_through_the_table() {
        let net = Arc::new(NetStack::loopback());
        let virt: VirtAddr = "10.66.0.2:8080".parse().unwrap();
        let handle = forward(net.clone(), virt, || async {
            let (real, far) = tokio::io::duplex(4096);
            tokio::spawn(echo(far));
            Ok(real)
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let mut resolver = Resolver::new();
        resolver.insert("api".into(), "10.66.0.2".parse().unwrap());

        let (mut client, server) = tokio::io::duplex(4096);
        let proxy = {
            let net = net.clone();
            tokio::spawn(async move { handle_connection(server, net, resolver, 80).await })
        };
        // HTTP CONNECT to the name on the forwarded port.
        client
            .write_all(b"CONNECT api:8080 HTTP/1.1\r\nHost: api\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        client.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut back),
        )
        .await
        .expect("echo timed out")
        .unwrap();
        assert_eq!(&back, b"hello");
        drop(client);
        let _ = proxy.await;
        handle.abort();
    }
}
