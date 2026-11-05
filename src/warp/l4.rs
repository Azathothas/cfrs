//! `podnet warp proxy --l4` (issue 140): each TCP client of the proxy is one
//! HTTP/3 CONNECT stream (RFC 9114, section 4.4) to the L4 door of WARP,
//! with no IP stack in between. The QUIC connection is one for all the
//! flows, with the client certificate and the pinned key of the device.
//! UDP is not carried in this mode.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

use super::h3;

/// The TLS name of the L4 door.
pub const L4_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

/// The variable of the form of the CONNECT of the L4 door (a test of the
/// form that the door takes, issue 140): `plain` (RFC 9114, the default),
/// `extended` (`:protocol cf-connect-tcp`, RFC 9220), or `header` (a plain
/// CONNECT with `cf-connect-proto: cf-connect-tcp`).
pub const FORM_VARIABLE: &str = "PODNET_WARP_L4_FORM";

/// A length or an index with a prefix of 7 bits, after `flags`.
fn put_len(out: &mut Vec<u8>, flags: u8, bits: u8, len: usize) {
    let max = (1usize << bits) - 1;
    if len < max {
        out.push(flags | len as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut v = len - max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

/// A literal field line with a literal name (001NHxxx), no Huffman code.
fn put_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    put_len(out, 0x20, 3, name.len());
    out.extend_from_slice(name.as_bytes());
    put_len(out, 0x00, 7, value.len());
    out.extend_from_slice(value.as_bytes());
}

/// The field section of a CONNECT to `authority` (`host:port`).
pub fn connect_headers(authority: &str) -> Vec<u8> {
    connect_headers_form(authority, &std::env::var(FORM_VARIABLE).unwrap_or_default())
}

/// [`connect_headers`] of one form of [`FORM_VARIABLE`].
pub fn connect_headers_form(authority: &str, form: &str) -> Vec<u8> {
    // :method CONNECT (static 15).
    let mut out = vec![0x00, 0x00, 0xc0 | 15];
    if form == "extended" {
        out.push(0xc0 | 23); // :scheme https
        out.push(0xc0 | 1); // :path /
    }
    // :authority (static name 0), a literal value with no Huffman code.
    out.push(0x50);
    put_len(&mut out, 0x00, 7, authority.len());
    out.extend_from_slice(authority.as_bytes());
    match form {
        "extended" => put_literal(&mut out, ":protocol", "cf-connect-tcp"),
        "header" => put_literal(&mut out, "cf-connect-proto", "cf-connect-tcp"),
        _ => {}
    }
    out
}

/// `host:port`, with an IPv6 address in brackets.
pub fn authority(host: &str, port: u16) -> String {
    match host.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => format!("[{v6}]:{port}"),
        Err(_) => format!("{host}:{port}"),
    }
}

/// The L4 door: one QUIC connection, made again when it closes.
pub struct L4 {
    endpoint: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    sni: String,
    conn: tokio::sync::Mutex<Option<h3::H3Conn>>,
}

impl L4 {
    pub fn new(endpoint: SocketAddr, tls: Arc<rustls::ClientConfig>, sni: &str) -> Self {
        L4 {
            endpoint,
            tls,
            sni: sni.to_string(),
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// The connection of now: a new one when there is none, or it closed.
    pub async fn connection(&self) -> Result<quinn::Connection> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref() {
            if c.conn.close_reason().is_none() {
                return Ok(c.conn.clone());
            }
        }
        let fresh = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            h3::open(self.endpoint, self.tls.clone(), &self.sni),
        )
        .await
        .map_err(|_| anyhow::anyhow!("no QUIC with the L4 door {} in 15 s", self.endpoint))??;
        let conn = fresh.conn.clone();
        *slot = Some(fresh);
        tracing::info!(door = %self.endpoint, sni = %self.sni, "the QUIC connection of the L4 door is open");
        Ok(conn)
    }

    /// A TCP connection to `host:port` through the L4 door: a local pipe
    /// end that carries it.
    pub async fn dial(&self, host: &str, port: u16) -> Result<DuplexStream> {
        let conn = self.connection().await?;
        let target = authority(host, port);
        let (send, recv, frames, status) = h3::request(&conn, &connect_headers(&target))
            .await
            .with_context(|| format!("CONNECT {target} through the L4 door"))?;
        if status != 200 {
            bail!("the L4 door refused CONNECT {target} with {status}");
        }
        let (local, remote) = tokio::io::duplex(256 * 1024);
        tokio::spawn(pump(send, recv, frames, remote));
        Ok(local)
    }
}

/// Copy the pipe to DATA frames of the stream, and the DATA frames of the
/// stream to the pipe.
async fn pump(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mut frames: h3::Frames,
    pipe: DuplexStream,
) {
    let (mut pipe_read, mut pipe_write) = tokio::io::split(pipe);
    let up = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match pipe_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    if send.write_all(&h3::frame(0x00, &buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let down = async {
        'outer: loop {
            loop {
                match frames.next_frame() {
                    Ok(Some((0x00, payload))) => {
                        if pipe_write.write_all(&payload).await.is_err() {
                            break 'outer;
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => break 'outer,
                }
            }
            match recv.read_chunk(64 * 1024, true).await {
                Ok(Some(chunk)) => frames.push(&chunk.bytes),
                _ => break,
            }
        }
        let _ = pipe_write.shutdown().await;
    };
    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_flow_through_an_l4_door_on_the_loopback() {
        crate::test_host::need_loopback!();
        use super::super::identity::Identity;
        crate::net::init_crypto();
        let server_id = Identity::generate().unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_id.cert_chain(), server_id.private_key())
            .unwrap();
        tls.alpn_protocols = vec![h3::ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut frames = h3::Frames::default();
            loop {
                while let Some((kind, payload)) = frames.next_frame().unwrap() {
                    if kind == 0x01 {
                        assert_eq!(payload, connect_headers_form("example.com:443", "plain"));
                        send.write_all(&h3::frame(0x01, &[0, 0, 0xc0 | 25]))
                            .await
                            .unwrap();
                    } else if kind == 0x00 {
                        send.write_all(&h3::frame(0x00, &payload)).await.unwrap();
                    }
                }
                match recv.read_chunk(65536, true).await {
                    Ok(Some(chunk)) => frames.push(&chunk.bytes),
                    _ => break,
                }
            }
            let _ = send.finish();
        });
        let client_id = Identity::generate().unwrap();
        let tls = super::super::session::tls_config_alpn(
            &client_id,
            server_id.spki_der().to_vec(),
            h3::ALPN,
        )
        .unwrap();
        let door = L4::new(addr, tls, L4_SNI);
        let mut pipe = door.dial("example.com", 443).await.unwrap();
        pipe.write_all(b"ping through L4").await.unwrap();
        let mut back = [0u8; 15];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipe.read_exact(&mut back),
        )
        .await
        .expect("an echo")
        .unwrap();
        assert_eq!(&back, b"ping through L4");
        task.abort();
    }

    #[test]
    fn the_connect_request() {
        let h = connect_headers_form("example.com:443", "plain");
        assert_eq!(&h[..5], &[0, 0, 0xcf, 0x50, 15]);
        assert_eq!(&h[5..], b"example.com:443");
        let long = "a".repeat(200) + ":1";
        let h = connect_headers_form(&long, "plain");
        let e = connect_headers_form("a:1", "extended");
        assert_eq!(&e[..5], &[0, 0, 0xcf, 0xd7, 0xc1]);
        assert!(e.windows(14).any(|w| w == b"cf-connect-tcp"));
        let p = connect_headers_form("a:1", "header");
        assert!(p.windows(16).any(|w| w == b"cf-connect-proto"));
        assert_eq!(h[4], 0x7f);
        assert_eq!(authority("2606:4700::1111", 443), "[2606:4700::1111]:443");
        assert_eq!(authority("1.1.1.1", 80), "1.1.1.1:80");
    }
}
