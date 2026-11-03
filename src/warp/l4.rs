//! `cfrs warp proxy --l4` (issue 140): each TCP client of the proxy is one
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

/// The field section of a CONNECT to `authority` (`host:port`).
pub fn connect_headers(authority: &str) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0xc0 | 15]; // :method CONNECT (static 15)
                                               // :authority (static name 0), a literal value with no Huffman code.
    out.push(0x50);
    let len = authority.len();
    if len < 127 {
        out.push(len as u8);
    } else {
        out.push(0x7f);
        let mut v = len - 127;
        while v >= 128 {
            out.push((v % 128) as u8 | 0x80);
            v /= 128;
        }
        out.push(v as u8);
    }
    out.extend_from_slice(authority.as_bytes());
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
                        assert_eq!(payload, connect_headers("example.com:443"));
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
        let h = connect_headers("example.com:443");
        assert_eq!(&h[..5], &[0, 0, 0xcf, 0x50, 15]);
        assert_eq!(&h[5..], b"example.com:443");
        let long = "a".repeat(200) + ":1";
        let h = connect_headers(&long);
        assert_eq!(h[4], 0x7f);
        assert_eq!(authority("2606:4700::1111", 443), "[2606:4700::1111]:443");
        assert_eq!(authority("1.1.1.1", 80), "1.1.1.1:80");
    }
}
