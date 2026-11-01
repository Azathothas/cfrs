//! A MASQUE CONNECT-IP session over HTTP/2 on TCP 443.
//!
//! This is the transport that makes the tunnel work where only 443 and 80 are
//! permitted: the MASQUE front door speaks HTTP/2 as happily as HTTP/3, and the
//! CONNECT-IP request is an ordinary `CONNECT` with a `cf-connect-proto` header
//! rather than an HTTP/3 extended connect with a `:protocol` pseudo-header. IP
//! packets then travel as capsules in the request body, in both directions.
//!
//! The credential is mutual TLS: the client certificate enrolled through
//! [`super::register::enrol_masque`] authenticates the device, and the server's
//! certificate is pinned to the SPKI the API returned.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use super::capsule::{self, CapsuleDecoder};
use super::identity::Identity;
use super::register::{CONNECT_URI, MASQUE_SNI};
use crate::egress::Proxy;
use crate::net::BoxedIo;

/// The text of a TLS failure when the front door shows a key that is not
/// the pinned key of the device record.
pub const PIN_MISMATCH: &str = "MASQUE peer key does not match the pinned key";

/// The HTTP/2 send capacity that the MASQUE stream asks for: the most
/// packet bytes that wait for the window of the front door.
pub const SEND_RESERVE: usize = 256 * 1024;

/// The HTTP/2 receive window of the MASQUE stream, and of the connection.
pub const STREAM_WINDOW: u32 = 4 << 20;
pub const CONNECTION_WINDOW: u32 = 8 << 20;

/// The smallest DATA frame that the front door sends: a capsule header
/// (2 bytes) and an IPv4 header (20 bytes).
pub const MIN_DATA_FRAME: usize = 22;

/// The budget of h2 for the framing overhead of small DATA frames. Each
/// frame under 256 bytes takes 256 bytes less its size until it is read.
/// The front door sends one DATA frame for each IP packet, and most are
/// small (QUIC and TCP ACKs). The receive task can fall behind during a
/// large transfer; then a full stream window of small frames waits in h2.
/// The budget holds that worst case: a window of frames of
/// [`MIN_DATA_FRAME`] bytes. A smaller budget closes the connection with
/// ENHANCE_YOUR_CALM (too_many_data_frames, issue 32). There is one stream
/// (the CONNECT-IP stream), so the stream window is the bound.
pub const DATA_FRAME_BUDGET: usize =
    STREAM_WINDOW as usize / MIN_DATA_FRAME * (256 - MIN_DATA_FRAME);

/// The HTTP/2 client settings of the MASQUE session.
pub fn h2_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .data_frame_budget(DATA_FRAME_BUDGET);
    builder
}

/// How long to wait for the TCP connect, TLS handshake and CONNECT response.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Verify the server only against a pinned SubjectPublicKeyInfo.
///
/// The front door's certificate is not issued by a public CA and its name is not
/// the address we dial, so ordinary chain validation cannot apply. What is
/// verified instead is the exact key the API told us to trust; a certificate
/// with a different key is refused.
#[derive(Debug)]
struct PinnedKey {
    expected: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = super::identity::spki_from_cert(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("unparsable peer certificate".into()))?;
        if got != self.expected {
            return Err(rustls::Error::General(PIN_MISMATCH.into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config(identity: &Identity, pinned_spki: Vec<u8>) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedKey {
        expected: pinned_spki,
        provider: Arc::clone(&provider),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(RootCertStore::empty())
        .with_client_auth_cert(identity.cert_chain(), identity.private_key())
        .context("installing the MASQUE client certificate")?;
    config.dangerous().set_certificate_verifier(verifier);
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// An established CONNECT-IP session.
pub struct MasqueSession {
    ping: Option<h2::PingPong>,
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    decoder: CapsuleDecoder,
    /// Set once the body stream ends.
    closed: bool,
}

/// The write half of a session, moved to whatever task pumps outbound packets.
pub struct MasqueTx {
    ping: Option<h2::PingPong>,
    send: h2::SendStream<Bytes>,
    closed: bool,
    dropped: u64,
}

/// The read half of a session, moved to whatever task pumps inbound packets.
pub struct MasqueRx {
    recv: h2::RecvStream,
    decoder: CapsuleDecoder,
    closed: bool,
}

impl MasqueSession {
    /// Dial the MASQUE front door over TCP and open the CONNECT-IP tunnel.
    pub async fn connect(
        endpoint: std::net::SocketAddr,
        identity: &Identity,
        pinned_spki: Vec<u8>,
        proxy: Option<&Proxy>,
    ) -> Result<Self> {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            Self::connect_inner(endpoint, identity, pinned_spki, proxy),
        )
        .await
        .context("MASQUE connect timed out")?
    }

    async fn connect_inner(
        endpoint: std::net::SocketAddr,
        identity: &Identity,
        pinned_spki: Vec<u8>,
        proxy: Option<&Proxy>,
    ) -> Result<Self> {
        // A sealed host permits no direct TCP. The proxy is the egress, and the
        // TLS handshake runs inside its CONNECT pipe exactly as it would over a
        // direct socket.
        let tcp: BoxedIo = crate::egress::dial(
            &endpoint.ip().to_string(),
            endpoint.port(),
            proxy,
            CONNECT_TIMEOUT,
        )
        .await
        .with_context(|| format!("TCP to the MASQUE front door {endpoint}"))?;

        let config = tls_config(identity, pinned_spki)?;
        let server_name = ServerName::try_from(MASQUE_SNI)
            .context("invalid MASQUE SNI")?
            .to_owned();
        let tls = TlsConnector::from(config)
            .connect(server_name, tcp)
            .await
            .map_err(|e| {
                crate::hop::at(
                    crate::hop::Hop::Tls,
                    anyhow::anyhow!(
                        "TLS handshake with the MASQUE front door: {}",
                        crate::hop::tls_text(&e)
                    ),
                )
            })?;

        let (client, mut connection) = h2_builder()
            .handshake(tls)
            .await
            .context("HTTP/2 handshake with the MASQUE front door")?;
        // Grab the PING handle before the connection is moved to its task;
        // a MASQUE tunnel that goes idle for too long is torn down by the edge.
        let ping = connection.ping_pong();
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::warn!(%err, "the MASQUE HTTP/2 connection closed");
            }
        });

        let mut client = client.ready().await.context("HTTP/2 client not ready")?;

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(CONNECT_URI)
            .header("cf-connect-proto", "cf-connect-ip")
            .header("capsule-protocol", "?1")
            .header("pq-enabled", "false")
            .header("user-agent", "")
            .body(())
            .context("building the CONNECT-IP request")?;

        let (response, send) = client
            .send_request(request, false)
            .context("sending the CONNECT-IP request")?;

        let response = response.await.context("awaiting the CONNECT-IP response")?;
        let status = response.status();
        if status != StatusCode::OK {
            bail!(
                "CONNECT-IP refused with {status}{}",
                if status.as_u16() == 403 {
                    " (the enrolled certificate was not accepted)"
                } else {
                    ""
                }
            );
        }

        Ok(Self {
            ping,
            send,
            recv: response.into_body(),
            decoder: CapsuleDecoder::new(),
            closed: false,
        })
    }

    /// Split into a write half and a read half so the two directions can be
    /// pumped from different tasks.
    pub fn split(self) -> (MasqueTx, MasqueRx) {
        (
            MasqueTx {
                ping: self.ping,
                send: self.send,
                closed: self.closed,
                dropped: 0,
            },
            MasqueRx {
                recv: self.recv,
                decoder: self.decoder,
                closed: self.closed,
            },
        )
    }

    /// Send one IP packet through the tunnel.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self.closed {
            bail!("the MASQUE session is closed");
        }
        let mut buf = BytesMut::with_capacity(packet.len() + 3);
        capsule::put_capsule(&mut buf, capsule::CAPSULE_DATA, packet);
        self.send
            .send_data(buf.freeze(), false)
            .context("writing a CONNECT-IP DATA capsule")?;
        Ok(())
    }

    /// Receive one IP packet, waiting for more body bytes if needed.
    pub async fn recv_packet(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.decoder.next_packet() {
                return Ok(Some(packet));
            }
            if self.closed {
                return Ok(None);
            }
            match self.recv.data().await {
                Some(Ok(data)) => {
                    let _ = self.recv.flow_control().release_capacity(data.len());
                    self.decoder.push(&data);
                }
                Some(Err(err)) => {
                    self.closed = true;
                    bail!("reading the CONNECT-IP body: {err}");
                }
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            }
        }
    }
}

impl MasqueTx {
    /// Send one IP packet through the tunnel.
    ///
    /// A packet goes out only when the stream has HTTP/2 send capacity for
    /// it. Without capacity, the packet is dropped, as a full router queue
    /// drops it: QUIC and TCP inside the tunnel then see a loss and slow
    /// down. Before, each packet went into the unbounded buffer of h2, so a
    /// large response filled it with no loss and no backpressure.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self.closed {
            bail!("the MASQUE session is closed");
        }
        let mut buf = BytesMut::with_capacity(packet.len() + 3);
        capsule::put_capsule(&mut buf, capsule::CAPSULE_DATA, packet);
        self.send.reserve_capacity(SEND_RESERVE);
        if self.send.capacity() < buf.len() {
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                tracing::debug!(
                    dropped = self.dropped,
                    "MASQUE send capacity is full; packets are dropped"
                );
            }
            return Ok(());
        }
        self.send
            .send_data(buf.freeze(), false)
            .context("writing a CONNECT-IP DATA capsule")?;
        Ok(())
    }

    /// The packets dropped for no send capacity.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Send an HTTP/2 PING to keep the connection alive through idle periods.
    pub fn keepalive(&mut self) -> Result<()> {
        if self.closed {
            bail!("the MASQUE session is closed");
        }
        match self.ping.as_mut() {
            Some(ping) => ping
                .send_ping(h2::Ping::opaque())
                .context("sending an HTTP/2 PING")?,
            None => bail!("HTTP/2 PING is unavailable on this connection"),
        }
        Ok(())
    }

    /// Close the request body, which tears the tunnel down.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.send
                .send_data(Bytes::new(), true)
                .context("closing the CONNECT-IP body")?;
            self.closed = true;
        }
        Ok(())
    }
}

impl MasqueRx {
    /// Receive one IP packet, waiting for more body bytes if needed.
    pub async fn recv_packet(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.decoder.next_packet() {
                return Ok(Some(packet));
            }
            if self.closed {
                return Ok(None);
            }
            match self.recv.data().await {
                Some(Ok(data)) => {
                    let _ = self.recv.flow_control().release_capacity(data.len());
                    self.decoder.push(&data);
                }
                Some(Err(err)) => {
                    self.closed = true;
                    bail!("reading the CONNECT-IP body: {err}");
                }
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The front door sends one small DATA frame for each packet (ACKs).
    /// A full stream window of 59-byte frames, with a reader that waits
    /// before it reads: the session must not close with ENHANCE_YOUR_CALM
    /// (issue 32, live run 41272142304: too_many_data_frames after 4 MiB).
    /// The budget of 8 MiB before held about 42000 of these frames.
    #[tokio::test]
    async fn many_small_data_frames_do_not_close_the_session() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (_request, mut respond) = conn.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let sender = tokio::spawn(async move {
                let mut frame = BytesMut::new();
                capsule::put_capsule(&mut frame, capsule::CAPSULE_DATA, &[0x45; 57]);
                let frame = frame.freeze();
                for _ in 0..STREAM_WINDOW as usize / frame.len() {
                    send.reserve_capacity(frame.len());
                    while send.capacity() < frame.len() {
                        futures::future::poll_fn(|cx| send.poll_capacity(cx))
                            .await
                            .unwrap()
                            .unwrap();
                    }
                    send.send_data(frame.clone(), false).unwrap();
                }
                send.send_data(Bytes::new(), true).unwrap();
            });
            while let Some(next) = conn.accept().await {
                drop(next);
            }
            sender.await.unwrap();
        });
        let (client, connection) = h2_builder().handshake(client_io).await.unwrap();
        tokio::spawn(connection);
        let mut client = client.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(CONNECT_URI)
            .body(())
            .unwrap();
        let (response, send) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        let session = MasqueSession {
            ping: None,
            send,
            recv: response.into_body(),
            decoder: CapsuleDecoder::new(),
            closed: false,
        };
        let (_tx, mut rx) = session.split();
        // A slow receive task: the frames pile up in h2 first.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let mut packets = 0;
        while let Some(_packet) = rx.recv_packet().await.unwrap() {
            packets += 1;
        }
        assert_eq!(packets, STREAM_WINDOW as usize / 59);
        server.abort();
    }

    /// A front door that never reads the CONNECT-IP body: the stream window
    /// fills, and then each packet is dropped (a loss for QUIC), not added
    /// to an unbounded buffer. The sender gets no error.
    #[tokio::test]
    async fn a_full_window_drops_packets() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(16 * 1024)
                .initial_connection_window_size(16 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (_request, mut respond) = conn.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let _send = respond.send_response(response, false).unwrap();
            // Drive the connection, and never read the request body.
            while let Some(next) = conn.accept().await {
                drop(next);
            }
        });
        let (client, connection) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(connection);
        let mut client = client.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(CONNECT_URI)
            .body(())
            .unwrap();
        let (response, send) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        let session = MasqueSession {
            ping: None,
            send,
            recv: response.into_body(),
            decoder: CapsuleDecoder::new(),
            closed: false,
        };
        let (mut tx, _rx) = session.split();
        let packet = vec![0x45u8; 1200];
        // The first packets of a new stream go out at once (a QUIC Initial
        // must not wait for a retransmission).
        for _ in 0..8 {
            tx.send_packet(&packet).unwrap();
        }
        assert_eq!(tx.dropped(), 0);
        for _ in 0..2000 {
            tx.send_packet(&packet).unwrap();
            tokio::task::yield_now().await;
        }
        // 2000 packets are 2.4 MB; the window is 16 KiB.
        assert!(tx.dropped() > 1900, "dropped {}", tx.dropped());
        server.abort();
    }
}
