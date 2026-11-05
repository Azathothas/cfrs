//! The QUIC edge transport.
//!
//! # The handshake
//!
//! QUIC is the default and the faster transport, but it needs UDP, which many
//! networks and most sandboxes do not allow. It is here for the normal case;
//! [`super::http2`] is what works where UDP is blocked.
//!
//! Two details decide whether this works at all:
//!
//! * **ALPN is `argotunnel`** and **SNI is `quic.cftunnel.com`**. These are
//!   *different strings*. Using the ALPN value as SNI completes key derivation
//!   and then dies silently after the handshake timeout, which is the most
//!   common way to get this transport wrong and the hardest to diagnose.
//! * **The edge certificate chains to Cloudflare-internal roots**, which are in
//!   no public trust store, so [`super::CF_EDGE_ROOTS_PEM`] is added to the
//!   platform roots rather than replacing them.
//!
//! # Streams
//!
//! The **first** stream the client opens is the control plane; the edge assumes
//! so, and opens everything else. Each visitor request then arrives as its own
//! bidi stream, framed by a six-byte signature and a version before the
//! Cap'n Proto payload.

use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, TransportConfig};

use super::{EdgeAddr, EdgeError};

/// Handshake timeout for the QUIC edge connection.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout. The edge sends keepalives, so a short idle timeout would drop
/// an otherwise healthy tunnel between them.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often to send a keepalive.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(1);

pub use super::MAX_EDGE_STREAMS;

/// The QUIC transport settings of an edge connection, with `initial_mtu` as
/// the first UDP payload size.
pub fn transport_config(initial_mtu: u16) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT).expect("30 s is a valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.initial_mtu(initial_mtu);
    transport.max_concurrent_bidi_streams(MAX_EDGE_STREAMS.into());
    transport
}

/// The rustls config for the QUIC edge.
///
/// Split out from [`client_config`] so the ALPN and the trust roots can be
/// asserted on directly: quinn's own config has no getters, so a test that
/// reads back a quinn config would prove nothing.
pub fn tls_config() -> Result<Arc<rustls::ClientConfig>, EdgeError> {
    super::edge_tls_config(super::QUIC_ALPN).map_err(EdgeError::Connect)
}

/// Build a quinn client config for the edge.
pub fn client_config() -> Result<ClientConfig, EdgeError> {
    let tls = tls_config()?;

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| EdgeError::Connect(format!("quic tls config: {e}")))?;

    let mut config = ClientConfig::new(Arc::new(quic_tls));

    // 1252 is the IPv4-safe payload size that avoids fragmentation-related
    // blackholing on consumer routers. cloudflared uses the same value.
    let transport = transport_config(1252);
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Make a client endpoint on an ephemeral UDP port, with the edge client
/// configuration.
pub fn build_endpoint() -> anyhow::Result<Endpoint> {
    let bind: std::net::SocketAddr = "[::]:0".parse().expect("a valid address");
    let mut endpoint = match Endpoint::client(bind) {
        Ok(endpoint) => endpoint,
        // A host without IPv6 refuses `[::]`; use IPv4 only.
        Err(_) => Endpoint::client("0.0.0.0:0".parse().expect("a valid address")).map_err(|e| {
            anyhow::anyhow!(
                "could not open a local UDP socket: {e}. QUIC needs UDP; \
                 where it is blocked, use --protocol http2"
            )
        })?,
    };
    endpoint.set_default_client_config(client_config().map_err(|e| anyhow::anyhow!("{e}"))?);
    Ok(endpoint)
}

/// Complete a QUIC handshake with `addr`. The SNI is `quic.cftunnel.com`
/// for every address.
pub async fn dial(endpoint: &Endpoint, addr: &EdgeAddr) -> anyhow::Result<quinn::Connection> {
    let socket = addr.socket();
    let connecting = endpoint
        .connect(socket, super::QUIC_SNI)
        .map_err(|e| anyhow::anyhow!("could not start connecting to {socket}: {e}"))?;
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(anyhow::anyhow!("QUIC handshake with {socket}: {e}")),
        Err(_) => Err(anyhow::anyhow!("QUIC handshake with {socket} timed out")),
    }
}

/// Try the addresses in sequence. Return the first connection.
pub async fn dial_any(
    endpoint: &Endpoint,
    edges: &[EdgeAddr],
) -> anyhow::Result<quinn::Connection> {
    let mut failures = Vec::new();
    for addr in edges {
        match dial(endpoint, addr).await {
            Ok(conn) => return Ok(conn),
            Err(err) => {
                tracing::debug!(error = %err, "QUIC edge attempt failed");
                failures.push(err.to_string());
            }
        }
    }
    if failures.is_empty() {
        anyhow::bail!("no edge addresses to dial");
    }
    anyhow::bail!("no edge answered: {}", failures.join("; "))
}

/// A QUIC connection in memory for tests: a local server (in the place of
/// the edge) and a client with the edge transport config of podnet.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub struct Pair {
        /// The connection on the side of the edge.
        pub edge: quinn::Connection,
        /// The connection on the side of podnet.
        pub client: quinn::Connection,
        _endpoints: (Endpoint, Endpoint),
    }

    pub async fn local_pair() -> Pair {
        crate::init_crypto();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["edge.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"podnet-test".to_vec()];
        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let server = Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let tls = crate::trust::client_config(&[cert.pem().as_bytes()], &[b"podnet-test"]).unwrap();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(transport_config(1252)));
        let client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connecting = client.connect_with(config, addr, "edge.test").unwrap();
        let (edge, client_conn) = tokio::join!(
            async { server.accept().await.unwrap().await.unwrap() },
            async { connecting.await.unwrap() }
        );
        Pair {
            edge,
            client: client_conn,
            _endpoints: (server, client),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A local QUIC server opens 200 streams to the client and keeps them
    /// open, as the edge does with 200 requests at the same time. With the
    /// default of quinn (100), the stream after the 100th waits.
    #[tokio::test]
    async fn the_edge_can_open_200_streams_at_the_same_time() {
        crate::test_host::need_loopback!();
        let pair = testing::local_pair().await;
        let edge = pair.edge.clone();
        let opener = tokio::spawn(async move {
            let mut streams = Vec::new();
            for i in 0..200 {
                let (mut send, recv) = tokio::time::timeout(Duration::from_secs(5), edge.open_bi())
                    .await
                    .unwrap_or_else(|_| panic!("stream {i} waits for the limit of the client"))
                    .unwrap();
                send.write_all(b"x").await.unwrap();
                streams.push((send, recv));
            }
            streams
        });
        let accept = async {
            let mut accepted = Vec::new();
            for _ in 0..200 {
                let (send, mut recv) = pair.client.accept_bi().await.unwrap();
                let mut byte = [0u8; 1];
                recv.read_exact(&mut byte).await.unwrap();
                accepted.push((send, recv));
            }
            accepted
        };
        let (accepted, opened) = tokio::join!(accept, opener);
        assert_eq!((accepted.len(), opened.unwrap().len()), (200, 200));
    }

    #[test]
    fn alpn_and_sni_are_distinct() {
        assert_eq!(super::super::QUIC_ALPN, b"argotunnel");
        assert_eq!(super::super::QUIC_SNI, "quic.cftunnel.com");
        assert_ne!(super::super::QUIC_SNI.as_bytes(), super::super::QUIC_ALPN);
    }

    #[test]
    fn the_quic_tls_config_offers_exactly_the_argotunnel_alpn() {
        let tls = tls_config().expect("quic tls config");
        assert_eq!(
            tls.alpn_protocols,
            vec![b"argotunnel".to_vec()],
            "the edge accepts one protocol; offering anything else fails selection"
        );
    }

    #[test]
    fn quinn_accepts_the_tls_config_it_is_given() {
        // The failure this catches is real: rustls 0.23 and quinn disagree
        // about crypto provider versions, and quinn's try_from is where that
        // surfaces, with an error that reads as a TLS problem at handshake.
        client_config().expect("quinn accepts the edge tls config");
    }
}
