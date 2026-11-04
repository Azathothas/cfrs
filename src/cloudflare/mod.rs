//! The Cloudflare tunnel edge protocol.
//!
//! # What this is
//!
//! A Cloudflare tunnel holds a long-lived connection to an edge machine. The
//! edge opens a stream per visitor request and the connector answers it by
//! talking to the origin. Two transports carry that connection:
//!
//! * **QUIC**, with ALPN `argotunnel` and SNI `quic.cftunnel.com`. Note the two
//!   strings are *different*: passing the ALPN value as SNI completes key
//!   derivation and then dies silently. This is the single most common mistake
//!   when writing a client, and it is why the constants below are separate.
//! * **HTTP/2**, with SNI `h2.cftunnel.com` and **no ALPN at all**. cloudflared
//!   omits the ALPN extension and then runs an HTTP/2 server on the connection,
//!   because the edge initiates every stream.
//!
//! The QUIC path needs UDP. The HTTP/2 path is TCP, which matters: it is the
//! only transport that can work where UDP is blocked.
//!
//! # Trust
//!
//! The edge certificate chains to Cloudflare-internal roots that are in no
//! public trust store, so they are embedded here. That is the same set
//! `cloudflared` ships, sourced from its `tlsconfig/cloudflare_ca.go` under
//! Apache-2.0.
//!
//! # Credentials
//!
//! Registration is a Cap'n Proto RPC over the first stream. The tunnel secret
//! goes on the wire verbatim, as `TunnelAuth.tunnelSecret`; it is not hashed or
//! otherwise transformed.

pub mod capnp;
pub mod http2;
pub mod quic;
pub mod rpc;
pub mod schema;
pub mod stream;

use std::net::SocketAddr;
use std::sync::Arc;
#[allow(unused_imports)]
use std::time::Duration;

/// ALPN for the QUIC transport.
pub const QUIC_ALPN: &[u8] = b"argotunnel";

/// SNI for the QUIC transport. Deliberately not the same as [`QUIC_ALPN`].
pub const QUIC_SNI: &str = "quic.cftunnel.com";

/// SNI for the HTTP/2 transport.
pub const H2_SNI: &str = "h2.cftunnel.com";

/// SRV record naming the edge, as cloudflared resolves it.
pub const EDGE_SRV: &str = "_v2-origintunneld._tcp.argotunnel.com";

/// Cloudflare-internal roots the edge certificate chains to.
///
/// From `cloudflared`'s `tlsconfig/cloudflare_ca.go`, Apache-2.0.
/// The cloudflared release whose protocol cfrs speaks (the tag of
/// `cloudflared-pin.txt`). Errors that a protocol change can cause name it.
pub const SPEAKS: &str = "cloudflared 2026.10.7";

pub const CF_EDGE_ROOTS_PEM: &[u8] = include_bytes!("cf-edge-roots.pem");

/// The six-byte preamble on a data stream, from `tunnelrpc/quic/protocol.go`.
pub const DATA_STREAM_SIGNATURE: [u8; 6] = [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];

/// The six-byte preamble on an RPC stream that the edge opens to call the
/// connector, from `tunnelrpc/quic/protocol.go`.
pub const RPC_STREAM_SIGNATURE: [u8; 6] = [0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65];

/// The protocol version that follows the data-stream signature.
pub const DATA_STREAM_VERSION: &[u8] = b"01";

/// Which edge transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Try QUIC, fall back to HTTP/2 if it cannot be established.
    Auto,
    /// QUIC only. Requires UDP.
    Quic,
    /// HTTP/2 only. Runs over TCP, so it works where UDP is blocked.
    Http2,
}

impl Protocol {
    /// Parse the `--protocol` value cloudflared accepts.
    pub fn parse(s: &str) -> Result<Protocol, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Protocol::Auto),
            "quic" => Ok(Protocol::Quic),
            "http2" | "h2" => Ok(Protocol::Http2),
            other => Err(format!(
                "unknown protocol {other:?}; expected auto, quic or http2"
            )),
        }
    }

    /// The name as cloudflared spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Auto => "auto",
            Protocol::Quic => "quic",
            Protocol::Http2 => "http2",
        }
    }

    /// The transports to attempt, in order.
    pub fn candidates(&self) -> Vec<Protocol> {
        match self {
            Protocol::Auto => vec![Protocol::Quic, Protocol::Http2],
            Protocol::Quic => vec![Protocol::Quic],
            Protocol::Http2 => vec![Protocol::Http2],
        }
    }
}

/// The IP version of an edge address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeIpVersion {
    V4,
    V6,
}

/// Which IP versions edge discovery returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersionFilter {
    /// IPv4 and IPv6, IPv4 first.
    #[default]
    Auto,
    V4Only,
    V6Only,
}

impl IpVersionFilter {
    /// True when `version` passes the filter.
    pub fn allows(self, version: EdgeIpVersion) -> bool {
        match self {
            Self::Auto => true,
            Self::V4Only => version == EdgeIpVersion::V4,
            Self::V6Only => version == EdgeIpVersion::V6,
        }
    }
}

/// One edge address (port 7844 in normal use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdgeAddr {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub version: EdgeIpVersion,
    /// The index of the SRV target (region1 is 0, region2 is 1); 0 when
    /// unknown.
    pub region: u8,
}

impl EdgeAddr {
    /// Make an address from a socket address (region 0).
    pub fn new(socket: SocketAddr) -> Self {
        Self {
            ip: socket.ip(),
            port: socket.port(),
            version: if socket.is_ipv4() {
                EdgeIpVersion::V4
            } else {
                EdgeIpVersion::V6
            },
            region: 0,
        }
    }

    /// The same address in region `region`.
    pub fn in_region(self, region: u8) -> Self {
        Self { region, ..self }
    }

    pub fn socket(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// The order of `edges` for the connection `conn_index`: the regions turn
/// by the index, so connection 1 (and 3) dials region2 first, as
/// cloudflared does. A fault of one region then does not hit each
/// connection. The order of the IP versions and the order in a region stay.
pub fn for_connection(edges: &[EdgeAddr], conn_index: u8) -> Vec<EdgeAddr> {
    let mut regions: Vec<u8> = edges.iter().map(|e| e.region).collect();
    regions.sort_unstable();
    regions.dedup();
    let mut versions: Vec<EdgeIpVersion> = Vec::new();
    for e in edges {
        if !versions.contains(&e.version) {
            versions.push(e.version);
        }
    }
    let count = regions.len().max(1);
    let shift = usize::from(conn_index) % count;
    let mut out = edges.to_vec();
    out.sort_by_key(|e| {
        let version = versions.iter().position(|v| *v == e.version);
        let region = regions.iter().position(|r| *r == e.region).unwrap_or(0);
        (version, (region + count - shift) % count)
    });
    out
}

/// Credentials for one tunnel, as returned by the provisioning API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Hex account tag from the provisioning response.
    pub account_tag: String,
    /// Raw secret bytes, sent to the edge untransformed.
    pub tunnel_secret: Vec<u8>,
    /// Tunnel UUID.
    pub tunnel_id: String,
}

impl Credentials {
    /// Parse a tunnel UUID into its 16 raw bytes, which is how it goes on the
    /// wire (`tunnelId :Data`).
    pub fn tunnel_id_bytes(&self) -> Result<[u8; 16], String> {
        parse_uuid(&self.tunnel_id)
    }
}

/// Parse a hyphenated UUID into 16 bytes.
fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!("tunnel id {:?} is not a 32-character uuid", s));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex in uuid {s:?}: {e}"))?;
    }
    Ok(out)
}

/// Why the edge could not be found or reached.
#[derive(Debug)]
pub enum EdgeError {
    /// The SRV lookup failed.
    Resolve(String),
    /// A transport could not connect.
    Connect(String),
    /// Registration was refused.
    Registration(String),
    /// The edge asked for something this client does not implement.
    Unsupported(String),
}

impl std::fmt::Display for EdgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeError::Resolve(m) => write!(f, "edge discovery failed: {m}"),
            EdgeError::Connect(m) => write!(f, "edge connect failed: {m}"),
            EdgeError::Registration(m) => write!(f, "registration refused: {m}"),
            EdgeError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for EdgeError {}

/// Build a rustls client config for the edge.
///
/// The embedded Cloudflare roots are added alongside the platform's, because
/// the edge presents a certificate that chains to internal CAs. `alpn` is
/// empty for the HTTP/2 transport, which cloudflared relies on: the edge
/// initiates every stream, so negotiating `h2` changes the handshake shape and
/// breaks it.
pub fn edge_tls_config(alpn: &[u8]) -> Result<Arc<rustls::ClientConfig>, String> {
    let alpns: &[&[u8]] = if alpn.is_empty() { &[] } else { &[alpn] };
    crate::trust::client_config(&[CF_EDGE_ROOTS_PEM], alpns)
        .map(Arc::new)
        .map_err(|e| format!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// podssh, cloudflared: connection 0 starts at region1, connection 1 at
    /// region2. IPv4 stays before IPv6.
    #[test]
    fn each_connection_starts_at_another_region() {
        let at = |text: &str, region: u8| EdgeAddr::new(text.parse().unwrap()).in_region(region);
        let edges = vec![
            at("198.41.192.1:7844", 0),
            at("198.41.192.2:7844", 0),
            at("198.41.200.1:7844", 1),
            at("198.41.200.2:7844", 1),
            at("[2606:4700:a0::1]:7844", 0),
            at("[2606:4700:a8::1]:7844", 1),
        ];
        let ips = |index: u8| -> Vec<String> {
            for_connection(&edges, index)
                .iter()
                .map(|e| e.ip.to_string())
                .collect()
        };
        assert_eq!(
            ips(0),
            [
                "198.41.192.1",
                "198.41.192.2",
                "198.41.200.1",
                "198.41.200.2",
                "2606:4700:a0::1",
                "2606:4700:a8::1"
            ]
        );
        assert_eq!(
            ips(1),
            [
                "198.41.200.1",
                "198.41.200.2",
                "198.41.192.1",
                "198.41.192.2",
                "2606:4700:a8::1",
                "2606:4700:a0::1"
            ]
        );
        assert_eq!(ips(2), ips(0));
        assert_eq!(ips(3), ips(1));
        // One region (CFRS_EDGE): the order stays.
        let one: Vec<EdgeAddr> = edges.iter().map(|e| e.in_region(0)).collect();
        assert_eq!(for_connection(&one, 1), one);
    }

    #[test]
    fn speaks_names_the_tag_of_the_pin() {
        let pin = include_str!("cloudflared-pin.txt");
        let tag = pin
            .lines()
            .find_map(|l| l.strip_prefix("tag "))
            .expect("the pin has a tag");
        assert_eq!(SPEAKS, format!("cloudflared {}", tag.trim()));
    }

    #[test]
    fn quic_alpn_and_sni_are_different_strings() {
        // Conflating these is the classic way to get a silent 10s handshake
        // timeout, so the distinction is asserted rather than left to a comment.
        assert_eq!(QUIC_ALPN, b"argotunnel");
        assert_eq!(QUIC_SNI, "quic.cftunnel.com");
        assert_ne!(
            QUIC_ALPN,
            QUIC_SNI.as_bytes(),
            "SNI must not be the ALPN value"
        );
    }

    #[test]
    fn the_data_stream_preamble_matches_the_source() {
        // From tunnelrpc/quic/protocol.go: dataStreamProtocolSignature.
        assert_eq!(DATA_STREAM_SIGNATURE, [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E]);
        assert_eq!(DATA_STREAM_VERSION, b"01");
    }

    #[test]
    fn protocols_parse_the_way_cloudflared_spells_them() {
        assert_eq!(Protocol::parse("auto").unwrap(), Protocol::Auto);
        assert_eq!(Protocol::parse("QUIC").unwrap(), Protocol::Quic);
        assert_eq!(Protocol::parse("http2").unwrap(), Protocol::Http2);
        assert_eq!(Protocol::parse("h2").unwrap(), Protocol::Http2);
        assert_eq!(Protocol::parse("").unwrap(), Protocol::Auto);
        assert!(Protocol::parse("carrier-pigeon").is_err());
    }

    #[test]
    fn auto_tries_quic_first_then_falls_back_to_http2() {
        // QUIC first because it is faster where it works; HTTP/2 second because
        // it is the only option when UDP is blocked.
        assert_eq!(
            Protocol::Auto.candidates(),
            vec![Protocol::Quic, Protocol::Http2]
        );
        assert_eq!(Protocol::Quic.candidates(), vec![Protocol::Quic]);
        assert_eq!(Protocol::Http2.candidates(), vec![Protocol::Http2]);
    }

    #[test]
    fn uuids_parse_to_their_sixteen_bytes() {
        let bytes = parse_uuid("c1267064-5604-4d16-9a83-66b7ed37f182").expect("valid uuid");
        assert_eq!(bytes[0], 0xc1);
        assert_eq!(bytes[15], 0x82);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn malformed_uuids_are_rejected() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("c126706456044d169a8366b7ed37f182z").is_err());
    }

    #[test]
    fn credentials_expose_the_raw_tunnel_id_bytes() {
        let creds = Credentials {
            account_tag: "5ab4e9dfbd435d24068829fda0077963".into(),
            tunnel_secret: vec![7u8; 32],
            tunnel_id: "c1267064-5604-4d16-9a83-66b7ed37f182".into(),
        };
        assert_eq!(creds.tunnel_id_bytes().unwrap()[0], 0xc1);
    }

    #[test]
    fn the_embedded_edge_roots_are_real_certificates() {
        // If this file were emptied or truncated, TLS to the edge would fail
        // with UnknownIssuer, so assert the roots actually parse.
        assert!(
            CF_EDGE_ROOTS_PEM.len() > 1000,
            "the embedded roots look empty: {} bytes",
            CF_EDGE_ROOTS_PEM.len()
        );
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let certs: Vec<_> = CertificateDer::pem_slice_iter(CF_EDGE_ROOTS_PEM)
            .filter_map(|c| c.ok())
            .collect();
        assert!(
            certs.len() >= 3,
            "expected Cloudflare's edge roots, found {}",
            certs.len()
        );
    }

    #[test]
    fn an_edge_tls_config_builds_for_both_transports() {
        assert!(
            edge_tls_config(QUIC_ALPN).is_ok(),
            "QUIC config should build with the argotunnel ALPN"
        );
        let h2 = edge_tls_config(&[]).expect("h2 config");
        assert!(
            h2.alpn_protocols.is_empty(),
            "the HTTP/2 transport must send no ALPN"
        );
        let quic = edge_tls_config(QUIC_ALPN).expect("quic config");
        assert_eq!(quic.alpn_protocols, vec![b"argotunnel".to_vec()]);
    }
}
