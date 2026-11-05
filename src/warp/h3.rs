//! A MASQUE CONNECT-IP session over HTTP/3 on UDP 443 (issue 157).
//!
//! The session of [`super::session`] is HTTP/2 on TCP 443: one TCP
//! connection carries each packet, so a lost segment stops each flow. Over
//! HTTP/3, each IP packet is an HTTP datagram (RFC 9297) in a QUIC datagram,
//! and a lost one is lost alone. The request is an extended CONNECT (RFC
//! 9220) with `:protocol cf-connect-ip`. The client certificate and the
//! pinned key of the front door are the same as for HTTP/2.
//!
//! The HTTP/3 client is minimal: a control stream with SETTINGS, one
//! request stream, QPACK with the static table only (the dynamic table has a
//! capacity of 0), and the datagrams. A packet that does not fit in a
//! datagram goes as a DATA capsule on the request stream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use bytes::{Bytes, BytesMut};

use super::capsule;

/// The ALPN of HTTP/3.
pub const ALPN: &[u8] = b"h3";

/// The HTTP/3 frame types that the client uses (RFC 9114, section 7.2).
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;

/// The SETTINGS of the client: extended CONNECT (RFC 9220), HTTP datagrams
/// (RFC 9297), and the draft value of the datagram setting that the front
/// door can still read.
const SETTINGS: &[(u64, u64)] = &[(0x08, 1), (0x33, 1), (0x276, 1)];

/// The QUIC transport of the session.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(10);
/// The first UDP payload size. 1242 bytes reach the front door on each path
/// that podnet knows; MTU discovery then goes up.
const INITIAL_MTU: u16 = 1242;
/// The most bytes of a frame that the client reads (a DATA frame of
/// capsules, or a HEADERS frame).
const MAX_FRAME: usize = 1 << 20;

// ── QUIC variable-length integers (RFC 9000, section 16) ─────────────────

pub fn put_varint(buf: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        buf.push(v as u8);
    } else if v < 1 << 14 {
        buf.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        buf.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        buf.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// A varint at the start of `buf`, and its length.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for b in &bytes[1..] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, len))
}

/// One HTTP/3 frame.
pub fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    put_varint(&mut out, kind);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// The frames of a stream, as its bytes come.
#[derive(Default)]
pub struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole frame: its type and its payload.
    pub fn next_frame(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        let Some((kind, a)) = get_varint(&self.buf) else {
            return Ok(None);
        };
        let Some((len, b)) = get_varint(&self.buf[a..]) else {
            return Ok(None);
        };
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_FRAME {
            bail!("an HTTP/3 frame of {len} bytes (the most is {MAX_FRAME})");
        }
        let start = a + b;
        if self.buf.len() < start + len {
            return Ok(None);
        }
        let payload = self.buf[start..start + len].to_vec();
        self.buf.drain(..start + len);
        Ok(Some((kind, payload)))
    }
}

// ── QPACK with the static table only (RFC 9204) ───────────────────────────

/// A prefixed integer (RFC 7541, section 5.1) with `bits` bits in the first
/// byte, whose other bits are `flags`.
fn put_prefixed(buf: &mut Vec<u8>, flags: u8, bits: u8, mut v: u64) {
    let max = (1u64 << bits) - 1;
    if v < max {
        buf.push(flags | v as u8);
        return;
    }
    buf.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        buf.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    buf.push(v as u8);
}

fn get_prefixed(buf: &[u8], bits: u8) -> Option<(u64, usize)> {
    let max = (1u64 << bits) - 1;
    let mut v = u64::from(*buf.first()?) & max;
    if v < max {
        return Some((v, 1));
    }
    let mut shift = 0;
    for (i, b) in buf.iter().enumerate().skip(1) {
        v = v.checked_add(u64::from(b & 0x7f).checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
    None
}

/// A string literal with no Huffman code: the H bit and a length of `bits`
/// bits, after `flags`.
fn put_string(buf: &mut Vec<u8>, flags: u8, bits: u8, s: &str) {
    put_prefixed(buf, flags, bits, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

/// The field section of the extended CONNECT of CONNECT-IP.
pub fn connect_ip_headers(authority: &str, protocol: &str) -> Vec<u8> {
    let mut out = vec![0x00, 0x00]; // Required Insert Count 0, Base 0.
    out.push(0xc0 | 15); // :method CONNECT (static 15)
    out.push(0xc0 | 23); // :scheme https (static 23)
    out.push(0xc0 | 1); // :path / (static 1)
                        // :authority (static name 0), a literal value.
    put_prefixed(&mut out, 0x50, 4, 0);
    put_string(&mut out, 0x00, 7, authority);
    for (name, value) in [
        (":protocol", protocol),
        ("capsule-protocol", "?1"),
        ("pq-enabled", "false"),
    ] {
        // A literal field line with a literal name (001NHxxx).
        put_string(&mut out, 0x20, 3, name);
        put_string(&mut out, 0x00, 7, value);
    }
    out
}

/// The `:status` of the static table, by index.
fn static_status(index: u64) -> Option<u16> {
    Some(match index {
        24 => 103,
        25 => 200,
        26 => 304,
        27 => 404,
        28 => 503,
        63 => 100,
        64 => 204,
        65 => 206,
        66 => 302,
        67 => 400,
        68 => 403,
        69 => 421,
        70 => 425,
        71 => 500,
        _ => return None,
    })
}

/// A string literal: its bytes and whether they are Huffman coded.
fn get_string(buf: &[u8], bits: u8) -> Option<(&[u8], bool, usize)> {
    let huffman = buf.first()? & (1 << bits) != 0;
    let (len, a) = get_prefixed(buf, bits)?;
    let len = usize::try_from(len).ok()?;
    let bytes = buf.get(a..a + len)?;
    Some((bytes, huffman, a + len))
}

/// The `:status` of a response field section. A status as a Huffman coded
/// literal is not read (0); the static table has the usual ones.
pub fn response_status(section: &[u8]) -> Result<u16> {
    let bad = || anyhow::anyhow!("an HTTP/3 field section that the client cannot read");
    let (ric, a) = get_prefixed(section, 8).ok_or_else(bad)?;
    if ric != 0 {
        bail!("the response uses the QPACK dynamic table, which has a capacity of 0");
    }
    let (_, b) = get_prefixed(&section[a..], 7).ok_or_else(bad)?;
    let mut i = a + b;
    let mut status = None;
    while i < section.len() {
        let rest = &section[i..];
        let first = rest[0];
        if first & 0x80 != 0 {
            // Indexed field line (1Txxxxxx).
            let (index, n) = get_prefixed(rest, 6).ok_or_else(bad)?;
            if first & 0x40 == 0 {
                bail!("the response uses the QPACK dynamic table");
            }
            status = status.or(static_status(index));
            i += n;
        } else if first & 0xc0 == 0x40 {
            // Literal with a name reference (01NTxxxx).
            let (index, n) = get_prefixed(rest, 4).ok_or_else(bad)?;
            if first & 0x10 == 0 {
                bail!("the response uses the QPACK dynamic table");
            }
            let (value, huffman, m) = get_string(&rest[n..], 7).ok_or_else(bad)?;
            if static_status(index).is_some() || index == 24 {
                status = status.or_else(|| {
                    if huffman {
                        Some(0)
                    } else {
                        std::str::from_utf8(value).ok()?.parse().ok()
                    }
                });
            }
            i += n + m;
        } else if first & 0xe0 == 0x20 {
            // Literal with a literal name (001NHxxx).
            let (name, name_huffman, n) = get_string(rest, 3).ok_or_else(bad)?;
            let (value, huffman, m) = get_string(&rest[n..], 7).ok_or_else(bad)?;
            if !name_huffman && name == b":status" {
                status = status.or_else(|| {
                    if huffman {
                        Some(0)
                    } else {
                        std::str::from_utf8(value).ok()?.parse().ok()
                    }
                });
            }
            i += n + m;
        } else {
            bail!("the response uses the QPACK dynamic table (post-base)");
        }
    }
    status.ok_or_else(|| anyhow::anyhow!("the response has no :status"))
}

// ── The session ───────────────────────────────────────────────────────────

/// The write half of an HTTP/3 session.
pub struct H3Tx {
    conn: quinn::Connection,
    send: quinn::SendStream,
    /// The control stream: it must stay open for the life of the session.
    _control: quinn::SendStream,
    /// The endpoint (its UDP socket) of the connection.
    _endpoint: quinn::Endpoint,
    /// The Quarter Stream ID and the Context ID 0 of each datagram.
    prefix: Vec<u8>,
}

/// The read half of an HTTP/3 session.
pub struct H3Rx {
    conn: quinn::Connection,
    recv: quinn::RecvStream,
    frames: Frames,
    quarter: u64,
}

/// What came from the front door.
pub enum Incoming {
    /// One IP packet (a datagram).
    Packet(Bytes),
    /// Bytes of capsules (DATA frames of the request stream).
    Capsules(Vec<u8>),
}

/// The QUIC client configuration of the session.
fn client_config(tls: Arc<rustls::ClientConfig>) -> Result<quinn::ClientConfig> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| anyhow::anyhow!("rustls to quinn: {err}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(IDLE_TIMEOUT).expect("a valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.initial_mtu(INITIAL_MTU);
    transport.datagram_receive_buffer_size(Some(4 << 20));
    transport.datagram_send_buffer_size(4 << 20);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// A QUIC connection with HTTP/3 (the control stream is open, the streams
/// of the server are read and dropped).
pub struct H3Conn {
    pub conn: quinn::Connection,
    control: quinn::SendStream,
    endpoint: quinn::Endpoint,
}

/// QUIC with HTTP/3 to `endpoint` (UDP), with the TLS config `tls` (its
/// ALPN must be [`ALPN`]).
pub async fn open(
    endpoint: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    sni: &str,
) -> Result<H3Conn> {
    let bind: SocketAddr = if endpoint.is_ipv4() {
        "0.0.0.0:0".parse().expect("an address")
    } else {
        "[::]:0".parse().expect("an address")
    };
    let mut quic = quinn::Endpoint::client(bind).context("a UDP socket for HTTP/3")?;
    quic.set_default_client_config(client_config(tls)?);
    let conn = quic
        .connect(endpoint, sni)
        .context("QUIC to the front door")?
        .await
        .map_err(|e| anyhow::anyhow!("QUIC to the front door {endpoint} (UDP, {sni}): {e}"))?;

    // The control stream: its type (0x00) and SETTINGS.
    let mut control = conn.open_uni().await.context("the HTTP/3 control stream")?;
    let mut settings = Vec::new();
    for (id, value) in SETTINGS {
        put_varint(&mut settings, *id);
        put_varint(&mut settings, *value);
    }
    let mut first = vec![0x00];
    first.extend_from_slice(&frame(FRAME_SETTINGS, &settings));
    control
        .write_all(&first)
        .await
        .context("the HTTP/3 SETTINGS")?;
    // The streams of the server (control, QPACK) are read and dropped.
    let accept = conn.clone();
    tokio::spawn(async move {
        while let Ok(mut stream) = accept.accept_uni().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(Some(_)) = stream.read(&mut buf).await {}
            });
        }
    });
    Ok(H3Conn {
        conn,
        control,
        endpoint: quic,
    })
}

/// Send the request `headers` on a new stream, and read the status of the
/// answer. The stream, and the frames after the answer.
pub async fn request(
    conn: &quinn::Connection,
    headers: &[u8],
) -> Result<(quinn::SendStream, quinn::RecvStream, Frames, u16)> {
    let (mut send, mut recv) = conn.open_bi().await.context("an HTTP/3 request stream")?;
    send.write_all(&frame(FRAME_HEADERS, headers))
        .await
        .context("sending the HTTP/3 request")?;
    let mut frames = Frames::default();
    let status = loop {
        if let Some((kind, payload)) = frames.next_frame()? {
            if kind == FRAME_HEADERS {
                break response_status(&payload)?;
            }
            continue;
        }
        match recv.read_chunk(64 * 1024, true).await {
            Ok(Some(chunk)) => frames.push(&chunk.bytes),
            Ok(None) => bail!("the front door closed the request stream with no answer"),
            Err(err) => bail!("reading the HTTP/3 answer: {err}"),
        }
    };
    Ok((send, recv, frames, status))
}

/// Open a CONNECT-IP session over HTTP/3 to `endpoint` (UDP), with the TLS
/// config of the session (`tls` must have the ALPN [`ALPN`]).
pub async fn connect(
    endpoint: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    sni: &str,
    authority: &str,
) -> Result<(H3Tx, H3Rx)> {
    let H3Conn {
        conn,
        control,
        endpoint: quic,
    } = open(endpoint, tls, sni).await?;
    let headers = connect_ip_headers(authority, "cf-connect-ip");
    let (send, recv, frames, status) = request(&conn, &headers).await?;
    if status != 200 {
        bail!(
            "CONNECT-IP over HTTP/3 refused with {status}{}",
            if status == 403 {
                " (the enrolled certificate was not accepted)"
            } else {
                ""
            }
        );
    }
    let id = u64::from(send.id());
    let quarter = id / 4;
    let mut prefix = Vec::new();
    put_varint(&mut prefix, quarter);
    put_varint(&mut prefix, 0);
    tracing::debug!(
        max_datagram = ?conn.max_datagram_size(),
        "the CONNECT-IP session over HTTP/3 is open"
    );
    Ok((
        H3Tx {
            conn: conn.clone(),
            send,
            _control: control,
            _endpoint: quic,
            prefix,
        },
        H3Rx {
            conn,
            recv,
            frames,
            quarter,
        },
    ))
}

impl H3Tx {
    /// Send each packet as a datagram; one that does not fit goes as a DATA
    /// capsule on the request stream.
    pub async fn send_packets<P: AsRef<[u8]>>(&mut self, packets: &[P]) -> Result<()> {
        let mut stream = BytesMut::new();
        for packet in packets {
            let packet = packet.as_ref();
            let fits = self
                .conn
                .max_datagram_size()
                .is_some_and(|max| self.prefix.len() + packet.len() <= max);
            if fits {
                let mut d = BytesMut::with_capacity(self.prefix.len() + packet.len());
                d.extend_from_slice(&self.prefix);
                d.extend_from_slice(packet);
                match self.conn.send_datagram_wait(d.freeze()).await {
                    Ok(()) => continue,
                    Err(quinn::SendDatagramError::TooLarge) => {}
                    Err(err) => bail!("an HTTP/3 datagram: {err}"),
                }
            }
            capsule::put_capsule(&mut stream, capsule::CAPSULE_DATA, packet);
        }
        if !stream.is_empty() {
            self.send
                .write_all(&frame(FRAME_DATA, &stream))
                .await
                .context("a DATA capsule on the CONNECT-IP stream")?;
        }
        Ok(())
    }

    /// Close the request stream and the connection.
    pub fn close(&mut self) {
        let _ = self.send.finish();
        self.conn.close(0u32.into(), b"");
    }

    /// The connection, for the liveness check.
    pub fn connection(&self) -> quinn::Connection {
        self.conn.clone()
    }
}

impl H3Rx {
    /// The next packet or capsule bytes; `None` at the end of the session.
    pub async fn next(&mut self) -> Result<Option<Incoming>> {
        loop {
            if let Some((kind, payload)) = self.frames.next_frame()? {
                if kind == FRAME_DATA {
                    return Ok(Some(Incoming::Capsules(payload)));
                }
                continue;
            }
            tokio::select! {
                datagram = self.conn.read_datagram() => match datagram {
                    Ok(d) => {
                        if let Some(packet) = self.packet_of(d) {
                            return Ok(Some(Incoming::Packet(packet)));
                        }
                    }
                    Err(quinn::ConnectionError::LocallyClosed) => return Ok(None),
                    Err(err) => bail!("the HTTP/3 session: {err}"),
                },
                chunk = self.recv.read_chunk(64 * 1024, true) => match chunk {
                    Ok(Some(chunk)) => self.frames.push(&chunk.bytes),
                    Ok(None) => return Ok(None),
                    Err(err) => bail!("reading the CONNECT-IP stream: {err}"),
                },
            }
        }
    }

    /// The IP packet of a datagram of this request with the Context ID 0.
    fn packet_of(&self, d: Bytes) -> Option<Bytes> {
        let (quarter, a) = get_varint(&d)?;
        let (context, b) = get_varint(&d[a..])?;
        (quarter == self.quarter && context == 0).then(|| d.slice(a + b..))
    }
}

/// Ready with an error when the QUIC connection closes (the keepalive and
/// the idle timeout of QUIC find a dead path).
pub async fn closed(conn: quinn::Connection) -> Result<()> {
    let reason = conn.closed().await;
    bail!("the HTTP/3 session closed: {reason}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_and_frames() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(get_varint(&b), Some((v, b.len())), "{v}");
        }
        // RFC 9000, appendix A.1.
        assert_eq!(get_varint(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(get_varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494878333, 4)));
        let mut frames = Frames::default();
        let one = frame(FRAME_HEADERS, b"abc");
        let two = frame(FRAME_DATA, &[7; 300]);
        frames.push(&one[..2]);
        assert!(frames.next_frame().unwrap().is_none());
        frames.push(&one[2..]);
        frames.push(&two);
        assert_eq!(
            frames.next_frame().unwrap(),
            Some((FRAME_HEADERS, b"abc".to_vec()))
        );
        assert_eq!(
            frames.next_frame().unwrap(),
            Some((FRAME_DATA, vec![7; 300]))
        );
        assert!(frames.next_frame().unwrap().is_none());
    }

    #[test]
    fn prefixed_integers() {
        // RFC 7541, C.1: 10 with a 5-bit prefix; 1337 with a 5-bit prefix.
        let mut b = Vec::new();
        put_prefixed(&mut b, 0, 5, 10);
        assert_eq!(b, [10]);
        b.clear();
        put_prefixed(&mut b, 0, 5, 1337);
        assert_eq!(b, [31, 154, 10]);
        assert_eq!(get_prefixed(&b, 5), Some((1337, 3)));
    }

    #[test]
    fn the_request_and_the_status() {
        let section = connect_ip_headers("cloudflareaccess.com", "cf-connect-ip");
        assert_eq!(&section[..5], &[0, 0, 0xcf, 0xd7, 0xc1]);
        assert!(section.windows(13).any(|w| w == b"cf-connect-ip"));
        assert!(section.windows(9).any(|w| w == b":protocol"));
        // :status 200 (static 25), then a literal header.
        let mut answer = vec![0, 0, 0xc0 | 25];
        put_string(&mut answer, 0x20, 3, "server");
        put_string(&mut answer, 0, 7, "cloudflare");
        assert_eq!(response_status(&answer).unwrap(), 200);
        // 403 is static 68: more than the 6-bit prefix holds.
        let mut refused = vec![0, 0];
        put_prefixed(&mut refused, 0xc0, 6, 68);
        assert_eq!(refused.len(), 4);
        assert_eq!(response_status(&refused).unwrap(), 403);
        // A literal value with a name reference to :status.
        let mut literal = vec![0, 0];
        put_prefixed(&mut literal, 0x50, 4, 24);
        put_string(&mut literal, 0, 7, "429");
        assert_eq!(response_status(&literal).unwrap(), 429);
        // The dynamic table is refused.
        assert!(response_status(&[1, 0, 0x80]).is_err());
        assert!(response_status(&[0, 0, 0x80 | 2]).is_err());
        assert!(response_status(&[0, 0]).is_err());
    }
}
