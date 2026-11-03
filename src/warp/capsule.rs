//! RFC 9297 capsules and the CONNECT-IP capsule types of RFC 9484.
//!
//! Over HTTP/2 there are no QUIC datagrams, so IP packets travel inside
//! `CAPSULE_CONNECT_IP_DATA` capsules in the request body's DATA frames. The
//! framing is a pair of QUIC variable-length integers (RFC 9000 §16) — the
//! capsule type and the value length — followed by the value.

use bytes::{BufMut, Bytes};

/// An IP packet. The only capsule type that carries traffic.
pub const CAPSULE_DATA: u64 = 0x00;
/// The tunnel assigning an address to the client.
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// The client asking for an address.
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// The tunnel advertising a route.
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// Write a QUIC variable-length integer.
pub fn put_varint(out: &mut impl BufMut, value: u64) {
    if value < 64 {
        out.put_u8(value as u8);
    } else if value < 16_384 {
        out.put_u8(0x40 | (value >> 8) as u8);
        out.put_u8(value as u8);
    } else if value < 1_073_741_824 {
        out.put_u8(0x80 | (value >> 24) as u8);
        out.put_u8((value >> 16) as u8);
        out.put_u8((value >> 8) as u8);
        out.put_u8(value as u8);
    } else {
        out.put_u8(0xC0 | (value >> 56) as u8);
        out.put_u8((value >> 48) as u8);
        out.put_u8((value >> 40) as u8);
        out.put_u8((value >> 32) as u8);
        out.put_u8((value >> 24) as u8);
        out.put_u8((value >> 16) as u8);
        out.put_u8((value >> 8) as u8);
        out.put_u8(value as u8);
    }
}

/// Read a QUIC variable-length integer, returning `(value, bytes_consumed)`.
pub fn get_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &byte in &input[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

/// Encode one capsule into `out`.
pub fn put_capsule(out: &mut impl BufMut, capsule_type: u64, value: &[u8]) {
    put_varint(out, capsule_type);
    put_varint(out, value.len() as u64);
    out.put_slice(value);
}

/// A streaming decoder for a capsule-framed byte stream.
///
/// Chunks are pushed as they arrive; whole capsules are consumed as they
/// complete, so a capsule split across DATA frames reassembles without copying
/// the payload twice.
///
/// A capsule longer than [`MAX_CAPSULE_LEN`] stops the decoder (issue 123):
/// [`error`](Self::error) then names it, and no more bytes are kept.
#[derive(Default)]
pub struct CapsuleDecoder {
    buf: Vec<u8>,
    error: Option<String>,
    /// The addresses of the last ADDRESS_ASSIGN capsule (issue 121).
    assigned: Option<Vec<(std::net::IpAddr, u8)>>,
}

/// The addresses of an ADDRESS_ASSIGN value (RFC 9484 section 4.7.1):
/// request id (varint), IP version (1 byte), address (4 or 16 bytes),
/// prefix length (1 byte), repeated. `None` for a value that does not
/// parse: the layout of the front door is not known for sure.
pub fn parse_address_assign(mut value: &[u8]) -> Option<Vec<(std::net::IpAddr, u8)>> {
    let mut out = Vec::new();
    while !value.is_empty() {
        let (_, n) = get_varint(value)?;
        value = &value[n..];
        let (&version, rest) = value.split_first()?;
        let len = match version {
            4 => 4,
            6 => 16,
            _ => return None,
        };
        if rest.len() < len + 1 {
            return None;
        }
        let ip = match version {
            4 => std::net::IpAddr::from(<[u8; 4]>::try_from(&rest[..4]).ok()?),
            _ => std::net::IpAddr::from(<[u8; 16]>::try_from(&rest[..16]).ok()?),
        };
        out.push((ip, rest[len]));
        value = &rest[len + 1..];
    }
    Some(out)
}

/// The longest capsule value that the decoder takes. An IP packet of the
/// tunnel is at most the MTU (1280); an HTTP/2 DATA frame of the front door
/// is at most 16 KiB. 64 KiB leaves room for control capsules.
pub const MAX_CAPSULE_LEN: u64 = 64 * 1024;

impl CapsuleDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8]) {
        if self.error.is_none() {
            self.buf.extend_from_slice(data);
        }
    }

    /// Why the decoder stopped: a capsule over the limit. The stream is
    /// then unusable.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Yield the next complete capsule, or `None` if more bytes are needed.
    pub fn next_capsule(&mut self) -> Option<(u64, Bytes)> {
        if self.error.is_some() {
            return None;
        }
        let (capsule_type, type_len) = get_varint(&self.buf)?;
        let (length, len_len) = get_varint(&self.buf[type_len..])?;
        if length > MAX_CAPSULE_LEN {
            self.error = Some(format!(
                "a capsule of type {capsule_type} claims {length} bytes (the limit is {MAX_CAPSULE_LEN})"
            ));
            self.buf = Vec::new();
            return None;
        }
        let header = type_len + len_len;
        let total = header + length as usize;
        if self.buf.len() < total {
            return None;
        }
        let value = Bytes::copy_from_slice(&self.buf[header..total]);
        self.buf.drain(..total);
        Some((capsule_type, value))
    }

    /// Yield the next IP packet, skipping the control capsules. An
    /// ADDRESS_ASSIGN is kept for [`take_assigned`](Self::take_assigned).
    pub fn next_packet(&mut self) -> Option<Bytes> {
        loop {
            let (capsule_type, value) = self.next_capsule()?;
            if capsule_type == CAPSULE_DATA && !value.is_empty() {
                return Some(value);
            }
            if capsule_type == CAPSULE_ADDRESS_ASSIGN {
                match parse_address_assign(&value) {
                    Some(addrs) => self.assigned = Some(addrs),
                    None => {
                        tracing::debug!(len = value.len(), "an ADDRESS_ASSIGN that does not parse")
                    }
                }
            }
        }
    }

    /// The addresses of an ADDRESS_ASSIGN that came since the last call.
    pub fn take_assigned(&mut self) -> Option<Vec<(std::net::IpAddr, u8)>> {
        self.assigned.take()
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // Issue 121: an ADDRESS_ASSIGN is parsed and kept.
    #[test]
    fn an_address_assign_is_kept() {
        let mut value = vec![0x01, 4, 172, 16, 0, 2, 32];
        value.extend([0x02, 6]);
        value.extend(
            "2606:4700:110:8a36::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        value.push(128);
        let mut d = CapsuleDecoder::new();
        d.push(&frame(CAPSULE_ADDRESS_ASSIGN, &value));
        d.push(&frame(CAPSULE_DATA, b"\x45packet"));
        assert_eq!(&d.next_packet().unwrap()[..], b"\x45packet");
        let assigned = d.take_assigned().unwrap();
        assert_eq!(assigned[0], ("172.16.0.2".parse().unwrap(), 32));
        assert_eq!(assigned[1].1, 128);
        assert!(d.take_assigned().is_none());
        assert!(parse_address_assign(&[0x01, 9, 1]).is_none());
        assert!(parse_address_assign(&[0x01, 4, 1, 2]).is_none());
    }

    // Issue 123: a length over the limit stops the decoder, and the bytes
    // after it are not kept. Before, the buffer grew without a limit.
    #[test]
    fn a_capsule_over_the_limit_stops_the_decoder() {
        let mut d = CapsuleDecoder::new();
        let mut head = BytesMut::new();
        put_varint(&mut head, CAPSULE_DATA);
        put_varint(&mut head, 1 << 30);
        d.push(&head);
        assert!(d.next_packet().is_none());
        assert!(d.error().unwrap().contains("1073741824"), "{:?}", d.error());
        for _ in 0..16 {
            d.push(&[0u8; 65536]);
        }
        assert_eq!(d.buffered(), 0);
        assert!(d.next_packet().is_none());
    }

    #[test]
    fn a_capsule_at_the_limit_decodes() {
        let value = vec![0x45u8; MAX_CAPSULE_LEN as usize];
        let mut d = CapsuleDecoder::new();
        d.push(&frame(CAPSULE_DATA, &value));
        assert_eq!(d.next_packet().unwrap().len(), value.len());
        assert!(d.error().is_none());
    }

    fn frame(capsule_type: u64, value: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        put_capsule(&mut out, capsule_type, value);
        out.to_vec()
    }

    /// The DATA capsule of the WARP front door holds a bare IP packet: no
    /// context ID before it (RFC 9484 has one, a varint 0).
    #[test]
    fn a_data_capsule_has_no_context_id() {
        let packet = b"\x45\x00\x00\x14ipv4";
        let mut buf = BytesMut::new();
        put_capsule(&mut buf, CAPSULE_DATA, packet);
        assert_eq!(buf[0], 0x00, "the type");
        assert_eq!(buf[1] as usize, packet.len(), "the length");
        assert_eq!(
            &buf[2..],
            packet,
            "the packet starts at once (0x45), no 0x00 context ID"
        );
        let mut d = CapsuleDecoder::new();
        d.push(&buf);
        assert_eq!(&d.next_packet().unwrap()[..], packet);
    }

    #[test]
    fn varint_boundaries() {
        for value in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            let (got, len) = get_varint(&buf).unwrap();
            assert_eq!(got, value);
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn capsule_roundtrip() {
        let packet = b"\x45\x00\x00\x14hello";
        let mut d = CapsuleDecoder::new();
        d.push(&frame(CAPSULE_DATA, packet));
        assert_eq!(&d.next_packet().unwrap()[..], packet);
        assert!(d.next_packet().is_none());
    }

    #[test]
    fn control_capsules_are_skipped() {
        let mut d = CapsuleDecoder::new();
        d.push(&frame(CAPSULE_ADDRESS_ASSIGN, b"\x00\x01"));
        d.push(&frame(CAPSULE_DATA, b"\x45\x00"));
        assert_eq!(&d.next_packet().unwrap()[..], b"\x45\x00");
    }

    #[test]
    fn a_capsule_split_across_chunks_reassembles() {
        let full = frame(CAPSULE_DATA, b"\x45\x00\x00\x14payload");
        let mut d = CapsuleDecoder::new();
        d.push(&full[..3]);
        assert!(d.next_packet().is_none());
        d.push(&full[3..]);
        assert_eq!(&d.next_packet().unwrap()[..], b"\x45\x00\x00\x14payload");
    }
}
