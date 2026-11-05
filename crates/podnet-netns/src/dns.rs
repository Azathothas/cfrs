//! DNS wire format: parse a question, build A/AAAA answers and queries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

/// DNS record types and the class this codec understands.
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;
/// The largest message a plain UDP answer may have.
pub const MAX_UDP: usize = 512;
/// The length of the fixed DNS header.
pub const HEADER_LEN: usize = 12;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

/// Lower-case a name and remove the trailing dot.
pub fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A parsed question, enough to build a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedQuery {
    pub id: u16,
    /// Flags from the request (RD is copied into the response).
    pub flags: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// The raw question bytes, reused verbatim in the response.
    pub question: Vec<u8>,
}

impl ParsedQuery {
    pub fn parse(message: &[u8]) -> Result<Self> {
        if message.len() < HEADER_LEN {
            bail!("DNS message is shorter than the header");
        }
        let id = u16::from_be_bytes([message[0], message[1]]);
        let flags = u16::from_be_bytes([message[2], message[3]]);
        let qdcount = u16::from_be_bytes([message[4], message[5]]);
        if qdcount == 0 {
            bail!("DNS message has no question");
        }
        let mut offset = HEADER_LEN;
        let mut labels: Vec<String> = Vec::new();
        let mut jumped = false;
        let mut jumps = 0;
        let mut name_end = offset;
        loop {
            let len = *message
                .get(offset)
                .ok_or_else(|| anyhow::anyhow!("DNS name runs past the message"))?;
            if len == 0 {
                if !jumped {
                    name_end = offset + 1;
                }
                break;
            }
            if len & 0xc0 == 0xc0 {
                // Compression pointer: follow it, but only once and only
                // backwards, so a malformed loop cannot hang the parser.
                if message.len() < offset + 2 {
                    bail!("DNS name has a truncated compression pointer");
                }
                let pointer = (((len & 0x3f) as usize) << 8) | message[offset + 1] as usize;
                if pointer >= offset {
                    bail!("DNS compression pointer does not point backwards");
                }
                if jumped {
                    bail!("DNS name has more than one compression pointer");
                }
                jumped = true;
                jumps += 1;
                if jumps > 8 {
                    bail!("DNS name has too many labels");
                }
                name_end = offset + 2;
                offset = pointer;
                continue;
            }
            if len > 63 {
                bail!("DNS label is longer than 63 bytes");
            }
            let start = offset + 1;
            let end = start + len as usize;
            let label = message
                .get(start..end)
                .ok_or_else(|| anyhow::anyhow!("DNS label runs past the message"))?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            if labels.len() > 128 {
                bail!("DNS name has too many labels");
            }
            offset = end;
        }
        let qtype = read_u16(message, name_end)?;
        let qclass = read_u16(message, name_end + 2)?;
        let question = message[HEADER_LEN..name_end + 4].to_vec();
        if labels.is_empty() {
            bail!("DNS question has an empty name");
        }
        Ok(Self {
            id,
            flags,
            name: labels.join("."),
            qtype,
            qclass,
            question,
        })
    }
}

fn read_u16(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("DNS field runs past the message"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Build a response: the original question, then one A/AAAA answer per
/// address. `rcode` is the low nibble of the flags.
///
/// UDP responses are kept within the classic 512-byte limit. When answers do
/// not fit, `ANCOUNT` counts only the records that were written and the `TC`
/// bit is set, so a client knows to retry over TCP; the message is never cut
/// in the middle of a record.
pub fn build_response(query: &ParsedQuery, answers: &[IpAddr], rcode: u8) -> Vec<u8> {
    let mut records = Vec::with_capacity(answers.len() * 28);
    let mut count = 0u16;
    let mut truncated = false;
    for ip in answers {
        let mut record = Vec::with_capacity(28);
        record.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        match ip {
            IpAddr::V4(ip) => {
                record.extend_from_slice(&TYPE_A.to_be_bytes());
                record.extend_from_slice(&query.qclass.max(CLASS_IN).to_be_bytes());
                record.extend_from_slice(&60u32.to_be_bytes());
                record.extend_from_slice(&4u16.to_be_bytes());
                record.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                record.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                record.extend_from_slice(&query.qclass.max(CLASS_IN).to_be_bytes());
                record.extend_from_slice(&60u32.to_be_bytes());
                record.extend_from_slice(&16u16.to_be_bytes());
                record.extend_from_slice(&ip.octets());
            }
        }
        if HEADER_LEN + query.question.len() + records.len() + record.len() > MAX_UDP {
            truncated = true;
            break;
        }
        records.extend_from_slice(&record);
        count += 1;
    }

    let mut out = Vec::with_capacity(HEADER_LEN + query.question.len() + records.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, copy RD, set RA, keep OPCODE, set RCODE.
    let mut flags = 0x8000 | (query.flags & 0x0100) | 0x0080 | (rcode as u16 & 0x000f);
    if truncated {
        flags |= 0x0200; // TC
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&count.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.question);
    out.extend_from_slice(&records);
    out
}

/// A tiny DNS *client* query builder, used by tests and by the resolver's
/// upstream path.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            bail!("DNS name {name:?} has an empty label");
        }
        if label.len() > 63 {
            bail!("DNS label {label:?} is over 63 bytes");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Extract the A/AAAA answers from a response (used to forward an upstream
/// reply into the virtual table, or in tests).
pub fn parse_answers(message: &[u8]) -> Result<Vec<IpAddr>> {
    if message.len() < HEADER_LEN {
        bail!("DNS response is shorter than the header");
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = HEADER_LEN;
    for _ in 0..qdcount {
        offset = skip_name(message, offset)?;
        offset += 4;
        if offset > message.len() {
            bail!("DNS question runs past the message");
        }
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        offset = skip_name(message, offset)?;
        let rtype = read_u16(message, offset)?;
        offset += 8; // type, class, ttl
        let rdlength = read_u16(message, offset)? as usize;
        offset += 2;
        let rdata = message
            .get(offset..offset + rdlength)
            .ok_or_else(|| anyhow::anyhow!("DNS answer data is truncated"))?;
        match (rtype, rdlength) {
            (TYPE_A, 4) => answers.push(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(rdata).unwrap(),
            ))),
            (TYPE_AAAA, 16) => answers.push(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).unwrap(),
            ))),
            _ => {}
        }
        offset += rdlength;
    }
    Ok(answers)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        let len = *message
            .get(offset)
            .ok_or_else(|| anyhow::anyhow!("DNS name runs past the message"))?;
        if len == 0 {
            return Ok(offset + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Ok(offset + 2);
        }
        offset += 1 + len as usize;
        if offset > message.len() {
            bail!("DNS name runs past the message");
        }
    }
}
