//! A virtual DNS resolver.
//!
//! Programs that resolve service names usually do it through `getaddrinfo`,
//! which reaches the kernel resolver, not the virtual network. Running a
//! resolver at the gateway (`10.66.0.1:53`) plus interposing `getaddrinfo` in
//! the shim lets a program resolve names the virtual network invented, with
//! no `/etc/hosts` and no real resolver.
//!
//! This module implements the wire format for the small subset a resolver
//! needs: a query question is parsed, and A/AAAA answers are built for a table
//! of names. Unknown names return `None` so a caller can forward them to a
//! real upstream, or an empty answer (`NOERROR` with no records).

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::Result;

pub use podnet_netns::dns::*;

/// A name-to-address table with an optional upstream.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    entries: HashMap<String, Vec<IpAddr>>,
    /// When a name is unknown, forward here instead of answering NXDOMAIN.
    pub upstream: Option<crate::vnet::addr::VirtAddr>,
    /// Answer every unknown A/AAAA with this address (a single-upstream
    /// configuration).
    pub catch_all: Option<IpAddr>,
}

impl Resolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry; the name is lowercased and its trailing dot stripped.
    pub fn insert(&mut self, name: &str, ip: IpAddr) {
        self.entries.entry(normalize(name)).or_default().push(ip);
    }

    pub fn with(mut self, name: &str, ip: IpAddr) -> Self {
        self.insert(name, ip);
        self
    }

    pub fn get(&self, name: &str) -> Option<&[IpAddr]> {
        self.entries.get(&normalize(name)).map(Vec::as_slice)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Parse `name=10.66.0.2` / `name=fd00::2` lines and `hosts`-style
    /// `10.66.0.2 name1 name2` lines.
    pub fn from_lines(lines: &[String]) -> Result<Self> {
        let mut resolver = Self::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((name, addr)) = line.split_once('=') {
                let ip: IpAddr = addr
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad address in {line:?}"))?;
                resolver.insert(name, ip);
                continue;
            }
            let mut parts = line.split_whitespace();
            let addr = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty resolver line"))?;
            let ip: IpAddr = addr.parse().map_err(|_| {
                anyhow::anyhow!("hosts line {line:?} does not start with an address")
            })?;
            for name in parts {
                resolver.insert(name, ip);
            }
        }
        Ok(resolver)
    }

    /// The answers for a name and record type.
    pub fn answers(&self, name: &str, qtype: u16) -> Vec<IpAddr> {
        let mut answers: Vec<IpAddr> = match self.get(name) {
            Some(ips) => ips
                .iter()
                .copied()
                .filter(|ip| {
                    matches!(
                        (qtype, ip),
                        (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))
                    )
                })
                .collect(),
            None => Vec::new(),
        };
        if answers.is_empty() {
            if let Some(ip) = self.catch_all {
                if matches!(
                    (qtype, ip),
                    (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))
                ) {
                    answers.push(ip);
                }
            }
        }
        answers
    }

    /// Handle a raw UDP DNS query. Returns `Some(response)` when the query can
    /// be answered locally, and `None` when it should be forwarded upstream
    /// (unknown name and an upstream is configured).
    pub fn handle(&self, query: &[u8]) -> Option<Vec<u8>> {
        let parsed = ParsedQuery::parse(query).ok()?;
        let answers = self.answers(&parsed.name, parsed.qtype);
        if answers.is_empty() && self.get(&parsed.name).is_none() {
            if self.upstream.is_some() {
                return None;
            }
            // Known name with no record of this type -> NODATA; unknown name
            // with no upstream -> NXDOMAIN.
            let rcode = if self.get(&parsed.name).is_some() {
                RCODE_NOERROR
            } else {
                RCODE_NXDOMAIN
            };
            return Some(build_response(&parsed, &[], rcode));
        }
        Some(build_response(&parsed, &answers, RCODE_NOERROR))
    }

    /// Turn a resolver into the shim's `getaddrinfo` table (name -> address),
    /// which is what a program that never speaks DNS still resolves through.
    pub fn hosts_pairs(&self) -> Vec<(String, IpAddr)> {
        let mut pairs: Vec<(String, IpAddr)> = self
            .entries
            .iter()
            .flat_map(|(name, ips)| ips.iter().map(move |ip| (name.clone(), *ip)))
            .collect();
        pairs.sort();
        pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn resolves_known_names() {
        let resolver = Resolver::new()
            .with("web", "10.66.0.2".parse().unwrap())
            .with("web", "10.66.0.3".parse().unwrap())
            .with("v6", "fd00::2".parse().unwrap());
        assert_eq!(resolver.answers("WEB.", TYPE_A).len(), 2);
        assert_eq!(resolver.answers("web", TYPE_AAAA).len(), 0);
        assert_eq!(resolver.answers("v6", TYPE_AAAA).len(), 1);
        assert_eq!(resolver.answers("v6", TYPE_A).len(), 0);
    }

    #[test]
    fn answers_a_query() {
        let resolver = Resolver::new().with("web", "10.66.0.2".parse().unwrap());
        let query = build_query(0x1234, "web", TYPE_A).unwrap();
        let response = resolver.handle(&query).unwrap();
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(response[2] & 0x80, 0x80, "QR bit");
        assert_eq!(
            parse_answers(&response).unwrap(),
            vec!["10.66.0.2".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn unknown_name_is_nxdomain_without_upstream() {
        let resolver = Resolver::new();
        let query = build_query(1, "nope", TYPE_A).unwrap();
        let response = resolver.handle(&query).unwrap();
        assert_eq!(response[3] & 0x0f, RCODE_NXDOMAIN);
        assert!(parse_answers(&response).unwrap().is_empty());
    }

    #[test]
    fn unknown_name_forwards_with_upstream() {
        let mut resolver = Resolver::new();
        resolver.upstream = Some(crate::vnet::addr::VirtAddr::v4(
            "10.66.0.1".parse().unwrap(),
            53,
        ));
        let query = build_query(1, "nope", TYPE_A).unwrap();
        assert!(resolver.handle(&query).is_none());
    }

    #[test]
    fn catch_all_maps_unknown() {
        let mut resolver = Resolver::new();
        resolver.catch_all = Some("10.66.0.9".parse().unwrap());
        let query = build_query(1, "anything", TYPE_A).unwrap();
        let response = resolver.handle(&query).unwrap();
        assert_eq!(
            parse_answers(&response).unwrap(),
            vec!["10.66.0.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn parses_hosts_and_pairs() {
        let resolver = Resolver::from_lines(&[
            "10.66.0.2 web api".into(),
            "db=10.66.0.3".into(),
            "# comment".into(),
        ])
        .unwrap();
        assert!(resolver.get("web").is_some());
        assert!(resolver.get("api").is_some());
        assert!(resolver.get("db").is_some());
        assert_eq!(resolver.hosts_pairs().len(), 3);
    }

    #[test]
    fn compression_pointer_in_question_is_followed() {
        // A question whose QNAME is a pointer to an earlier name.
        let mut message = vec![0u8; HEADER_LEN];
        message[4..6].copy_from_slice(&1u16.to_be_bytes());
        // Place "web" at offset 12, then a pointer question at 17.
        message.extend_from_slice(&[3, b'w', b'e', b'b', 0]);
        message.extend_from_slice(&[0xc0, 0x0c]);
        message.extend_from_slice(&TYPE_A.to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        let parsed = ParsedQuery::parse(&message).unwrap();
        assert_eq!(parsed.name, "web");
    }

    #[test]
    fn rejects_malformed_queries() {
        assert!(ParsedQuery::parse(&[]).is_err());
        assert!(ParsedQuery::parse(&[0u8; HEADER_LEN]).is_err());
        let mut looped = vec![0u8; HEADER_LEN];
        looped[4..6].copy_from_slice(&1u16.to_be_bytes());
        looped.extend_from_slice(&[0xc0, 0x0c]); // pointer to itself
        looped.extend_from_slice(&TYPE_A.to_be_bytes());
        looped.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert!(ParsedQuery::parse(&looped).is_err());
    }

    #[test]
    fn a_large_answer_set_truncates_cleanly() {
        // 40 A records do not fit in 512 bytes. The response must carry only
        // whole records, count them correctly, and set TC.
        let query = build_query(7, "many", TYPE_A).unwrap();
        let parsed = ParsedQuery::parse(&query).unwrap();
        let answers: Vec<IpAddr> = (1..=40u8)
            .map(|last| IpAddr::V4(Ipv4Addr::new(10, 66, 0, last)))
            .collect();
        let response = build_response(&parsed, &answers, RCODE_NOERROR);
        assert!(response.len() <= MAX_UDP, "{} bytes", response.len());
        assert_eq!(response[2] & 0x02, 0x02, "TC bit must be set");
        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        let parsed_answers = parse_answers(&response).unwrap();
        assert_eq!(
            parsed_answers.len(),
            ancount,
            "ANCOUNT must match the records"
        );
        assert!(ancount < answers.len());
    }
}
