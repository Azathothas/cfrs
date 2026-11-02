#[allow(unused_imports)]
use crate::prelude::*;
use std::net::Ipv6Addr;

// ── fake-IP DNS ─────────────────────────────────────────────────────────────

pub(crate) struct FakeDns {
    pub(crate) by_ip: HashMap<Ipv4Addr, String>,
    pub(crate) by_name: HashMap<String, Ipv4Addr>,
    pub(crate) next: u32,
    /// Answer AAAA with a fake IPv6 address (the seccomp backend only: the
    /// TUN of the netns backend has no IPv6).
    pub(crate) v6: bool,
}

impl FakeDns {
    /// Answer a query from the pool. An A query gets the fake address of the
    /// name. Other types get an empty NOERROR answer, so the caller uses IPv4.
    pub(crate) fn answer(&mut self, query: &crate::dns::ParsedQuery) -> Vec<u8> {
        if query.qtype == crate::dns::TYPE_A {
            let fake = self.address_for(&query.name);
            crate::dns::build_response(query, &[IpAddr::V4(fake)], crate::dns::RCODE_NOERROR)
        } else if query.qtype == crate::dns::TYPE_AAAA && self.v6 {
            // A pinned name (--map) has no fake address: it gets no AAAA.
            let v4 = self.address_for(&query.name);
            let answers = if self.by_ip.contains_key(&v4) {
                vec![IpAddr::V6(fake_v6(v4))]
            } else {
                Vec::new()
            };
            crate::dns::build_response(query, &answers, crate::dns::RCODE_NOERROR)
        } else {
            crate::dns::build_response(query, &[], crate::dns::RCODE_NOERROR)
        }
    }

    /// The name of a fake address of either family.
    pub(crate) fn name_for_ip(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(v4) => self.name_for(v4),
            IpAddr::V6(v6) => unfake_v6(v6).and_then(|v4| self.name_for(v4)),
        }
    }

    /// Pin a name to a real address, so it resolves locally with no fake IP.
    pub(crate) fn pin(&mut self, name: &str, ip: IpAddr) {
        if let IpAddr::V4(v4) = ip {
            self.by_name.insert(name.to_string(), v4);
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            by_ip: HashMap::new(),
            by_name: HashMap::new(),
            next: 0,
            v6: false,
        }
    }

    pub(crate) fn address_for(&mut self, name: &str) -> Ipv4Addr {
        if let Some(ip) = self.by_name.get(name) {
            return *ip;
        }
        let ip = Ipv4Addr::from((FAKE_IP_BASE + (self.next % FAKE_IP_COUNT)).to_be_bytes());
        self.next += 1;
        self.by_name.insert(name.to_string(), ip);
        self.by_ip.insert(ip, name.to_string());
        ip
    }

    pub(crate) fn name_for(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }
}

/// The fake IPv6 address of a fake IPv4 address: `FAKE_IP6_PREFIX` (a ULA)
/// and the 32 bits of the IPv4 address.
pub(crate) fn fake_v6(v4: Ipv4Addr) -> Ipv6Addr {
    let mut octets = FAKE_IP6_PREFIX;
    octets[12..].copy_from_slice(&v4.octets());
    Ipv6Addr::from(octets)
}

/// The fake IPv4 address of a fake IPv6 address, or `None` for any other.
pub(crate) fn unfake_v6(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v6.octets();
    (o[..12] == FAKE_IP6_PREFIX[..12]).then(|| Ipv4Addr::new(o[12], o[13], o[14], o[15]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue 99: a fake IPv6 address carries the fake IPv4 address, and
    /// only an address of the prefix maps back.
    #[test]
    fn a_fake_ipv6_address_maps_back() {
        let v4 = Ipv4Addr::new(198, 18, 0, 7);
        let v6 = fake_v6(v4);
        assert_eq!(v6.to_string(), "fd63:6672:7300::c612:7");
        assert_eq!(unfake_v6(v6), Some(v4));
        assert_eq!(unfake_v6("2606:4700:4700::1111".parse().unwrap()), None);
        let mut dns = FakeDns::new();
        let fake = dns.address_for("example.com");
        assert_eq!(
            dns.name_for_ip(IpAddr::V6(fake_v6(fake))),
            Some("example.com")
        );
    }
}
