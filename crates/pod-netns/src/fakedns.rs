#[allow(unused_imports)]
use crate::prelude::*;

// ── fake-IP DNS ─────────────────────────────────────────────────────────────

pub(crate) struct FakeDns {
    pub(crate) by_ip: HashMap<Ipv4Addr, String>,
    pub(crate) by_name: HashMap<String, Ipv4Addr>,
    pub(crate) next: u32,
}

impl FakeDns {
    /// Answer a query from the pool. An A query gets the fake address of the
    /// name. Other types get an empty NOERROR answer, so the caller uses IPv4.
    pub(crate) fn answer(&mut self, query: &crate::dns::ParsedQuery) -> Vec<u8> {
        if query.qtype == crate::dns::TYPE_A {
            let fake = self.address_for(&query.name);
            crate::dns::build_response(query, &[IpAddr::V4(fake)], crate::dns::RCODE_NOERROR)
        } else {
            crate::dns::build_response(query, &[], crate::dns::RCODE_NOERROR)
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
