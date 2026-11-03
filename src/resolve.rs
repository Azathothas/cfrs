//! Name resolution for each direct dial of cfrs ([`crate::egress`]).
//!
//! The chain, in order:
//!
//! 1. An IP address is used as it is.
//! 2. A pin of `--resolve HOST=IP` or `CFRS_RESOLVE` (a comma-separated list
//!    of `HOST=IP`). TLS still checks the name of the certificate.
//! 3. The system resolver (`/etc/resolv.conf`), with a time limit of
//!    [`STEP_TIMEOUT`].
//! 4. DNS over HTTPS by IP address, at two operators: Cloudflare (1.1.1.1,
//!    1.0.0.1), then Google (8.8.8.8, 8.8.4.4). TLS checks the IP address in
//!    the certificate. An answer that the name does not exist (NXDOMAIN) skips
//!    the other server of that operator; the next operator is asked (issue
//!    119: a new name is NXDOMAIN at one operator for minutes, and has an
//!    address at the other).
//!
//! A dial through a proxy gives the name to the proxy and resolves nothing
//! here.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;

/// The variable of the pins.
pub const PINS_VARIABLE: &str = "CFRS_RESOLVE";
/// The time limit of one step of the chain, and of one DoH server.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// A DoH server, by IP address.
#[derive(Clone, Copy, Debug)]
pub struct DohServer {
    pub operator: &'static str,
    /// The URL, with the IP address as its host.
    pub url: &'static str,
}

/// The DoH servers, in the order of the chain.
pub const DOH_SERVERS: &[DohServer] = &[
    DohServer {
        operator: "Cloudflare",
        url: "https://1.1.1.1/dns-query",
    },
    DohServer {
        operator: "Cloudflare",
        url: "https://1.0.0.1/dns-query",
    },
    DohServer {
        operator: "Google",
        url: "https://8.8.8.8/resolve",
    },
    DohServer {
        operator: "Google",
        url: "https://8.8.4.4/resolve",
    },
];

/// The DoH servers by name. cfrs asks them only through a proxy, which
/// resolves the name: some proxies refuse a CONNECT to an IP address. With
/// no proxy, the name would need the chain that it is part of.
pub const DOH_SERVERS_BY_NAME: &[DohServer] = &[
    DohServer {
        operator: "Cloudflare",
        url: "https://cloudflare-dns.com/dns-query",
    },
    DohServer {
        operator: "Google",
        url: "https://dns.google/resolve",
    },
];

/// The DoH servers to ask, in order: by IP address, then by name when a
/// proxy carries the request.
pub fn doh_servers() -> Vec<DohServer> {
    let mut servers = DOH_SERVERS.to_vec();
    for server in DOH_SERVERS_BY_NAME {
        let host = server
            .url
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or_default();
        if crate::egress::proxy_for(host, 443).is_some() {
            servers.push(*server);
        }
    }
    servers
}

static PINS: OnceLock<HashMap<String, Vec<IpAddr>>> = OnceLock::new();

/// Set the pins of `--resolve`. Call it before the first dial; a later call
/// has no effect. The pins of `CFRS_RESOLVE` are added to them.
pub fn set_pins(list: &str) -> Result<()> {
    let mut pins = parse_pins(list)?;
    if let Ok(env) = std::env::var(PINS_VARIABLE) {
        for (host, ips) in parse_pins(&env).context(PINS_VARIABLE)? {
            pins.entry(host).or_default().extend(ips);
        }
    }
    let _ = PINS.set(pins);
    Ok(())
}

fn pins() -> &'static HashMap<String, Vec<IpAddr>> {
    PINS.get_or_init(|| match std::env::var(PINS_VARIABLE) {
        Ok(list) => parse_pins(&list).unwrap_or_else(|err| {
            tracing::warn!("{PINS_VARIABLE}: {err:#}; no pins are used");
            HashMap::new()
        }),
        Err(_) => HashMap::new(),
    })
}

/// Parse `HOST=IP[,HOST=IP]...`. One host may have several entries.
pub fn parse_pins(list: &str) -> Result<HashMap<String, Vec<IpAddr>>> {
    let mut pins: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (host, ip) = entry
            .split_once('=')
            .with_context(|| format!("{entry:?} is not HOST=IP"))?;
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            bail!("{entry:?} has no host");
        }
        let ip: IpAddr = ip
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .with_context(|| format!("{entry:?}: the address is not an IP address"))?;
        pins.entry(host).or_default().push(ip);
    }
    Ok(pins)
}

/// Resolve `host` with the chain.
///
/// The future is boxed: a DoH lookup dials, and a dial resolves, so the type
/// of the future must end here.
pub fn resolve(host: &str) -> futures::future::BoxFuture<'_, Result<Vec<IpAddr>>> {
    Box::pin(resolve_chain(host))
}

async fn resolve_chain(host: &str) -> Result<Vec<IpAddr>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(ips) = pins().get(&name) {
        tracing::debug!(%host, step = "pin", ?ips, "resolved");
        return Ok(ips.clone());
    }
    let mut failures = Vec::new();
    match tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host((host, 0))).await {
        Ok(Ok(addrs)) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if !ips.is_empty() {
                tracing::debug!(%host, step = "system", ?ips, "resolved");
                return Ok(dedup(ips));
            }
            failures.push("system resolver: no address".to_string());
        }
        Ok(Err(err)) => failures.push(format!("system resolver: {err}")),
        Err(_) => failures.push(format!(
            "system resolver: no answer in {} s",
            STEP_TIMEOUT.as_secs()
        )),
    }
    match doh_addresses(&name).await {
        Ok((ips, server)) => {
            tracing::debug!(%host, step = "doh", server, ?ips, "resolved");
            Ok(ips)
        }
        Err(err) => {
            failures.push(format!("DNS over HTTPS: {err:#}"));
            bail!("resolving {host}: {}", failures.join("; "))
        }
    }
}

/// Which step of the chain resolves `host` now (issue 94): `pin`,
/// `system`, `doh`, or `none`. A name that only DoH resolves is new: the
/// resolver of a visitor can still answer NXDOMAIN (a cached negative
/// answer) for some time.
pub async fn answering_step(host: &str) -> &'static str {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if pins().contains_key(&name) {
        return "pin";
    }
    if let Ok(Ok(mut addrs)) =
        tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host((host, 0))).await
    {
        if addrs.next().is_some() {
            return "system";
        }
    }
    match doh_addresses(&name).await {
        Ok(_) => "doh",
        Err(_) => "none",
    }
}

fn dedup(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen = Vec::with_capacity(ips.len());
    ips.retain(|ip| {
        let new = !seen.contains(ip);
        seen.push(*ip);
        new
    });
    ips
}

/// The A and AAAA addresses of `name` by DoH. Gives the addresses and the
/// server that answered.
async fn doh_addresses(name: &str) -> Result<(Vec<IpAddr>, &'static str)> {
    doh_addresses_with(&doh_servers(), name, |server, rtype| async move {
        doh_query_at(&server, name, rtype).await
    })
    .await
}

/// The loop of [`doh_addresses`], with the query as an argument (for the
/// tests). An NXDOMAIN answer skips the other servers of its operator.
async fn doh_addresses_with<F, Fut>(
    servers: &[DohServer],
    name: &str,
    query: F,
) -> Result<(Vec<IpAddr>, &'static str)>
where
    F: Fn(DohServer, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<DohAnswer>>,
{
    let mut last = None;
    let mut nx_operators: Vec<&'static str> = Vec::new();
    for server in servers {
        if nx_operators.contains(&server.operator) {
            continue;
        }
        let a = query(*server, "A").await;
        let aaaa = query(*server, "AAAA").await;
        match (a, aaaa) {
            (Err(err), Err(_)) => {
                last = Some(err);
                continue;
            }
            (a, aaaa) => {
                let mut ips = Vec::new();
                let mut nxdomain = false;
                for answer in [a, aaaa].into_iter().flatten() {
                    nxdomain |= answer.status == 3;
                    ips.extend(
                        answer
                            .answer
                            .iter()
                            .filter(|r| r.rtype == 1 || r.rtype == 28)
                            .filter_map(|r| r.data.trim().parse::<IpAddr>().ok()),
                    );
                }
                if !ips.is_empty() {
                    return Ok((dedup(ips), server.url));
                }
                if nxdomain {
                    nx_operators.push(server.operator);
                    continue;
                }
                last = Some(anyhow::anyhow!("{} has no address for {name}", server.url));
            }
        }
    }
    if !nx_operators.is_empty() {
        let verb = if nx_operators.len() > 1 {
            "say"
        } else {
            "says"
        };
        bail!(
            "{} {verb} that {name} does not exist",
            nx_operators.join(" and ")
        );
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no DoH server")))
}

/// A JSON answer of DoH.
#[derive(Debug, Deserialize)]
pub struct DohAnswer {
    #[serde(rename = "Status", default)]
    pub status: u16,
    #[serde(rename = "Answer", default)]
    pub answer: Vec<DohRecord>,
}

/// One record of a JSON answer.
#[derive(Debug, Deserialize)]
pub struct DohRecord {
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(default)]
    pub data: String,
}

/// Ask the DoH servers for `rtype` records of `name`, one server after the
/// other, until one answers. An NXDOMAIN answer is an answer.
pub async fn doh_query(name: &str, rtype: &str) -> Result<DohAnswer> {
    let mut failures = Vec::new();
    for server in &doh_servers() {
        match doh_query_at(server, name, rtype).await {
            Ok(answer) => return Ok(answer),
            Err(err) => failures.push(format!("{}: {err:#}", server.url)),
        }
    }
    bail!("DoH {rtype} {name}: {}", failures.join("; "))
}

async fn doh_query_at(server: &DohServer, name: &str, rtype: &str) -> Result<DohAnswer> {
    let url = format!("{}?name={name}&type={rtype}", server.url);
    let request = crate::fetch::Request::new("GET", url)
        .header("Accept", "application/dns-json")
        .timeout(STEP_TIMEOUT);
    // The DoH server is an IP address, so this dial resolves no name.
    let response = request.send().await?;
    if !response.is_success() {
        bail!("HTTP {}", response.status);
    }
    response.json()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins() {
        let pins = parse_pins(
            "api.trycloudflare.com=104.16.1.1, Api.TryCloudflare.com.=[2606::1],x=1.2.3.4",
        )
        .unwrap();
        assert_eq!(pins["api.trycloudflare.com"].len(), 2);
        assert_eq!(pins["x"], vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        for bad in ["noequals", "=1.2.3.4", "h=notanip"] {
            assert!(parse_pins(bad).is_err(), "{bad}");
        }
    }

    /// The servers by name come after the servers by IP address, and only
    /// through a proxy.
    #[test]
    fn the_servers_by_name_need_a_proxy() {
        let servers = doh_servers();
        assert!(servers.len() >= DOH_SERVERS.len());
        for (i, s) in DOH_SERVERS.iter().enumerate() {
            assert_eq!(servers[i].url, s.url);
        }
        let by_name = servers.len() - DOH_SERVERS.len();
        let proxied = crate::egress::proxy_for("cloudflare-dns.com", 443).is_some();
        assert_eq!(by_name > 0, proxied);
    }

    #[test]
    fn the_servers_are_ip_addresses_of_two_operators() {
        let mut operators: Vec<&str> = DOH_SERVERS.iter().map(|s| s.operator).collect();
        operators.dedup();
        assert!(operators.len() >= 2);
        for server in DOH_SERVERS {
            let host = server
                .url
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap();
            assert!(host.parse::<IpAddr>().is_ok(), "{}", server.url);
        }
    }

    fn answer(status: u16, data: &[&str]) -> DohAnswer {
        DohAnswer {
            status,
            answer: data
                .iter()
                .map(|d| DohRecord {
                    rtype: if d.contains(':') { 28 } else { 1 },
                    data: d.to_string(),
                })
                .collect(),
        }
    }

    /// The servers of the test: Cloudflare (two), then Google (two).
    fn servers() -> Vec<DohServer> {
        DOH_SERVERS.to_vec()
    }

    // Issue 119: a new name is NXDOMAIN at Cloudflare and has an address at
    // Google. Before, the first NXDOMAIN stopped the chain.
    #[tokio::test]
    async fn nxdomain_at_one_operator_asks_the_next_operator() {
        let asked = std::sync::Mutex::new(Vec::new());
        let (ips, server) = doh_addresses_with(&servers(), "new.example", |s, rtype| {
            asked.lock().unwrap().push(s.url);
            async move {
                Ok(match (s.operator, rtype) {
                    ("Cloudflare", _) => answer(3, &[]),
                    (_, "A") => answer(0, &["192.0.2.9"]),
                    _ => answer(0, &[]),
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(ips, vec!["192.0.2.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(server, "https://8.8.8.8/resolve");
        // The second server of Cloudflare is not asked.
        let asked = asked.into_inner().unwrap();
        assert!(!asked.contains(&"https://1.0.0.1/dns-query"), "{asked:?}");
    }

    #[tokio::test]
    async fn nxdomain_at_each_operator_is_an_error_that_names_them() {
        let err = doh_addresses_with(&servers(), "no.example", |_, _| async {
            Ok(answer(3, &[]))
        })
        .await
        .unwrap_err();
        assert_eq!(
            format!("{err}"),
            "Cloudflare and Google say that no.example does not exist"
        );
    }

    #[tokio::test]
    async fn a_server_that_fails_is_skipped() {
        let (ips, _) = doh_addresses_with(&servers(), "x.example", |s, _| async move {
            if s.url.contains("1.1.1.1") {
                bail!("timed out")
            }
            Ok(answer(0, &["2001:db8::1"]))
        })
        .await
        .unwrap();
        assert_eq!(ips, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn an_ip_address_is_used_as_it_is() {
        assert_eq!(
            resolve("192.0.2.7").await.unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolve("[::1]").await.unwrap(),
            vec!["::1".parse::<IpAddr>().unwrap()]
        );
    }
}
