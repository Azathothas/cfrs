//! Edge discovery that works without a system resolver.
//!
//! `cloudflared` finds the tunnel edge by resolving
//! `_v2-origintunneld._tcp.argotunnel.com`, which returns the regional names
//! and port 7844. A sealed sandbox usually has no working resolver: every
//! nameserver in `/etc/resolv.conf` is unreachable, and DNS over TLS on 853 is
//! blocked as well. The lookup therefore runs over HTTPS instead: Cloudflare's
//! DNS-over-HTTPS endpoint answers the same SRV and address records on TCP 443,
//! which is the one egress such a host has.
//!
//! Order of attempts:
//!
//! 1. DoH over HTTPS, through the proxy when one is configured.
//! 2. The crate's resolver path, which uses the system resolver and then DoT.
//! 3. A short list of anycast addresses, for a host where DNS is entirely
//!    unusable. These are a last resort and are labelled as such.
//!
//! The port comes from the SRV record, not from a constant, so a future change
//! at Cloudflare is followed rather than guessed.

use std::net::IpAddr;

use crate::cloudflare::{EdgeAddr, EdgeIpVersion, IpVersionFilter};
use anyhow::{bail, Context, Result};

/// The SRV record cloudflared resolves.
pub const EDGE_SRV: &str = "_v2-origintunneld._tcp.argotunnel.com";

/// Last-resort anycast addresses, used only when both resolvers fail.
///
/// These are Cloudflare's published edge anycast addresses. They are not a
/// substitute for discovery: the SRV record is the authority, and this list is
/// here so a host with no DNS at all can still reach the service.
const STATIC_EDGE_IPS: &[&str] = &[
    "198.41.192.167",
    "198.41.192.227",
    "198.41.200.13",
    "198.41.200.53",
];

/// The port the SRV record names when the static list is used.
const STATIC_EDGE_PORT: u16 = 7844;

/// Resolve the edge, preferring DoH, then the system resolver, then the
/// static list. Returns at least one address or an error naming every attempt.
pub async fn discover(filter: IpVersionFilter) -> Result<Vec<EdgeAddr>> {
    let mut failures = Vec::new();

    match discover_doh(filter).await {
        Ok(edges) if !edges.is_empty() => return Ok(edges),
        Ok(_) => failures.push("DoH returned no addresses".to_string()),
        Err(err) => failures.push(format!("DoH: {err:#}")),
    }

    match discover_system(filter).await {
        Ok(edges) if !edges.is_empty() => return Ok(edges),
        Ok(_) => failures.push("the system resolver returned no addresses".to_string()),
        Err(err) => failures.push(format!("system resolver: {err:#}")),
    }

    let edges = static_edges(filter);
    if edges.is_empty() {
        failures.push("the static list has no address for this IP version".to_string());
    } else {
        tracing::warn!("using the static edge list; DNS discovery failed");
        return Ok(edges);
    }

    bail!("edge discovery failed: {}", failures.join("; "))
}

/// Resolve the SRV record and its targets with the system resolver
/// (`/etc/resolv.conf`).
pub async fn discover_system(filter: IpVersionFilter) -> Result<Vec<EdgeAddr>> {
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .context("reading the system resolver configuration")?
        .build()
        .context("starting the system resolver")?;
    let srv = resolver
        .srv_lookup(EDGE_SRV)
        .await
        .with_context(|| format!("SRV lookup of {EDGE_SRV}"))?;
    let mut edges = Vec::new();
    for record in srv.answers() {
        let hickory_resolver::proto::rr::RData::SRV(record) = &record.data else {
            continue;
        };
        let target = record.target.to_utf8();
        let port = record.port;
        let Ok(ips) = resolver.lookup_ip(target.trim_end_matches('.')).await else {
            continue;
        };
        for ip in ips.iter() {
            let edge = EdgeAddr::new(std::net::SocketAddr::new(ip, port));
            if filter.allows(edge.version) && !edges.contains(&edge) {
                edges.push(edge);
            }
        }
    }
    edges.sort_by_key(|e| e.version != EdgeIpVersion::V4);
    Ok(edges)
}

/// Resolve through Cloudflare's DNS-over-HTTPS JSON API.
pub async fn discover_doh(filter: IpVersionFilter) -> Result<Vec<EdgeAddr>> {
    let srv = query(EDGE_SRV, "SRV").await?;
    let mut targets: Vec<(String, u16)> = Vec::new();
    for answer in &srv.answer {
        if answer.rtype != 33 {
            continue;
        }
        if let Some((target, port)) = parse_srv(&answer.data) {
            targets.push((target, port));
        }
    }
    if targets.is_empty() {
        bail!("the SRV answer carried no target");
    }

    let mut edges = Vec::new();
    for (target, port) in targets {
        let records: &[(&str, u16)] = match filter {
            IpVersionFilter::V4Only => &[("A", 1)],
            IpVersionFilter::V6Only => &[("AAAA", 28)],
            IpVersionFilter::Auto => &[("A", 1), ("AAAA", 28)],
        };
        for (rtype, wanted) in records {
            let answer = match query(&target, rtype).await {
                Ok(answer) => answer,
                Err(err) => {
                    tracing::debug!(%target, rtype, %err, "address lookup failed");
                    continue;
                }
            };
            for entry in &answer.answer {
                if entry.rtype != *wanted {
                    continue;
                }
                let Ok(ip) = entry.data.trim().parse::<IpAddr>() else {
                    continue;
                };
                edges.push(EdgeAddr {
                    ip,
                    port,
                    version: if ip.is_ipv4() {
                        EdgeIpVersion::V4
                    } else {
                        EdgeIpVersion::V6
                    },
                });
            }
        }
    }
    Ok(edges)
}

async fn query(name: &str, rtype: &str) -> Result<crate::resolve::DohAnswer> {
    let answer = crate::resolve::doh_query(name, rtype).await?;
    if answer.status != 0 {
        bail!("DoH status {} for {name} {rtype}", answer.status);
    }
    Ok(answer)
}

/// Parse an SRV `data` field: `priority weight port target`.
fn parse_srv(data: &str) -> Option<(String, u16)> {
    let mut parts = data.split_whitespace();
    let _priority = parts.next()?;
    let _weight = parts.next()?;
    let port: u16 = parts.next()?.parse().ok()?;
    let target = parts.next()?.trim_end_matches('.').to_string();
    if target.is_empty() {
        return None;
    }
    Some((target, port))
}

fn static_edges(filter: IpVersionFilter) -> Vec<EdgeAddr> {
    let mut out = Vec::new();
    for text in STATIC_EDGE_IPS {
        let Ok(ip) = text.parse::<IpAddr>() else {
            continue;
        };
        let version = if ip.is_ipv4() {
            EdgeIpVersion::V4
        } else {
            EdgeIpVersion::V6
        };
        let keep = match filter {
            IpVersionFilter::Auto => true,
            IpVersionFilter::V4Only => version == EdgeIpVersion::V4,
            IpVersionFilter::V6Only => version == EdgeIpVersion::V6,
        };
        if keep {
            out.push(EdgeAddr {
                ip,
                port: STATIC_EDGE_PORT,
                version,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_srv_data_field() {
        assert_eq!(
            parse_srv("2 1 7844 region2.v2.argotunnel.com."),
            Some(("region2.v2.argotunnel.com".to_string(), 7844))
        );
        assert_eq!(parse_srv("garbage"), None);
    }

    #[test]
    fn decodes_a_cloudflare_doh_answer() {
        let body = r#"{"Status":0,"Answer":[{"name":"_v2-origintunneld._tcp.argotunnel.com","type":33,"TTL":300,"data":"2 1 7844 region2.v2.argotunnel.com"}]}"#;
        let parsed: crate::resolve::DohAnswer = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.status, 0);
        assert_eq!(parsed.answer.len(), 1);
        assert_eq!(parsed.answer[0].rtype, 33);
    }

    #[test]
    fn the_static_list_respects_the_filter() {
        assert!(static_edges(IpVersionFilter::V4Only)
            .iter()
            .all(|e| e.version == EdgeIpVersion::V4));
        assert!(static_edges(IpVersionFilter::V6Only).is_empty());
    }
}
