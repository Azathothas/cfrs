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
//! 1. DoH by IP address ([`crate::resolve::settings`]), through the proxy
//!    when one is configured.
//! 2. The system resolver.
//! 3. A short list of anycast addresses, for a host where DNS is entirely
//!    unusable. These are a last resort and are labelled as such.
//!
//! The port comes from the SRV record, not from a constant, so a future change
//! at Cloudflare is followed rather than guessed. An SRV answer of another
//! shape (more than two targets, a target outside `argotunnel.com`, two
//! ports) is not used: podnet takes [`fixed_targets`] and says why.
//!
//! The record, the zone of its targets, the fixed targets and the static
//! addresses are data of the edge of `pod-services`.

use std::net::IpAddr;

use crate::cloudflare::{EdgeAddr, EdgeIpVersion, IpVersionFilter};
use crate::services::{self, EDGE};
use anyhow::{bail, Context, Result};

/// The SRV record cloudflared resolves: the fact `srv-name`.
pub fn edge_srv() -> &'static str {
    services::text(EDGE, "srv-name")
}

/// Last-resort anycast addresses, used only when both resolvers fail: the
/// fact `static-addresses`.
///
/// These are Cloudflare's published edge anycast addresses. They are not a
/// substitute for discovery: the SRV record is the authority, and this list is
/// here so a host with no DNS at all can still reach the service.
fn static_edge_ips() -> Vec<&'static str> {
    let ips = services::get(EDGE)
        .texts("static-addresses")
        .unwrap_or_default();
    ips.iter().map(|ip| ip.as_ref()).collect()
}

/// The SRV targets when the SRV answer has an unexpected shape: the
/// endpoints of the role `h2`.
pub fn fixed_targets() -> Vec<(&'static str, u16)> {
    let endpoints = services::endpoints_of(EDGE, "h2");
    endpoints.iter().map(|e| (e.host(), e.port())).collect()
}

/// The SRV targets to use: `targets` when they have the known shape, else
/// [`fixed_targets`], with one line that gives the reason.
pub fn checked_targets(targets: Vec<(String, u16)>) -> Vec<(String, u16)> {
    let mut ports: Vec<u16> = targets.iter().map(|(_, p)| *p).collect();
    ports.sort();
    ports.dedup();
    let reason = if targets.is_empty() {
        Some("it has no target".to_string())
    } else if targets.len() > 2 {
        Some(format!("it has {} targets, not 1 or 2", targets.len()))
    } else if let Some((name, _)) = targets
        .iter()
        .find(|(name, _)| !name.to_ascii_lowercase().ends_with(&format!(".{}", zone())))
    {
        Some(format!("the target {name} is not under {}", zone()))
    } else if ports.len() > 1 {
        Some(format!("it has the ports {ports:?}, not one port"))
    } else {
        None
    };
    match reason {
        None => {
            // A stable order: region1 is region 0 at each lookup.
            let mut targets = targets;
            targets.sort();
            targets
        }
        Some(reason) => {
            let fixed = fixed_targets();
            let names: Vec<&str> = fixed.iter().map(|(n, _)| *n).collect();
            tracing::warn!(
                "the SRV answer of {} has an unexpected shape: {reason}; podnet uses {} on port {}",
                edge_srv(),
                names.join(" and "),
                services::edge_port()
            );
            fixed.into_iter().map(|(n, p)| (n.to_string(), p)).collect()
        }
    }
}

/// The zone of the targets of the SRV record: the fact `srv-target-zone`.
fn zone() -> &'static str {
    services::text(EDGE, "srv-target-zone")
}

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
        .srv_lookup(edge_srv())
        .await
        .with_context(|| format!("SRV lookup of {}", edge_srv()))?;
    let targets: Vec<(String, u16)> = srv
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::SRV(srv) => Some((
                srv.target.to_utf8().trim_end_matches('.').to_string(),
                srv.port,
            )),
            _ => None,
        })
        .collect();
    let mut edges = Vec::new();
    for (region, (target, port)) in (0u8..).zip(checked_targets(targets)) {
        let Ok(ips) = resolver.lookup_ip(target.as_str()).await else {
            continue;
        };
        for ip in ips.iter() {
            let edge = EdgeAddr::new(std::net::SocketAddr::new(ip, port)).in_region(region);
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
    let srv = query(edge_srv(), "SRV").await?;
    let mut targets: Vec<(String, u16)> = Vec::new();
    for answer in &srv.records {
        if answer.kind != 33 {
            continue;
        }
        if let Some((target, port)) = parse_srv(&answer.data) {
            targets.push((target, port));
        }
    }
    let targets = checked_targets(targets);

    let mut edges = Vec::new();
    for (region, (target, port)) in (0u8..).zip(targets) {
        let records: &[(&str, u64)] = match filter {
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
            for entry in &answer.records {
                if entry.kind != *wanted {
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
                    region,
                });
            }
        }
    }
    Ok(edges)
}

async fn query(name: &str, rtype: &str) -> Result<crate::resolve::DohAnswer> {
    let answer = crate::resolve::doh_query(name, rtype).await?;
    if answer.status != Some(0) {
        let status = answer.status.map_or("missing".into(), |s| s.to_string());
        bail!("DoH status {status} for {name} {rtype}");
    }
    Ok(answer)
}

/// Parse an SRV `data` field: `priority weight port target`.
pub(crate) fn parse_srv(data: &str) -> Option<(String, u16)> {
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
    for text in static_edge_ips() {
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
                port: services::edge_port(),
                version,
                // The first two are in region1, the others in region2.
                region: u8::from(!text.starts_with("198.41.192.")),
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
        let parsed = pod_dns::json::parse(body.as_bytes()).unwrap();
        assert_eq!(parsed.status, Some(0));
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].kind, 33);
    }

    #[test]
    fn an_srv_answer_of_another_shape_gives_the_fixed_names() {
        let t = |list: &[(&str, u16)]| -> Vec<(String, u16)> {
            list.iter().map(|(n, p)| (n.to_string(), *p)).collect()
        };
        let fixed = t(&fixed_targets());
        let good = t(&[
            ("region1.v2.argotunnel.com", 7844),
            ("region2.v2.argotunnel.com", 7844),
        ]);
        assert_eq!(checked_targets(good.clone()), good);
        let three = t(&[
            ("a.argotunnel.com", 7844),
            ("b.argotunnel.com", 7844),
            ("c.argotunnel.com", 7844),
        ]);
        assert_eq!(checked_targets(three), fixed);
        assert_eq!(checked_targets(t(&[("evil.example.com", 7844)])), fixed);
        assert_eq!(
            checked_targets(t(&[("a.argotunnel.com", 7844), ("b.argotunnel.com", 443)])),
            fixed
        );
        assert_eq!(checked_targets(Vec::new()), fixed);
    }

    #[test]
    fn the_static_list_respects_the_filter() {
        assert!(static_edges(IpVersionFilter::V4Only)
            .iter()
            .all(|e| e.version == EdgeIpVersion::V4));
        assert!(static_edges(IpVersionFilter::V6Only).is_empty());
    }
}
