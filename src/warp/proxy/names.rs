//! The names of the WARP commands (`warp forward`, `warp proxy`, `warp nc`,
//! `warp exec`): a literal address or a pin of podnet first, then DNS
//! queries through the tunnel (issue 81).
//!
//! T-073: the pins of `--resolve` and `PODNET_RESOLVE`
//! ([`crate::resolve::pinned`]) come before any query. Before, they did
//! nothing on these commands.

use std::net::IpAddr;

use anyhow::{bail, Result};

use super::query;
use crate::warp::ip::WarpStack;

/// The order of the dial: IPv4 addresses, then IPv6, each in the order of
/// the answer, with no copy.
pub fn order(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in addresses
        .iter()
        .filter(|a| a.is_ipv4())
        .chain(addresses.iter().filter(|a| a.is_ipv6()))
    {
        if !out.contains(ip) {
            out.push(*ip);
        }
    }
    out
}

/// The addresses of `name` that need no query, in the order of the dial:
/// a literal address, else the pins `pins` of `name`.
fn known(name: &str, pins: Vec<IpAddr>) -> Option<Vec<IpAddr>> {
    if let Ok(ip) = name
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return Some(vec![ip]);
    }
    (!pins.is_empty()).then(|| order(pins))
}

/// The A and the AAAA addresses of `name`: its pins, else DNS queries
/// through the tunnel.
pub async fn resolve_all(stack: &WarpStack, name: &str) -> Result<Vec<IpAddr>> {
    resolve_all_with(stack, name, crate::resolve::pinned(name)).await
}

async fn resolve_all_with(stack: &WarpStack, name: &str, pins: Vec<IpAddr>) -> Result<Vec<IpAddr>> {
    if let Some(known) = known(name, pins) {
        return Ok(known);
    }
    let (a, aaaa) = tokio::join!(
        query(stack, name, podnet_netns::dns::TYPE_A),
        query(stack, name, podnet_netns::dns::TYPE_AAAA)
    );
    let mut all: Vec<IpAddr> = a.unwrap_or_default();
    all.extend(aaaa.unwrap_or_default());
    if all.is_empty() {
        bail!("no address for {name} through WARP");
    }
    Ok(order(all))
}

/// The first address of `name` (IPv4 first): its first pin, else DNS
/// through the tunnel. The AAAA query is sent only when there is no A
/// record (issue 114: before, a lost AAAA answer delayed each name by the
/// time limit).
pub async fn resolve(stack: &WarpStack, name: &str) -> Result<IpAddr> {
    resolve_with(stack, name, crate::resolve::pinned(name)).await
}

async fn resolve_with(stack: &WarpStack, name: &str, pins: Vec<IpAddr>) -> Result<IpAddr> {
    if let Some(known) = known(name, pins) {
        return Ok(known[0]);
    }
    let a = query(stack, name, podnet_netns::dns::TYPE_A).await;
    if let Some(ip) = a.as_ref().ok().and_then(|a| a.first()) {
        return Ok(*ip);
    }
    let aaaa = query(stack, name, podnet_netns::dns::TYPE_AAAA).await;
    match (a, aaaa) {
        (_, Ok(aaaa)) if !aaaa.is_empty() => Ok(aaaa[0]),
        (Err(err), _) | (_, Err(err)) => {
            Err(err.context(format!("no address for {name} through WARP")))
        }
        _ => bail!("no address for {name} through WARP"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue 81: IPv4 first, then IPv6, no copy; an IPv6-only answer
    /// stays.
    #[test]
    fn the_dial_order() {
        let a: IpAddr = "1.2.3.4".parse().unwrap();
        let b: IpAddr = "2606:4700::1".parse().unwrap();
        let c: IpAddr = "5.6.7.8".parse().unwrap();
        assert_eq!(order(vec![b, a, c, a]), vec![a, c, b]);
        assert_eq!(order(vec![b]), vec![b]);
    }

    #[test]
    fn the_stack_takes_the_ipv6_address_of_an_ipv4_tunnel() {
        let v6: std::net::Ipv6Addr = "2606:4700:110:8a1::2".parse().unwrap();
        let config =
            crate::warp::StackConfig::new("172.16.0.2".parse().unwrap()).with_ipv6(Some(v6));
        assert_eq!(config.local_v6, Some(v6));
        let only_v6 = crate::warp::StackConfig::new(IpAddr::V6(v6)).with_ipv6(Some(v6));
        assert_eq!(
            only_v6.local_v6, None,
            "no second address for an IPv6 tunnel"
        );
    }

    /// T-073: a pinned name gives its pins (IPv4 first), and no packet
    /// leaves the stack: no DNS query goes into the tunnel.
    #[tokio::test]
    async fn warp_resolve_takes_the_pin_first() {
        let device =
            crate::vnet::device::LinkDevice::tunnel_bounded(crate::warp::ip::TUNNEL_MTU, 64);
        let sent = device.outbound();
        let config = crate::warp::ip::StackConfig::new("172.16.0.2".parse().unwrap());
        let stack = WarpStack::on_device(device, config);
        // podnet's settings with the pins of `--resolve`: the key of a pin
        // has no case and no final dot.
        let settings = pod_dns::Settings {
            pins: crate::resolve::parse_pins(
                "pinned.t073.test=2001:db8::9,pinned.t073.test=192.0.2.9",
            )
            .unwrap(),
            ..crate::resolve::settings()
        };
        let pins = settings.pinned("Pinned.T073.test.");
        let limit = std::time::Duration::from_secs(2);
        let all = tokio::time::timeout(
            limit,
            resolve_all_with(&stack, "pinned.t073.test", pins.clone()),
        )
        .await
        .map(|r| r.map_err(|e| format!("{e:#}")));
        let one = tokio::time::timeout(limit, resolve_with(&stack, "pinned.t073.test", pins))
            .await
            .map(|r| r.map_err(|e| format!("{e:#}")));
        let v4: IpAddr = "192.0.2.9".parse().unwrap();
        let v6: IpAddr = "2001:db8::9".parse().unwrap();
        assert_eq!(sent.len(), 0, "no DNS packet goes into the stack");
        assert_eq!(all, Ok(Ok(vec![v4, v6])));
        assert_eq!(one, Ok(Ok(v4)));
    }
}
