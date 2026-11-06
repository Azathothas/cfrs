//! Name resolution for each direct dial of podnet ([`crate::egress`]): the
//! resolver of `pod-dns` (PodUtils/podcrates) with podnet's settings
//! ([`settings`]).
//!
//! The chain, in order:
//!
//! 1. An IP address is used as it is.
//! 2. A pin of `--resolve HOST=IP` or `PODNET_RESOLVE` (a comma-separated list
//!    of `HOST=IP`). TLS still checks the name of the certificate.
//! 3. The system resolver (`/etc/resolv.conf`), with a time limit of
//!    [`STEP_TIMEOUT`].
//! 4. DNS over HTTPS by IP address, at the operators of the services of the
//!    kind `doh` of `pod-services` that serve the JSON form: Cloudflare, then
//!    Google, IPv4 and IPv6. On a host with no IPv4 default route, the IPv6
//!    servers go first. TLS checks the IP address in the certificate. An
//!    answer that the name does not exist (NXDOMAIN) skips the other servers
//!    of that operator; the next operator is asked (issue 119). Through a
//!    proxy that resolves names, the servers by name come after them.
//!
//! A dial through a proxy gives the name to the proxy and resolves nothing
//! here. The host of the proxy itself, and each name that a DoH query
//! resolves, use steps 1 to 3 only ([`plain`]): a DoH query can go through
//! the proxy (issue 259).

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, Result};
use pod_dns::{Names, Nxdomain};
use tokio::time::Instant;

pub use pod_dns::json::{Answer as DohAnswer, Record as DohRecord};
pub use pod_dns::route::has_default_route;

/// The variable of the pins.
pub const PINS_VARIABLE: &str = "PODNET_RESOLVE";
/// The time limit of one step of the chain, and of one DoH server.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(5);

static PINS: OnceLock<Vec<(String, IpAddr)>> = OnceLock::new();

/// Set the pins of `--resolve`. Call it before the first dialer (the one of
/// `--proxy` or `--no-proxy`, else of the first dial): the resolver of each
/// dialer reads them, and a later call has no effect. The pins of
/// `PODNET_RESOLVE` are added to them.
pub fn set_pins(list: &str) -> Result<()> {
    let mut pins = parse_pins(list)?;
    if let Ok(env) = std::env::var(PINS_VARIABLE) {
        let parsed = parse_pins(&env)
            .context(PINS_VARIABLE)
            .map_err(|e| crate::exit::fault(crate::exit::Fault::Config, e))?;
        pins.extend(parsed);
    }
    let _ = PINS.set(pins);
    Ok(())
}

fn pins() -> Vec<(String, IpAddr)> {
    PINS.get_or_init(|| match std::env::var(PINS_VARIABLE) {
        Ok(list) => parse_pins(&list).unwrap_or_else(|err| {
            tracing::warn!("{PINS_VARIABLE}: {err:#}; no pins are used");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    })
    .clone()
}

/// Parse `HOST=IP[,HOST=IP]...`. One host may have several entries.
pub fn parse_pins(list: &str) -> Result<Vec<(String, IpAddr)>> {
    pod_dns::parse_pins(list).map_err(anyhow::Error::msg)
}

/// podnet's settings of the resolver: the pins, the DoH servers of
/// `pod-services` with the JSON form, the family of this host first, by
/// address and then by name, each step [`STEP_TIMEOUT`], A and AAAA both,
/// NXDOMAIN asks the next operator, no cache of addresses, the roots of
/// [`crate::trust`] and podnet's user agent.
pub fn settings() -> pod_dns::Settings {
    static SETTINGS: OnceLock<pod_dns::Settings> = OnceLock::new();
    SETTINGS.get_or_init(read_settings).clone()
}

/// [`settings`], read at the first dial: after the pins of `--resolve`.
fn read_settings() -> pod_dns::Settings {
    let services = pod_services::of_kind("doh").filter(|s| s.text("json-path").is_some());
    let servers = pod_dns::doh::of_services(services, &["v4", "v6"]);
    let context = crate::trust::context();
    let trust = match context.client_config_with(&[], &[]) {
        Ok(config) => pod_tls::Trust::caller(Arc::new(config)).unwrap_or(pod_tls::Trust::Default),
        Err(_) => pod_tls::Trust::Default,
    };
    pod_dns::Settings {
        resolvers: pod_dns::route::by_family(&servers, has_default_route(false)),
        names: Names::Last,
        pins: pins(),
        each: STEP_TIMEOUT,
        connect: STEP_TIMEOUT,
        system: Some(STEP_TIMEOUT),
        both: true,
        nxdomain: Nxdomain::NextOperator,
        memory: false,
        trust,
        user_agent: format!("podnet/{}", env!("CARGO_PKG_VERSION")),
    }
}

/// The chain with no DoH: for the host of a proxy and for each dial of a DoH
/// query.
pub fn plain() -> Arc<pod_dns::Resolver> {
    Arc::new(pod_dns::Resolver::new(settings()).with_observer(crate::egress::counters()))
}

/// The chain whose DoH queries go through `dial`, whose own resolver is
/// [`plain`].
pub fn with_doh(dial: Arc<dyn pod_core::Dial>) -> pod_dns::Resolver {
    pod_dns::Resolver::new(settings())
        .with_doh(crate::trust::context().clone(), dial)
        .with_observer(crate::egress::counters())
}

/// The time limit of the whole chain: each step, and each question of each
/// DoH server.
fn chain_limit(resolver: &pod_dns::Resolver) -> Duration {
    STEP_TIMEOUT * (1 + 2 * resolver.settings().resolvers.len() as u32)
}

/// Resolve `host` with the chain of the process.
pub async fn resolve(host: &str) -> Result<Vec<IpAddr>> {
    let resolver = crate::egress::resolver();
    let deadline = Instant::now() + chain_limit(&resolver);
    resolver
        .ips(host, deadline)
        .await
        .map_err(|e| anyhow::anyhow!("resolving {host}: {e}"))
}

/// Which step of the chain resolves `host` now (issue 94): `literal`, `pin`,
/// `system`, `doh`, or `none`. A name that only DoH resolves is new: the
/// resolver of a visitor can still answer NXDOMAIN (a cached negative
/// answer) for some time.
pub async fn answering_step(host: &str) -> &'static str {
    let resolver = crate::egress::resolver();
    let deadline = Instant::now() + chain_limit(&resolver);
    let found = resolver.find(host, 0, deadline, None).await;
    found.map_or("none", |f| f.source.name())
}

/// Ask the DoH servers for `rtype` records of `name`, one server after the
/// other, until one answers. An NXDOMAIN answer is an answer.
pub async fn doh_query(name: &str, rtype: &str) -> Result<DohAnswer> {
    let resolver = crate::egress::resolver();
    let deadline = Instant::now() + chain_limit(&resolver);
    let way = resolver.way().context("the chain asks no DoH")?;
    way.query(name, rtype, deadline)
        .await
        .map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// podnet's settings: the servers of two operators by address, the
    /// names last, A and AAAA both, NXDOMAIN asks the next operator, no
    /// cache, and a bound of 5 s for each step.
    #[test]
    fn the_settings_are_podnet_s() {
        let settings = settings();
        let mut operators: Vec<&str> = settings
            .resolvers
            .iter()
            .map(|r| r.operator.as_str())
            .collect();
        operators.dedup();
        assert!(operators.len() >= 2, "{operators:?}");
        assert!(settings.resolvers.iter().all(|r| r.json.is_some()));
        assert_eq!(settings.names, Names::Last);
        assert_eq!(
            (settings.both, settings.nxdomain, settings.memory),
            (true, Nxdomain::NextOperator, false)
        );
        assert_eq!(
            (settings.each, settings.connect, settings.system),
            (STEP_TIMEOUT, STEP_TIMEOUT, Some(STEP_TIMEOUT))
        );
        assert!(settings.user_agent.starts_with("podnet/"));
    }
}
