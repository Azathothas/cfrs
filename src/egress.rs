//! Each outbound TCP connection of podnet: the dial of `pod-proxy`
//! (PodUtils/podcrates) with podnet's settings, directly or through a proxy.
//!
//! [`dial`] is the one path. It takes the proxy of the choice of the process:
//!
//! * `--proxy URL` or `PODNET_PROXY` ([`set_proxy`]), a value of the user
//!   that can be a command;
//! * `--no-proxy` ([`set_direct`]);
//! * else the variables, in the order of curl: `HTTPS_PROXY`, `https_proxy`,
//!   `ALL_PROXY`, `all_proxy`; else the proxy of a tool's file (git, npm,
//!   pip, `/etc/environment`).
//!
//! `NO_PROXY` (or `no_proxy`) names the targets that do not use the proxy,
//! `--proxy`'s too, by the rules of [`rules`]. A proxy can be HTTP
//! (`CONNECT`, Basic or Digest) or SOCKS5 (`socks5://` resolves the name on
//! this host, `socks5h://` gives the name to the proxy), on TCP, on a Unix
//! socket or at a command. A direct dial resolves the name with the chain
//! of [`crate::resolve`] and races its addresses (RFC 8305). Each dial is
//! one decision `egress` of [`crate::decisions`].
//!
//! The words and the hops of a failure are podnet's: a proxy's refusal is a
//! [`Refusal`], and a failure through a proxy is at the hop `proxy`.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Result;
use pod_core::{BoxFuture, Class, Connected, Dial, Failure, Found, Resolve, Source, Stage, Target};
use pod_proxy::{Dialer, Environment, Origin, Rules, Settings};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::hop::{self, Hop};
use crate::net::BoxedIo;

pub use pod_proxy::{
    group_errors, Carrier, ChildIo, DialError, NoProxy, Proxy, ProxyKind, ATTEMPT_DELAY,
};

/// The variables of the proxy, in the order that podnet reads them.
pub const PROXY_VARIABLES: &[&str] = &pod_proxy::PROXY_VARS_UPPER_FIRST;
/// The variables of the list of targets that do not use the proxy.
pub const NO_PROXY_VARIABLES: &[&str] = &pod_proxy::NO_PROXY_VARS_UPPER_FIRST;
/// The port of an `http://` proxy URL with no port, as in curl.
pub const HTTP_PORT: u16 = 8080;

/// podnet's rules of the proxy settings: the upper case first, a URL that
/// cannot be used passed over with a warning, `http://` on port 8080, an
/// entry `host:port` of `NO_PROXY` for that port only, and the loopback
/// through the proxy unless `NO_PROXY` names it.
pub fn rules() -> Rules {
    Rules {
        proxy_vars: &pod_proxy::PROXY_VARS_UPPER_FIRST,
        no_proxy_vars: &pod_proxy::NO_PROXY_VARS_UPPER_FIRST,
        skip_unusable: true,
        http_port: HTTP_PORT,
        no_proxy_ports: true,
        loopback_direct: false,
    }
}

/// The proxy of a URL by podnet's rules, as a variable gives it: no command.
pub fn parse(spec: &str) -> Result<Proxy> {
    Proxy::parse_with(spec, false, HTTP_PORT).map_err(anyhow::Error::msg)
}

/// How podnet reaches the network, as `podnet status` names it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxyChoice {
    /// The proxy of the variables, if one is set (the default).
    #[default]
    FromEnvironment,
    /// No proxy (`--no-proxy`).
    Direct,
    /// This proxy (`--proxy URL`).
    Via(Proxy),
}

/// The choice of the process and its dialer.
struct Way {
    choice: ProxyChoice,
    dialer: Arc<Dialer>,
}

static WAY: OnceLock<Way> = OnceLock::new();

/// The way of the process: the one set, else the variables and the proxy
/// of a tool's file, read at the first use.
fn way() -> &'static Way {
    WAY.get_or_init(|| {
        let var = |name: &str| std::env::var_os(name);
        let env =
            Environment::read_with(&var, rules()).or_detected(&var, &pod_proxy::detect::read_file);
        Way {
            choice: ProxyChoice::FromEnvironment,
            dialer: Arc::new(dialer(pod_proxy::ProxyChoice::FromEnvironment(env))),
        }
    })
}

/// Use the proxy that the user gave (`--proxy`, `PODNET_PROXY`): it can be
/// a command, and `NO_PROXY` still applies. Call it before the first
/// connection; a later call has no effect. The proxy, or why `spec` cannot
/// be used.
pub fn set_proxy(spec: &str) -> Result<Proxy> {
    let var = |name: &str| std::env::var_os(name);
    let env =
        Environment::read_with(&var, rules()).with_proxy(spec, Origin::User("--proxy".into()));
    let proxy = match env.proxy.as_ref().map(|given| &given.value) {
        Some(Ok(proxy)) => proxy.clone(),
        Some(Err(why)) => anyhow::bail!("{why}"),
        None => anyhow::bail!("the value names no proxy"),
    };
    let dialer = Arc::new(dialer(pod_proxy::ProxyChoice::FromEnvironment(env)));
    let _ = WAY.set(Way {
        choice: ProxyChoice::Via(proxy.clone()),
        dialer,
    });
    Ok(proxy)
}

/// Connect directly (`--no-proxy`). Call it before the first connection.
pub fn set_direct() {
    let dialer = Arc::new(dialer(pod_proxy::ProxyChoice::Direct));
    let _ = WAY.set(Way {
        choice: ProxyChoice::Direct,
        dialer,
    });
}

/// The choice of this process.
pub fn choice() -> ProxyChoice {
    way().choice.clone()
}

/// A dialer with podnet's settings: its program, no user agent and no
/// `TCP_NOTSENT_LOWAT`, its resolver (with no DoH for a proxy's own host:
/// a DoH query can need the same proxy), and its counters.
fn dialer(proxy: pod_proxy::ProxyChoice) -> Dialer {
    let mut settings = Settings::new("podnet", proxy);
    settings.lowat = None;
    Dialer::new(settings, Arc::new(Resolver { doh: true }))
        .with_proxy_resolver(Arc::new(Resolver { doh: false }))
        .with_observer(Arc::new(Counters))
}

/// The proxy for `host:port`, after `NO_PROXY`, or `None` for a direct
/// connection.
pub fn proxy_for(host: &str, port: u16) -> Option<Proxy> {
    way().dialer.proxy_at(host, port).ok().flatten()
}

/// Connect to `host:port`: through `via` when it is given, else through the
/// proxy of [`proxy_for`], else directly.
pub async fn dial(
    host: &str,
    port: u16,
    via: Option<&Proxy>,
    timeout: Duration,
) -> Result<BoxedIo> {
    match via {
        Some(proxy) => {
            open(
                &dialer(pod_proxy::ProxyChoice::Via(proxy.clone())),
                host,
                port,
                timeout,
            )
            .await
        }
        None => open(&way().dialer, host, port, timeout).await,
    }
}

/// Connect to `host:port` with no proxy: each address of the name, with
/// [`ATTEMPT_DELAY`] between the starts.
pub async fn dial_direct(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    dialer(pod_proxy::ProxyChoice::Direct)
        .tcp(host, port, timeout)
        .await
        .map_err(|e| failed(e, host, port, None))
}

/// Connect to the first of `addrs` that answers, with no proxy. The
/// attempts start [`ATTEMPT_DELAY`] apart, or at once when the attempt
/// before fails. Gives the index of the address and the stream.
pub async fn dial_addrs(addrs: &[SocketAddr], timeout: Duration) -> Result<(usize, TcpStream)> {
    pod_proxy::dial_addrs(addrs, timeout)
        .await
        .map_err(|e| error_of(&e))
}

/// [`dial`] with `dialer`, and podnet's words of a failure.
async fn open(dialer: &Dialer, host: &str, port: u16, timeout: Duration) -> Result<BoxedIo> {
    let proxy = dialer.proxy_at(host, port).ok().flatten();
    match dialer.stream(host, port, timeout).await {
        Ok((stream, _)) => Ok(Box::new(stream)),
        Err(e) => Err(failed(e, host, port, proxy.as_ref())),
    }
}

/// A failed dial in podnet's words: through a proxy, `HOST:PORT through
/// the proxy URL`, at the hop `proxy`, with its [`Refusal`]; directly,
/// `connecting to HOST:PORT`, at the hop `dns` when the name did not
/// resolve.
fn failed(e: DialError, host: &str, port: u16, proxy: Option<&Proxy>) -> anyhow::Error {
    let at = pod_proxy::authority(host, port);
    match proxy {
        Some(proxy) => {
            let err = match &e {
                DialError::ProxyRefused { status, reason, .. } => {
                    anyhow::Error::new(Refusal::of(*status, reason))
                }
                _ => error_of(&e),
            };
            hop::at(
                Hop::Proxy,
                err.context(format!("{at} through the proxy {}", proxy.label())),
            )
        }
        None => {
            let stage = e.stage_and_class().0;
            let err = error_of(&e).context(format!("connecting to {at}"));
            match stage {
                Stage::Dns => hop::at(Hop::Dns, err),
                Stage::Proxy => hop::at(Hop::Proxy, err),
                _ => err,
            }
        }
    }
}

/// The error of a dial: when every address failed, the error of I/O of the
/// last one, with its kind and the words of each address (`podnet doctor`
/// reads a refusal of this host by the kind); else the error of the dial.
fn error_of(e: &DialError) -> anyhow::Error {
    match e {
        DialError::Connect {
            kind: Some(kind),
            detail,
            ..
        } => anyhow::Error::new(std::io::Error::new(*kind, detail.clone())),
        _ => anyhow::Error::new(e.clone()),
    }
}

/// A proxy answered and refused the connection: an HTTP status that is not
/// 2xx (`status`), or a SOCKS5 refusal (`status` 0). A lost connection is
/// not a refusal.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub status: u16,
    pub text: String,
}

impl Refusal {
    /// The refusal of a proxy's `status` and `reason` (`pod-proxy` gives a
    /// SOCKS5 refusal the status of its HTTP case, and a reason that starts
    /// with `SOCKS5`).
    fn of(status: u16, reason: &str) -> Refusal {
        if reason.starts_with("SOCKS5") {
            return Refusal {
                status: 0,
                text: reason.to_string(),
            };
        }
        let text = match reason.trim() {
            "" => format!("the proxy refused CONNECT with HTTP {status}"),
            reason => format!("the proxy refused CONNECT with HTTP {status}: {reason}"),
        };
        Refusal { status, text }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Refusal {}

/// The refusal of a proxy in the chain of `err`, if there is one.
pub fn refusal(err: &anyhow::Error) -> Option<&Refusal> {
    // An error with a hop holds the refusal in its own chain.
    err.chain().find_map(|e| {
        e.downcast_ref::<Refusal>().or_else(|| {
            e.downcast_ref::<hop::AtHop>()
                .and_then(|h| refusal(h.inner()))
        })
    })
}

/// The dial of podnet for a crate that takes a [`Dial`] (the HTTP client of
/// [`crate::fetch`]): [`dial`], through `via` or the choice of the process,
/// with podnet's words; the error is the cause of the failure.
pub struct Egress {
    via: Option<Proxy>,
}

/// The dial of the process, or through `via` alone.
pub fn egress(via: Option<Proxy>) -> Arc<dyn Dial> {
    Arc::new(Egress { via })
}

/// The way out of one request through `proxy`, or the client's with none
/// ([`pod_proxy::client::Request::via`]).
pub fn via(proxy: Option<&Proxy>) -> Option<Arc<dyn Dial>> {
    proxy.map(|p| egress(Some(p.clone())))
}

impl Dial for Egress {
    fn label(&self) -> String {
        match &self.via {
            Some(proxy) => proxy.label(),
            None => way().dialer.label(),
        }
    }

    fn dial<'a>(
        &'a self,
        target: &'a Target,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Connected, Failure>> {
        Box::pin(async move {
            let limit = deadline.saturating_duration_since(Instant::now());
            match dial(&target.host(), target.port(), self.via.as_ref(), limit).await {
                Ok(io) => Ok(Connected::new(Box::new(io))),
                Err(e) => {
                    let stage = match hop::of(&e) {
                        Some(Hop::Proxy) => Stage::Proxy,
                        Some(Hop::Dns) => Stage::Dns,
                        _ => Stage::Connect,
                    };
                    Err(Failure::caused(
                        stage,
                        Class::Unavailable,
                        format!("{e:#}"),
                        e,
                    ))
                }
            }
        })
    }

    fn names_inside(&self) -> bool {
        match &self.via {
            Some(proxy) => proxy.kind() != (ProxyKind::Socks5 { remote_dns: false }),
            None => way().dialer.names_inside(),
        }
    }
}

/// podnet's resolver as the dial asks it: the chain of [`crate::resolve`]
/// (an IP address, the pins, the system resolver, DoH), one source; with no
/// DoH for the host of a proxy.
struct Resolver {
    doh: bool,
}

/// The one source of podnet's chain.
const CHAIN: Source = Source {
    rank: 0,
    name: "chain",
};

impl Resolve for Resolver {
    fn label(&self) -> String {
        if self.doh {
            "the chain of podnet".into()
        } else {
            "the chain of podnet with no DoH".into()
        }
    }

    fn resolve_from<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        deadline: Instant,
        after: Option<Source>,
    ) -> BoxFuture<'a, Result<Found, Failure>> {
        Box::pin(async move {
            if after.is_some() {
                return Err(Failure::new(
                    Stage::Dns,
                    Class::Unavailable,
                    "no source after the chain of podnet",
                ));
            }
            let lookup = if self.doh {
                crate::resolve::resolve(host)
            } else {
                crate::resolve::resolve_no_doh(host)
            };
            let left = deadline.saturating_duration_since(Instant::now());
            let ips: Vec<IpAddr> = match tokio::time::timeout_at(deadline, lookup).await {
                Ok(Ok(ips)) => ips,
                Ok(Err(e)) => {
                    // The chain names the host itself; the dial names it too.
                    let text = format!("{e:#}");
                    let bare = host.trim_start_matches('[').trim_end_matches(']');
                    let text = text
                        .strip_prefix(&format!("resolving {bare}: "))
                        .unwrap_or(&text)
                        .to_string();
                    return Err(Failure::new(Stage::Dns, Class::Unavailable, text));
                }
                Err(_) => {
                    let text = format!("no answer in {:.1} s", left.as_secs_f64());
                    return Err(Failure::new(Stage::Dns, Class::Timeout, text));
                }
            };
            let addrs = ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            Ok(Found {
                addrs,
                source: CHAIN,
                more: false,
            })
        })
    }
}

/// The counters of the decisions of [`crate::decisions`].
struct Counters;

impl pod_core::Observer for Counters {
    fn decision(&self, decision: &'static str, outcome: &str) {
        crate::decisions::count(decision, outcome);
    }
}

/// The status line of a proxy answer to `CONNECT` (the fuzz target).
pub(crate) fn parse_status(head: &[u8]) -> Result<u16> {
    let line = String::from_utf8_lossy(head);
    let (status, _) = pod_proxy::http::parse_status_line(&line).map_err(anyhow::Error::msg)?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// podnet's words of a refusal: the status and the reason, and a SOCKS5
    /// refusal with the status 0.
    #[test]
    fn a_refusal_has_podnet_s_words() {
        let refused = Refusal::of(403, "Forbidden: not on the egress allowlist");
        assert_eq!(refused.status, 403);
        assert_eq!(
            refused.text,
            "the proxy refused CONNECT with HTTP 403: Forbidden: not on the egress allowlist"
        );
        assert_eq!(
            Refusal::of(502, " ").text,
            "the proxy refused CONNECT with HTTP 502"
        );
        let socks = Refusal::of(407, "SOCKS5: the proxy refused the user and the password");
        assert_eq!(
            (socks.status, socks.text.as_str()),
            (0, "SOCKS5: the proxy refused the user and the password")
        );
    }

    /// A dial that no address took keeps the kind of its last error and
    /// the words of each address, as podnet's dial gave them.
    #[test]
    fn a_failed_dial_keeps_the_kind_of_its_error() {
        let e = DialError::Connect {
            target: "h:1".into(),
            detail: "192.0.2.1:1: No route to host".into(),
            cut: None,
            kind: Some(std::io::ErrorKind::HostUnreachable),
        };
        let err = failed(e, "h", 1, None);
        assert_eq!(
            format!("{err:#}"),
            "connecting to h:1: 192.0.2.1:1: No route to host"
        );
        let io = err.chain().find_map(|e| e.downcast_ref::<std::io::Error>());
        assert_eq!(
            io.map(|e| e.kind()),
            Some(std::io::ErrorKind::HostUnreachable)
        );
    }

    /// podnet's rules: the upper case first, port 8080 for `http://`, the
    /// port of a `NO_PROXY` entry, and the loopback through the proxy.
    #[test]
    fn the_rules_are_podnet_s() {
        let set = |name: &str| match name {
            "HTTPS_PROXY" => Some("proxy.example".into()),
            "https_proxy" => Some("http://lower.example:3128".into()),
            "NO_PROXY" => Some("internal.example:8443".into()),
            _ => None,
        };
        let env = Environment::read_with(&set, rules());
        let proxy = env.proxy_at("relay.example", 443, &[]).unwrap().unwrap();
        assert_eq!(
            (proxy.host.as_str(), proxy.port),
            ("proxy.example", HTTP_PORT)
        );
        assert!(env
            .proxy_at("internal.example", 8443, &[])
            .unwrap()
            .is_none());
        assert!(env
            .proxy_at("internal.example", 443, &[])
            .unwrap()
            .is_some());
        assert!(
            env.proxy_at("127.0.0.1", 80, &[]).unwrap().is_some(),
            "the loopback takes the proxy"
        );
        assert_eq!(parse("http://127.0.0.1").unwrap().port, HTTP_PORT);
    }
}
