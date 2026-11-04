//! Local forwards into WARP (issue 143): `cfrs warp forward -L
//! LISTEN=HOST:PORT`. Each connection to LISTEN goes through the WARP
//! session to HOST:PORT. A name is resolved inside the tunnel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use pod_netns::listen::ProxyListen;
use pod_netns::socks::ProxyHost;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use super::ip::WarpStack;
use super::proxy::Bound;

/// One rule of `-L`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub listen: ProxyListen,
    pub host: ProxyHost,
    pub port: u16,
}

impl Rule {
    /// `LISTEN=HOST:PORT`. LISTEN is `PORT` (127.0.0.1), `ADDR:PORT`,
    /// `tcp://ADDR:PORT` or `unix:/PATH`. HOST:PORT can start with
    /// `tunnel:` or `tcp://`; an IPv6 address is in brackets.
    pub fn parse(spec: &str) -> Result<Self> {
        let (listen, target) = spec
            .rsplit_once('=')
            .with_context(|| format!("{spec:?}: give LISTEN=HOST:PORT"))?;
        let listen = match listen.parse::<u16>() {
            Ok(0) => bail!("{spec:?}: the listen port must be 1 to 65535"),
            Ok(port) => ProxyListen::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            Err(_) => ProxyListen::parse(listen).with_context(|| format!("{spec:?}"))?,
        };
        let target = target
            .strip_prefix("tunnel:")
            .or_else(|| target.strip_prefix("tcp://"))
            .unwrap_or(target);
        let (host, port) = target
            .rsplit_once(':')
            .with_context(|| format!("{spec:?}: give HOST:PORT after ="))?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .with_context(|| format!("{spec:?}: the port must be 1 to 65535"))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.contains(['/', ' ', '[', ']']) {
            bail!("{spec:?}: give HOST:PORT after =");
        }
        let host = match host.parse::<IpAddr>() {
            Ok(ip) => ProxyHost::Ip(ip),
            Err(_) => ProxyHost::Domain(host.to_ascii_lowercase()),
        };
        // A loopback target is the host itself, not a host in the tunnel.
        let loopback = match &host {
            ProxyHost::Ip(ip) => ip.is_loopback() || ip.is_unspecified(),
            ProxyHost::Domain(name) => name == "localhost" || name.ends_with(".localhost"),
        };
        if loopback {
            bail!("{spec:?}: the target is a loopback address; WARP does not reach the host");
        }
        Ok(Rule { listen, host, port })
    }

    /// The target as text: `HOST:PORT`, `[IPV6]:PORT`.
    pub fn target(&self) -> String {
        match &self.host {
            ProxyHost::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            host => format!("{host}:{}", self.port),
        }
    }
}

/// A running forward: its listener and its accept task.
pub struct Forward {
    pub listen: ProxyListen,
    pub rule: Rule,
    task: tokio::task::JoinHandle<()>,
}

impl Forward {
    /// Stop the forward.
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Accept connections on `bound` and send each one through the WARP session
/// of `live` to the target of `rule`. At most `max` connections at the same
/// time (0: no limit); a connection over it is closed at once.
pub fn run(live: Arc<super::Live<WarpStack>>, bound: Bound, rule: Rule, max: usize) -> Forward {
    let listen = bound.listen().clone();
    if let ProxyListen::Tcp(addr) = &listen {
        if !addr.ip().is_loopback() {
            warn!(%addr, target = %rule.target(), "the forward listens on an address that other hosts can reach");
        }
    }
    let limit = Arc::new(tokio::sync::Semaphore::new(if max == 0 {
        tokio::sync::Semaphore::MAX_PERMITS
    } else {
        max
    }));
    let task = {
        let rule = rule.clone();
        match bound {
            Bound::Tcp(listener, _) => tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    connection(&live, &limit, &rule, stream);
                }
            }),
            Bound::Unix(listener, _) => tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    connection(&live, &limit, &rule, stream);
                }
            }),
        }
    };
    info!(%listen, target = %rule.target(), "WARP forward is listening");
    Forward { listen, rule, task }
}

/// Serve one connection of a forward on its own task.
fn connection<S>(
    live: &Arc<super::Live<WarpStack>>,
    limit: &Arc<tokio::sync::Semaphore>,
    rule: &Rule,
    mut stream: S,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(permit) = limit.clone().try_acquire_owned() else {
        warn!(target = %rule.target(), "WARP forward: a connection is refused, --max-connections is reached");
        return;
    };
    let live = live.clone();
    let rule = rule.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let stack = match live.get().await {
            Ok(stack) => stack,
            Err(err) => {
                warn!(error = %format!("{err:#}"), "WARP forward: no session");
                return;
            }
        };
        let mut remote = match super::proxy::dial(stack, rule.host.clone(), rule.port).await {
            Ok(remote) => remote,
            Err(err) => {
                warn!(target = %rule.target(), error = %format!("{err:#}"), "WARP forward: no connection");
                return;
            }
        };
        if let Err(err) = tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
            debug!(target = %rule.target(), error = %err, "WARP forward: the connection ended");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rules_of_a_local_forward() {
        let rule = Rule::parse("5432=tunnel:db.internal:5432").unwrap();
        assert_eq!(
            rule.listen,
            ProxyListen::Tcp("127.0.0.1:5432".parse().unwrap())
        );
        assert_eq!(rule.host, ProxyHost::Domain("db.internal".into()));
        assert_eq!(rule.target(), "db.internal:5432");
        let rule = Rule::parse("tcp://0.0.0.0:8080=[2606:4700::1111]:80").unwrap();
        assert_eq!(
            rule.listen,
            ProxyListen::Tcp("0.0.0.0:8080".parse().unwrap())
        );
        assert_eq!(rule.target(), "[2606:4700::1111]:80");
        let rule = Rule::parse("unix:/run/x.sock=1.1.1.1:443").unwrap();
        assert_eq!(rule.listen, ProxyListen::Unix("/run/x.sock".into()));
        assert_eq!(rule.host, ProxyHost::Ip("1.1.1.1".parse().unwrap()));
        assert_eq!(
            Rule::parse("127.0.0.1:9000=example.com:443").unwrap().port,
            443
        );
        for bad in [
            "5432",
            "0=a:1",
            "5432=db",
            "5432=db:0",
            "5432=:22",
            "5432=127.0.0.1:22",
            "5432=tunnel:localhost:22",
            "5432=[::1]:22",
            "nothing=a:1",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
    }
}
