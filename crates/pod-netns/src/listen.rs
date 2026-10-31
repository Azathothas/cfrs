//! Listen addresses for the proxy front doors.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

/// Where the proxy accepts clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyListen {
    /// An `AF_UNIX` socket, usually an abstract-free filesystem path.
    Unix(PathBuf),
    /// A real TCP listener, for a host that permits `AF_INET` binds.
    Tcp(SocketAddr),
}

impl ProxyListen {
    /// Parse `unix:/path` or `tcp://host:port`.
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            if path.is_empty() {
                bail!("unix: listen address has no path");
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        for prefix in ["tcp://", "tcp:"] {
            if let Some(rest) = value.strip_prefix(prefix) {
                return Ok(Self::Tcp(
                    rest.parse()
                        .with_context(|| format!("bad TCP listen address {rest:?}"))?,
                ));
            }
        }
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Tcp(addr));
        }
        bail!("listen address {value:?} is not unix:/path or tcp://host:port")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_addresses() {
        assert_eq!(
            ProxyListen::parse("unix:/tmp/x.sock").unwrap(),
            ProxyListen::Unix(PathBuf::from("/tmp/x.sock"))
        );
        assert_eq!(
            ProxyListen::parse("tcp://127.0.0.1:1080").unwrap(),
            ProxyListen::Tcp("127.0.0.1:1080".parse().unwrap())
        );
        assert_eq!(
            ProxyListen::parse("127.0.0.1:1080").unwrap(),
            ProxyListen::Tcp("127.0.0.1:1080".parse().unwrap())
        );
        assert!(ProxyListen::parse("nonsense").is_err());
        assert!(ProxyListen::parse("unix:").is_err());
    }
}
