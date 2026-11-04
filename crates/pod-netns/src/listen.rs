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
    /// Parse `unix:/path`, `unix:///path` or `tcp://host:port`.
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(path) = value
            .strip_prefix("unix://")
            .or_else(|| value.strip_prefix("unix:"))
        {
            if path.is_empty() {
                bail!("unix: listen address has no path");
            }
            // unix:///tmp/x is /tmp/x, not ///tmp/x (issue 95).
            let path = if path.starts_with('/') {
                format!("/{}", path.trim_start_matches('/'))
            } else {
                path.to_string()
            };
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

impl std::fmt::Display for ProxyListen {
    /// `unix:PATH` or `tcp://HOST:PORT`, the form that [`ProxyListen::parse`]
    /// reads.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

/// Bind a Unix socket at `path` that only its owner can use: mode 0600. A
/// client must have write permission on the socket to connect.
pub fn bind_private(
    path: impl AsRef<std::path::Path>,
) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let path = path.as_ref();
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unix_url_with_three_slashes_is_an_absolute_path() {
        for value in [
            "unix:///tmp/x.sock",
            "unix://tmp/x.sock",
            "unix:/tmp/x.sock",
            "unix:////tmp/x.sock",
        ] {
            let want = if value == "unix://tmp/x.sock" {
                "tmp/x.sock"
            } else {
                "/tmp/x.sock"
            };
            assert_eq!(
                ProxyListen::parse(value).unwrap(),
                ProxyListen::Unix(PathBuf::from(want)),
                "{value}"
            );
        }
    }

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
