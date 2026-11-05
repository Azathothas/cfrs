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

/// The default directory of the inbound sockets of the seccomp backend
/// (issue 306): `$XDG_RUNTIME_DIR/podnet-netns-inbound` when that directory is
/// of this user, else `podnet-netns-inbound-UID` in the temporary directory.
/// Before, the default was `/tmp/podnet-netns-inbound`, one name for all users.
pub fn default_inbound_dir() -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid() has no precondition.
    let uid = unsafe { libc::geteuid() };
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        let mine = std::fs::metadata(&runtime)
            .map(|m| m.is_dir() && m.uid() == uid)
            .unwrap_or(false);
        if runtime.is_absolute() && mine {
            return runtime.join("podnet-netns-inbound");
        }
    }
    std::env::temp_dir().join(format!("podnet-netns-inbound-{uid}"))
}

/// Make `dir` a private directory of this user, or check the directory that
/// is there (issue 306). A new directory gets mode 0700. A directory that
/// is there must be a directory (not a symbolic link), of the effective
/// user, and not writable by the group or by others. Each other directory
/// is an error: another user could put a socket in it first.
pub fn private_dir(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("making the directory {}", parent.display()))?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("making the directory {}", dir.display())),
    }
    let meta = std::fs::symlink_metadata(dir)
        .with_context(|| format!("reading the directory {}", dir.display()))?;
    // SAFETY: geteuid() has no precondition.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if meta.uid() != uid {
        bail!(
            "the directory {} is of uid {}, not of this user (uid {uid}): give --inbound-dir with a directory of your own",
            dir.display(),
            meta.uid()
        );
    }
    if meta.mode() & 0o022 != 0 {
        bail!(
            "the directory {} is writable by the group or by others (mode {:o}): remove that permission (chmod go-w), or give another --inbound-dir",
            dir.display(),
            meta.mode() & 0o7777
        );
    }
    Ok(())
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

    /// Issue 306: a new inbound directory has mode 0700. A directory that
    /// the group or others can write, a symbolic link, and (as root) a
    /// directory of another user are refused.
    #[test]
    fn the_inbound_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let new = base.path().join("a/inbound");
        private_dir(&new).unwrap();
        let mode = std::fs::metadata(&new).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        private_dir(&new).unwrap();

        let open = base.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = format!("{:#}", private_dir(&open).unwrap_err());
        assert!(err.contains("writable by the group or by others"), "{err}");

        let link = base.path().join("link");
        std::os::unix::fs::symlink(&new, &link).unwrap();
        let err = format!("{:#}", private_dir(&link).unwrap_err());
        assert!(err.contains("not a directory"), "{err}");

        // SAFETY: geteuid() has no precondition.
        if unsafe { libc::geteuid() } == 0 {
            let foreign = base.path().join("foreign");
            std::fs::create_dir(&foreign).unwrap();
            std::os::unix::fs::chown(&foreign, Some(65534), Some(65534)).unwrap();
            let err = format!("{:#}", private_dir(&foreign).unwrap_err());
            assert!(err.contains("not of this user"), "{err}");
        }
    }

    /// Issue 306: the default inbound directory is not one name for all
    /// users.
    #[test]
    fn the_default_inbound_directory_is_of_this_user() {
        let dir = default_inbound_dir();
        assert_ne!(dir, PathBuf::from("/tmp/podnet-netns-inbound"));
        // SAFETY: geteuid() has no precondition.
        let uid = unsafe { libc::geteuid() };
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name == "podnet-netns-inbound" || name == format!("podnet-netns-inbound-{uid}"),
            "{}",
            dir.display()
        );
    }
}
