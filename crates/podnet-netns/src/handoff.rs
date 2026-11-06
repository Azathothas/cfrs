//! The handoff of a plain upstream to the program under the seccomp backend
//! (T-065).
//!
//! A proxy on a Unix socket (one SOCKS5 or HTTP hop) gives a plain stream
//! after its handshake: no TLS and no framing stays in the supervisor. The
//! supervisor installs this socket at the descriptor number of the program
//! (`SECCOMP_ADDFD_FLAG_SETFD`) and starts no relay. The kernel then moves
//! the bytes. After the handoff, the supervisor sees no byte of the flow:
//! no byte count, no idle limit, no log line of the data.
//!
//! The entry of the socket stays ([`crate::sockopt::Connected`]) under the
//! inode of the upstream socket. The options and the addresses of the
//! program thus stay the same.
//!
//! The handoff occurs only when it is safe: one call waits for the dial,
//! the descriptor of the call still refers to the socket, no other
//! descriptor of the pod refers to the socket, and the supervisor has no
//! unread byte of the program. Else the relay starts. A TCP upstream keeps
//! the relay: the owner decides if the handoff becomes the default for it.

use crate::fdtable::{Key, Table};
use crate::prelude::*;
use crate::seccomp::{child_fd_flags, notif_addfd_setfd};

/// The connected upstream at the end of a dial.
pub(crate) enum Link {
    /// A stream that the supervisor relays.
    Relay(Upstream),
    /// A plain Unix stream that the program can hold.
    Plain(OwnedFd),
}

impl Link {
    /// The stream for a relay.
    pub(crate) fn into_relay(self) -> Result<Upstream> {
        match self {
            Link::Relay(upstream) => Ok(upstream),
            Link::Plain(fd) => {
                let stream = std::os::unix::net::UnixStream::from(fd);
                stream.set_nonblocking(true)?;
                Ok(Box::new(tokio::net::UnixStream::from_std(stream)?))
            }
        }
    }
}

/// The first call of a dial: its notification, its task and its descriptor.
#[derive(Clone, Copy)]
pub(crate) struct Caller {
    pub(crate) id: u64,
    pub(crate) pid: u32,
    pub(crate) fd: i32,
}

/// The hop of a chain whose upstream is plain: the only hop, SOCKS5 or
/// HTTP, on a Unix socket.
pub(crate) fn plain_hop(chain: &[Proxy]) -> Option<&Proxy> {
    match chain {
        [only] if only.is_unix() && matches!(only.kind, ProxyKind::Socks5 | ProxyKind::Http) => {
            Some(only)
        }
        _ => None,
    }
}

/// Dial the proxy on its Unix socket and do the handshake for `target`.
pub(crate) async fn dial_plain(proxy: &Proxy, target: &str) -> Result<Link> {
    let path = proxy
        .unix_path
        .as_deref()
        .context("the proxy has no socket")?;
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| format!("connect to unix proxy {path}"))?;
    let stream = match proxy.kind {
        ProxyKind::Socks5 => crate::upstream::socks5_connect(stream, proxy, target).await?,
        _ => crate::upstream::http_connect(stream, proxy, target).await?,
    };
    Ok(Link::Plain(stream.into_std()?.into()))
}

/// Install `upstream` at the descriptor of `caller`, in place of the end
/// `key` of the socket pair. Return the key of the upstream socket, or
/// `None` when the handoff is not safe or fails (then the relay starts).
pub(crate) fn hand_off(
    lfd: RawFd,
    caller: Caller,
    waiting: &[u64],
    (upstream, pair): (&OwnedFd, &tokio::net::UnixStream),
    (map, key): (&mut Table, Key),
) -> Option<Key> {
    if waiting != [caller.id]
        || unread(pair.as_raw_fd()) != 0
        || map.key_of(caller.pid, caller.fd) != key
        || map.other_copy(caller.pid, caller.fd, key)
    {
        return None;
    }
    // The upstream gets the flags of the descriptor of the program.
    let flags = child_fd_flags(caller.pid, caller.fd)?;
    set_flag(
        upstream.as_raw_fd(),
        libc::O_NONBLOCK,
        flags & libc::O_NONBLOCK != 0,
    )
    .ok()?;
    let cloexec = (flags & libc::O_CLOEXEC) as u32;
    let new_key = crate::fdtable::inode_of(upstream.as_raw_fd()).ok()?;
    notif_addfd_setfd(lfd, caller.id, upstream.as_raw_fd(), caller.fd, cloexec).ok()?;
    Some(new_key)
}

/// The number of bytes that wait to be read on `fd` (`FIONREAD`).
fn unread(fd: RawFd) -> i32 {
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int to `n`.
    match unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) } {
        0 => n,
        _ => -1,
    }
}

/// Set or clear the file status flag `flag` of `fd`.
fn set_flag(fd: RawFd, flag: i32, on: bool) -> Result<()> {
    // SAFETY: F_GETFL and F_SETFL take no pointer.
    let old = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if old < 0 {
        return Err(std::io::Error::last_os_error()).context("F_GETFL");
    }
    let new = if on { old | flag } else { old & !flag };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, new) } < 0 {
        return Err(std::io::Error::last_os_error()).context("F_SETFL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_unix_hop_of_socks5_or_http_is_plain() {
        let unix = Proxy::parse("unix:/run/proxy.sock").unwrap();
        let tcp = Proxy::parse("socks5://127.0.0.1:1080").unwrap();
        assert!(plain_hop(std::slice::from_ref(&unix)).is_some());
        assert!(plain_hop(std::slice::from_ref(&tcp)).is_none());
        assert!(plain_hop(&[unix.clone(), unix]).is_none());
        let direct = Proxy::parse("direct").unwrap();
        assert!(plain_hop(&[direct]).is_none());
    }

    #[test]
    fn a_plain_link_becomes_a_relay_stream_and_unread_counts_bytes() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        (&a).write_all(b"abc").unwrap();
        assert_eq!(unread(b.as_raw_fd()), 3);
        set_flag(b.as_raw_fd(), libc::O_NONBLOCK, true).unwrap();
        let flags = unsafe { libc::fcntl(b.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::AsyncReadExt;
            let mut up = Link::Plain(b.into()).into_relay().unwrap();
            let mut buf = [0u8; 3];
            up.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"abc");
        });
    }
}
