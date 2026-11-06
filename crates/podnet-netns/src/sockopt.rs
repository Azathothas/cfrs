//! The options and the addresses of a socket of the program under the
//! seccomp backend (T-063).
//!
//! The program has one end of an `AF_UNIX` socketpair in place of each
//! `AF_INET` socket. The kernel refuses the IP and TCP options on it
//! (`TCP_NODELAY`: `EOPNOTSUPP`) and gives the `AF_UNIX` address for
//! `getsockname` and `getpeername`. So the supervisor answers these calls
//! from the entry of the socket: it keeps each option that the program set,
//! the address that the program bound, and the peer of a connected stream.
//! A connected TCP socket keeps its entry ([`Connected`]) until the program
//! closes it.

use crate::prelude::*;
use crate::seccomp::{notif_continue, notif_respond, read_mem, sockaddr_in, write_mem, Sock};

/// The options that the program set on a socket: (level, name) to value.
pub(crate) type Options = HashMap<(i32, i32), Vec<u8>>;

/// The longest option value that the supervisor keeps.
const MAX_OPTION: usize = 256;

/// A connected TCP socket of the program. Its data goes through a relay
/// task; the entry keeps the facts that the program can ask for.
pub(crate) struct Connected {
    /// The address that the program connected to (a fake address of a
    /// name stays the fake address, as the program knows it).
    pub(crate) peer: (IpAddr, u16),
    /// The local address: the bound address, else the unspecified address
    /// of the family of the peer with an ephemeral port.
    pub(crate) local: (IpAddr, u16),
    pub(crate) options: Options,
}

impl Connected {
    pub(crate) fn new(
        fd: i32,
        peer: (IpAddr, u16),
        bound: Option<(IpAddr, u16)>,
        options: Options,
    ) -> Self {
        let local = bound.filter(|(_, port)| *port != 0).unwrap_or_else(|| {
            let ip = match peer.0 {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            (ip, ephemeral_port(fd))
        });
        Connected {
            peer,
            local,
            options,
        }
    }
}

/// A port of the ephemeral range of Linux (32768 to 60999), stable for one
/// descriptor.
fn ephemeral_port(fd: i32) -> u16 {
    32768 + (fd.unsigned_abs() % 28232) as u16
}

/// The options of an entry, when the entry keeps them.
fn options_of(entry: &mut Sock) -> Option<&mut Options> {
    match entry {
        Sock::Stream { options, .. } => Some(options),
        Sock::Connected(c) => Some(&mut c.options),
        Sock::Datagram { .. } | Sock::Icmp(_) => None,
    }
}

/// `setsockopt` on a socket of the program: 0, and the value is kept for
/// `getsockopt`. An `AF_UNIX` socketpair rejects the IP-level options,
/// which makes the resolver of glibc give up before it sends.
pub(crate) fn handle_setsockopt(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    (map, key): (&mut HashMap<Key, Sock>, Key),
    verbose: bool,
) -> Result<()> {
    let Some(entry) = map.get_mut(&key) else {
        return notif_continue(lfd, id);
    };
    let (level, name, optval, len) = (a[1] as i32, a[2] as i32, a[3], a[4] as usize);
    if verbose {
        eprintln!(
            "podnet-netns: setsockopt answered by the pod (fd {}, level {level}, option {name})",
            a[0] as i32
        );
    }
    if let Some(options) = options_of(entry) {
        if optval != 0 && len > 0 && len <= MAX_OPTION {
            if let Ok(value) = read_mem(mem, optval, len) {
                options.insert((level, name), value);
            }
        }
    }
    notif_respond(lfd, id, 0, 0)
}

pub(crate) fn handle_getsockopt(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    (map, key): (&mut HashMap<Key, Sock>, Key),
) -> Result<()> {
    let level = a[1] as i32;
    let optname = a[2] as i32;
    let optval = a[3];
    let optlen_ptr = a[4];
    let Some(entry) = map.get_mut(&key) else {
        return notif_continue(lfd, id);
    };
    if !writable || optval == 0 || optlen_ptr == 0 {
        return notif_continue(lfd, id);
    }
    let len = read_mem(mem, optlen_ptr, 4)?;
    let len = u32::from_ne_bytes(len[..4].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_OPTION {
        return notif_continue(lfd, id);
    }
    // An int option of SOL_SOCKET: the kernel writes at most the length of
    // the caller, and puts the length that it wrote in *optlen.
    let value: Option<Vec<u8>> = if level == libc::SOL_SOCKET && optname == libc::SO_TYPE {
        let ty = match entry {
            Sock::Stream { .. } | Sock::Connected(_) => libc::SOCK_STREAM,
            Sock::Datagram { .. } | Sock::Icmp(_) => libc::SOCK_DGRAM,
        };
        Some(ty.to_ne_bytes().to_vec())
    } else if level == libc::SOL_SOCKET && optname == libc::SO_ERROR {
        // Issue 302: the error of a failed connect, once; then 0.
        let error = match entry {
            Sock::Stream { error, .. } => std::mem::take(error),
            Sock::Connected(_) | Sock::Datagram { .. } | Sock::Icmp(_) => 0,
        };
        Some(error.to_ne_bytes().to_vec())
    } else {
        // T-063: the value that the program set.
        options_of(entry).and_then(|o| o.get(&(level, optname)).cloned())
    };
    if let Some(value) = value {
        let out = len.min(value.len());
        write_mem(mem, optval, &value[..out])?;
        write_mem(mem, optlen_ptr, &(out as u32).to_ne_bytes())?;
        return notif_respond(lfd, id, 0, 0);
    }
    write_mem(mem, optval, &vec![0u8; len])?;
    notif_respond(lfd, id, 0, 0)
}

/// `getsockname` (`peer` false) and `getpeername` (`peer` true).
pub(crate) fn handle_sockname(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    (map, key): (&mut HashMap<Key, Sock>, Key),
    peer: bool,
) -> Result<()> {
    let Some(entry) = map.get(&key) else {
        return notif_continue(lfd, id);
    };
    if !writable {
        // Issue 98: the caller's sockaddr cannot be written. The kernel answer
        // would be the AF_UNIX socketpair (family 1), which programs take as
        // an address and abort on (ngtcp2). A clean error in its place.
        return notif_respond(lfd, id, -1, libc::EOPNOTSUPP);
    }
    let unspecified = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    // Answer with a plausible INET address so a program that checks it does not
    // see an AF_UNIX socketpair.
    let (ip, port) = match (entry, peer) {
        (Sock::Stream { bound, .. }, false) => bound.unwrap_or(unspecified),
        // A stream with no connect has no peer, as in the kernel.
        (Sock::Stream { .. }, true) => return notif_respond(lfd, id, -1, libc::ENOTCONN),
        (Sock::Connected(c), false) => c.local,
        (Sock::Connected(c), true) => c.peer,
        (Sock::Datagram { dest, .. }, _) => dest.unwrap_or(unspecified),
        (Sock::Icmp(icmp), peer) => match icmp.name(peer) {
            Some(name) => name,
            None => return notif_respond(lfd, id, -1, libc::ENOTCONN),
        },
    };
    let family = if ip.is_ipv4() {
        libc::AF_INET as u16
    } else {
        libc::AF_INET6 as u16
    };
    let bytes = sockaddr_in(family, ip, port);
    // The contract of the kernel: write at most *addrlen bytes of the
    // address, then put the full length in *addrlen. Before (issue 301), the
    // full address was written past a smaller buffer of the caller.
    if a[2] == 0 {
        return notif_respond(lfd, id, -1, libc::EFAULT);
    }
    let Ok(capacity) = read_mem(mem, a[2], 4) else {
        return notif_respond(lfd, id, -1, libc::EFAULT);
    };
    let capacity = i32::from_ne_bytes(capacity[..4].try_into().unwrap());
    if capacity < 0 {
        return notif_respond(lfd, id, -1, libc::EINVAL);
    }
    let capacity = (capacity as usize).min(bytes.len());
    if capacity > 0 {
        if a[1] == 0 {
            return notif_respond(lfd, id, -1, libc::EFAULT);
        }
        write_mem(mem, a[1], &bytes[..capacity])?;
    }
    // socklen_t is 4 bytes (before, 8 bytes were written over it).
    let out_len = (bytes.len() as u32).to_ne_bytes();
    write_mem(mem, a[2], &out_len)?;
    notif_respond(lfd, id, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connected_socket_has_a_plausible_local_address() {
        let peer = (IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let c = Connected::new(7, peer, None, Options::new());
        assert_eq!(c.peer, peer);
        assert!(c.local.0.is_ipv4() && c.local.0.is_unspecified());
        assert!((32768..61000).contains(&c.local.1));
        let bound = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5000);
        assert_eq!(
            Connected::new(7, peer, Some(bound), Options::new()).local,
            bound
        );
        let v6 = (IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 22);
        assert!(Connected::new(7, v6, None, Options::new())
            .local
            .0
            .is_ipv6());
    }
}
