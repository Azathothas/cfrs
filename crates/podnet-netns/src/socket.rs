//! The `socket` call of the program under the seccomp backend. An `AF_INET`
//! or `AF_INET6` socket of the kinds stream and datagram becomes one end of
//! an `AF_UNIX` socket pair; the supervisor keeps the other end. An ICMP
//! datagram socket (a ping socket) gets its own kind (T-066,
//! `src/icmp.rs`). With `-v`, the pod logs each socket that it makes so
//! (T-071).

use crate::prelude::*;
use crate::seccomp::{notif_addfd_send, notif_continue, notif_respond, set_nonblocking, Sock};

/// The `socket` call: a socket pair in place of an `AF_INET` socket.
pub(crate) fn handle_socket(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    map: &mut crate::fdtable::Table,
    verbose: bool,
) -> Result<()> {
    if !map.has_room() {
        return notif_respond(lfd, id, -1, libc::EMFILE);
    }
    let domain = a[0] as i32;
    let ty = a[1] as i32;
    let kind = ty & 0xf; // SOCK_STREAM=1, SOCK_DGRAM=2
    let inet = domain == libc::AF_INET || domain == libc::AF_INET6;
    let protocol = a[2] as i32;
    let icmp = kind == libc::SOCK_DGRAM
        && ((domain == libc::AF_INET && protocol == libc::IPPROTO_ICMP)
            || (domain == libc::AF_INET6 && protocol == libc::IPPROTO_ICMPV6));
    if !inet || (kind != libc::SOCK_STREAM && kind != libc::SOCK_DGRAM) {
        return notif_continue(lfd, id);
    }
    // ADDFD only accepts O_CLOEXEC in newfd_flags on older kernels, so
    // SOCK_NONBLOCK is applied to the shared description instead: the child's
    // fd is a dup of `theirs`, so the flag is inherited.
    let mut newfd_flags = 0u32;
    if ty & libc::SOCK_CLOEXEC != 0 {
        newfd_flags |= libc::O_CLOEXEC as u32;
    }
    let nonblocking = ty & libc::SOCK_NONBLOCK != 0;
    if kind == libc::SOCK_STREAM {
        // A std pair is blocking on both ends; only the supervisor's end is
        // made non-blocking, so the child gets a blocking socket unless it
        // asked for SOCK_NONBLOCK.
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        set_nonblocking(ours.as_raw_fd())?;
        if nonblocking {
            set_nonblocking(theirs.as_raw_fd())?;
        }
        let key = crate::fdtable::inode_of(theirs.as_raw_fd())?;
        notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
        drop(theirs);
        map.insert(
            key,
            Sock::Stream {
                pair: tokio::net::UnixStream::from_std(ours)?,
                bound: None,
                inbound: None,
                error: 0,
                options: Default::default(),
            },
        );
    } else {
        let (ours, theirs) = std::os::unix::net::UnixDatagram::pair()?;
        set_nonblocking(ours.as_raw_fd())?;
        if nonblocking {
            set_nonblocking(theirs.as_raw_fd())?;
        }
        // A copy of the end of the program, for intercepted reads.
        let copy = theirs.try_clone()?;
        let key = crate::fdtable::inode_of(theirs.as_raw_fd())?;
        notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
        drop(theirs);
        let pair = Arc::new(tokio::net::UnixDatagram::from_std(ours)?);
        let v6 = domain == libc::AF_INET6;
        let inbox = Arc::new(crate::inbox::Inbox::new(copy, v6));
        let entry = match icmp {
            true => Sock::Icmp(crate::icmp::Icmp {
                pair,
                inbox,
                v6,
                dest: None,
                ident: None,
            }),
            false => Sock::Datagram {
                pair,
                dest: None,
                relay: None,
                inbox,
            },
        };
        map.insert(key, entry);
    }
    if verbose {
        eprintln!("podnet-netns: {}", emulation_line(domain, kind, icmp));
    }
    Ok(())
}

/// The line of `-v` for a socket that the pod makes as a socket pair.
fn emulation_line(domain: i32, kind: i32, icmp: bool) -> String {
    let family = if domain == libc::AF_INET6 {
        "IPv6"
    } else {
        "IPv4"
    };
    let kind = if kind == libc::SOCK_STREAM {
        "TCP"
    } else if icmp {
        "ICMP"
    } else {
        "UDP"
    };
    format!("socket emulated as a socket pair ({family} {kind})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_emulation_line_names_the_family_and_the_kind() {
        assert_eq!(
            emulation_line(libc::AF_INET6, libc::SOCK_DGRAM, false),
            "socket emulated as a socket pair (IPv6 UDP)"
        );
        assert_eq!(
            emulation_line(libc::AF_INET, libc::SOCK_STREAM, false),
            "socket emulated as a socket pair (IPv4 TCP)"
        );
        assert_eq!(
            emulation_line(libc::AF_INET, libc::SOCK_DGRAM, true),
            "socket emulated as a socket pair (IPv4 ICMP)"
        );
    }
}
