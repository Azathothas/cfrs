//! ICMP datagram sockets of the program under the seccomp backend (T-066).
//!
//! `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` (a ping socket) and
//! `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)` get one end of an
//! `AF_UNIX` datagram socketpair, as a UDP socket does. The proxy carries no
//! ICMP, so the supervisor does not relay these datagrams. It answers an echo
//! request to the gateway of the pod ([`TUN_GW`], the gateway of the netns
//! backend too) with an echo reply from that address. An echo to another
//! destination gets `EACCES`. The pod has no IPv6 gateway: each echo of an
//! IPv6 socket gets `EACCES`.
//!
//! The reads go through the inbox of the socket (`src/inbox.rs`), so
//! `recvfrom` gives the gateway as the source.

use crate::inbox::{read_target, Inbox, RecvTarget, WireSource};
use crate::prelude::*;

/// `ICMP_ECHO` and `ICMP_ECHOREPLY`.
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
/// `ICMP6_ECHO_REQUEST`.
const ECHO_REQUEST_V6: u8 = 128;

/// An ICMP datagram socket of the program.
pub(crate) struct Icmp {
    pub(crate) pair: Arc<tokio::net::UnixDatagram>,
    pub(crate) inbox: Arc<Inbox>,
    pub(crate) v6: bool,
    /// The destination of `connect`.
    pub(crate) dest: Option<IpAddr>,
    /// The identifier of `bind` (the port of the address). The kernel puts
    /// it in each echo request of the socket.
    pub(crate) ident: Option<u16>,
}

impl Icmp {
    /// The address of `getsockname` (`peer` false) or `getpeername`.
    /// `None`: the socket has no peer.
    pub(crate) fn name(&self, peer: bool) -> Option<(IpAddr, u16)> {
        if peer {
            return self.dest.map(|ip| (ip, 0));
        }
        let ip = match self.v6 {
            true => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            false => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        Some((ip, self.ident.unwrap_or(0)))
    }
}

/// The calls on an ICMP socket that the supervisor answers here: `connect`,
/// `bind`, `sendto`, `sendmsg` and `sendmmsg`. `None` for another call or
/// another socket: the usual handler takes it.
pub(crate) async fn handle(
    lfd: RawFd,
    id: u64,
    nr: i32,
    a: [u64; 6],
    (mem, writable): (RawFd, bool),
    (map, key): (&mut HashMap<Key, Sock>, Key),
) -> Option<Result<()>> {
    let Some(Sock::Icmp(icmp)) = map.get_mut(&key) else {
        return None;
    };
    let nr = nr as libc::c_long;
    let answer = if nr == libc::SYS_connect || nr == libc::SYS_bind {
        address(mem, a[1], a[2] as usize).map(|to| {
            match (nr == libc::SYS_connect, to) {
                (true, to) => icmp.dest = to.map(|(ip, _)| ip),
                (false, to) => icmp.ident = to.map(|(_, port)| port).filter(|p| *p != 0),
            }
            0
        })
    } else if nr == libc::SYS_sendto {
        match payload(mem, &[(a[1], a[2] as usize)]) {
            Ok(data) => match address(mem, a[4], a[5] as usize) {
                Ok(to) => send(icmp, to.map(|(ip, _)| ip), &data).await,
                Err(errno) => Err(errno),
            },
            Err(errno) => Err(errno),
        }
    } else if nr == libc::SYS_sendmsg {
        send_msghdr(icmp, mem, a[1]).await
    } else if nr == libc::SYS_sendmmsg {
        send_many(icmp, (mem, writable), a[1], a[2] as usize).await
    } else {
        return None;
    };
    Some(match answer {
        Ok(value) => notif_respond(lfd, id, value, 0),
        Err(errno) => notif_respond(lfd, id, -1, errno),
    })
}

/// The address at `ptr` (`len` bytes) of the program. `Ok(None)`: no
/// address, or `AF_UNSPEC`.
fn address(mem: RawFd, ptr: u64, len: usize) -> std::result::Result<Option<(IpAddr, u16)>, i32> {
    if ptr == 0 || len < 2 {
        return Ok(None);
    }
    let bytes = read_mem(mem, ptr, len.min(128)).map_err(|_| libc::EFAULT)?;
    if u16::from_ne_bytes([bytes[0], bytes[1]]) == libc::AF_UNSPEC as u16 {
        return Ok(None);
    }
    match parse_sockaddr(&bytes) {
        Some((_, ip, port)) => Ok(Some((ip, port))),
        None => Err(libc::EINVAL),
    }
}

/// The bytes of the parts `parts` (address, length) of the program.
fn payload(mem: RawFd, parts: &[(u64, usize)]) -> std::result::Result<Vec<u8>, i32> {
    let total = parts
        .iter()
        .fold(0usize, |sum, (_, len)| sum.saturating_add(*len));
    if total > MAX_DATAGRAM {
        return Err(libc::EMSGSIZE);
    }
    let mut data = Vec::with_capacity(total);
    for &(base, len) in parts.iter().filter(|(_, len)| *len > 0) {
        data.extend_from_slice(&read_mem(mem, base, len).map_err(|_| libc::EFAULT)?);
    }
    Ok(data)
}

/// Send one `struct msghdr` at `msg`.
async fn send_msghdr(icmp: &Icmp, mem: RawFd, msg: u64) -> std::result::Result<i64, i32> {
    let (target, _) = read_target(mem, true, [0, msg, 0, 0, 0, 0])?;
    let RecvTarget::Msg {
        iovs,
        name,
        name_capacity,
        ..
    } = target
    else {
        return Err(libc::EINVAL);
    };
    let data = payload(mem, &iovs)?;
    let to = address(mem, name, name_capacity)?;
    send(icmp, to.map(|(ip, _)| ip), &data).await
}

/// `sendmmsg`: each message, and its `msg_len`. Without write access to the
/// memory of the program, one message (as for UDP).
async fn send_many(
    icmp: &Icmp,
    (mem, writable): (RawFd, bool),
    msgvec: u64,
    vlen: usize,
) -> std::result::Result<i64, i32> {
    const MMSGHDR_SIZE: u64 = std::mem::size_of::<libc::mmsghdr>() as u64;
    const MSG_LEN_OFFSET: u64 = std::mem::offset_of!(libc::mmsghdr, msg_len) as u64;
    let count = if writable { vlen.min(64) } else { vlen.min(1) };
    let mut sent = 0;
    for index in 0..count {
        let entry = msgvec + index as u64 * MMSGHDR_SIZE;
        match send_msghdr(icmp, mem, entry).await {
            Ok(bytes) => {
                if writable {
                    let len = (bytes as u32).to_ne_bytes();
                    write_mem(mem, entry + MSG_LEN_OFFSET, &len).map_err(|_| libc::EFAULT)?;
                }
                sent += 1;
            }
            Err(errno) if sent == 0 => return Err(errno),
            Err(_) => break,
        }
    }
    Ok(sent)
}

/// Send one echo request of the program to `to` (else to the destination
/// of `connect`). Give the byte count, or the errno.
async fn send(icmp: &Icmp, to: Option<IpAddr>, data: &[u8]) -> std::result::Result<i64, i32> {
    let Some(to) = to.or(icmp.dest) else {
        return Err(libc::EDESTADDRREQ);
    };
    let reply = echo_reply(icmp.v6, icmp.ident, data)?;
    if icmp.v6 || to != IpAddr::V4(TUN_GW) {
        return Err(libc::EACCES);
    }
    let source = WireSource::Ip(SocketAddr::new(to, 0));
    icmp.inbox.deliver(&icmp.pair, source, &reply).await;
    Ok(data.len() as i64)
}

/// The echo reply to the echo request `request` (an ICMP header and the
/// data, as a ping socket sends it). `EINVAL` for another message, as the
/// kernel gives. The identifier is `ident` when the socket is bound; the
/// checksum is correct. For IPv6, only the check is done.
fn echo_reply(v6: bool, ident: Option<u16>, request: &[u8]) -> std::result::Result<Vec<u8>, i32> {
    let want = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST };
    if request.len() < 8 || request[0] != want || request[1] != 0 {
        return Err(libc::EINVAL);
    }
    let mut reply = request.to_vec();
    reply[0] = ECHO_REPLY;
    if let Some(ident) = ident {
        reply[4..6].copy_from_slice(&ident.to_be_bytes());
    }
    reply[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum(&reply);
    reply[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(reply)
}

/// The internet checksum (RFC 1071) of `data`.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_echo_request_gets_a_reply_with_a_good_checksum() {
        let request = [8, 0, 0, 0, 0x12, 0x34, 0, 7, b'p', b'o', b'd'];
        let reply = echo_reply(false, None, &request).unwrap();
        assert_eq!(reply[0], ECHO_REPLY);
        assert_eq!(&reply[4..], &request[4..]);
        assert_eq!(checksum(&reply), 0);
        let bound = echo_reply(false, Some(0xabcd), &request).unwrap();
        assert_eq!(&bound[4..6], &[0xab, 0xcd]);
        assert_eq!(checksum(&bound), 0);
    }

    #[test]
    fn another_message_gets_einval() {
        assert_eq!(echo_reply(false, None, &[8, 0, 0]), Err(libc::EINVAL));
        assert_eq!(echo_reply(false, None, &[0; 8]), Err(libc::EINVAL));
        assert_eq!(
            echo_reply(true, None, &[8, 0, 0, 0, 0, 0, 0, 0]),
            Err(libc::EINVAL)
        );
        assert!(echo_reply(true, None, &[128, 0, 0, 0, 0, 0, 0, 0]).is_ok());
    }
}
