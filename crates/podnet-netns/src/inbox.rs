#[allow(unused_imports)]
use crate::prelude::*;

// ── the receive side of a datagram socket of the seccomp backend ────────────
//
// The supervisor puts each datagram for the program into the socketpair of
// the socket, so `poll`, `epoll` and `read` work on a real descriptor. The
// kernel gives the `AF_UNIX` address of the socketpair as the source of such
// a datagram. Thus the supervisor intercepts `recvfrom` and `recvmsg` on an
// unconnected datagram socket of the program (issue 305): it reads the
// datagram from its copy of the end of the program, and it writes the data
// and the logical source address into the memory of the program. A read of a
// connected socket stays direct.
//
// The source of each datagram is kept in a queue, with the length and a hash
// of the datagram. A read that the supervisor does not see (`read`,
// `recvmmsg`, a read of a connected socket) takes a datagram with no entry
// removed; the next intercepted read finds its entry by the length and the
// hash, and removes the older entries.

use std::hash::{Hash, Hasher};

/// The source of a datagram, as the relay gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WireSource {
    Ip(SocketAddr),
    Name(String, u16),
}

/// The most queued entries for one socket. The socketpair holds far fewer
/// datagrams; the limit stops a growth with no end when entries are not
/// taken (a host that refuses writes to the memory of the program).
const MAX_PENDING: usize = 4096;

/// The most remembered destinations for one socket.
const MAX_PEERS: usize = 64;

/// The largest datagram that the supervisor reads from the socketpair.
const MAX_READ: usize = 65536;

struct Pending {
    source: WireSource,
    len: usize,
    hash: u64,
}

fn digest(data: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

/// The receive state of one datagram socket of the program.
pub(crate) struct Inbox {
    /// A copy of the end of the program. It shares the file status flags of
    /// the end of the program, so each read uses `MSG_DONTWAIT`.
    child_end: std::os::unix::net::UnixDatagram,
    pending: std::sync::Mutex<VecDeque<Pending>>,
    /// The destinations of the program: the address on the wire (as the
    /// relay sends it) and the address that the program used.
    peers: std::sync::Mutex<VecDeque<(WireSource, IpAddr, u16)>>,
    /// The socket is `AF_INET6`.
    v6: bool,
}

impl Inbox {
    pub(crate) fn new(child_end: std::os::unix::net::UnixDatagram, v6: bool) -> Self {
        Self {
            child_end,
            pending: std::sync::Mutex::new(VecDeque::new()),
            peers: std::sync::Mutex::new(VecDeque::new()),
            v6,
        }
    }

    /// Put `payload` into the socketpair (through `pair`, the end of the
    /// supervisor) and queue its source. The lock is held from the send to
    /// the push, so a read sees the entry of each datagram that it can get.
    pub(crate) async fn deliver(
        &self,
        pair: &tokio::net::UnixDatagram,
        source: WireSource,
        payload: &[u8],
    ) {
        loop {
            if pair.writable().await.is_err() {
                return;
            }
            // Done when the datagram is sent, or when the send fails for a
            // reason other than a full socketpair.
            let done = {
                let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
                match pair.try_send(payload) {
                    Ok(_) => {
                        pending.push_back(Pending {
                            source: source.clone(),
                            len: payload.len(),
                            hash: digest(payload),
                        });
                        if pending.len() > MAX_PENDING {
                            pending.pop_front();
                        }
                        true
                    }
                    Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
                }
            };
            if done {
                return;
            }
        }
    }

    /// The descriptor of the copy of the end of the program.
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.child_end.as_raw_fd()
    }

    /// Remember that the program sent to `ip:port`, which went to the relay
    /// as `wire`.
    pub(crate) fn remember(&self, wire: WireSource, ip: IpAddr, port: u16) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        peers.retain(|(w, _, _)| *w != wire);
        peers.push_back((wire, ip, port));
        if peers.len() > MAX_PEERS {
            peers.pop_front();
        }
    }

    /// Take one datagram (or look at it, with `peek`) and its source. `None`
    /// when no datagram waits.
    pub(crate) fn take(
        &self,
        peek: bool,
    ) -> std::io::Result<Option<(Vec<u8>, Option<WireSource>)>> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = vec![0u8; MAX_READ];
        let mut flags = libc::MSG_DONTWAIT;
        if peek {
            flags |= libc::MSG_PEEK;
        }
        // SAFETY: the buffer is valid for its length.
        let n = unsafe {
            libc::recv(
                self.child_end.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                flags,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(None);
            }
            return Err(e);
        }
        buf.truncate(n as usize);
        let hash = digest(&buf);
        let found = pending
            .iter()
            .position(|p| p.len == buf.len() && p.hash == hash);
        let source = found.map(|index| {
            // The entries before it are of datagrams that a direct read took.
            pending.drain(..index);
            if peek {
                pending[0].source.clone()
            } else {
                pending.pop_front().map(|p| p.source).unwrap()
            }
        });
        Ok(Some((buf, source)))
    }

    /// The address that the program sees as the source: the destination
    /// that the program used for this source, else the source itself.
    pub(crate) fn address(&self, source: Option<WireSource>) -> Vec<u8> {
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let (ip, port) = match source {
            None => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            Some(source) => {
                if let Some((_, ip, port)) = peers.iter().find(|(w, _, _)| *w == source) {
                    (*ip, *port)
                } else {
                    match source {
                        WireSource::Name(name, port) => peers
                            .iter()
                            .find(|(w, _, _)| matches!(w, WireSource::Name(n, _) if *n == name))
                            .map(|(_, ip, _)| (*ip, port))
                            .unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)),
                        WireSource::Ip(addr) => {
                            // A proxy can answer for a name with the address of
                            // the host. With one name on this port, that name
                            // is the source.
                            let mut named = peers.iter().filter(|(w, _, p)| {
                                *p == addr.port() && matches!(w, WireSource::Name(..))
                            });
                            match (named.next(), named.next()) {
                                (Some((_, ip, port)), None) => (*ip, *port),
                                _ => (addr.ip(), addr.port()),
                            }
                        }
                    }
                }
            }
        };
        sockaddr_for(self.v6, ip, port)
    }
}

/// The `sockaddr` of `ip:port` for a socket of the family `v6`: an IPv4
/// address on an `AF_INET6` socket is IPv4-mapped, as the kernel gives it.
fn sockaddr_for(v6: bool, ip: IpAddr, port: u16) -> Vec<u8> {
    match (v6, ip) {
        (true, IpAddr::V4(v4)) => crate::seccomp::sockaddr_in(
            libc::AF_INET6 as u16,
            IpAddr::V6(v4.to_ipv6_mapped()),
            port,
        ),
        (_, IpAddr::V6(_)) => crate::seccomp::sockaddr_in(libc::AF_INET6 as u16, ip, port),
        (false, IpAddr::V4(_)) => crate::seccomp::sockaddr_in(libc::AF_INET as u16, ip, port),
    }
}

/// The source of a SOCKS5 UDP datagram, and the offset of its payload.
pub(crate) fn udp_source(datagram: &[u8]) -> Option<(WireSource, usize)> {
    if datagram.len() < 4 {
        return None;
    }
    let (source, off) = match datagram[3] {
        0x01 if datagram.len() >= 10 => {
            let ip = Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]);
            let port = u16::from_be_bytes([datagram[8], datagram[9]]);
            (WireSource::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 10)
        }
        0x04 if datagram.len() >= 22 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&datagram[4..20]);
            let port = u16::from_be_bytes([datagram[20], datagram[21]]);
            (
                WireSource::Ip(SocketAddr::new(IpAddr::V6(o.into()), port)),
                22,
            )
        }
        0x03 => {
            let len = *datagram.get(4)? as usize;
            let off = 4 + 1 + len + 2;
            if datagram.len() < off {
                return None;
            }
            let name = String::from_utf8_lossy(&datagram[5..5 + len]).into_owned();
            let port = u16::from_be_bytes([datagram[off - 2], datagram[off - 1]]);
            (WireSource::Name(name, port), off)
        }
        _ => return None,
    };
    Some((source, off))
}

/// Where an intercepted read writes its result in the memory of the program.
/// The handler reads the pointers and the lengths before the read, so the
/// result can be written later, from a task (a blocking read).
pub(crate) enum RecvTarget {
    /// `recvfrom(fd, buf, len, flags, addr, addrlen)`. `addr_capacity` is
    /// `*addrlen` when `addr` and `addrlen` are set.
    From {
        buf: u64,
        len: usize,
        addr: u64,
        addrlen: u64,
        addr_capacity: Option<usize>,
    },
    /// `recvmsg(fd, msg, flags)`, with the iovecs and `msg_namelen` of
    /// `msg`.
    Msg {
        msg: u64,
        iovs: Vec<(u64, usize)>,
        name: u64,
        name_capacity: usize,
    },
}

/// Write `data` and its source `addr` as the result of `target`. Return the
/// value of the system call.
pub(crate) fn complete(
    mem: RawFd,
    pid: u32,
    target: &RecvTarget,
    flags: i32,
    data: &[u8],
    addr: &[u8],
) -> std::result::Result<i64, i32> {
    let write = |at: u64, bytes: &[u8]| {
        crate::seccomp::write_mem_to(mem, pid, at, bytes).map_err(|_| libc::EFAULT)
    };
    let copied = match target {
        RecvTarget::From {
            buf,
            len,
            addr: addr_ptr,
            addrlen,
            addr_capacity,
        } => {
            let copied = data.len().min(*len);
            if copied > 0 {
                write(*buf, &data[..copied])?;
            }
            if let Some(capacity) = addr_capacity {
                let out = addr.len().min(*capacity);
                if out > 0 {
                    write(*addr_ptr, &addr[..out])?;
                }
                write(*addrlen, &(addr.len() as u32).to_ne_bytes())?;
            }
            copied
        }
        RecvTarget::Msg {
            msg,
            iovs,
            name,
            name_capacity,
        } => {
            let mut copied = 0;
            for (base, len) in iovs {
                if copied == data.len() {
                    break;
                }
                let part = (*len).min(data.len() - copied);
                if part > 0 {
                    write(*base, &data[copied..copied + part])?;
                    copied += part;
                }
            }
            if *name != 0 {
                let out = addr.len().min(*name_capacity);
                if out > 0 {
                    write(*name, &addr[..out])?;
                }
                let at = *msg + std::mem::offset_of!(libc::msghdr, msg_namelen) as u64;
                write(at, &(addr.len() as u32).to_ne_bytes())?;
            }
            // No control data.
            let at = *msg + std::mem::offset_of!(libc::msghdr, msg_controllen) as u64;
            write(at, &0usize.to_ne_bytes())?;
            let out_flags = if copied < data.len() {
                libc::MSG_TRUNC
            } else {
                0
            };
            let at = *msg + std::mem::offset_of!(libc::msghdr, msg_flags) as u64;
            write(at, &out_flags.to_ne_bytes())?;
            copied
        }
    };
    Ok(if flags & libc::MSG_TRUNC != 0 {
        data.len() as i64
    } else {
        copied as i64
    })
}

/// The most iovecs in one `msghdr` (`UIO_MAXIOV` of the kernel).
const UIO_MAXIOV: usize = 1024;

/// Read the target of an intercepted `recvfrom` or `recvmsg` from the
/// memory of the program. `Err` is the errno for the program.
pub(crate) fn read_target(
    mem: RawFd,
    recvmsg: bool,
    a: [u64; 6],
) -> std::result::Result<(RecvTarget, i32), i32> {
    use crate::seccomp::{read_mem, read_word};
    if !recvmsg {
        let addr_capacity = if a[4] != 0 && a[5] != 0 {
            let bytes = read_mem(mem, a[5], 4).map_err(|_| libc::EFAULT)?;
            let capacity = i32::from_ne_bytes(bytes[..4].try_into().unwrap());
            if capacity < 0 {
                return Err(libc::EINVAL);
            }
            Some(capacity as usize)
        } else {
            None
        };
        let target = RecvTarget::From {
            buf: a[1],
            len: a[2] as usize,
            addr: a[4],
            addrlen: a[5],
            addr_capacity,
        };
        return Ok((target, a[3] as i32));
    }
    let msg = a[1];
    let hdr = read_mem(mem, msg, std::mem::size_of::<libc::msghdr>()).map_err(|_| libc::EFAULT)?;
    let name = read_word(&hdr, std::mem::offset_of!(libc::msghdr, msg_name));
    let name_capacity = u32::from_ne_bytes(
        hdr[std::mem::offset_of!(libc::msghdr, msg_namelen)..][..4]
            .try_into()
            .unwrap(),
    ) as usize;
    let iov_ptr = read_word(&hdr, std::mem::offset_of!(libc::msghdr, msg_iov));
    let iov_len = read_word(&hdr, std::mem::offset_of!(libc::msghdr, msg_iovlen)) as usize;
    if iov_len > UIO_MAXIOV {
        return Err(libc::EMSGSIZE);
    }
    let size = std::mem::size_of::<libc::iovec>();
    let raw = read_mem(mem, iov_ptr, iov_len * size).map_err(|_| libc::EFAULT)?;
    let iovs = raw
        .chunks_exact(size)
        .map(|iov| {
            (
                read_word(iov, std::mem::offset_of!(libc::iovec, iov_base)),
                read_word(iov, std::mem::offset_of!(libc::iovec, iov_len)) as usize,
            )
        })
        .collect();
    let target = RecvTarget::Msg {
        msg,
        iovs,
        name,
        name_capacity,
    };
    Ok((target, a[2] as i32))
}

/// `recvfrom` and `recvmsg` (issue 305): on an unconnected datagram socket of
/// the program, the supervisor reads the datagram and writes the data and its
/// logical source address into the memory of the program. Another read
/// stays direct: a socket that is not ours, a connected socket, or a host
/// that refuses writes to the memory of the program (the source is then the
/// `AF_UNIX` address of the socketpair).
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_recv(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    map: &HashMap<Key, Sock>,
    key: Key,
    recvmsg: bool,
    pid: u32,
) -> Result<()> {
    let fd = a[0] as i32;
    let inbox = match map.get(&key) {
        Some(Sock::Datagram {
            dest: None, inbox, ..
        }) if writable => inbox.clone(),
        _ => return notif_continue(lfd, id),
    };
    let flags = if recvmsg { a[2] } else { a[3] } as i32;
    if flags & libc::MSG_ERRQUEUE != 0 {
        return notif_continue(lfd, id);
    }
    if flags & libc::MSG_OOB != 0 {
        return notif_respond(lfd, id, -1, libc::EOPNOTSUPP);
    }
    let (target, flags) = match read_target(mem, recvmsg, a) {
        Ok(t) => t,
        Err(errno) => return notif_respond(lfd, id, -1, errno),
    };
    let peek = flags & libc::MSG_PEEK != 0;
    match inbox.take(peek) {
        Ok(Some((data, source))) => {
            let addr = inbox.address(source);
            match complete(mem, pid, &target, flags, &data, &addr) {
                Ok(value) => notif_respond(lfd, id, value, 0),
                Err(errno) => notif_respond(lfd, id, -1, errno),
            }
        }
        Ok(None) => {
            let nonblocking = flags & libc::MSG_DONTWAIT != 0
                || child_fd_flags(pid, fd).is_some_and(|f| f & libc::O_NONBLOCK != 0);
            if nonblocking {
                return notif_respond(lfd, id, -1, libc::EAGAIN);
            }
            // A blocking read waits in its own task: the other system calls
            // of the program go on.
            tokio::spawn(wait_recv(lfd, id, pid, inbox, target, flags));
            Ok(())
        }
        Err(e) => notif_respond(lfd, id, -1, e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

/// Wait for a datagram for the blocking read `id`, then answer it. Stop when
/// the read ends without an answer (a signal, or the exit of the program).
async fn wait_recv(
    lfd: RawFd,
    id: u64,
    pid: u32,
    inbox: Arc<Inbox>,
    target: RecvTarget,
    flags: i32,
) {
    let peek = flags & libc::MSG_PEEK != 0;
    let Ok(ready) = crate::readable_copy(inbox.raw_fd()) else {
        let _ = notif_respond(lfd, id, -1, libc::EIO);
        return;
    };
    loop {
        let guard = tokio::select! {
            guard = ready.readable() => guard.ok(),
            _ = tokio::time::sleep(Duration::from_millis(200)) => None,
        };
        if !notif_id_valid(lfd, id) {
            return;
        }
        match inbox.take(peek) {
            Ok(Some((data, source))) => {
                let addr = inbox.address(source);
                let (mem, _) = open_mem_of(pid);
                let answer = complete(mem, pid, &target, flags, &data, &addr);
                if mem >= 0 {
                    unsafe { libc::close(mem) };
                }
                let _ = match answer {
                    Ok(value) => notif_respond(lfd, id, value, 0),
                    Err(errno) => notif_respond(lfd, id, -1, errno),
                };
                return;
            }
            Ok(None) => {
                if let Some(mut guard) = guard {
                    guard.clear_ready();
                }
            }
            Err(e) => {
                let _ = notif_respond(lfd, id, -1, e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_read_from_the_socks5_header() {
        let d = crate::upstream::wrap_udp(b"x", "10.0.0.1".parse().unwrap(), 53);
        assert_eq!(
            udp_source(&d),
            Some((WireSource::Ip("10.0.0.1:53".parse().unwrap()), 10))
        );
        let d = crate::upstream::wrap_udp_name(b"x", "stun.example", 19302);
        assert_eq!(
            udp_source(&d),
            Some((WireSource::Name("stun.example".into(), 19302), 19))
        );
        assert_eq!(udp_source(&[0, 0, 0, 3, 200]), None);
    }

    /// A direct read takes a datagram; the next intercepted read still
    /// gets the source of its own datagram.
    #[test]
    fn a_direct_read_does_not_shift_the_sources() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (ours, theirs) = std::os::unix::net::UnixDatagram::pair().unwrap();
            ours.set_nonblocking(true).unwrap();
            let program = theirs.try_clone().unwrap();
            let inbox = Inbox::new(theirs, false);
            let pair = tokio::net::UnixDatagram::from_std(ours).unwrap();
            let a = WireSource::Ip("10.0.0.1:1".parse().unwrap());
            let b = WireSource::Ip("10.0.0.2:2".parse().unwrap());
            inbox.deliver(&pair, a, b"first").await;
            inbox.deliver(&pair, b.clone(), b"second").await;
            let mut buf = [0u8; 16];
            let n = program.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"first");
            let (data, source) = inbox.take(true).unwrap().unwrap();
            assert_eq!(
                (data.as_slice(), source.as_ref()),
                (&b"second"[..], Some(&b))
            );
            let (data, source) = inbox.take(false).unwrap().unwrap();
            assert_eq!((data.as_slice(), source), (&b"second"[..], Some(b)));
            assert!(inbox.take(false).unwrap().is_none());
        });
    }

    /// A name, or the address of the host that a proxy gives for a name,
    /// is the address that the program sent to.
    #[test]
    fn the_source_is_the_address_of_the_program() {
        let (_, theirs) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let inbox = Inbox::new(theirs, false);
        let fake: IpAddr = "198.18.0.5".parse().unwrap();
        inbox.remember(WireSource::Name("echo.example".into(), 7777), fake, 7777);
        let want = crate::seccomp::sockaddr_in(libc::AF_INET as u16, fake, 7777);
        let by_name = inbox.address(Some(WireSource::Name("echo.example".into(), 7777)));
        assert_eq!(by_name, want);
        let by_host = inbox.address(Some(WireSource::Ip("93.184.216.34:7777".parse().unwrap())));
        assert_eq!(by_host, want);
        let other = inbox.address(Some(WireSource::Ip("10.0.0.1:53".parse().unwrap())));
        assert_eq!(
            other,
            crate::seccomp::sockaddr_in(libc::AF_INET as u16, "10.0.0.1".parse().unwrap(), 53)
        );
        let (_, theirs) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let v6 = Inbox::new(theirs, true);
        assert_eq!(
            v6.address(Some(WireSource::Ip("10.0.0.1:53".parse().unwrap())))
                .len(),
            28
        );
    }
}
