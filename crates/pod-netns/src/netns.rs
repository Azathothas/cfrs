#[allow(unused_imports)]
use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};

/// A std `Ipv4Addr` as smoltcp's wire type.
pub(crate) fn smol_v4(addr: Ipv4Addr) -> Ipv4Address {
    Ipv4Address::from_bytes(&addr.octets())
}

// ── tunables ────────────────────────────────────────────────────────────────

/// Address on the TUN inside the namespace (the guest side of the /31).
pub(crate) const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 66, 255, 255);
/// The gateway the stack impersonates, and the DNS server handed to the guest.
pub(crate) const TUN_GW: Ipv4Addr = Ipv4Addr::new(10, 66, 255, 254);
pub(crate) const TUN_PREFIX: u8 = 31;
pub(crate) const TUN_MTU: usize = 1500;
pub(crate) const TCP_BUF: usize = 64 * 1024;
pub(crate) const DNS_PORT: u16 = 53;
/// The longest wait of the netns stack loop between two passes.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// RFC 2544 benchmarking range, used by proxychains and friends for fake IPs.
pub(crate) const FAKE_IP_BASE: u32 = 0xC612_0000; // 198.18.0.0
pub(crate) const FAKE_IP_COUNT: u32 = 1 << 17; // 198.18.0.0/15
/// The first 96 bits of a fake IPv6 address: fd63:6672:7300::/96 (a ULA).
pub(crate) const FAKE_IP6_PREFIX: [u8; 16] = [
    0xfd, 0x63, 0x66, 0x72, 0x73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub(crate) const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
pub(crate) const IFF_TUN: libc::c_int = 0x0001;
pub(crate) const IFF_NO_PI: libc::c_int = 0x1000;

// ── errors ──────────────────────────────────────────────────────────────────

/// Exit code for "this host cannot run any backend", distinct from a failure
/// of the program itself.
pub(crate) const EXIT_NO_BACKEND: i32 = 3;
// ── namespace + TUN setup (child side) ──────────────────────────────────────

pub(crate) fn write_proc(path: &str, data: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open {path}"))?;
    f.write_all(data.as_bytes())
        .with_context(|| format!("write {path}"))
}

pub(crate) fn write_id_maps(pid: u32) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    write_proc(&format!("/proc/{pid}/setgroups"), "deny")?;
    write_proc(&format!("/proc/{pid}/uid_map"), &format!("{uid} {uid} 1\n"))?;
    write_proc(&format!("/proc/{pid}/gid_map"), &format!("{gid} {gid} 1\n"))?;
    Ok(())
}

pub(crate) fn ifreq_for(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate().take(libc::IF_NAMESIZE - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

pub(crate) fn bringup_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        bail!("socket() for lo: {}", std::io::Error::last_os_error());
    }
    let mut ifr = ifreq_for("lo");
    let r = unsafe {
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _)
    };
    unsafe { libc::close(sock) };
    if r < 0 {
        bail!("ioctl SIOCSIFFLAGS lo: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Create and configure the TUN device inside the namespace. Returns its fd.
pub(crate) fn create_tun(name: &str) -> Result<OwnedFd> {
    if name.len() >= libc::IF_NAMESIZE {
        bail!("TUN name {name:?} is too long");
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr = ifreq_for(name);
    let r = unsafe {
        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
        libc::ioctl(
            owned.as_raw_fd(),
            TUNSETIFF as _,
            &mut ifr as *mut libc::ifreq,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("ioctl TUNSETIFF");
    }

    // Configure with ioctls rather than `ip`: RTNETLINK can fail inside a user
    // namespace even when the ioctls succeed.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        bail!(
            "socket() for tun config: {}",
            std::io::Error::last_os_error()
        );
    }
    let guard = FdGuard(sock);
    let set_addr = |cmd: libc::c_ulong, addr: Ipv4Addr| -> Result<()> {
        let mut ifr = ifreq_for(name);
        let r = unsafe {
            let sin = &mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
            (*sin).sin_family = libc::AF_INET as u16;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
            libc::ioctl(guard.0, cmd as _, &ifr as *const _)
        };
        if r < 0 {
            bail!("ioctl {cmd:#x}: {}", std::io::Error::last_os_error());
        }
        Ok(())
    };

    let mut mtu_ifr = ifreq_for(name);
    let mtu_r = unsafe {
        mtu_ifr.ifr_ifru.ifru_mtu = TUN_MTU as libc::c_int;
        libc::ioctl(guard.0, libc::SIOCSIFMTU as _, &mtu_ifr as *const _)
    };
    if mtu_r < 0 {
        bail!("ioctl SIOCSIFMTU: {}", std::io::Error::last_os_error());
    }
    set_addr(libc::SIOCSIFADDR, TUN_ADDR)?;
    let netmask = u32::MAX << (32 - TUN_PREFIX as u32);
    set_addr(libc::SIOCSIFNETMASK, Ipv4Addr::from(netmask.to_be_bytes()))?;

    let mut up = ifreq_for(name);
    let up_r = unsafe {
        up.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(guard.0, libc::SIOCSIFFLAGS as _, &up as *const _)
    };
    if up_r < 0 {
        bail!("ioctl SIOCSIFFLAGS up: {}", std::io::Error::last_os_error());
    }

    // Default route via the gateway the userspace stack impersonates.
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
    let dst = &mut route.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in;
    let gw = &mut route.rt_gateway as *mut libc::sockaddr as *mut libc::sockaddr_in;
    let mask = &mut route.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*dst).sin_family = libc::AF_INET as u16;
        (*gw).sin_family = libc::AF_INET as u16;
        (*gw).sin_addr.s_addr = u32::from_ne_bytes(TUN_GW.octets());
        (*mask).sin_family = libc::AF_INET as u16;
    }
    route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    let name_c = CString::new(name)?;
    route.rt_dev = name_c.as_ptr() as *mut libc::c_char;
    if unsafe { libc::ioctl(guard.0, libc::SIOCADDRT as _, &route as *const _) } < 0 {
        bail!("ioctl SIOCADDRT: {}", std::io::Error::last_os_error());
    }
    Ok(owned)
}

pub(crate) struct FdGuard(RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// ── fd passing (child → parent) ─────────────────────────────────────────────

/// A control-message buffer with the alignment of `cmsghdr`.
///
/// A plain `[u8; N]` has alignment 1, so `CMSG_FIRSTHDR` can return a
/// misaligned `*mut cmsghdr`. A debug build aborts on that dereference.
#[repr(C, align(8))]
struct CmsgBuf([u8; 64]);

/// [`send_fd`] that does not allocate, for a child after `fork()` in a
/// multi-threaded process: 0, or -1 on an error.
pub(crate) unsafe fn send_fd_raw(sock: RawFd, fd: RawFd) -> libc::c_int {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut cmsg = CmsgBuf([0u8; 64]);
    let fd_len = std::mem::size_of::<RawFd>() as u32;
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = libc::CMSG_SPACE(fd_len) as _;
    let hdr = libc::CMSG_FIRSTHDR(&msg);
    if hdr.is_null() {
        return -1;
    }
    (*hdr).cmsg_level = libc::SOL_SOCKET;
    (*hdr).cmsg_type = libc::SCM_RIGHTS;
    (*hdr).cmsg_len = libc::CMSG_LEN(fd_len) as _;
    std::ptr::copy_nonoverlapping(
        (&fd as *const RawFd).cast::<u8>(),
        libc::CMSG_DATA(hdr),
        fd_len as usize,
    );
    if libc::sendmsg(sock, &msg, 0) < 0 {
        -1
    } else {
        0
    }
}

/// Send one fd over a unix socketpair with SCM_RIGHTS.
pub(crate) fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut cmsg = CmsgBuf([0u8; 64]);
    let fd_len = std::mem::size_of::<RawFd>() as u32;
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(fd_len) } as _;
    unsafe {
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if hdr.is_null() {
            bail!("the control buffer is too small for one fd");
        }
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(fd_len) as _;
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(hdr),
            fd_len as usize,
        );
        if libc::sendmsg(sock, &msg, 0) < 0 {
            bail!("sendmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive one fd over a unix socketpair.
pub(crate) fn recv_fd(sock: RawFd) -> Result<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut cmsg = CmsgBuf([0u8; 64]);
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.0.len() as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        bail!("recvmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
    }
    if n == 0 {
        bail!("the peer closed the socket before it sent a descriptor");
    }
    let hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if hdr.is_null() {
        bail!("no fd in the received message");
    }
    let (level, kind) = unsafe { ((*hdr).cmsg_level, (*hdr).cmsg_type) };
    if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
        bail!("the received control message is not SCM_RIGHTS");
    }
    let mut fd: RawFd = -1;
    // Copy bytes, not elements.
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(hdr) as *const u8,
            (&mut fd as *mut RawFd).cast::<u8>(),
            std::mem::size_of::<RawFd>(),
        );
    }
    Ok(fd)
}

// ── TUN as a smoltcp device ─────────────────────────────────────────────────

pub(crate) struct Tun {
    pub(crate) fd: RawFd,
    pub(crate) mtu: usize,
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: VecDeque<Vec<u8>>,
}

impl Tun {
    pub(crate) fn new(fd: RawFd, mtu: usize) -> Self {
        // The read loop drains until EAGAIN, so the fd must not block.
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        Self {
            fd,
            mtu,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }

    /// Read whatever the kernel has queued into `rx`.
    pub(crate) fn read_ready(&mut self) {
        loop {
            let mut buf = vec![0u8; self.mtu];
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, self.mtu) };
            if n <= 0 {
                break;
            }
            buf.truncate(n as usize);
            self.rx.push_back(buf);
        }
    }

    pub(crate) fn flush(&mut self) {
        while let Some(pkt) = self.tx.pop_front() {
            let mut off = 0;
            while off < pkt.len() {
                let n = unsafe {
                    libc::write(self.fd, pkt[off..].as_ptr() as *const _, pkt.len() - off)
                };
                if n <= 0 {
                    return;
                }
                off += n as usize;
            }
        }
    }
}

impl Device for Tun {
    type RxToken<'a> = TunRx;
    type TxToken<'a> = TunTx<'a>;
    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((TunRx(pkt), TunTx { out: &mut self.tx }))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTx { out: &mut self.tx })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

pub(crate) struct TunRx(Vec<u8>);
impl RxToken for TunRx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}
pub(crate) struct TunTx<'a> {
    pub(crate) out: &'a mut VecDeque<Vec<u8>>,
}
impl TxToken for TunTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.out.push_back(buf);
        r
    }
}

/// One outbound flow: a smoltcp TCP socket and the upstream proxy connection.
pub(crate) struct Flow {
    pub(crate) upstream: Upstream,
    pub(crate) to_upstream: Vec<u8>,
    pub(crate) to_app: Vec<u8>,
    pub(crate) up_eof: bool,
}

pub(crate) struct Backend {
    pub(crate) device: Tun,
    pub(crate) interface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) dns: FakeDns,
    /// destination port → listener handle created for it
    /// Every TCP socket of the stack, with its destination port. A socket
    /// starts in the listen state and becomes one connection.
    pub(crate) listeners: HashMap<SocketHandle, u16>,
    /// Upstream dials in progress, for connections that are established in
    /// the stack but have no flow yet.
    pub(crate) dialing: HashMap<SocketHandle, (String, tokio::task::JoinHandle<Result<Upstream>>)>,
    pub(crate) flows: HashMap<SocketHandle, Flow>,
    pub(crate) proxies: Vec<Proxy>,
    pub(crate) rules: Vec<Rule>,
    pub(crate) verbose: bool,
}

impl Backend {
    pub(crate) fn new(
        fd: RawFd,
        proxies: Vec<Proxy>,
        rules: Vec<Rule>,
        maps: Vec<(String, IpAddr)>,
        verbose: bool,
    ) -> Result<Self> {
        let mut device = Tun::new(fd, TUN_MTU);
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = seed();
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(smol_v4(TUN_GW)), TUN_PREFIX))
                .unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(smol_v4(TUN_GW))
            .unwrap();
        // Accept packets addressed to any destination: the guest connects to
        // real addresses, and we impersonate all of them.
        interface.set_any_ip(true);

        let sockets = SocketSet::new(Vec::new());
        let mut dns = FakeDns::new();
        for (name, ip) in &maps {
            dns.pin(name, *ip);
        }
        Ok(Self {
            device,
            interface,
            sockets,
            dns,
            listeners: HashMap::new(),
            dialing: HashMap::new(),
            flows: HashMap::new(),
            proxies,
            rules,
            verbose,
        })
    }

    /// Each SYN needs a socket in the listen state for its port before
    /// smoltcp processes the packet. A listen socket becomes the connection,
    /// so add one listen socket for each SYN that has no free one.
    pub(crate) fn observe_syns(&mut self) {
        let mut wanted: HashMap<u16, usize> = HashMap::new();
        for pkt in &self.device.rx {
            if let Some((_src, _sport, _dst, dport)) = parse_tcp_syn(pkt) {
                *wanted.entry(dport).or_default() += 1;
            }
        }
        for (port, count) in wanted {
            let free = self
                .listeners
                .iter()
                .filter(|(handle, p)| {
                    **p == port
                        && self.sockets.get::<tcp::Socket>(**handle).state() == tcp::State::Listen
                })
                .count();
            for _ in free..count {
                // Bound the table: a program that sweeps ports must not grow
                // it without limit.
                if self.listeners.len() >= MAX_TRACKED_FDS {
                    return;
                }
                let mut socket = tcp_socket();
                if socket.listen(IpListenEndpoint { addr: None, port }).is_ok() {
                    let handle = self.sockets.add(socket);
                    self.listeners.insert(handle, port);
                    if self.verbose {
                        eprintln!("pod-netns: listening for outbound port {port}");
                    }
                }
            }
        }
    }

    /// Remove the sockets of finished connections from the stack.
    pub(crate) fn reap_closed(&mut self) {
        let closed: Vec<SocketHandle> = self
            .listeners
            .keys()
            .copied()
            .filter(|handle| {
                !self.flows.contains_key(handle)
                    && !self.dialing.contains_key(handle)
                    && self.sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Closed
            })
            .collect();
        for handle in closed {
            self.listeners.remove(&handle);
            self.sockets.remove(handle);
        }
    }

    pub(crate) async fn tick(&mut self) -> Result<()> {
        self.observe_syns();
        self.answer_dns();
        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        self.accept_flows().await;
        self.shuttle().await;
        self.reap_closed();
        self.device.flush();
        Ok(())
    }

    /// Answer each IPv4 UDP query to port 53 from the fake-IP pool, before
    /// smoltcp sees it.
    ///
    /// The reply must come from the address that the client sent to (the
    /// resolver in its resolv.conf), or a connected UDP socket drops it. A
    /// smoltcp UDP socket cannot set that source address, so the reply packet
    /// is made here with the two addresses swapped.
    pub(crate) fn answer_dns(&mut self) {
        let mut kept = VecDeque::with_capacity(self.device.rx.len());
        while let Some(pkt) = self.device.rx.pop_front() {
            match dns_reply_packet(&pkt, &mut self.dns) {
                Some(reply) => self.device.tx.push_back(reply),
                None => kept.push_back(pkt),
            }
        }
        self.device.rx = kept;
    }

    /// Start an upstream dial for each new connection, and make a flow when
    /// a dial completes. A dial runs in its own task, so a slow proxy does not
    /// stop the other flows.
    pub(crate) async fn accept_flows(&mut self) {
        let handles: Vec<SocketHandle> = self.listeners.keys().copied().collect();
        for handle in handles {
            if self.flows.contains_key(&handle) || self.dialing.contains_key(&handle) {
                continue;
            }
            // The destination is the local endpoint of the socket.
            let target = {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if !matches!(socket.state(), tcp::State::Established) {
                    continue;
                }
                let Some(local) = socket.local_endpoint() else {
                    continue;
                };
                let IpAddress::Ipv4(dst_ip) = local.addr else {
                    continue;
                };
                let b = dst_ip.as_bytes();
                let dst_ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                match self.dns.name_for(dst_ip) {
                    Some(name) => format!("{name}:{}", local.port),
                    None => format!("{dst_ip}:{}", local.port),
                }
            };
            let chain = select_chain(&self.rules, &self.proxies, &target).to_vec();
            if self.verbose {
                let hops: Vec<String> = chain.iter().map(Proxy::endpoint).collect();
                eprintln!("pod-netns: {target} via {}", hops.join(" -> "));
            }
            let dial_target = target.clone();
            let task = tokio::spawn(async move {
                within_timeout(
                    "upstream connect",
                    connect_upstream_async(&chain, &dial_target),
                )
                .await
            });
            self.dialing.insert(handle, (target, task));
        }

        let ready: Vec<SocketHandle> = self
            .dialing
            .iter()
            .filter(|(_, (_, task))| task.is_finished())
            .map(|(handle, _)| *handle)
            .collect();
        for handle in ready {
            let (target, task) = self.dialing.remove(&handle).expect("listed above");
            match task.await {
                Ok(Ok(upstream)) => {
                    self.flows.insert(
                        handle,
                        Flow {
                            upstream,
                            to_upstream: Vec::new(),
                            to_app: Vec::new(),
                            up_eof: false,
                        },
                    );
                }
                Ok(Err(e)) => {
                    if self.verbose {
                        eprintln!("pod-netns: upstream for {target} failed: {e:#}");
                    }
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("pod-netns: dial task for {target} failed: {e}");
                    }
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
            }
        }
    }

    pub(crate) async fn shuttle(&mut self) {
        let handles: Vec<SocketHandle> = self.flows.keys().copied().collect();
        for handle in handles {
            let mut flow = self.flows.remove(&handle).unwrap();
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let mut close = false;

            // app → upstream
            while socket.can_recv() {
                match socket.recv(|buf| {
                    let n = buf.len().min(64 * 1024);
                    flow.to_upstream.extend_from_slice(&buf[..n]);
                    (n, ())
                }) {
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
            while !flow.to_upstream.is_empty() {
                match poll_once(flow.upstream.write(&flow.to_upstream)).unwrap_or_else(would_block)
                {
                    Ok(0) => break,
                    Ok(n) => {
                        flow.to_upstream.drain(..n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        close = true;
                        break;
                    }
                }
            }

            // upstream → app
            let mut buf = [0u8; 16 * 1024];
            loop {
                match poll_once(flow.upstream.read(&mut buf)).unwrap_or_else(would_block) {
                    Ok(0) => {
                        flow.up_eof = true;
                        break;
                    }
                    Ok(n) => flow.to_app.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        close = true;
                        break;
                    }
                }
            }
            while !flow.to_app.is_empty() && socket.can_send() {
                match socket.send_slice(&flow.to_app) {
                    Ok(n) => {
                        flow.to_app.drain(..n);
                    }
                    Err(_) => break,
                }
            }

            if (flow.up_eof && flow.to_app.is_empty()) || close || !socket.may_send() {
                socket.close();
                self.flows.remove(&handle);
                continue;
            }
            self.flows.insert(handle, flow);
        }
    }
}

pub(crate) fn tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    socket
}

/// Poll `future` one time. Return its output, or `None` when it is pending.
///
/// The stack loop wakes at a short interval, so a no-op waker is sufficient:
/// the I/O driver still records readiness for the next poll.
pub(crate) fn poll_once<F: std::future::Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => Some(output),
        std::task::Poll::Pending => None,
    }
}

/// The result of an I/O call that did not complete.
pub(crate) fn would_block() -> std::io::Result<usize> {
    Err(std::io::ErrorKind::WouldBlock.into())
}

/// If `pkt` is an IPv4 UDP datagram to port 53 that holds a DNS query, return
/// the reply datagram. Return `None` for any other packet.
pub(crate) fn dns_reply_packet(pkt: &[u8], dns: &mut FakeDns) -> Option<Vec<u8>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != libc::IPPROTO_UDP as u8 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    // A fragment cannot be parsed alone.
    let fragment = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff;
    if ihl < 20 || fragment != 0 || pkt.len() < ihl + 8 {
        return None;
    }
    let udp = &pkt[ihl..];
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if dport != DNS_PORT || udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let query = crate::dns::ParsedQuery::parse(&udp[8..udp_len]).ok()?;
    let answer = dns.answer(&query);

    let total = 20 + 8 + answer.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[0x45, 0, 0, 0]);
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x40, 0, 64, libc::IPPROTO_UDP as u8, 0, 0]);
    out.extend_from_slice(&pkt[16..20]); // source: the resolver address
    out.extend_from_slice(&pkt[12..16]); // destination: the client
    let checksum = ipv4_checksum(&out[..20]);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&((8 + answer.len()) as u16).to_be_bytes());
    // A zero UDP checksum means "none" on IPv4.
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&answer);
    Some(out)
}

/// The one's-complement checksum of an IPv4 header.
pub(crate) fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in header.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
}

/// Parse a bare TCP SYN and return (src ip, src port, dst ip, dst port).
pub(crate) fn parse_tcp_syn(pkt: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 {
        return None;
    }
    if pkt[9] != 6 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 20 {
        return None;
    }
    let flags = pkt[ihl + 13];
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None; // SYN set, ACK clear
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    Some((src, sport, dst, dport))
}

// ── process orchestration ───────────────────────────────────────────────────

pub(crate) fn run(args: Args) -> Result<i32> {
    let (parent, child) = socketpair()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: new namespace, TUN, then the program.
        unsafe { libc::close(parent) };
        let result = child_setup(child, &args);
        // child_setup only returns on error; it execs on success.
        if let Err(e) = result {
            eprintln!("pod-netns: {e:#}");
            unsafe { libc::_exit(EXIT_NO_BACKEND) };
        }
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(child) };

    // Parent: the child reports whether it made a user namespace; if so, write
    // its id maps before it continues, then take the TUN fd.
    let mut kind = [0u8; 1];
    if read_exact_fd(parent, &mut kind)? == 0 {
        bail!("child died before reporting its namespace");
    }
    if kind[0] == b'u' {
        write_id_maps(pid as u32).context("write uid/gid maps")?;
        write_all_fd(parent, b"a")?;
    }
    let tun_fd = recv_fd(parent).context("receive TUN fd")?;
    unsafe { libc::close(parent) };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let proxies = args.proxies.clone();
    let rules = args.rules.clone();
    let maps = args.maps.clone();
    let verbose = args.verbose;
    let result = runtime.block_on(async move {
        let mut backend = Backend::new(tun_fd, proxies, rules, maps, verbose)?;
        let fd = backend.device.fd;
        let async_fd = crate::readable_copy(fd)?;
        loop {
            backend.device.read_ready();
            backend.tick().await?;
            // Wake on TUN input or a short timer, whichever comes first. The
            // readiness must be cleared after the TUN is drained: if it stays
            // set, this loop never parks, and the I/O driver never marks an
            // upstream socket readable.
            tokio::select! {
                guard = async_fd.readable() => {
                    if let Ok(mut guard) = guard {
                        backend.device.read_ready();
                        guard.clear_ready();
                    }
                }
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
            }
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                return Ok::<i32, anyhow::Error>(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
        }
    });
    // Reap if the loop exited without seeing it.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    result
}

pub(crate) fn child_setup(sock: RawFd, args: &Args) -> Result<()> {
    // A network namespace alone needs CAP_SYS_ADMIN; the user-namespace pair
    // works unprivileged and the parent writes the maps.
    let userns = if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
        false
    } else {
        let e = std::io::Error::last_os_error();
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
            bail!(
                "unshare(CLONE_NEWNET) failed ({e}) and unshare(CLONE_NEWUSER|CLONE_NEWNET) failed ({})",
                std::io::Error::last_os_error()
            );
        }
        true
    };
    // Tell the parent, and wait for the id maps before using the namespace.
    write_all_fd(sock, if userns { b"u" } else { b"n" })?;
    if userns {
        let mut ack = [0u8; 1];
        if read_exact_fd(sock, &mut ack)? == 0 {
            bail!("parent died before writing the id maps");
        }
    }
    bringup_loopback()?;
    let tun = create_tun("eth0")?;
    send_fd(sock, tun.as_raw_fd())?;
    unsafe { libc::close(sock) };
    std::mem::forget(tun); // the parent owns its own handle; keep ours open too
                           // The resolver of the host (often 127.0.0.53) is on the loopback of the
                           // host, which this namespace does not have: give the program a
                           // resolv.conf with the gateway of the TUN, where the pod answers DNS
                           // (issue 61). A failure leaves the host file, with a warning.
    if let Err(e) = private_resolv_conf() {
        eprintln!("pod-netns: warning: the program keeps the resolver of the host ({e:#})");
    }

    let program = &args.program;
    let path = CString::new(program[0].as_bytes())?;
    let mut argv: Vec<CString> = Vec::with_capacity(program.len() + 1);
    for a in program {
        argv.push(CString::new(a.as_bytes())?);
    }
    let ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env = crate::child_env(args.keep_proxy_env);
    let envp: Vec<*const libc::c_char> = env
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    unsafe {
        libc::execvpe(path.as_ptr(), ptrs.as_ptr(), envp.as_ptr());
    }
    bail!(
        "execvpe {}: {}",
        program[0],
        std::io::Error::last_os_error()
    )
}

/// In a new mount namespace, put a resolv.conf with the TUN gateway over
/// /etc/resolv.conf (a bind mount of a file that is then unlinked).
fn private_resolv_conf() -> Result<()> {
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        bail!("unshare(CLONE_NEWNS): {}", std::io::Error::last_os_error());
    }
    let root = CString::new("/")?;
    // Make the mounts private, so the bind mount does not reach the host.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        bail!(
            "mount --make-rprivate /: {}",
            std::io::Error::last_os_error()
        );
    }
    let file = std::env::temp_dir().join(format!("pod-netns-resolv-{}.conf", std::process::id()));
    std::fs::write(&file, format!("nameserver {TUN_GW}\noptions ndots:0\n"))
        .context("writing the resolv.conf of the pod")?;
    let source = CString::new(file.as_os_str().as_encoded_bytes())?;
    let target = CString::new("/etc/resolv.conf")?;
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    let err = std::io::Error::last_os_error();
    let _ = std::fs::remove_file(&file);
    if rc != 0 {
        bail!("bind mount over /etc/resolv.conf: {err}");
    }
    Ok(())
}

pub(crate) fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if n <= 0 {
            bail!("write: {}", std::io::Error::last_os_error());
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

pub(crate) fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if n < 0 {
            bail!("read: {}", std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(off);
        }
        off += n as usize;
    }
    Ok(off)
}

pub(crate) fn socketpair() -> Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}
