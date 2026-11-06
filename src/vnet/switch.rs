//! Switch mode: connect userspace stacks on one host or on different hosts.
//!
//! A switch is a hub. Each peer connects to it with a byte stream (a unix
//! socket, a TCP connection, or a `podnet` WebSocket forward through a tunnel)
//! and sends IP packets in the framing of [`crate::vnet::framing`]. The switch
//! learns the source address of each peer and sends each packet to the peer
//! that owns its destination address. It floods a packet for an address that
//! it does not know yet to all other peers.
//!
//! [`attach`] connects a [`NetStack`] made with [`NetStack::over_link`] to a
//! switch. A [`Faults`] value makes the link drop, duplicate or reorder
//! packets on purpose, with a seed, so a test can repeat a fault exactly.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use podnet_netns::listen::ProxyListen;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::vnet::device::PacketQueue;
use crate::vnet::framing::{FrameDecoder, FrameEncoder};
use crate::vnet::stack::NetStack;

/// The number of packets a slow peer may have in its queue.
const PEER_QUEUE: usize = 1024;

/// Faults to put on a link. Each rate is a probability from 0.0 to 1.0.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Faults {
    /// Drop the packet.
    pub drop: f64,
    /// Send the packet two times.
    pub duplicate: f64,
    /// Hold the packet and send it after the next one.
    pub reorder: f64,
    /// The seed of the random sequence. The same seed gives the same faults.
    pub seed: u64,
}

impl Faults {
    /// True when no fault is set.
    pub fn is_none(&self) -> bool {
        self.drop <= 0.0 && self.duplicate <= 0.0 && self.reorder <= 0.0
    }
}

/// Applies [`Faults`] to a sequence of packets.
#[derive(Debug)]
pub struct FaultInjector {
    faults: Faults,
    state: u64,
    held: Option<Vec<u8>>,
    /// Counters: dropped, duplicated, reordered.
    pub dropped: u64,
    pub duplicated: u64,
    pub reordered: u64,
}

impl FaultInjector {
    pub fn new(faults: Faults) -> Self {
        Self {
            faults,
            // xorshift must not start at zero.
            state: faults.seed ^ 0x9e37_79b9_7f4a_7c15,
            held: None,
            dropped: 0,
            duplicated: 0,
            reordered: 0,
        }
    }

    fn chance(&mut self, rate: f64) -> bool {
        if rate <= 0.0 {
            return false;
        }
        // xorshift64*
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        let value = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        (value >> 11) as f64 / (1u64 << 53) as f64 <= rate
    }

    /// Give one packet. Return the packets to send now: none, one, or more.
    pub fn apply(&mut self, packet: Vec<u8>) -> Vec<Vec<u8>> {
        if self.chance(self.faults.drop) {
            self.dropped += 1;
            return self.held.take().into_iter().collect();
        }
        let mut out = Vec::with_capacity(3);
        if self.held.is_none() && self.chance(self.faults.reorder) {
            self.reordered += 1;
            self.held = Some(packet);
            return out;
        }
        if self.chance(self.faults.duplicate) {
            self.duplicated += 1;
            out.push(packet.clone());
        }
        out.push(packet);
        if let Some(held) = self.held.take() {
            out.push(held);
        }
        out
    }
}

/// The source and destination addresses of an IPv4 or IPv6 packet.
pub fn packet_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let src: [u8; 4] = packet[12..16].try_into().ok()?;
            let dst: [u8; 4] = packet[16..20].try_into().ok()?;
            Some((IpAddr::from(src), IpAddr::from(dst)))
        }
        6 if packet.len() >= 40 => {
            let src: [u8; 16] = packet[8..24].try_into().ok()?;
            let dst: [u8; 16] = packet[24..40].try_into().ok()?;
            Some((IpAddr::from(src), IpAddr::from(dst)))
        }
        _ => None,
    }
}

/// The forwarding table of a switch.
#[derive(Default)]
struct Table {
    next_id: u64,
    peers: HashMap<u64, mpsc::Sender<Vec<u8>>>,
    owners: HashMap<IpAddr, u64>,
    /// The packets that were dropped because their source address is of
    /// another peer.
    spoofed: u64,
}

impl Table {
    fn forward(&mut self, from: u64, packet: Vec<u8>) {
        let Some((src, dst)) = packet_addresses(&packet) else {
            return;
        };
        // Issue 309: a source address is of the first peer that sends from
        // it, until that peer leaves. A packet of another peer with that
        // source is dropped. Before, the last sender took the address and
        // got the replies to it.
        match self.owners.entry(src) {
            std::collections::hash_map::Entry::Occupied(entry) if *entry.get() != from => {
                self.spoofed += 1;
                debug!(%src, peer = from, owner = *entry.get(), "dropped a packet with the source address of another peer");
                return;
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(from);
            }
        }
        match self.owners.get(&dst).copied() {
            Some(owner) if owner != from => {
                if let Some(peer) = self.peers.get(&owner) {
                    let _ = peer.try_send(packet);
                }
            }
            Some(_) => {}
            None => {
                for (id, peer) in &self.peers {
                    if *id != from {
                        let _ = peer.try_send(packet.clone());
                    }
                }
            }
        }
    }

    fn remove(&mut self, id: u64) {
        self.peers.remove(&id);
        self.owners.retain(|_, owner| *owner != id);
    }
}

/// A running switch.
pub struct Switch {
    pub listen: ProxyListen,
    task: JoinHandle<()>,
}

impl Switch {
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// The effective user of this process.
fn own_uid() -> u32 {
    // SAFETY: geteuid() has no precondition.
    unsafe { libc::geteuid() }
}

/// True when the process at the other end of `stream` is of the user
/// `owner` (`SO_PEERCRED`). A unix socket of the switch or of the shim
/// takes the same user only (issue 308).
fn peer_is(stream: &tokio::net::UnixStream, owner: u32) -> bool {
    match stream.peer_cred() {
        Ok(cred) => cred.uid() == owner,
        Err(_) => false,
    }
}

/// The variable with the shared token of a TCP switch (issue 309).
pub const TOKEN_VARIABLE: &str = "PODNET_SWITCH_TOKEN";

/// The first line that a peer of a TCP switch sends: this text, the token
/// and a line feed. The switch answers `ok` and a line feed, or closes.
const HELLO: &str = "podnet-switch/1 ";

/// The longest first line that a TCP switch reads.
const HELLO_MAX: usize = 4096;

/// The time that a TCP peer has for the first line, and for the answer.
const HELLO_TIME: std::time::Duration = std::time::Duration::from_secs(10);

/// The token of a TCP switch: the text of `file` with no white space at the
/// ends, else the value of [`TOKEN_VARIABLE`]. `None` when there is none.
pub fn token(file: Option<&std::path::Path>) -> Result<Option<String>> {
    if let Some(path) = file {
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.len() > HELLO_MAX as u64 {
            anyhow::bail!(
                "{} is not a token file: it has {} bytes",
                path.display(),
                meta.len()
            );
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let token = text.trim();
        if token.is_empty() {
            anyhow::bail!("the token file {} is empty", path.display());
        }
        return Ok(Some(token.to_string()));
    }
    Ok(std::env::var(TOKEN_VARIABLE)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty()))
}

/// Check a token for a first line or a newline in it.
fn check_token(token: &str) -> Result<()> {
    if token.is_empty() || token.len() > HELLO_MAX - HELLO.len() - 1 {
        anyhow::bail!(
            "the switch token is empty or longer than {} bytes",
            HELLO_MAX - HELLO.len() - 1
        );
    }
    if token.bytes().any(|b| b == b'\n' || b == b'\r') {
        anyhow::bail!("the switch token has a line end in it");
    }
    Ok(())
}

/// Compare two byte strings in a time that does not depend on where they
/// differ.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Read one line (up to `\n`, at most [`HELLO_MAX`] bytes) byte by byte, so
/// that no byte after it is taken from the stream.
async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < HELLO_MAX {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        line.push(byte[0]);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "no line end",
    ))
}

/// The switch side of the first line: true when the peer sent the token.
async fn take_hello(stream: &mut tokio::net::TcpStream, token: &str) -> bool {
    let Ok(Ok(line)) = tokio::time::timeout(HELLO_TIME, read_line(stream)).await else {
        return false;
    };
    let mut want = HELLO.as_bytes().to_vec();
    want.extend_from_slice(token.as_bytes());
    if !same_bytes(&line, &want) {
        let _ = stream.write_all(b"refused\n").await;
        return false;
    }
    stream.write_all(b"ok\n").await.is_ok()
}

/// The peer side of the first line: send the token, and wait for `ok`.
async fn give_hello(stream: &mut tokio::net::TcpStream, token: &str) -> Result<()> {
    check_token(token)?;
    stream
        .write_all(format!("{HELLO}{token}\n").as_bytes())
        .await
        .context("sending the token to the switch")?;
    let answer = tokio::time::timeout(HELLO_TIME, read_line(stream))
        .await
        .context("the switch did not answer the token in time")?
        .context("reading the answer of the switch")?;
    if answer != b"ok" {
        anyhow::bail!(
            "the switch refused the token: give the token of the switch ({TOKEN_VARIABLE} or --switch-token-file)"
        );
    }
    Ok(())
}

/// Accept peers on `listen` and forward packets between them.
///
/// A TCP listener needs `token` (issue 309): each TCP peer sends it first,
/// and a peer with no token or a wrong one is closed. A unix listener takes
/// the same user only, and needs no token.
pub async fn serve(listen: ProxyListen, token: Option<String>) -> Result<Switch> {
    serve_for(listen, token, own_uid()).await
}

/// [`serve`], with the user that a unix peer must have.
async fn serve_for(listen: ProxyListen, token: Option<String>, owner: u32) -> Result<Switch> {
    let table = Arc::new(Mutex::new(Table::default()));
    let mut listen = listen;
    let task = match &listen {
        ProxyListen::Tcp(addr) => {
            let Some(token) = token else {
                anyhow::bail!(
                    "a TCP switch needs a shared token: set {TOKEN_VARIABLE}, or give --switch-token-file"
                );
            };
            check_token(&token)?;
            let token: Arc<str> = token.into();
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding tcp://{addr}"))?;
            // Issue 300: keep the bound address (the port that the kernel
            // chose for port 0), not the requested one.
            listen = ProxyListen::Tcp(listener.local_addr()?);
            tokio::spawn(async move {
                while let Ok((mut stream, from)) = listener.accept().await {
                    let table = table.clone();
                    let token = token.clone();
                    tokio::spawn(async move {
                        if !take_hello(&mut stream, &token).await {
                            warn!(%from, "refused a switch peer with no token or a wrong one");
                            return;
                        }
                        debug!(%from, "switch peer connected");
                        peer(stream, table).await;
                    });
                }
            })
        }
        ProxyListen::Unix(path) => {
            crate::net::claim_socket_path(path, false)?;
            let listener = podnet_netns::listen::bind_private(path)
                .with_context(|| format!("binding unix:{}", path.display()))?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    // Issue 308: the same user only. Root can connect to a
                    // socket of mode 0600 too.
                    if !peer_is(&stream, owner) {
                        warn!("refused a switch peer of another user");
                        continue;
                    }
                    debug!("switch peer connected");
                    tokio::spawn(peer(stream, table.clone()));
                }
            })
        }
    };
    info!(%listen, "switch is listening");
    Ok(Switch { listen, task })
}

/// Serve one peer of the switch until its stream closes.
async fn peer<S>(stream: S, table: Arc<Mutex<Table>>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PEER_QUEUE);
    let id = {
        let mut table = table.lock().unwrap();
        table.next_id += 1;
        let id = table.next_id;
        table.peers.insert(id, tx);
        id
    };
    let (mut read, mut write) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let Ok(frame) = FrameEncoder::encode(&packet) else {
                continue;
            };
            if write.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    let mut decoder = FrameDecoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let Ok(packets) = decoder.push(&buf[..n]) else {
            break;
        };
        let mut table = table.lock().unwrap();
        for packet in packets {
            table.forward(id, packet);
        }
    }
    table.lock().unwrap().remove(id);
    writer.abort();
    debug!(id, "switch peer left");
}

/// Move packets between a stack link and a byte stream, until the stream
/// closes. Apply `faults` to the packets that the stack sends.
pub async fn pump<S>(link_in: PacketQueue, link_out: PacketQueue, stream: S, faults: Faults)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let outbound = async move {
        let mut injector = FaultInjector::new(faults);
        loop {
            let packet = std::future::poll_fn(|cx| link_out.poll_recv(cx)).await;
            for packet in injector.apply(packet) {
                let Ok(frame) = FrameEncoder::encode(&packet) else {
                    continue;
                };
                if write.write_all(&frame).await.is_err() {
                    return;
                }
            }
        }
    };
    let inbound = async move {
        let mut decoder = FrameDecoder::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let Ok(packets) = decoder.push(&buf[..n]) else {
                return;
            };
            for packet in packets {
                link_in.push(packet);
            }
        }
    };
    tokio::select! {
        _ = outbound => {}
        _ = inbound => {}
    }
}

/// Connect `stack` to the switch at `switch`. The returned task moves the
/// packets until the connection closes. A TCP switch needs its `token`
/// (issue 309); a unix switch needs none.
pub async fn attach(
    stack: &NetStack,
    switch: &ProxyListen,
    faults: Faults,
    token: Option<&str>,
) -> Result<JoinHandle<()>> {
    let link_in = stack.link_in();
    let link_out = stack.link_out();
    Ok(match switch {
        ProxyListen::Tcp(addr) => {
            let Some(token) = token else {
                anyhow::bail!(
                    "a TCP switch needs its token: set {TOKEN_VARIABLE}, or give --switch-token-file"
                );
            };
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .with_context(|| format!("connecting to the switch at tcp://{addr}"))?;
            give_hello(&mut stream, token)
                .await
                .with_context(|| format!("the switch at tcp://{addr}"))?;
            tokio::spawn(pump(link_in, link_out, stream, faults))
        }
        ProxyListen::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .with_context(|| format!("connecting to the switch at unix:{}", path.display()))?;
            tokio::spawn(pump(link_in, link_out, stream, faults))
        }
    })
}

/// Bind an abstract `AF_UNIX` stream listener named `name` (no leading NUL).
#[cfg(target_os = "linux")]
fn abstract_listener(name: &str) -> Result<tokio::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&addr)
        .with_context(|| format!("binding the abstract name {name}"))?;
    listener.set_nonblocking(true)?;
    Ok(tokio::net::UnixListener::from_std(listener)?)
}

/// Connect to an abstract `AF_UNIX` stream socket named `name`.
#[cfg(target_os = "linux")]
fn abstract_connect(name: &str) -> Result<tokio::net::UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let stream = std::os::unix::net::UnixStream::connect_addr(&addr)
        .with_context(|| format!("connecting to the abstract name {name}"))?;
    stream.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(stream)?)
}

/// Serve the control socket of the shim (`PODNET_VNET_CONTROL=name`).
///
/// When a shim program binds a virtual address, the shim sends
/// `RegisterBind`. The stack then listens on the same virtual address and
/// sends each connection that arrives (from the switch) to the abstract
/// socket of the program. Thus a program on this host can accept
/// connections from stacks on other hosts.
///
/// An abstract name has no file permissions, so each local user can send to
/// it. The socket has `SO_PASSCRED`, and a datagram of another user is
/// dropped (issue 308).
#[cfg(target_os = "linux")]
pub fn serve_control(stack: Arc<NetStack>, name: &str) -> Result<JoinHandle<()>> {
    serve_control_for(stack, name, own_uid())
}

/// [`serve_control`], with the user that a sender must have.
#[cfg(target_os = "linux")]
fn serve_control_for(stack: Arc<NetStack>, name: &str, owner: u32) -> Result<JoinHandle<()>> {
    use std::os::fd::AsRawFd;
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let socket = std::os::unix::net::UnixDatagram::bind_addr(&addr)
        .with_context(|| format!("binding the control name {name}"))?;
    // A datagram that comes before this has no credentials: it is dropped.
    let on: libc::c_int = 1;
    // SAFETY: a valid socket, and a c_int option of the size given.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("SO_PASSCRED on the control name {name}"));
    }
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UnixDatagram::from_std(socket)?;
    Ok(tokio::spawn(async move {
        let mut exported = std::collections::HashSet::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let fd = socket.as_raw_fd();
            let Ok((n, uid)) = socket
                .async_io(tokio::io::Interest::READABLE, || {
                    recv_with_uid(fd, &mut buf)
                })
                .await
            else {
                break;
            };
            if uid != Some(owner) {
                debug!(uid = ?uid, "dropped a control datagram of another user");
                continue;
            }
            let Ok(Some((message, _))) = crate::vnet::control::ControlMessage::decode(&buf[..n])
            else {
                debug!("dropped a control datagram that does not decode");
                continue;
            };
            if let crate::vnet::control::ControlMessage::RegisterBind { addr, .. } = message {
                if exported.insert(addr) {
                    if let Err(err) = export(stack.clone(), addr).await {
                        debug!(%addr, error = %err, "could not export a shim listener");
                        exported.remove(&addr);
                    }
                }
            }
        }
    }))
}

/// Receive one datagram from `fd` with the user of its sender: the
/// `SCM_CREDENTIALS` message that `SO_PASSCRED` adds. `None` when the
/// datagram has no credentials.
#[cfg(target_os = "linux")]
fn recv_with_uid(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<(usize, Option<u32>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // Space for one control message: aligned, and larger than
    // CMSG_SPACE(sizeof(struct ucred)).
    let mut control = [0u64; 8];
    // SAFETY: msghdr is plain data; all zero is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: msg points to buffers that live for the call.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut uid = None;
    // SAFETY: the CMSG macros walk the control buffer that recvmsg filled,
    // within msg_controllen.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_CREDENTIALS
            {
                let cred: libc::ucred = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                uid = Some(cred.uid);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        uid = None;
    }
    Ok((n as usize, uid))
}

/// Listen on `addr` in the stack and send each connection to the abstract
/// socket of the shim program that bound `addr` on this host. A socket of
/// another user at that name gets no connection (issue 308).
#[cfg(target_os = "linux")]
pub async fn export(stack: Arc<NetStack>, addr: crate::vnet::addr::VirtAddr) -> Result<()> {
    let mut listener = stack.listen(addr).await?;
    let name = addr.abstract_name()?;
    info!(%addr, "exported a shim listener to the switch");
    tokio::spawn(async move {
        while let Ok(mut virtual_conn) = listener.accept().await {
            let name = name.clone();
            tokio::spawn(async move {
                match abstract_connect(&name) {
                    Ok(local) if !peer_is(&local, own_uid()) => {
                        warn!(%name, "the abstract name is of another user: no connection");
                    }
                    Ok(mut local) => {
                        let _ = tokio::io::copy_bidirectional(&mut virtual_conn, &mut local).await;
                    }
                    Err(err) => debug!(error = %err, "the shim listener is gone"),
                }
            });
        }
    });
    Ok(())
}

/// Make the remote virtual address `addr` reachable for shim programs on this
/// host: bind its abstract name here, and connect each client through the
/// stack (and so through the switch). A client of another user is refused
/// (issue 308).
#[cfg(target_os = "linux")]
pub fn import(stack: Arc<NetStack>, addr: crate::vnet::addr::VirtAddr) -> Result<JoinHandle<()>> {
    let listener = abstract_listener(&addr.abstract_name()?)?;
    info!(%addr, "imported a remote address for shim programs");
    Ok(tokio::spawn(async move {
        while let Ok((mut local, _)) = listener.accept().await {
            if !peer_is(&local, own_uid()) {
                debug!(%addr, "refused a client of another user");
                continue;
            }
            let stack = stack.clone();
            tokio::spawn(async move {
                match stack.connect(addr).await {
                    Ok(mut virtual_conn) => {
                        let _ = tokio::io::copy_bidirectional(&mut local, &mut virtual_conn).await;
                    }
                    Err(err) => debug!(%addr, error = %err, "connect through the switch failed"),
                }
            });
        }
    }))
}

#[cfg(test)]
mod tests;
