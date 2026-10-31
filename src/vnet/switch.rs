//! Switch mode: connect userspace stacks on one host or on different hosts.
//!
//! A switch is a hub. Each peer connects to it with a byte stream (a unix
//! socket, a TCP connection, or a `cfrs` WebSocket forward through a tunnel)
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
use pod_netns::listen::ProxyListen;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info};

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
}

impl Table {
    fn forward(&mut self, from: u64, packet: Vec<u8>) {
        let Some((src, dst)) = packet_addresses(&packet) else {
            return;
        };
        self.owners.insert(src, from);
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

/// Accept peers on `listen` and forward packets between them.
pub async fn serve(listen: ProxyListen) -> Result<Switch> {
    let table = Arc::new(Mutex::new(Table::default()));
    let task = match &listen {
        ProxyListen::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding tcp://{addr}"))?;
            tokio::spawn(async move {
                while let Ok((stream, from)) = listener.accept().await {
                    debug!(%from, "switch peer connected");
                    tokio::spawn(peer(stream, table.clone()));
                }
            })
        }
        ProxyListen::Unix(path) => {
            let _ = std::fs::remove_file(path);
            let listener = tokio::net::UnixListener::bind(path)
                .with_context(|| format!("binding unix:{}", path.display()))?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    debug!("switch peer connected");
                    tokio::spawn(peer(stream, table.clone()));
                }
            })
        }
    };
    info!(?listen, "switch is listening");
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
/// packets until the connection closes.
pub async fn attach(stack: &NetStack, switch: &ProxyListen, faults: Faults) -> Result<JoinHandle<()>> {
    let link_in = stack.link_in();
    let link_out = stack.link_out();
    Ok(match switch {
        ProxyListen::Tcp(addr) => {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .with_context(|| format!("connecting to the switch at tcp://{addr}"))?;
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

/// Serve the control socket of the shim (`CFRSNET_CONTROL=name`).
///
/// When a shim program binds a virtual address, the shim sends
/// `RegisterBind`. The stack then listens on the same virtual address and
/// sends each connection that arrives (from the switch) to the abstract
/// socket of the program. Thus a program on this host can accept
/// connections from stacks on other hosts.
#[cfg(target_os = "linux")]
pub fn serve_control(stack: Arc<NetStack>, name: &str) -> Result<JoinHandle<()>> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let socket = std::os::unix::net::UnixDatagram::bind_addr(&addr)
        .with_context(|| format!("binding the control name {name}"))?;
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UnixDatagram::from_std(socket)?;
    Ok(tokio::spawn(async move {
        let mut exported = std::collections::HashSet::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let Ok(n) = socket.recv(&mut buf).await else {
                break;
            };
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

/// Listen on `addr` in the stack and send each connection to the abstract
/// socket of the shim program that bound `addr` on this host.
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
/// stack (and so through the switch).
#[cfg(target_os = "linux")]
pub fn import(stack: Arc<NetStack>, addr: crate::vnet::addr::VirtAddr) -> Result<JoinHandle<()>> {
    let listener = abstract_listener(&addr.abstract_name()?)?;
    info!(%addr, "imported a remote address for shim programs");
    Ok(tokio::spawn(async move {
        while let Ok((mut local, _)) = listener.accept().await {
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
mod tests {
    use super::*;
    use crate::vnet::addr::VirtAddr;
    use crate::vnet::stack::StackConfig;
    use std::net::Ipv4Addr;

    #[test]
    fn the_same_seed_gives_the_same_faults() {
        let faults = Faults {
            drop: 0.2,
            duplicate: 0.1,
            reorder: 0.1,
            seed: 7,
        };
        let run = || {
            let mut injector = FaultInjector::new(faults);
            (0u8..200)
                .flat_map(|i| injector.apply(vec![i]))
                .map(|p| p[0])
                .collect::<Vec<u8>>()
        };
        let first = run();
        assert_eq!(first, run());
        assert!(first.len() < 200 + 40, "some packets dropped");
        assert_ne!(first, (0u8..200).collect::<Vec<u8>>());
    }

    #[test]
    fn no_faults_keep_the_sequence() {
        let mut injector = FaultInjector::new(Faults::default());
        let out: Vec<Vec<u8>> = (0u8..50).flat_map(|i| injector.apply(vec![i])).collect();
        assert_eq!(out, (0u8..50).map(|i| vec![i]).collect::<Vec<_>>());
    }

    #[test]
    fn reads_packet_addresses() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[12..16].copy_from_slice(&[10, 66, 0, 2]);
        v4[16..20].copy_from_slice(&[10, 66, 0, 3]);
        assert_eq!(
            packet_addresses(&v4),
            Some((
                IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 66, 0, 3))
            ))
        );
        assert_eq!(packet_addresses(&[0x45, 0]), None);
    }

    fn config(last: u8) -> StackConfig {
        StackConfig {
            local_v4: Ipv4Addr::new(10, 66, 0, last),
            ..StackConfig::default()
        }
    }

    const PAYLOAD_LEN: usize = 64 * 1024;

    /// Two stacks on one switch, with a lossy link that also duplicates and
    /// reorders: TCP still carries every byte in order.
    #[tokio::test]
    async fn two_stacks_talk_through_a_lossy_switch() {
        let dir = tempfile::tempdir().unwrap();
        let listen = ProxyListen::Unix(dir.path().join("switch.sock"));
        let switch = serve(listen.clone()).await.unwrap();

        let server = NetStack::over_link(config(2));
        let client = NetStack::over_link(config(3));
        let faults = Faults {
            drop: 0.1,
            duplicate: 0.05,
            reorder: 0.05,
            seed: 42,
        };
        let _a = attach(&server, &listen, faults).await.unwrap();
        let _b = attach(&client, &listen, faults).await.unwrap();

        let address = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 8080);
        let mut listener = server.listen(address).await.unwrap();
        let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let accept = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let mut got = Vec::new();
            conn.read_to_end(&mut got).await.unwrap();
            got
        });
        let mut conn = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.connect(address),
        )
        .await
        .expect("connect in time")
        .unwrap();
        conn.write_all(&payload).await.unwrap();
        AsyncWriteExt::shutdown(&mut conn).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(60), accept)
            .await
            .expect("transfer in time")
            .unwrap();
        assert_eq!(got.len(), expected.len());
        assert!(got == expected, "the bytes arrived changed");
        switch.abort();
    }

    /// A program on host A listens on an abstract name (as the shim does); a
    /// program on host B connects to the imported name. The bytes go through
    /// two stacks and a switch.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exported_and_imported_names_meet_through_the_switch() {
        let dir = tempfile::tempdir().unwrap();
        let listen = ProxyListen::Unix(dir.path().join("switch.sock"));
        let switch = serve(listen.clone()).await.unwrap();
        let a = Arc::new(NetStack::over_link(config(2)));
        let b = Arc::new(NetStack::over_link(config(3)));
        let _la = attach(&a, &listen, Faults::default()).await.unwrap();
        let _lb = attach(&b, &listen, Faults::default()).await.unwrap();

        // Both "hosts" share one abstract namespace in this test. Thus B
        // connects through its stack directly, which is what an imported name
        // does for each client. A port from the pid keeps parallel runs apart.
        let port = 7000 + (std::process::id() % 1000) as u16;
        let addr = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), port);
        let program = abstract_listener(&addr.abstract_name().unwrap()).unwrap();
        export(a.clone(), addr).await.unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = program.accept().await.unwrap();
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(b"pong").await.unwrap();
        });

        let mut conn = b.connect(addr).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(10), conn.read_exact(&mut reply))
            .await
            .expect("reply in time")
            .unwrap();
        assert_eq!(&reply, b"pong");
        switch.abort();
    }
}
