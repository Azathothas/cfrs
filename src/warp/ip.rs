//! A userspace IPv4/IPv6 stack over a MASQUE CONNECT-IP session.
//!
//! The point of this module is that nothing it carries touches the host's
//! socket layer. A packet handed to [`WarpStack::tcp_connect`] is built by
//! `smoltcp`, encapsulated in a CONNECT-IP capsule and written to the HTTP/2
//! request body; the reply arrives the same way and is handed back to
//! `smoltcp`. A destination the host's own firewall refuses — port 7844, say —
//! is therefore reachable, because the host never sees a `connect()` for it.
//!
//! One driver task owns the interface and the socket set. Callers hold a
//! [`WarpStack`], which is a command channel into that task.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::vnet::device::LinkDevice;

/// The MTU the tunnel carries. 1280 is the IPv6 minimum and what the WARP
/// client uses; anything larger is dropped by the front door.
pub const TUNNEL_MTU: usize = 1280;

/// The send and receive buffers of each TCP connection (issue 93: 128 KiB
/// was at most 2.8 MB/s at an RTT of 46 ms).
const TCP_BUFFER: usize = 512 * 1024;
/// The variable with the TCP window of the userspace stack, in segments of
/// the MTU, or `none` for no limit (issue 100). For a measurement.
pub const TCP_BURST_VARIABLE: &str = "CFRS_WARP_TCP_BURST";

/// The default TCP window (issue 100): no limit. With smoltcp 0.11, a
/// window over 1 segment stalled on the direct path (live run
/// 41567562797), so 1 was the default. With smoltcp 0.12, no window
/// stalls: a download of 20 MB with no limit was 12.1 and 16.8 MB/s over
/// HTTP/2 and 44.8 and 66.1 MB/s over HTTP/3, against 7.1 to 9.5 MB/s with
/// 1 segment (live runs 41630694087 and 41633242174).
const TCP_BURST_DEFAULT: Option<usize> = None;

/// The largest value of [`TCP_BURST_VARIABLE`]: more segments do not fit
/// in the receive buffer.
const TCP_BURST_MAX: usize = TCP_BUFFER.div_ceil(TUNNEL_MTU - 60);

/// The variable of the congestion controller of the TCP connections of the
/// stack (issue 134): `none` (the default), `reno` or `cubic`.
pub const CC_VARIABLE: &str = "CFRS_WARP_CC";

static CC: std::sync::OnceLock<smoltcp::socket::tcp::CongestionControl> =
    std::sync::OnceLock::new();

/// `none`, `reno` (RFC 5681) or `cubic` (RFC 9438).
pub fn parse_cc(value: &str) -> Result<smoltcp::socket::tcp::CongestionControl> {
    use smoltcp::socket::tcp::CongestionControl;
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(CongestionControl::None),
        "reno" => Ok(CongestionControl::Reno),
        "cubic" => Ok(CongestionControl::Cubic),
        other => Err(crate::exit::fault(
            crate::exit::Fault::Config,
            anyhow::anyhow!("--cc (or {CC_VARIABLE}) {other:?}: give none, reno or cubic"),
        )),
    }
}

/// Set the congestion controller of this process (`--cc`). A later call
/// does nothing.
pub fn set_cc(cc: smoltcp::socket::tcp::CongestionControl) {
    if CC.set(cc).is_ok() {
        tracing::debug!(
            ?cc,
            "the congestion controller of the TCP connections of WARP"
        );
    }
}

/// The congestion controller: `--cc`, else [`CC_VARIABLE`], else none. A
/// bad variable is reported by [`check_cc`] before this is read.
fn cc() -> smoltcp::socket::tcp::CongestionControl {
    if let Some(cc) = CC.get() {
        return *cc;
    }
    std::env::var(CC_VARIABLE)
        .ok()
        .and_then(|v| parse_cc(&v).ok())
        .unwrap_or(smoltcp::socket::tcp::CongestionControl::None)
}

/// Check [`CC_VARIABLE`] before a command opens a session: a bad value is a
/// configuration error (exit 78).
pub fn check_cc() -> Result<()> {
    match std::env::var(CC_VARIABLE) {
        Ok(v) => parse_cc(&v).map(|_| ()),
        Err(_) => Ok(()),
    }
}

/// The TCP window of [`TCP_BURST_VARIABLE`]: `None` for no limit.
fn tcp_burst() -> Result<Option<usize>> {
    parse_tcp_burst(std::env::var(TCP_BURST_VARIABLE).ok().as_deref())
}

/// Check [`TCP_BURST_VARIABLE`] before a command opens a session (issue
/// 111): a bad value is a configuration error (exit 78).
pub fn check_tcp_burst() -> Result<()> {
    tcp_burst().map(|_| ())
}

/// Issue 111: a value that is not a number from 1 to [`TCP_BURST_MAX`] or
/// `none` is an error. Before, it gave the default with no message, so a
/// measurement could not be trusted.
fn parse_tcp_burst(value: Option<&str>) -> Result<Option<usize>> {
    let Some(value) = value else {
        return Ok(TCP_BURST_DEFAULT);
    };
    let value = value.trim();
    if value == "none" {
        return Ok(None);
    }
    match value.parse::<usize>() {
        Ok(n) if (1..=TCP_BURST_MAX).contains(&n) => Ok(Some(n)),
        _ => Err(crate::exit::fault(
            crate::exit::Fault::Config,
            anyhow::anyhow!(
                "{TCP_BURST_VARIABLE}={value:?}: give a number of segments from 1 to {TCP_BURST_MAX}, or none"
            ),
        )),
    }
}

/// The interval of the liveness check of the MASQUE session.
const KEEPALIVE: Duration = Duration::from_secs(15);
/// The most bytes of packets in one write to the MASQUE stream (issue 122).
const BATCH_BYTES: usize = 16 * 1024;
/// The most packets in the outbound queue of the tunnel device.
const OUTBOUND_PACKETS: usize = 512;
/// The packets from the session that wait for the stack (#278): about
/// 5 MB at the MTU. A full queue drops, so the peer sends again.
const INBOUND_PACKETS: usize = 4096;

/// The counters of the links of the WARP stacks of this process (issue
/// 134): each session adds to them.
static LINK_STATS: std::sync::LazyLock<std::sync::Arc<crate::vnet::device::DeviceStats>> =
    std::sync::LazyLock::new(Default::default);

/// The counters of the links of the WARP stacks of this process.
pub fn link_stats() -> crate::vnet::device::DeviceStatsSnapshot {
    LINK_STATS.snapshot()
}
const UDP_PACKETS: usize = 64;
/// A TCP connection that has no answer of the peer for this time is
/// aborted: a connect, data that is not acknowledged, or a keepalive
/// (issue 125).
const TCP_TIMEOUT: Duration = Duration::from_secs(60);
/// The interval of the TCP keepalive of an idle connection (issue 125).
const TCP_KEEPALIVE: Duration = Duration::from_secs(20);
/// The time that a closed connection has to send its data and its FIN.
/// After it, the connection is aborted and its socket is freed (issue 125).
const TCP_LINGER: Duration = Duration::from_secs(30);
const UDP_PAYLOAD: usize = 64 * 1024;

/// A live handle on the userspace stack. A clone is a handle on the same
/// stack.
#[derive(Clone)]
pub struct WarpStack {
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Why the session closed (issue 178): the first cause wins.
    reason: Reason,
    local: IpAddr,
    renew: Option<crate::ws_relay::RelayBudget>,
}

/// The cause of the close of a session.
type Reason = std::sync::Arc<std::sync::Mutex<Option<String>>>;

/// Mark the session closed for `why` (the first cause stays).
fn mark_closed(closed: &std::sync::atomic::AtomicBool, reason: &Reason, why: String) {
    {
        let mut slot = reason.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(why);
        }
    }
    closed.store(true, std::sync::atomic::Ordering::Relaxed);
}

enum Command {
    TcpConnect {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<u32>>,
    },
    TcpSend {
        id: u32,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<usize>>,
    },
    TcpRecv {
        id: u32,
        max: usize,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    TcpClose {
        id: u32,
    },
    /// Send a FIN; the receive side stays open (issue 125).
    TcpShutdown {
        id: u32,
    },
    UdpBind {
        reply: oneshot::Sender<Result<(u32, u16)>>,
    },
    UdpSend {
        id: u32,
        data: Vec<u8>,
        to: SocketAddr,
        reply: oneshot::Sender<Result<usize>>,
    },
    UdpRecv {
        id: u32,
        max: usize,
        reply: oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>,
    },
    UdpClose {
        id: u32,
    },
}

enum Pending {
    TcpConnect {
        id: u32,
        handle: SocketHandle,
        reply: oneshot::Sender<Result<u32>>,
    },
    TcpSend {
        handle: SocketHandle,
        /// The bytes that the socket did not take yet.
        data: Vec<u8>,
        /// The length of the data of the command: the answer, when the
        /// socket took each byte.
        total: usize,
        reply: oneshot::Sender<Result<usize>>,
    },
    TcpRecv {
        handle: SocketHandle,
        max: usize,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    UdpSend {
        handle: SocketHandle,
        data: Vec<u8>,
        to: IpEndpoint,
        reply: oneshot::Sender<Result<usize>>,
    },
    UdpRecv {
        handle: SocketHandle,
        max: usize,
        reply: oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>,
    },
}

impl Pending {
    fn handle(&self) -> SocketHandle {
        match self {
            Pending::TcpConnect { handle, .. }
            | Pending::TcpSend { handle, .. }
            | Pending::TcpRecv { handle, .. }
            | Pending::UdpSend { handle, .. }
            | Pending::UdpRecv { handle, .. } => *handle,
        }
    }

    /// Complete the operation with an error.
    fn fail(self, why: &str) {
        let err = || anyhow::anyhow!("{why}");
        match self {
            Pending::TcpConnect { reply, .. } => drop(reply.send(Err(err()))),
            Pending::TcpSend { reply, .. } | Pending::UdpSend { reply, .. } => {
                drop(reply.send(Err(err())))
            }
            Pending::TcpRecv { reply, .. } => drop(reply.send(Err(err()))),
            Pending::UdpRecv { reply, .. } => drop(reply.send(Err(err()))),
        }
    }
}

/// How to configure the interface the tunnel exposes.
pub struct StackConfig {
    /// The address the tunnel assigned to us.
    pub local: IpAddr,
    /// The IPv6 address of the tunnel too, when `local` is IPv4 (issue
    /// 81): the stack then has both, and a default route for each.
    pub local_v6: Option<std::net::Ipv6Addr>,
    /// The next hop for everything not on-link. The tunnel is point to point,
    /// so any address in the assigned subnet works; WARP uses `.1`.
    pub gateway: IpAddr,
    pub mtu: usize,
    /// The budget of the relay that carries the session, if any.
    pub renew: Option<crate::ws_relay::RelayBudget>,
}

impl StackConfig {
    pub fn new(local: IpAddr) -> Self {
        let gateway = match local {
            IpAddr::V4(v4) => {
                let mut o = v4.octets();
                o[3] = 1;
                IpAddr::V4(o.into())
            }
            IpAddr::V6(v6) => IpAddr::V6(v6),
        };
        Self {
            local,
            local_v6: None,
            gateway,
            mtu: TUNNEL_MTU,
            renew: None,
        }
    }

    /// Add the IPv6 address of the tunnel.
    pub fn with_ipv6(mut self, v6: Option<std::net::Ipv6Addr>) -> Self {
        if self.local.is_ipv4() {
            self.local_v6 = v6;
        }
        self
    }
}

fn to_smol(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

fn to_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_smol(addr.ip()), addr.port())
}

fn from_endpoint(ep: IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(v4), ep.port),
        IpAddress::Ipv6(v6) => SocketAddr::new(IpAddr::V6(v6), ep.port),
    }
}

/// Make the interface of the tunnel: the addresses and the default routes.
fn build_iface(config: &StackConfig, device: &mut LinkDevice) -> Interface {
    let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = 0x0c_f2_5e_ed_00_00_00_01;
    let mut iface = Interface::new(iface_config, device, Instant::ZERO);

    iface.update_ip_addrs(|addrs| {
        let cidr = match config.local {
            IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4), 32),
            IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6), 128),
        };
        addrs.push(cidr).ok();
        if let Some(v6) = config.local_v6 {
            addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128)).ok();
        }
    });
    match config.gateway {
        IpAddr::V4(gw) => {
            iface.routes_mut().add_default_ipv4_route(gw).ok();
        }
        IpAddr::V6(gw) => {
            iface.routes_mut().add_default_ipv6_route(gw).ok();
        }
    }
    if let Some(v6) = config.local_v6 {
        // The tunnel is point to point: the own address is a next hop
        // that needs no neighbour discovery.
        iface.routes_mut().add_default_ipv6_route(v6).ok();
    }
    iface
}

/// Log an ADDRESS_ASSIGN of the front door: info when the stack has the
/// address, a warning when not (issue 121: the stack uses the address of
/// the device record).
fn log_assigned(assigned: &[(IpAddr, u8)], ours: &[IpAddr]) -> bool {
    let shown: Vec<String> = assigned.iter().map(|(ip, p)| format!("{ip}/{p}")).collect();
    let all_ours = assigned.iter().all(|(ip, _)| ours.contains(ip));
    if all_ours {
        tracing::info!(assigned = %shown.join(" "), "the front door assigned the addresses of the stack");
    } else {
        tracing::warn!(
            assigned = %shown.join(" "),
            stack = ?ours,
            "the front door assigned an address that the stack does not have"
        );
    }
    all_ours
}

/// Run the driver in a task, with its supervisor.
fn spawn_driver(
    driver: Driver,
    cmd_rx: mpsc::Receiver<Command>,
    notify: std::sync::Arc<Notify>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reason: Reason,
) {
    let task = {
        let notify = notify.clone();
        let closed = closed.clone();
        tokio::spawn(async move {
            let mut driver = driver;
            driver.run(cmd_rx, notify, closed).await;
        })
    };
    // Issue 112: the stack is closed when the driver ends, also by a panic,
    // so that Live replaces it with a new session.
    tokio::spawn(supervise(task, closed, notify, reason));
}

/// Wait for the driver task to end. Then mark the stack closed. A panic of
/// the driver is logged (issue 112).
async fn supervise(
    driver: tokio::task::JoinHandle<()>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    notify: std::sync::Arc<Notify>,
    reason: Reason,
) {
    let why = match driver.await {
        Err(err) if err.is_panic() => {
            tracing::warn!("the userspace stack stopped with a panic; a new session replaces it");
            "the userspace stack stopped with a panic"
        }
        _ => "the userspace stack stopped",
    };
    mark_closed(&closed, &reason, why.into());
    notify.notify_one();
}

impl WarpStack {
    /// Start the stack over an established session.
    pub fn start(
        tx: super::session::MasqueTx,
        rx: super::session::MasqueRx,
        config: StackConfig,
    ) -> Result<Self> {
        // The packets that wait for the MASQUE sender (issue 93): about
        // 600 KB at the MTU; a full queue drops, so TCP and QUIC see a loss.
        let burst = tcp_burst()?;
        tracing::debug!(segments = ?burst, "the TCP window of the userspace stack");
        let mut device = LinkDevice::tunnel_bounded(config.mtu, OUTBOUND_PACKETS)
            .with_inbound_limit(INBOUND_PACKETS)
            .with_max_burst(burst)
            .with_stats(LINK_STATS.clone());
        let inbound = device.inbound();
        let outbound = device.outbound();

        let iface = build_iface(&config, &mut device);

        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let notify = std::sync::Arc::new(Notify::new());
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reason: Reason = Default::default();

        // Issue 104: a session that gives no pong and no data is closed, so
        // that Live opens a new one (before, a stalled session stayed).
        let mut tx = tx;
        if let Some(keepalive) = tx.keepalive(&rx) {
            let notify = notify.clone();
            let closed = closed.clone();
            let reason = reason.clone();
            tokio::spawn(async move {
                if let Err(err) = keepalive.run(KEEPALIVE).await {
                    tracing::warn!(error = %format!("{err:#}"), "the MASQUE session is dead");
                    mark_closed(&closed, &reason, format!("no pong: {err:#}"));
                    notify.notify_one();
                }
            });
        }

        {
            let notify = notify.clone();
            let closed = closed.clone();
            let reason = reason.clone();
            tokio::spawn(async move {
                let why = loop {
                    // Issue 122: the packets that wait go out together, up
                    // to BATCH_BYTES, in one DATA frame.
                    let mut batch = vec![outbound.recv().await];
                    let mut bytes = batch[0].len();
                    while bytes < BATCH_BYTES {
                        let Some(next) = outbound.pop() else { break };
                        bytes += next.len();
                        batch.push(next);
                    }
                    if let Err(err) = tx.send_packets(&batch).await {
                        // The session cannot send again: mark the stack closed,
                        // so that a new session replaces it.
                        tracing::warn!(error = %format!("{err:#}"), "the MASQUE send loop ended");
                        break format!("a send failed: {err:#}");
                    }
                    notify.notify_one();
                };
                mark_closed(&closed, &reason, why);
                notify.notify_one();
            });
        }

        {
            let notify = notify.clone();
            let inbound = inbound.clone();
            let closed = closed.clone();
            let reason = reason.clone();
            let ours: Vec<IpAddr> = std::iter::once(config.local)
                .chain(config.local_v6.map(IpAddr::V6))
                .collect();
            tokio::spawn(async move {
                let mut rx = rx;
                loop {
                    let packet = rx.recv_packet().await;
                    // Issue 121: the address that the front door assigned.
                    if let Some(assigned) = rx.take_assigned() {
                        log_assigned(&assigned, &ours);
                    }
                    let why = match packet {
                        Ok(Some(packet)) => {
                            if !inbound.push(packet.to_vec()) {
                                LINK_STATS
                                    .rx_dropped
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            notify.notify_one();
                            continue;
                        }
                        Ok(None) => "the front door ended the session".to_string(),
                        Err(err) => {
                            tracing::warn!(error = %format!("{err:#}"), "the MASQUE receive loop ended");
                            format!("a receive failed: {err:#}")
                        }
                    };
                    mark_closed(&closed, &reason, why);
                    break;
                }
                notify.notify_one();
            });
        }

        {
            let notify = notify.clone();
            let closed = closed.clone();
            let reason = reason.clone();
            spawn_driver(Driver::new(iface, device), cmd_rx, notify, closed, reason);
        }

        Ok(Self {
            cmd: cmd_tx,
            notify,
            closed,
            reason,
            local: config.local,
            renew: config.renew,
        })
    }

    /// A stack over a bare device, with no MASQUE session (for the tests):
    /// the test moves the packets of the device.
    #[cfg(test)]
    pub(crate) fn on_device(mut device: LinkDevice, config: StackConfig) -> Self {
        let iface = build_iface(&config, &mut device);
        let (cmd, cmd_rx) = mpsc::channel(256);
        let notify = std::sync::Arc::new(Notify::new());
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reason: Reason = Default::default();
        spawn_driver(
            Driver::new(iface, device),
            cmd_rx,
            notify.clone(),
            closed.clone(),
            reason.clone(),
        );
        Self {
            cmd,
            notify,
            closed,
            reason,
            local: config.local,
            renew: config.renew,
        }
    }

    /// Wake the driver (for the tests, after a packet in the device).
    #[cfg(test)]
    pub(crate) fn wake(&self) {
        self.notify.notify_one();
    }

    /// True when the MASQUE session of this stack can no longer carry a
    /// packet in one direction or the other.
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed) || self.cmd.is_closed()
    }

    /// Why the session closed (issue 178), when it did.
    /// Whether the budget of the relay of this session is spent: a new
    /// session must take the new flows.
    pub fn renew_due(&self) -> bool {
        self.renew.as_ref().is_some_and(|b| b.spent())
    }

    pub fn close_reason(&self) -> Option<String> {
        self.reason
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Close the session on purpose (issue 185: --session-max-age). Its
    /// flows end, and `Live` opens a new session.
    pub fn close_session(&self, why: &str) {
        mark_closed(&self.closed, &self.reason, why.to_string());
        self.notify.notify_one();
    }

    fn alive(&self) -> Result<()> {
        if self.is_closed() {
            bail!("the MASQUE session is closed");
        }
        Ok(())
    }

    /// Open a TCP connection to `remote` through the tunnel.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<TcpConn> {
        self.alive()?;
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::TcpConnect { remote, reply })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        let id = wait.await.context("userspace stack driver is gone")??;
        Ok(TcpConn {
            id,
            cmd: self.cmd.clone(),
            notify: self.notify.clone(),
        })
    }

    /// Bind a UDP socket on the tunnel.
    pub async fn udp_bind(&self) -> Result<UdpConn> {
        self.alive()?;
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::UdpBind { reply })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        let (id, port) = wait.await.context("userspace stack driver is gone")??;
        Ok(UdpConn {
            id,
            local: SocketAddr::new(self.local, port),
            cmd: self.cmd.clone(),
            notify: self.notify.clone(),
            _close: std::sync::Arc::new(CloseOnDrop {
                cmd: self.cmd.clone(),
                notify: self.notify.clone(),
                close: Some(Command::UdpClose { id }),
            }),
        })
    }
}

/// A TCP connection carried by the userspace stack.
pub struct TcpConn {
    id: u32,
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
}

impl TcpConn {
    pub async fn send(&self, data: Vec<u8>) -> Result<usize> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::TcpSend {
                id: self.id,
                data,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }

    /// Read up to `max` bytes. An empty vector means the peer closed.
    pub async fn recv(&self, max: usize) -> Result<Vec<u8>> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::TcpRecv {
                id: self.id,
                max,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }

    /// Send a FIN: the peer reads the end of the data. The receive side
    /// stays open (issue 125).
    pub async fn shutdown(&self) {
        let _ = self.cmd.send(Command::TcpShutdown { id: self.id }).await;
        self.notify.notify_one();
    }

    pub async fn close(&self) {
        let _ = self.cmd.send(Command::TcpClose { id: self.id }).await;
        self.notify.notify_one();
    }
}

impl Drop for TcpConn {
    /// A connection that is dropped with no close (a cancelled task) is
    /// closed too (issue 125). A second close does nothing.
    fn drop(&mut self) {
        if self.cmd.try_send(Command::TcpClose { id: self.id }).is_ok() {
            self.notify.notify_one();
        }
    }
}

/// Send a command when the last clone of a handle is dropped.
struct CloseOnDrop {
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
    close: Option<Command>,
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(close) = self.close.take() {
            if self.cmd.try_send(close).is_ok() {
                self.notify.notify_one();
            }
        }
    }
}

/// A UDP socket carried by the userspace stack.
#[derive(Clone)]
pub struct UdpConn {
    id: u32,
    local: SocketAddr,
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
    /// The last clone frees the socket (issue 125).
    _close: std::sync::Arc<CloseOnDrop>,
}

impl UdpConn {
    /// The address this socket is bound to inside the tunnel.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub async fn send_to(&self, data: Vec<u8>, to: SocketAddr) -> Result<usize> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::UdpSend {
                id: self.id,
                data,
                to,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }

    pub async fn recv_from(&self, max: usize) -> Result<(Vec<u8>, SocketAddr)> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::UdpRecv {
                id: self.id,
                max,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }
}

struct Driver {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: LinkDevice,
    registry: HashMap<u32, SocketHandle>,
    pending: VecDeque<Pending>,
    /// The closed TCP sockets that still send, with the time of the close.
    closing: Vec<(SocketHandle, Instant)>,
    next_id: u32,
    next_ephemeral: u16,
}

impl Driver {
    fn new(iface: Interface, device: LinkDevice) -> Self {
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            registry: HashMap::new(),
            pending: VecDeque::new(),
            closing: Vec::new(),
            next_id: 1,
            next_ephemeral: 40_000,
        }
    }

    /// True when the tunnel has an address of the family of `ip`.
    fn has_family(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.iface.ipv4_addr().is_some(),
            IpAddr::V6(_) => self.iface.ipv6_addr().is_some(),
        }
    }

    fn now() -> Instant {
        use std::sync::OnceLock;
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let start = START.get_or_init(std::time::Instant::now);
        Instant::from_micros(start.elapsed().as_micros() as i64)
    }

    async fn run(
        &mut self,
        mut cmd_rx: mpsc::Receiver<Command>,
        notify: std::sync::Arc<Notify>,
        closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        loop {
            while let Ok(cmd) = cmd_rx.try_recv() {
                self.apply(cmd);
            }

            let now = Self::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let moved = self.progress();
            self.reap(now);

            // Issue 125: the operations of a dead session fail now. Before,
            // a read waited for data that could not come.
            if closed.load(std::sync::atomic::Ordering::Relaxed) {
                self.fail_all("the MASQUE session is closed");
                break;
            }
            // A read or a write changed a window: poll again at once, so
            // that the window update goes out now (issue 93).
            if moved {
                tokio::task::yield_now().await;
                continue;
            }

            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_millis(d.total_millis().max(1)))
                .unwrap_or(Duration::from_millis(50))
                .min(Duration::from_millis(50));

            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = notify.notified() => {}
                cmd = cmd_rx.recv() => match cmd {
                    Some(cmd) => self.apply(cmd),
                    None => break,
                },
            }
        }
    }

    fn tcp_socket() -> tcp::Socket<'static> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        );
        socket.set_timeout(Some(TCP_TIMEOUT.into()));
        socket.set_keep_alive(Some(TCP_KEEPALIVE.into()));
        // podssh: no Nagle. A small write (a keystroke of SSH, a small
        // request) goes at once; with Nagle it waited for the ACK of the
        // data before it (one round trip through WARP).
        socket.set_nagle_enabled(false);
        // Issue 134: none unless --cc says otherwise (smoltcp 0.12 takes
        // cubic by default when its feature is on).
        socket.set_congestion_control(cc());
        socket
    }

    /// Remove a socket and fail each pending operation on it.
    fn forget(&mut self, handle: SocketHandle) {
        let pending = std::mem::take(&mut self.pending);
        for op in pending {
            if op.handle() == handle {
                op.fail("the connection is closed");
            } else {
                self.pending.push_back(op);
            }
        }
        self.closing.retain(|(h, _)| *h != handle);
        self.sockets.remove(handle);
    }

    /// Fail each pending operation and abort each connection.
    fn fail_all(&mut self, why: &str) {
        for op in std::mem::take(&mut self.pending) {
            op.fail(why);
        }
        for (_, socket) in self.sockets.iter_mut() {
            if let smoltcp::socket::Socket::Tcp(tcp) = socket {
                tcp.abort();
            }
        }
    }

    /// Free the sockets of the closed connections that are done, or that
    /// had [`TCP_LINGER`] to finish (issue 125: before, each closed socket
    /// stayed for the life of the stack).
    fn reap(&mut self, now: Instant) {
        let mut done = Vec::new();
        for (handle, at) in &self.closing {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            match socket.state() {
                tcp::State::Closed | tcp::State::TimeWait => done.push(*handle),
                _ if now - *at > TCP_LINGER.into() => socket.abort(),
                _ => {}
            }
        }
        for handle in done {
            self.forget(handle);
        }
    }

    /// The number of sockets in the stack (for the tests).
    #[cfg(test)]
    fn socket_count(&self) -> usize {
        self.sockets.iter().count()
    }

    fn udp_socket() -> udp::Socket<'static> {
        udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_PAYLOAD],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_PAYLOAD],
            ),
        )
    }

    fn handle_of(&self, id: u32) -> Option<SocketHandle> {
        self.registry.get(&id).copied()
    }

    fn apply(&mut self, cmd: Command) {
        match cmd {
            Command::TcpConnect { remote, reply } => {
                let id = self.next_id;
                self.next_id += 1;
                let local_port = self.next_ephemeral;
                self.next_ephemeral = if self.next_ephemeral >= 60_000 {
                    40_000
                } else {
                    self.next_ephemeral + 1
                };

                let local_addr = match remote.ip() {
                    IpAddr::V4(_) => self.iface.ipv4_addr().map(IpAddress::Ipv4),
                    IpAddr::V6(_) => self.iface.ipv6_addr().map(IpAddress::Ipv6),
                };
                let Some(local_addr) = local_addr else {
                    let _ = reply.send(Err(anyhow::anyhow!(
                        "the tunnel has no address for {remote}"
                    )));
                    return;
                };

                let handle = self.sockets.add(Self::tcp_socket());
                let result = {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.connect(
                        self.iface.context(),
                        to_endpoint(remote),
                        IpListenEndpoint {
                            addr: Some(local_addr),
                            port: local_port,
                        },
                    )
                };
                if let Err(err) = result {
                    self.sockets.remove(handle);
                    let _ = reply.send(Err(anyhow::anyhow!("connect {remote}: {err}")));
                    return;
                }
                self.registry.insert(id, handle);
                self.pending
                    .push_back(Pending::TcpConnect { id, handle, reply });
            }

            Command::TcpSend { id, data, reply } => match self.handle_of(id) {
                Some(handle) => self.pending.push_back(Pending::TcpSend {
                    handle,
                    total: data.len(),
                    data,
                    reply,
                }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such connection {id}")));
                }
            },

            Command::TcpRecv { id, max, reply } => match self.handle_of(id) {
                Some(handle) => self
                    .pending
                    .push_back(Pending::TcpRecv { handle, max, reply }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such connection {id}")));
                }
            },

            Command::TcpClose { id } => {
                if let Some(handle) = self.registry.remove(&id) {
                    self.sockets.get_mut::<tcp::Socket>(handle).close();
                    self.closing.push((handle, Self::now()));
                }
            }

            Command::TcpShutdown { id } => {
                if let Some(handle) = self.handle_of(id) {
                    self.sockets.get_mut::<tcp::Socket>(handle).close();
                }
            }

            Command::UdpClose { id } => {
                if let Some(handle) = self.registry.remove(&id) {
                    self.forget(handle);
                }
            }

            Command::UdpBind { reply } => {
                let id = self.next_id;
                self.next_id += 1;
                let local_port = self.next_ephemeral;
                self.next_ephemeral = if self.next_ephemeral >= 60_000 {
                    40_000
                } else {
                    self.next_ephemeral + 1
                };
                if self.iface.ipv4_addr().is_none() && self.iface.ipv6_addr().is_none() {
                    let _ = reply.send(Err(anyhow::anyhow!("the tunnel has no address")));
                    return;
                }
                // Issue 112: no local address, so that smoltcp takes the
                // source of the family of each destination. A bind to the
                // IPv4 address made a send to IPv6 panic in smoltcp.
                let handle = self.sockets.add(Self::udp_socket());
                let result = {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    socket.bind(IpListenEndpoint {
                        addr: None,
                        port: local_port,
                    })
                };
                if let Err(err) = result {
                    self.sockets.remove(handle);
                    let _ = reply.send(Err(anyhow::anyhow!("udp bind: {err}")));
                    return;
                }
                self.registry.insert(id, handle);
                let _ = reply.send(Ok((id, local_port)));
            }

            Command::UdpSend {
                id,
                data,
                to,
                reply,
            } => match self.handle_of(id) {
                Some(_) if !self.has_family(to.ip()) => {
                    let family = if to.is_ipv4() { "IPv4" } else { "IPv6" };
                    let _ = reply.send(Err(anyhow::anyhow!(
                        "the tunnel has no {family} address for {to}"
                    )));
                }
                Some(handle) => self.pending.push_back(Pending::UdpSend {
                    handle,
                    data,
                    to: to_endpoint(to),
                    reply,
                }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such socket {id}")));
                }
            },

            Command::UdpRecv { id, max, reply } => match self.handle_of(id) {
                Some(handle) => self
                    .pending
                    .push_back(Pending::UdpRecv { handle, max, reply }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such socket {id}")));
                }
            },
        }
    }

    /// Complete each pending operation that can complete. True when one did.
    fn progress(&mut self) -> bool {
        let before = self.pending.len();
        let mut still_waiting = VecDeque::with_capacity(self.pending.len());
        while let Some(op) = self.pending.pop_front() {
            match op {
                Pending::TcpConnect { id, handle, reply } if reply.is_closed() => {
                    // Issue 125: the caller gave up (a timeout): free the
                    // socket. Before, its SYN was sent again for ever.
                    self.registry.remove(&id);
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.closing.push((handle, Self::now()));
                }
                Pending::TcpConnect { id, handle, reply } => {
                    let state = self.sockets.get_mut::<tcp::Socket>(handle).state();
                    match state {
                        tcp::State::Established => {
                            let _ = reply.send(Ok(id));
                        }
                        tcp::State::Closed | tcp::State::TimeWait => {
                            self.registry.remove(&id);
                            self.sockets.remove(handle);
                            let _ = reply.send(Err(anyhow::anyhow!("connection refused or reset")));
                        }
                        _ => still_waiting.push_back(Pending::TcpConnect { id, handle, reply }),
                    }
                }
                Pending::TcpSend {
                    handle,
                    mut data,
                    total,
                    reply,
                } => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    if socket.can_send() {
                        match socket.send_slice(&data) {
                            Ok(sent) => {
                                data.drain(..sent);
                                if data.is_empty() {
                                    // Each byte of the command: the answer
                                    // is its length. Before, it was the last
                                    // part only, and the caller sent the
                                    // other parts again (an upload of more
                                    // than the send buffer was corrupt).
                                    let _ = reply.send(Ok(total));
                                } else {
                                    still_waiting.push_back(Pending::TcpSend {
                                        handle,
                                        data,
                                        total,
                                        reply,
                                    });
                                }
                            }
                            Err(err) => {
                                let _ = reply.send(Err(anyhow::anyhow!("tcp send: {err}")));
                            }
                        }
                    } else if !socket.may_send() {
                        let _ = reply.send(Err(anyhow::anyhow!("connection closed")));
                    } else {
                        still_waiting.push_back(Pending::TcpSend {
                            handle,
                            data,
                            total,
                            reply,
                        });
                    }
                }
                // A read whose caller gave up (a timeout) takes no data:
                // the data stays for the next read. Before, it was lost.
                Pending::TcpRecv { reply, .. } if reply.is_closed() => {}
                Pending::UdpRecv { reply, .. } if reply.is_closed() => {}
                Pending::TcpRecv { handle, max, reply } => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    if socket.can_recv() {
                        let mut buf = vec![0u8; max];
                        match socket.recv_slice(&mut buf) {
                            Ok(n) => {
                                buf.truncate(n);
                                let _ = reply.send(Ok(buf));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(anyhow::anyhow!("tcp recv: {err}")));
                            }
                        }
                    } else if !socket.may_recv() {
                        let _ = reply.send(Ok(Vec::new()));
                    } else {
                        still_waiting.push_back(Pending::TcpRecv { handle, max, reply });
                    }
                }
                Pending::UdpSend {
                    handle,
                    data,
                    to,
                    reply,
                } => {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    let len = data.len();
                    match socket.send_slice(&data, to) {
                        Ok(()) => {
                            let _ = reply.send(Ok(len));
                        }
                        Err(udp::SendError::BufferFull) => {
                            still_waiting.push_back(Pending::UdpSend {
                                handle,
                                data,
                                to,
                                reply,
                            });
                        }
                        Err(err) => {
                            let _ = reply.send(Err(anyhow::anyhow!("udp send: {err}")));
                        }
                    }
                }
                Pending::UdpRecv { handle, max, reply } => {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    if socket.can_recv() {
                        let mut buf = vec![0u8; max];
                        match socket.recv_slice(&mut buf) {
                            Ok((n, from)) => {
                                buf.truncate(n);
                                let _ = reply.send(Ok((buf, from_endpoint(from.endpoint))));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(anyhow::anyhow!("udp recv: {err}")));
                            }
                        }
                    } else {
                        still_waiting.push_back(Pending::UdpRecv { handle, max, reply });
                    }
                }
            }
        }
        let moved = still_waiting.len() < before;
        self.pending = still_waiting;
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // podssh: the TCP sockets of the stack have no Nagle.
    #[test]
    fn the_tcp_sockets_have_no_nagle() {
        assert!(!Driver::tcp_socket().nagle_enabled());
    }

    fn driver(config: &StackConfig) -> Driver {
        let mut device = LinkDevice::tunnel_bounded(TUNNEL_MTU, 16);
        let iface = build_iface(config, &mut device);
        Driver::new(iface, device)
    }

    fn bind(d: &mut Driver) -> u32 {
        let (reply, mut wait) = oneshot::channel();
        d.apply(Command::UdpBind { reply });
        wait.try_recv().unwrap().unwrap().0
    }

    /// Send one datagram and poll. The result of the send, and the packet
    /// that went out (if any).
    fn send(d: &mut Driver, id: u32, to: &str) -> (Option<Result<usize>>, Option<Vec<u8>>) {
        let (reply, mut wait) = oneshot::channel();
        d.apply(Command::UdpSend {
            id,
            data: b"query".to_vec(),
            to: to.parse().unwrap(),
            reply,
        });
        d.progress();
        d.iface.poll(Driver::now(), &mut d.device, &mut d.sockets);
        d.progress();
        (wait.try_recv().ok(), d.device.outbound().pop())
    }

    fn source_of(packet: &[u8]) -> IpAddr {
        match packet[0] >> 4 {
            4 => IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
            6 => IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
            v => panic!("IP version {v}"),
        }
    }

    // Issue 112: a datagram to IPv6 on a tunnel with an IPv4 address only
    // is refused. Before, smoltcp panicked ("IP version mismatch").
    #[test]
    fn udp_to_ipv6_on_an_ipv4_tunnel_is_refused() {
        let config = StackConfig::new("172.16.0.2".parse().unwrap());
        let mut d = driver(&config);
        let id = bind(&mut d);
        let (result, packet) = send(&mut d, id, "[2606:4700:4700::1111]:53");
        let err = result.expect("a reply").unwrap_err();
        assert!(format!("{err}").contains("no IPv6 address"), "{err}");
        assert!(packet.is_none());
        // The stack still works for IPv4.
        let (result, packet) = send(&mut d, id, "1.1.1.1:53");
        assert_eq!(result.expect("a reply").unwrap(), 5);
        assert_eq!(source_of(&packet.expect("a packet")), config.local);
    }

    // Issue 112: on a tunnel with both families, each datagram has the
    // source of the family of its destination.
    #[test]
    fn udp_on_a_dual_stack_tunnel_takes_the_source_of_each_family() {
        let v6: std::net::Ipv6Addr = "2606:4700:110:8a36::2".parse().unwrap();
        let config = StackConfig::new("172.16.0.2".parse().unwrap()).with_ipv6(Some(v6));
        let mut d = driver(&config);
        let id = bind(&mut d);
        let (result, packet) = send(&mut d, id, "[2606:4700:4700::1111]:53");
        assert_eq!(result.expect("a reply").unwrap(), 5);
        assert_eq!(source_of(&packet.expect("a packet")), IpAddr::V6(v6));
        let (result, packet) = send(&mut d, id, "1.1.1.1:53");
        assert_eq!(result.expect("a reply").unwrap(), 5);
        assert_eq!(source_of(&packet.expect("a packet")), config.local);
    }

    #[test]
    fn udp_to_ipv4_on_an_ipv6_tunnel_is_refused() {
        let config = StackConfig::new("2606:4700:110:8a36::2".parse().unwrap());
        let mut d = driver(&config);
        let id = bind(&mut d);
        let (result, packet) = send(&mut d, id, "1.1.1.1:53");
        let err = result.expect("a reply").unwrap_err();
        assert!(format!("{err}").contains("no IPv4 address"), "{err}");
        assert!(packet.is_none());
    }

    // Issue 112: a driver that panics closes the stack, so that Live opens
    // a new session.
    #[tokio::test]
    async fn a_panic_of_the_driver_closes_the_stack() {
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let notify = std::sync::Arc::new(Notify::new());
        let driver = tokio::spawn(async { panic!("a test panic of the driver") });
        let reason: Reason = Default::default();
        supervise(driver, closed.clone(), notify, reason.clone()).await;
        assert!(closed.load(std::sync::atomic::Ordering::Relaxed));
        // Issue 178: the cause is kept, and the first cause wins.
        assert_eq!(
            reason.lock().unwrap().as_deref(),
            Some("the userspace stack stopped with a panic")
        );
        mark_closed(&closed, &reason, "later".into());
        assert_eq!(
            reason.lock().unwrap().as_deref(),
            Some("the userspace stack stopped with a panic")
        );

        let (cmd, cmd_rx) = mpsc::channel(1);
        let stack = WarpStack {
            cmd,
            notify: std::sync::Arc::new(Notify::new()),
            closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reason: Default::default(),
            local: "172.16.0.2".parse().unwrap(),
            renew: None,
        };
        assert!(!stack.is_closed());
        drop(cmd_rx);
        assert!(stack.is_closed());
        assert!(stack.udp_bind().await.is_err());
    }

    /// A peer on the other side of the tunnel: a smoltcp node at
    /// 198.51.100.7 with one TCP socket that listens on port 80.
    struct Peer {
        device: LinkDevice,
        iface: Interface,
        sockets: SocketSet<'static>,
        tcp: SocketHandle,
    }

    const PEER: &str = "198.51.100.7:80";

    fn peer() -> Peer {
        let mut device = LinkDevice::tunnel(TUNNEL_MTU);
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::v4(198, 51, 100, 7), 24)).ok();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(198, 51, 100, 1))
            .ok();
        let mut sockets = SocketSet::new(Vec::new());
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
        );
        socket.listen(80).unwrap();
        let tcp = sockets.add(socket);
        Peer {
            device,
            iface,
            sockets,
            tcp,
        }
    }

    /// Move the packets of each side to the other, and poll both, `n` times.
    fn pump(d: &mut Driver, p: &mut Peer, n: usize) {
        for _ in 0..n {
            let now = Driver::now();
            d.iface.poll(now, &mut d.device, &mut d.sockets);
            d.progress();
            d.reap(now);
            while let Some(packet) = d.device.outbound().pop() {
                p.device.inbound().push(packet);
            }
            p.iface.poll(now, &mut p.device, &mut p.sockets);
            while let Some(packet) = p.device.outbound().pop() {
                d.device.inbound().push(packet);
            }
        }
    }

    fn connect(d: &mut Driver, p: &mut Peer) -> u32 {
        let (reply, mut wait) = oneshot::channel();
        d.apply(Command::TcpConnect {
            remote: PEER.parse().unwrap(),
            reply,
        });
        for _ in 0..50 {
            pump(d, p, 1);
            if let Ok(id) = wait.try_recv() {
                return id.unwrap();
            }
        }
        panic!("no connection");
    }

    fn recv(d: &mut Driver, p: &mut Peer, id: u32) -> Vec<u8> {
        let (reply, mut wait) = oneshot::channel();
        d.apply(Command::TcpRecv {
            id,
            max: 1024,
            reply,
        });
        for _ in 0..50 {
            pump(d, p, 1);
            if let Ok(data) = wait.try_recv() {
                return data.unwrap();
            }
        }
        panic!("no data");
    }

    fn v4_driver() -> Driver {
        driver(&StackConfig::new("172.16.0.2".parse().unwrap()))
    }

    // Issue 125: a closed connection frees its socket. Before, each socket
    // stayed in the stack for the life of the session.
    #[test]
    fn a_closed_connection_frees_its_socket() {
        let mut d = v4_driver();
        let mut p = peer();
        for round in 0..3 {
            let id = connect(&mut d, &mut p);
            let peer_socket = p.sockets.get_mut::<tcp::Socket>(p.tcp);
            peer_socket.send_slice(b"hello").unwrap();
            peer_socket.close();
            assert_eq!(recv(&mut d, &mut p, id), b"hello");
            d.apply(Command::TcpClose { id });
            pump(&mut d, &mut p, 30);
            assert_eq!(d.socket_count(), 0, "round {round}");
            assert!(d.registry.is_empty());
            // The peer listens again for the next round.
            let peer_socket = p.sockets.get_mut::<tcp::Socket>(p.tcp);
            peer_socket.abort();
            pump(&mut d, &mut p, 2);
            p.sockets.get_mut::<tcp::Socket>(p.tcp).listen(80).unwrap();
        }
    }

    // A send of more than the send buffer: the answer is the whole length,
    // and the peer gets each byte once, in order. Before, the answer was the
    // last part only, and the proxy sent the parts before it again (an
    // upload through warp proxy gave "bad record mac").
    #[test]
    fn a_large_send_is_answered_with_its_length() {
        let mut d = v4_driver();
        let mut p = peer();
        let id = connect(&mut d, &mut p);
        let data: Vec<u8> = (0..(TCP_BUFFER * 2 + 12_345) as u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let (reply, mut wait) = oneshot::channel();
        d.apply(Command::TcpSend {
            id,
            data: data.clone(),
            reply,
        });
        let mut got = Vec::with_capacity(data.len());
        let mut answer = None;
        for _ in 0..20_000 {
            pump(&mut d, &mut p, 1);
            let peer_socket = p.sockets.get_mut::<tcp::Socket>(p.tcp);
            let mut buf = [0u8; 64 * 1024];
            while let Ok(n) = peer_socket.recv_slice(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            if answer.is_none() {
                if let Ok(result) = wait.try_recv() {
                    answer = Some(result.unwrap());
                }
            }
            if answer.is_some() && got.len() == data.len() {
                break;
            }
        }
        assert_eq!(answer, Some(data.len()));
        assert_eq!(got.len(), data.len());
        assert!(got == data, "the peer got other bytes");
    }

    // Issue 125: a shutdown sends a FIN, and the answer of the peer still
    // comes back.
    #[test]
    fn a_shutdown_reaches_the_peer_and_the_answer_comes_back() {
        let mut d = v4_driver();
        let mut p = peer();
        let id = connect(&mut d, &mut p);
        d.apply(Command::TcpShutdown { id });
        pump(&mut d, &mut p, 10);
        let peer_socket = p.sockets.get_mut::<tcp::Socket>(p.tcp);
        assert!(!peer_socket.may_recv(), "the peer has the FIN");
        peer_socket.send_slice(b"answer").unwrap();
        assert_eq!(recv(&mut d, &mut p, id), b"answer");
    }

    // Issue 125: a connect that the caller gave up frees its socket.
    #[test]
    fn a_cancelled_connect_frees_its_socket() {
        let mut d = v4_driver();
        let (reply, wait) = oneshot::channel();
        d.apply(Command::TcpConnect {
            remote: "192.0.2.1:443".parse().unwrap(),
            reply,
        });
        assert_eq!(d.socket_count(), 1);
        drop(wait);
        for _ in 0..3 {
            let now = Driver::now();
            d.iface.poll(now, &mut d.device, &mut d.sockets);
            d.progress();
            d.reap(now);
        }
        assert_eq!(d.socket_count(), 0);
        assert!(d.pending.is_empty());
    }

    #[test]
    fn a_udp_close_frees_its_socket() {
        let mut d = v4_driver();
        let id = bind(&mut d);
        assert_eq!(d.socket_count(), 1);
        d.apply(Command::UdpClose { id });
        assert_eq!(d.socket_count(), 0);
    }

    // Issue 125: the last clone of a UdpConn sends the close.
    #[test]
    fn the_last_clone_of_a_udp_socket_closes_it() {
        let (cmd, mut rx) = mpsc::channel(4);
        let notify = std::sync::Arc::new(Notify::new());
        let conn = UdpConn {
            id: 7,
            local: "172.16.0.2:40000".parse().unwrap(),
            cmd: cmd.clone(),
            notify: notify.clone(),
            _close: std::sync::Arc::new(CloseOnDrop {
                cmd,
                notify,
                close: Some(Command::UdpClose { id: 7 }),
            }),
        };
        let clone = conn.clone();
        drop(conn);
        assert!(rx.try_recv().is_err());
        drop(clone);
        assert!(matches!(rx.try_recv(), Ok(Command::UdpClose { id: 7 })));
    }

    // Issue 125: when the session is dead, a pending read fails. Before, it
    // waited for ever.
    #[test]
    fn a_dead_session_fails_the_pending_operations() {
        let mut d = v4_driver();
        let mut p = peer();
        let id = connect(&mut d, &mut p);
        let (reply, mut wait) = oneshot::channel();
        d.apply(Command::TcpRecv { id, max: 10, reply });
        d.progress();
        assert!(wait.try_recv().is_err(), "the read waits");
        d.fail_all("the MASQUE session is closed");
        let err = wait.try_recv().unwrap().unwrap_err();
        assert!(format!("{err}").contains("closed"), "{err}");
        assert!(d.pending.is_empty());
    }

    #[test]
    fn an_assigned_address_is_checked() {
        let ours: Vec<IpAddr> = vec!["172.16.0.2".parse().unwrap()];
        assert!(log_assigned(&[("172.16.0.2".parse().unwrap(), 32)], &ours));
        assert!(!log_assigned(&[("172.16.0.9".parse().unwrap(), 32)], &ours));
    }

    // Issue 111: a bad value is an error, not the default.
    #[test]
    fn the_congestion_controller() {
        use smoltcp::socket::tcp::CongestionControl;
        assert_eq!(parse_cc("none").unwrap(), CongestionControl::None);
        assert_eq!(parse_cc(" Reno ").unwrap(), CongestionControl::Reno);
        assert_eq!(parse_cc("cubic").unwrap(), CongestionControl::Cubic);
        let err = parse_cc("bbr").unwrap_err();
        assert_eq!(crate::exit::code_of(&err), 78);
        // No --cc and no variable: none, as before smoltcp 0.12.
        if std::env::var(CC_VARIABLE).is_err() {
            assert_eq!(
                Driver::tcp_socket().congestion_control(),
                CongestionControl::None
            );
        }
    }

    #[test]
    fn the_tcp_burst_variable_is_checked() {
        assert_eq!(parse_tcp_burst(None).unwrap(), TCP_BURST_DEFAULT);
        assert_eq!(parse_tcp_burst(Some("none")).unwrap(), None);
        assert_eq!(parse_tcp_burst(Some(" 8 ")).unwrap(), Some(8));
        assert_eq!(parse_tcp_burst(Some("430")).unwrap(), Some(430));
        for bad in ["", "0", "abc", "-1", "431", "999999999", "8 segments"] {
            let err = parse_tcp_burst(Some(bad)).unwrap_err();
            assert_eq!(crate::exit::code_of(&err), 78, "{bad:?}");
            assert!(format!("{err}").contains(TCP_BURST_VARIABLE), "{err}");
        }
    }

    #[test]
    fn a_tcp_socket_has_a_timeout_and_a_keepalive() {
        let socket = Driver::tcp_socket();
        assert_eq!(socket.timeout(), Some(TCP_TIMEOUT.into()));
        assert_eq!(socket.keep_alive(), Some(TCP_KEEPALIVE.into()));
    }
}
