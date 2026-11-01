//! A QUIC socket whose datagrams travel through the WARP session.
//!
//! The Cloudflare edge's preferred transport is QUIC on UDP 7844. WARP carries
//! UDP, so the only missing piece is a [`quinn::AsyncUdpSocket`] backed by the
//! userspace stack instead of a kernel socket. This module is that adapter.
//!
//! # Why not a kernel socket
//!
//! A sealed host can refuse `bind(2)` on `AF_INET` and `connect(2)` to every
//! destination, including loopback. The userspace stack already owns a UDP
//! socket inside the tunnel's address space, so the adapter moves datagrams
//! between quinn and that socket and the kernel is never asked.
//!
//! # Shape
//!
//! * [`WarpUdpSocket::try_send`] pushes into a bounded channel; one task writes
//!   each datagram to the userspace socket.
//! * a second task reads from that socket into a queue;
//!   [`WarpUdpSocket::poll_recv`] pops from the queue.
//! * the send poller waits on a notification the writer fires after each
//!   datagram, so a full channel is backpressure rather than a spin.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use futures::task::AtomicWaker;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, EndpointConfig, UdpPoller};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use super::ip::{UdpConn, WarpStack};

/// Datagrams that may sit in the send queue before quinn is told to wait.
const SEND_QUEUE: usize = 1024;
/// Largest datagram read from the userspace socket.
const MAX_DATAGRAM: usize = 65_535;

/// Datagrams waiting for `poll_recv`, with the peer each came from.
type Inbound = Arc<Mutex<VecDeque<(Vec<u8>, SocketAddr)>>>;

/// A quinn-compatible UDP socket over the WARP stack.
pub struct WarpUdpSocket {
    out: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    inbound: Inbound,
    recv_waker: Arc<AtomicWaker>,
    send_ready: Arc<Notify>,
    local: SocketAddr,
    sent: AtomicU64,
    received: AtomicU64,
    closed: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for WarpUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WarpUdpSocket")
            .field("local", &self.local)
            .field("sent", &self.sent.load(Ordering::Relaxed))
            .field("received", &self.received.load(Ordering::Relaxed))
            .finish()
    }
}

impl WarpUdpSocket {
    fn new(udp: UdpConn, local: SocketAddr) -> Arc<Self> {
        let (out, mut out_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(SEND_QUEUE);
        let inbound: Inbound = Arc::new(Mutex::new(VecDeque::new()));
        let recv_waker = Arc::new(AtomicWaker::new());
        let send_ready = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        let writer = {
            let udp = udp.clone();
            let send_ready = send_ready.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                while let Some((to, data)) = out_rx.recv().await {
                    if udp.send_to(data, to).await.is_err() {
                        closed.store(true, Ordering::Relaxed);
                        break;
                    }
                    send_ready.notify_waiters();
                }
            })
        };

        let reader = {
            let udp = udp.clone();
            let inbound = inbound.clone();
            let recv_waker = recv_waker.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                loop {
                    match udp.recv_from(MAX_DATAGRAM).await {
                        Ok((data, from)) => {
                            inbound.lock().unwrap().push_back((data, from));
                            recv_waker.wake();
                        }
                        Err(_) => {
                            closed.store(true, Ordering::Relaxed);
                            recv_waker.wake();
                            break;
                        }
                    }
                }
            })
        };

        Arc::new(Self {
            out,
            inbound,
            recv_waker,
            send_ready,
            local,
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            closed,
            tasks: vec![writer, reader],
        })
    }
}

impl Drop for WarpUdpSocket {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl AsyncUdpSocket for WarpUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SendPoller {
            out: self.out.clone(),
            ready: self.send_ready.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        match self
            .out
            .try_send((transmit.destination, transmit.contents.to_vec()))
        {
            Ok(()) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if self.closed.load(Ordering::Relaxed) {
            // The userspace socket is gone; receiving can never succeed again.
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        loop {
            let next = self.inbound.lock().unwrap().pop_front();
            match next {
                Some((data, from)) => {
                    let len = data.len().min(bufs[0].len());
                    bufs[0][..len].copy_from_slice(&data[..len]);
                    meta[0] = RecvMeta {
                        addr: from,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    self.received.fetch_add(1, Ordering::Relaxed);
                    return Poll::Ready(Ok(1));
                }
                None => {
                    // Register before the re-check, so a datagram that arrives
                    // between the pop and the registration still wakes us.
                    self.recv_waker.register(cx.waker());
                    if self.inbound.lock().unwrap().is_empty() {
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// The write-readiness half of the socket.
#[derive(Debug)]
struct SendPoller {
    out: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ready: Arc<Notify>,
}

impl UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.out.capacity() > 0 {
            return Poll::Ready(Ok(()));
        }
        let notified = this.ready.notified();
        tokio::pin!(notified);
        match notified.poll(cx) {
            Poll::Ready(()) => Poll::Ready(Ok(())),
            // A send may have drained the queue between the capacity check and
            // the registration. Re-check before parking.
            Poll::Pending if this.out.capacity() > 0 => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Build a QUIC endpoint whose only socket is the WARP session.
///
/// The endpoint dials the real edge address. Its datagrams leave the host on
/// TCP 443 inside the MASQUE session and arrive at the edge on 7844, so this
/// host never opens a connection to 7844.
pub async fn endpoint(stack: &WarpStack) -> Result<quinn::Endpoint> {
    let udp = stack
        .udp_bind()
        .await
        .context("binding a UDP socket inside the WARP session")?;
    let local = udp.local_addr();
    let socket = WarpUdpSocket::new(udp, local);
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|err| anyhow::anyhow!("building the QUIC endpoint: {err}"))?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// The TLS and transport configuration the edge expects.
fn client_config() -> Result<quinn::ClientConfig> {
    use crate::cloudflare::{CF_EDGE_ROOTS_PEM, QUIC_ALPN as ALPN};
    let tls = crate::trust::client_config(&[CF_EDGE_ROOTS_PEM], &[ALPN])?;

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| anyhow::anyhow!("rustls to quinn: {err}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    // The tunnel carries packets of TUNNEL_MTU bytes. 1232 fits an IPv6 and
    // UDP header in that; MTU discovery stops at the IPv4 size.
    let ip_udp_v4 = 28;
    let mut transport = crate::cloudflare::quic::transport_config(1232);
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    discovery.upper_bound((super::ip::TUNNEL_MTU - ip_udp_v4) as u16);
    transport.mtu_discovery_config(Some(discovery));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_poller_reports_ready_when_the_queue_has_room() {
        let (out, _rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(4);
        let mut poller = SendPoller {
            out,
            ready: Arc::new(Notify::new()),
        };
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut poller).poll_writable(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }
}
