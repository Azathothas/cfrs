//! A Cloudflare quick tunnel whose edge connection is carried by WARP.
//!
//! The edge answers on port 7844 and nowhere else, so a host that filters that
//! port cannot tunnel directly. This module closes the gap without a local
//! relay: the QUIC client is given a socket that writes its datagrams into the
//! WARP MASQUE session, which leaves the host on TCP 443 and is delivered to
//! the edge on 7844 at Cloudflare. The host never opens a connection to 7844,
//! and no kernel UDP socket is needed either.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use cfrs::warp::{start_quick_tunnel, WarpClient};
//!
//! let client = WarpClient::register().await?;
//! let stack = client.connect().await?;
//! // The origin is a local HTTP server; visitors arrive on 443 at the edge.
//! let tunnel = start_quick_tunnel(stack, 8080).await?;
//! println!("{}", tunnel.url);
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cfrs_edge::edge::IpVersionFilter;
use cfrs_edge::{api, pool, quic_dial, rpc, supervisor};
use tokio::sync::oneshot;

use super::ip::WarpStack;

/// How long to wait for the QUIC handshake through WARP before giving up.
const WARP_DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// A running quick tunnel.
pub struct QuickTunnelHandle {
    /// The public `https://<name>.trycloudflare.com` URL.
    pub url: String,
    /// The tunnel id the edge assigned.
    pub tunnel_id: uuid::Uuid,
    /// The edge colo the connection landed in.
    pub location: String,
    /// The real edge address the QUIC connection was carried to.
    pub edge: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    metrics: supervisor::SupervisorMetrics,
    /// Kept alive for the tunnel's lifetime. Dropping either tears down the
    /// WARP session and the QUIC endpoint the edge connection rides on.
    _stack: WarpStack,
    _endpoint: quinn::Endpoint,
}

impl QuickTunnelHandle {
    /// Stream, byte-in and byte-out counters since the tunnel started.
    pub fn metrics(&self) -> (u64, u64, u64) {
        self.metrics.snapshot()
    }

    /// Close the tunnel.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Provision a quick tunnel and carry its edge connection over `stack`.
///
/// `local_port` is the origin the edge should reach: visitor streams are
/// proxied to `127.0.0.1:local_port`, exactly as `cloudflared --url` does.
pub async fn start_quick_tunnel(stack: WarpStack, local_port: u16) -> Result<QuickTunnelHandle> {
    // 1. Anonymous provisioning. Reachable on 443 through the proxy.
    let tunnel = api::request_tunnel(api::DEFAULT_SERVICE_URL, api::DEFAULT_USER_AGENT)
        .await
        .context("requesting a quick tunnel")?;
    let url = if tunnel.hostname.starts_with("https://") {
        tunnel.hostname.clone()
    } else {
        format!("https://{}", tunnel.hostname)
    };
    let tunnel_id = uuid::Uuid::parse_str(&tunnel.id).context("the tunnel id is not a UUID")?;

    // 2. Find the real edge. The SRV record resolves to an address on 7844,
    //    which is the point: it is resolved here but dialled from inside WARP.
    let edges = crate::edge_discovery::discover(IpVersionFilter::V4Only)
        .await
        .context("discovering the tunnel edge")?;
    let Some(first) = edges.first() else {
        bail!("edge discovery returned no addresses");
    };
    let real_edge = first.socket();

    // 3. A QUIC endpoint whose socket is the WARP session.
    let endpoint = super::quic::endpoint(&stack)
        .await
        .context("building the QUIC socket inside the WARP session")?;
    let conn = tokio::time::timeout(WARP_DIAL_TIMEOUT, quic_dial::dial_any(&endpoint, &edges))
        .await
        .context("the QUIC handshake through WARP timed out")?
        .context("the QUIC handshake through WARP failed")?;

    // 4. Register the tunnel on that connection.
    let auth = rpc::TunnelAuth {
        account_tag: tunnel.account_tag.clone(),
        tunnel_secret: tunnel.secret.clone(),
    };
    let options =
        rpc::ConnectionOptions::default_for_quick_tunnel(cfrs_edge::manager::CLIENT_VERSION);
    let (details, control) = rpc::register_connection(&conn, &auth, tunnel_id, 0, &options)
        .await
        .context("registering the tunnel on the edge")?;

    // 5. Serve visitor streams to the origin.
    let metrics = supervisor::SupervisorMetrics::default();
    let pool = Arc::new(pool::Pool::new(local_port));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    {
        let conn = conn.clone();
        let metrics = metrics.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            let _ = supervisor::run(conn, local_port, metrics, pool, shutdown_rx).await;
        });
    }

    // Keep the control session alive for the tunnel's lifetime.
    tokio::spawn(async move {
        let _control = control;
        std::future::pending::<()>().await;
    });

    Ok(QuickTunnelHandle {
        url,
        tunnel_id,
        location: details.location,
        edge: real_edge,
        shutdown: Some(shutdown_tx),
        metrics,
        _stack: stack,
        _endpoint: endpoint,
    })
}
