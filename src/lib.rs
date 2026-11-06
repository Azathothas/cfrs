//! podnet — expose anything on the public Electrosphere through Cloudflare
//! tunnels, from Rust.
//!
//! The crate is usable as a library:
//!
//! ```no_run
//! use podnet::{Service, Tunnel};
//!
//! # async fn run() -> anyhow::Result<()> {
//! let handle = Tunnel::quick()
//!     .service(Service::parse("http://127.0.0.1:8080")?)
//!     .build()?
//!     .start()
//!     .await?;
//! println!("{:?}", handle.url());
//! handle.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! It speaks the Cloudflare quick-tunnel protocol natively (QUIC + Cap'n Proto
//! RPC, no `cloudflared` subprocess) and also accepts named-tunnel tokens.

/// `println!`, `print!` and `eprintln!` that drop a failed write (issue
/// 74). The std macros panic when the write fails: a detached instance
/// writes to its log, and a full disk or a closed stream must not stop it.
/// A command that only prints keeps the default action of SIGPIPE.
macro_rules! println {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stdout(), $($arg)*);
    }};
}

#[allow(unused_macros)]
macro_rules! print {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::write!(::std::io::stdout(), $($arg)*);
    }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr(), $($arg)*);
    }};
}

/// `fetch_update` of an atomic with a loop of `compare_exchange_weak`
/// (#214: `fetch_update` is deprecated in a later Rust; `try_update`
/// needs a newer Rust than the MSRV). Gives the old value, or `Err` with
/// the value when `f` gives `None`.
macro_rules! update_atomic {
    ($atomic:expr, $f:expr) => {{
        let atomic = $atomic;
        let f = $f;
        let mut now = atomic.load(::std::sync::atomic::Ordering::SeqCst);
        loop {
            match f(now) {
                None => break Err(now),
                Some(next) => {
                    match atomic.compare_exchange_weak(
                        now,
                        next,
                        ::std::sync::atomic::Ordering::SeqCst,
                        ::std::sync::atomic::Ordering::SeqCst,
                    ) {
                        Ok(old) => break Ok(old),
                        Err(seen) => now = seen,
                    }
                }
            }
        }
    }};
}

pub mod agent;
pub mod autostart;
pub mod bug_report;
pub mod cloudflare;
pub mod config;
pub mod connect;
pub mod decisions;
pub mod detach;
pub mod doctor;
pub mod edge_discovery;
pub mod edge_h2;
pub mod egress;
pub mod exit;
pub mod feature;
pub mod fetch;
#[doc(hidden)]
pub mod fuzzing;
pub mod gate;
pub mod hop;
pub mod ingress;
pub mod instances;
pub mod manual;
pub mod metrics;
pub mod net;
pub mod origin;
pub mod ports;
pub mod preflight;
pub mod proxy;
pub mod qr;
pub mod quicktunnel;
pub mod race;
pub mod relay;
pub mod relay_pool;
pub mod relay_reverse;
pub mod report;
pub mod resolve;
pub mod rlimit;
pub mod service;
pub mod services;
pub mod share;
pub mod state;
pub mod status;
#[cfg(test)]
#[path = "../tests/test_host/mod.rs"]
mod test_host;
pub mod transport;
pub mod trust;
pub mod tunnel;
pub mod udp;
pub mod update;
pub mod util;
pub mod vnet;
pub mod warp;
pub mod ws;
pub mod ws_relay;
pub mod yaml;

pub use config::{Config, Credentials, Protocol, ReconnectPolicy, Transport};
pub use egress::Proxy;
pub use ingress::{ForwardTarget, Ingress, IngressRule, OriginOptions, Service};
pub use metrics::{Metrics, MetricsSnapshot};
pub use share::{ShareApp, ShareConfig, ShareControl, ShareMode};
pub use tunnel::{Tunnel, TunnelBuilder, TunnelHandle, Verified};
pub use vnet::{NetStack, VirtAddr, VirtualSubnet};
pub use warp::{Identity, MasqueSession, StackConfig, WarpClient, WarpStack};
pub use ws::LocalSpec;

/// Install the rustls crypto provider. Called automatically by
/// [`Tunnel::start`]; call it early if you build TLS yourself.
pub fn init_crypto() {
    net::init_crypto();
}
