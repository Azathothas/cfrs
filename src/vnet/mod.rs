//! A userspace virtual network for sealed sandboxes.
//!
//! This module implements the design in `docs/virtual-network.md`:
//! a private
//! IPv4/IPv6 address space that exists without a network namespace, without a
//! TUN/TAP device, and without `CAP_NET_ADMIN`. Two layers compose:
//!
//! 1. **Socket interposition** ([`shim`]) — an `LD_PRELOAD` library that
//!    rewrites a program's `AF_INET`/`AF_INET6` sockets to `AF_UNIX` abstract
//!    sockets, encoding the intended `IP:port` in the socket name
//!    ([`addr`]). The kernel only ever sees `AF_UNIX`.
//! 2. **A userspace IP stack** ([`stack`]) — a `smoltcp` interface whose link
//!    layer is an in-process packet queue ([`device`]) or a tunnel. It owns
//!    the addresses, the TCP and UDP state machines, and the routing.
//!
//! Either layer works alone: two interposed programs on the same host talk
//! over abstract names with no stack, and the stack gives an addressed
//! network that reaches a remote peer. Together they give addressed, routed,
//! unmodified programs.
//!
//! # Layers
//!
//! * [`addr`] — `podnet-vnet/<family>/<address>/<port>` names and the `10.66.0.0/24`
//!   / `fd00:66::/64` plan.
//! * [`framing`] — length-prefixed packet framing over a byte stream.
//! * [`device`] — in-process link devices: queue, tunnel-backed, capture,
//!   fault injection and record/replay.
//! * [`stack`] — the `smoltcp` interface, listeners, connectors, UDP, and a
//!   monotonic poll loop.
//! * [`policy`] — per-address allow/deny, evaluated at connect time.
//! * [`dns`] — a virtual resolver at the gateway for names in the network.
//! * [`socks`] — SOCKS5 and HTTP `CONNECT` for programs that cannot be
//!   interposed.
//! * [`control`] — the shim/stack control protocol.
//! * [`shim`] — build and locate the `LD_PRELOAD` library.
//!
//! The CLI exposes it as `podnet net`; see the `net` command of the binary.

pub mod addr;
pub mod control;
pub mod device;
pub mod dns;
pub mod doctor;
pub mod framing;
pub mod policy;
pub mod proxy;
pub mod record;
pub mod shim;
pub mod stack;
pub mod switch;
pub mod tailscale_ssh;

pub use podnet_netns::{socks, tailscale, upstream};

pub use addr::{Family, VirtAddr, VirtualSubnet};
pub use control::{ControlMessage, ControlOp};
pub use device::{DeviceStats, LinkDevice, TunnelDevice};
pub use podnet_netns::tailscale::{Dialer, TailscaleProxy};
pub use podnet_netns::upstream::{Proxy as UpstreamProxy, ProxyKind, Rule, Upstream};
pub use policy::{Acl, AclAction, AclRule};
pub use proxy::{handle_connection, ProxyListen};
pub use record::{PcapFile, RecordedPacket, Recorder, Replayer};
pub use stack::{Clock, NetStack, StackConfig, StackEvent, TcpStream, UdpSocket};
pub use tailscale_ssh::{LocalUser, Shims};

// #215: the stack owns more than the 2 addresses that smoltcp allows by
// default (the local address, the gateway, their IPv6 counterparts, each
// address of a virtual listener). .cargo/config.toml sets the limit for a
// build in the repository; a build without it (cargo install, a crate that
// depends on podnet) fails here, not later with lost addresses.
const _: () = assert!(
    smoltcp::config::IFACE_MAX_ADDR_COUNT >= 8,
    "build podnet with the environment variable SMOLTCP_IFACE_MAX_ADDR_COUNT=8 (.cargo/config.toml of the repository sets it)"
);
