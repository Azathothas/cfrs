//! podnet-netns: run a program with all its network traffic sent through a
//! SOCKS5 or HTTP proxy. No `LD_PRELOAD` is necessary.
//!
//! The kernel enforces the redirection, so static binaries, Go binaries and
//! programs that do not use libc `connect(3)` get the same treatment.
//!
//! Two backends are available:
//!
//! * `netns`: the child gets a new user and network namespace. A TUN device is
//!   its only interface. A `smoltcp` stack on the host side of the TUN sends
//!   each flow to the upstream proxy. This backend needs unprivileged user
//!   namespaces and `/dev/net/tun`.
//! * `seccomp`: a `SECCOMP_RET_USER_NOTIF` filter stops the socket system
//!   calls of the child. The supervisor answers them and gives the child
//!   connected descriptors with `SECCOMP_IOCTL_NOTIF_ADDFD`. This backend needs
//!   only seccomp.
//!
//! ```text
//!   podnet pod [OPTIONS] -- PROGRAM
//!     |
//!     +- child:  namespace or seccomp filter, then exec PROGRAM
//!     |
//!     +- parent: fake-IP DNS, routing rules, SOCKS5/HTTP/tailnet upstream
//! ```
//!
//! The library also gives the parts that other programs use: the upstream
//! client ([`upstream`]), the proxy server codec ([`socks`]), the DNS codec
//! ([`dns`]), listen addresses ([`listen`]) and the tailnet dialer
//! ([`tailscale`]).
//!
//! Use [`main_with_args`] to run the full command line from another program.

pub mod dns;
pub mod listen;
pub mod raw;
pub mod socks;
pub mod tailscale;
pub mod upstream;

mod cli;
mod connect;
mod dgram;
mod doctor;
mod fakedns;
mod fdtable;
mod frontdoor;
mod handoff;
mod icmp;
mod inbox;
mod netns;
mod recvmmsg;
mod seccomp;
mod socket;
mod sockopt;

pub use cli::{set_program_name, usage, usage_for};
pub use listen::ProxyListen;
pub use upstream::{Net, Proxy, ProxyKind, Rule, RuleMatch, Upstream};

/// The common imports of the internal modules.
#[allow(unused_imports)]
mod prelude {
    pub(crate) use std::collections::{HashMap, VecDeque};
    pub(crate) use std::ffi::CString;
    pub(crate) use std::io::Write;
    pub(crate) use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    pub(crate) use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    pub(crate) use std::sync::Arc;
    pub(crate) use std::time::Duration;

    pub(crate) use anyhow::{bail, Context, Result};
    pub(crate) use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
    pub(crate) use smoltcp::phy::{
        ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
    };
    pub(crate) use smoltcp::socket::tcp;
    pub(crate) use smoltcp::socket::udp;
    pub(crate) use smoltcp::time::Instant as SmolInstant;
    pub(crate) use smoltcp::wire::{
        HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address,
    };

    pub(crate) use crate::upstream::{
        connect_upstream, connect_upstream_async, dial_proxy, select_chain, socks5_udp_associate,
        within_timeout, wrap_udp, Proxy, ProxyKind, Rule, RuleMatch, Upstream,
    };

    pub(crate) use crate::cli::*;
    pub(crate) use crate::dgram::*;
    pub(crate) use crate::doctor::*;
    pub(crate) use crate::fakedns::*;
    pub(crate) use crate::fdtable::Key;
    pub(crate) use crate::frontdoor::*;
    pub(crate) use crate::netns::*;
    pub(crate) use crate::seccomp::*;
}

#[allow(unused_imports)]
use prelude::*;

/// Register a copy (`dup`) of `fd` with the tokio reactor, for readable
/// events. The copy is closed when the `AsyncFd` is dropped; `fd` stays open.
pub(crate) fn readable_copy(fd: RawFd) -> std::io::Result<tokio::io::unix::AsyncFd<OwnedFd>> {
    let copy = unsafe { libc::dup(fd) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `copy` is a new open descriptor that nothing else owns.
    let owned = unsafe { OwnedFd::from_raw_fd(copy) };
    // SAFETY: the OwnedFd holds `copy` open and returns it from as_raw_fd
    // until the AsyncFd drops it.
    unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(owned, tokio::io::Interest::READABLE)
    }
    .map_err(std::io::Error::from)
}

/// The exit code of a usage error (sysexits `EX_USAGE`).
pub const USAGE: i32 = 64;

/// Run the command line of `podnet pod` with `argv` (without the program name).
/// Return the exit status.
pub fn main_with_args(argv: &[String]) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("podnet-netns: {e:#}");
            return USAGE;
        }
    };
    if args.doctor {
        return doctor(args.doctor_json);
    }
    if args.serve.is_some() {
        if args.proxies.is_empty() {
            eprintln!("podnet-netns: --serve needs at least one -x upstream");
            return USAGE;
        }
        let listen = args.serve.clone().unwrap();
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("podnet-netns: {e:#}");
                return EXIT_NO_BACKEND;
            }
        };
        let outcome = runtime.block_on(serve_front_door(
            listen,
            args.proxies.clone(),
            args.rules.clone(),
            args.verbose,
        ));
        match outcome {
            Ok(()) => return 0,
            Err(e) => {
                eprintln!("podnet-netns: {e:#}");
                return EXIT_NO_BACKEND;
            }
        }
    }
    // Issue 95: no -x, no proxy variable and no rule is a usage mistake
    // (exit 64), not a host that has no backend (exit 3).
    if args.proxies.is_empty() && args.rules.is_empty() {
        eprintln!(
            "podnet-netns: no proxy: give -x PROXY, or set ALL_PROXY, HTTPS_PROXY or HTTP_PROXY"
        );
        return USAGE;
    }
    warn_unreachable(&args.proxies);
    // Inbound listeners exist on the seccomp backend only (issue 69).
    if args.inbound_dir_given && matches!(args.backend, BackendKind::Netns) {
        eprintln!("podnet-netns: --inbound-dir works with --backend seccomp only");
        return USAGE;
    }
    let warn_inbound = |backend: &str| {
        if args.inbound_dir_given {
            warn(&format!(
                "warning: the {backend} backend has no inbound listeners; --inbound-dir is not used (give --backend seccomp)"
            ));
        }
    };
    let name_backend = args.name_backend;
    let netns = |args: Args| {
        name_the_backend(name_backend, BackendKind::Netns);
        run(args)
    };
    let seccomp = |args: Args| {
        name_the_backend(name_backend, BackendKind::Seccomp);
        run_seccomp(args)
    };
    let result = match args.backend {
        BackendKind::Netns => netns(args),
        BackendKind::Seccomp => seccomp(args),
        BackendKind::Auto if args.prefer_udp && doctor::probe_seccomp_notif().ok => seccomp(args),
        BackendKind::Auto => {
            // The netns backend needs unshare and a TUN; without them the
            // seccomp backend is the only thing that can work.
            if probe_unshare(libc::CLONE_NEWNET).ok
                || probe_unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET).ok
            {
                warn_inbound("netns");
                netns(args)
            } else {
                seccomp(args)
            }
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("podnet-netns: {e:#}");
            EXIT_NO_BACKEND
        }
    }
}

/// The proxy variables that a program in the pod does not get: the pod is
/// its egress, and a program that used them would send to a host proxy that
/// the pod cannot reach (issue 61).
pub(crate) const PROXY_VARIABLES: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The environment of the program, as `KEY=VALUE` C strings for execve:
/// the environment of this process without [`PROXY_VARIABLES`] (unless
/// `keep_proxy`). Built before the fork; this process's own environment is
/// not changed (podnet warp run calls podnet-netns on a thread). Prints one line
/// that names the removed variables.
pub(crate) fn child_env(keep_proxy: bool) -> Vec<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let mut removed = Vec::new();
    let env: Vec<std::ffi::CString> = std::env::vars_os()
        .filter(|(key, _)| {
            let drop = !keep_proxy && key.to_str().is_some_and(|k| PROXY_VARIABLES.contains(&k));
            if drop {
                removed.push(key.to_string_lossy().into_owned());
            }
            !drop
        })
        .filter_map(|(key, value)| {
            let mut entry = key.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            std::ffi::CString::new(entry).ok()
        })
        .collect();
    if !removed.is_empty() {
        warn(&format!(
            "the program does not get {} (the pod is its egress; --keep-proxy-env keeps them)",
            removed.join(", ")
        ));
    }
    env
}

/// The variable that silences the warnings of podnet-netns (issue 115): set
/// and not empty. `podnet -q` sets it. Errors are still printed.
pub const QUIET_VARIABLE: &str = "PODNET_NETNS_QUIET";

/// True when [`QUIET_VARIABLE`] is set.
pub fn quiet() -> bool {
    std::env::var_os(QUIET_VARIABLE).is_some_and(|v| !v.is_empty())
}

/// Print a warning on stderr, unless [`quiet`].
pub(crate) fn warn(text: &str) {
    if !quiet() {
        eprintln!("podnet-netns: {text}");
    }
}

/// The line that names the backend that runs and its limits (T-071).
fn backend_line(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Seccomp => "seccomp backend: socket options and addresses are emulated; use --backend netns when a program fails",
        _ => "netns backend: UDP other than DNS does not go through, and a loopback listener of the program is not seen from outside; use --backend seccomp when a program needs them",
    }
}

/// Print [`backend_line`] once on stderr when `on`, unless [`quiet`].
fn name_the_backend(on: bool, kind: BackendKind) {
    if on {
        warn(backend_line(kind));
    }
}

/// Add `single-request` to `RES_OPTIONS` of a program environment (issue
/// 113). glibc then sends the A and the AAAA query one after the other.
/// Without it, glibc sends both with one `sendmmsg`; when the seccomp
/// supervisor cannot write `msg_len` into the program, glibc sees the
/// first message as not sent, and `getaddrinfo` with `AF_UNSPEC` fails.
/// A value that has `single-request` or `single-request-reopen` stays.
pub(crate) fn with_single_request(env: &mut Vec<std::ffi::CString>) {
    const KEY: &[u8] = b"RES_OPTIONS=";
    match env.iter_mut().find(|e| e.as_bytes().starts_with(KEY)) {
        Some(entry) => {
            let value = String::from_utf8_lossy(&entry.as_bytes()[KEY.len()..]).into_owned();
            if value
                .split_whitespace()
                .any(|o| o == "single-request" || o == "single-request-reopen")
            {
                return;
            }
            let value = format!("{} single-request", value.trim());
            if let Ok(new) = std::ffi::CString::new(format!("RES_OPTIONS={}", value.trim())) {
                *entry = new;
            }
        }
        None => env.push(std::ffi::CString::new("RES_OPTIONS=single-request").unwrap()),
    }
}

/// Warn when an upstream does not answer a connect in 2 s. The program
/// still runs (it may open no connection), but each connection that it
/// opens fails; before, a dead upstream gave no line at all.
fn warn_unreachable(proxies: &[upstream::Proxy]) {
    use std::net::ToSocketAddrs;
    let limit = std::time::Duration::from_secs(2);
    for proxy in proxies {
        let (shown, result) = match &proxy.unix_path {
            Some(path) => (
                format!("unix:{path}"),
                std::os::unix::net::UnixStream::connect(path).map(drop),
            ),
            None => {
                let shown = format!("{}:{}", proxy.host, proxy.port);
                let result = (proxy.host.as_str(), proxy.port)
                    .to_socket_addrs()
                    .and_then(|mut addrs| {
                        addrs.next().ok_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::NotFound, "no address")
                        })
                    })
                    .and_then(|addr| std::net::TcpStream::connect_timeout(&addr, limit).map(drop));
                (shown, result)
            }
        };
        if let Err(err) = result {
            warn(&format!(
                "warning: the upstream {shown} does not answer ({err}); the connect() of each connection of the program is refused"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::with_single_request;
    use crate::prelude::*;

    fn res_options(env: &[std::ffi::CString]) -> Vec<String> {
        env.iter()
            .filter_map(|e| {
                e.to_str()
                    .ok()?
                    .strip_prefix("RES_OPTIONS=")
                    .map(str::to_string)
            })
            .collect()
    }

    // Issue 113: the pod adds single-request, and keeps a value that has it.
    #[test]
    fn res_options_gets_single_request() {
        let c = |s: &str| std::ffi::CString::new(s).unwrap();
        let mut env = vec![c("PATH=/bin")];
        with_single_request(&mut env);
        assert_eq!(res_options(&env), ["single-request"]);
        let mut env = vec![c("RES_OPTIONS=ndots:2")];
        with_single_request(&mut env);
        assert_eq!(res_options(&env), ["ndots:2 single-request"]);
        let mut env = vec![c("RES_OPTIONS=single-request-reopen")];
        with_single_request(&mut env);
        assert_eq!(res_options(&env), ["single-request-reopen"]);
        with_single_request(&mut env);
        assert_eq!(res_options(&env).len(), 1);
    }

    #[test]
    fn fake_dns_is_stable_and_reversible() {
        let mut dns = FakeDns::new();
        let a = dns.address_for("example.com");
        let b = dns.address_for("example.com");
        assert_eq!(a, b, "the same name must map to the same fake ip");
        assert_eq!(dns.name_for(a), Some("example.com"));
        let other = dns.address_for("example.org");
        assert_ne!(a, other);
        assert!(a.octets()[0] == 198 && a.octets()[1] == 18);
    }

    #[test]
    fn the_filter_covers_the_bypass_surfaces() {
        let syscalls = intercepted_syscalls();
        for required in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_setsockopt,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(
                syscalls.contains(&required),
                "syscall {required} is not intercepted"
            );
        }
    }

    #[test]
    fn parses_a_tcp_syn() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[33] = 0x02; // SYN
        assert_eq!(
            parse_tcp_syn(&pkt),
            Some((
                Ipv4Addr::new(10, 0, 0, 2),
                40000,
                Ipv4Addr::new(93, 184, 216, 34),
                443
            ))
        );

        // An ACK is not a SYN.
        pkt[33] = 0x10;
        assert_eq!(parse_tcp_syn(&pkt), None);
        // UDP is not TCP.
        pkt[9] = 17;
        pkt[33] = 0x02;
        assert_eq!(parse_tcp_syn(&pkt), None);
        // Too short.
        assert_eq!(parse_tcp_syn(&pkt[..20]), None);
    }

    // Issue 190: the answer to a failed dial is a RST|ACK of the SYN.
    #[test]
    fn the_rst_reply_answers_the_syn() {
        use crate::netns::{ipv4_checksum, rst_reply_for_syn};
        let mut syn = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
        syn.extend_from_slice(&[10, 0, 0, 2, 93, 184, 216, 34]);
        let c = ipv4_checksum(&syn[..20]);
        syn[10..12].copy_from_slice(&c.to_be_bytes());
        syn.extend_from_slice(&40000u16.to_be_bytes());
        syn.extend_from_slice(&443u16.to_be_bytes());
        syn.extend_from_slice(&1000u32.to_be_bytes());
        syn.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        let rst = rst_reply_for_syn(&syn).unwrap();
        assert_eq!(rst.len(), 40);
        assert_eq!(&rst[12..16], &[93, 184, 216, 34]);
        assert_eq!(&rst[16..20], &[10, 0, 0, 2]);
        assert_eq!(u16::from_be_bytes([rst[20], rst[21]]), 443);
        assert_eq!(u16::from_be_bytes([rst[22], rst[23]]), 40000);
        assert_eq!(
            u32::from_be_bytes([rst[28], rst[29], rst[30], rst[31]]),
            1001
        );
        assert_eq!(rst[33], 0x14, "RST and ACK");
        // A correct header sums to zero.
        assert_eq!(ipv4_checksum(&rst[..20]), 0);
        let mut pseudo = rst[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&rst[20..40]);
        assert_eq!(ipv4_checksum(&pseudo), 0);
        // Another packet gets no answer.
        assert!(rst_reply_for_syn(&rst).is_none());
    }
}
