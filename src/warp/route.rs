//! The routes and the resolver of `cfrs warp tun --default-route` (issue
//! 77): with CAP_NET_ADMIN, the whole host goes through WARP.
//!
//! * Host routes through the gateway of the default route for each
//!   address that the MASQUE connection uses (the proxy, the front door,
//!   the relay), so that the connection does not go into the tunnel.
//! * Default routes on the TUN: `0.0.0.0/1` and `128.0.0.0/1`, and
//!   `::/1` and `8000::/1` (more specific than the default route, which
//!   stays). They go away while the session is down, so that traffic
//!   fails fast.
//! * DNS: `resolvectl` on the TUN when systemd-resolved runs, else
//!   `/etc/resolv.conf` with 1.1.1.1 and 1.0.0.1 (a copy is kept).
//!
//! [`Routes`] puts each change back when it is dropped. The calls are
//! ioctls (`SIOCADDRT`, `SIOCDELRT`): no hook script and no shell runs
//! as root.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};

/// The gateway and the device of the IPv4 default route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub dev: String,
    pub gateway: Ipv4Addr,
}

/// The default route of `/proc/net/route` (the lowest metric).
pub fn parse_route_table(text: &str) -> Option<Gateway> {
    let mut best: Option<(u32, Gateway)> = None;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        let Ok(gw) = u32::from_str_radix(f[2], 16) else {
            continue;
        };
        let metric = f[6].parse().unwrap_or(u32::MAX);
        let gateway = Ipv4Addr::from(gw.to_le_bytes());
        if gateway.is_unspecified() {
            continue;
        }
        if best.as_ref().is_none_or(|(m, _)| metric < *m) {
            best = Some((
                metric,
                Gateway {
                    dev: f[0].to_string(),
                    gateway,
                },
            ));
        }
    }
    best.map(|(_, g)| g)
}

pub fn default_gateway() -> Option<Gateway> {
    parse_route_table(&std::fs::read_to_string("/proc/net/route").ok()?)
}

fn socket(family: libc::c_int) -> Result<OwnedFd> {
    // SAFETY: a socket call; the descriptor is owned below.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("a socket for the route ioctls");
    }
    // SAFETY: a descriptor that this function opened.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sin(addr: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: sockaddr_in and sockaddr have the same size.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
}

fn mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix)))
    }
}

/// Add (`SIOCADDRT`) or delete (`SIOCDELRT`) an IPv4 route.
fn route4(add: bool, dst: Ipv4Addr, prefix: u8, via: Option<Ipv4Addr>, dev: &str) -> Result<()> {
    let ctl = socket(libc::AF_INET)?;
    let dev_c = std::ffi::CString::new(dev)?;
    // SAFETY: a zeroed rtentry with its fields set; rt_dev points to a
    // live string.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = sin(dst);
    rt.rt_genmask = sin(mask(prefix));
    rt.rt_flags = libc::RTF_UP;
    if prefix == 32 {
        rt.rt_flags |= libc::RTF_HOST;
    }
    if let Some(gw) = via {
        rt.rt_gateway = sin(gw);
        rt.rt_flags |= libc::RTF_GATEWAY;
    }
    rt.rt_dev = dev_c.as_ptr() as *mut libc::c_char;
    let cmd = if add {
        libc::SIOCADDRT
    } else {
        libc::SIOCDELRT
    };
    // SAFETY: an ioctl with a live rtentry.
    if unsafe { libc::ioctl(ctl.as_raw_fd(), cmd as _, &rt as *const libc::rtentry) } < 0 {
        let err = std::io::Error::last_os_error();
        // A route that is there (add) or not there (delete) is no fault.
        let fine = (add && err.raw_os_error() == Some(libc::EEXIST))
            || (!add && err.raw_os_error() == Some(libc::ESRCH));
        if !fine {
            return Err(err).with_context(|| {
                format!(
                    "{} the route {dst}/{prefix} on {dev}",
                    if add { "adding" } else { "deleting" }
                )
            });
        }
    }
    Ok(())
}

/// `struct in6_rtmsg` of linux/ipv6_route.h.
#[repr(C)]
struct In6Rtmsg {
    dst: libc::in6_addr,
    src: libc::in6_addr,
    gateway: libc::in6_addr,
    kind: u32,
    dst_len: u16,
    src_len: u16,
    metric: u32,
    info: libc::c_ulong,
    flags: u32,
    ifindex: libc::c_int,
}

/// Add or delete an IPv6 route on `dev`.
fn route6(add: bool, dst: Ipv6Addr, prefix: u16, dev: &str) -> Result<()> {
    let ctl = socket(libc::AF_INET6)?;
    let dev_c = std::ffi::CString::new(dev)?;
    // SAFETY: a C string; 0 when the device does not exist.
    let ifindex = unsafe { libc::if_nametoindex(dev_c.as_ptr()) };
    if ifindex == 0 {
        bail!("no interface {dev}");
    }
    // SAFETY: a zeroed in6_rtmsg with its fields set.
    let mut rt: In6Rtmsg = unsafe { std::mem::zeroed() };
    rt.dst = libc::in6_addr {
        s6_addr: dst.octets(),
    };
    rt.dst_len = prefix;
    rt.metric = 1;
    rt.flags = libc::RTF_UP as u32;
    rt.ifindex = ifindex as libc::c_int;
    let cmd = if add {
        libc::SIOCADDRT
    } else {
        libc::SIOCDELRT
    };
    // SAFETY: an ioctl with a live in6_rtmsg.
    if unsafe { libc::ioctl(ctl.as_raw_fd(), cmd as _, &mut rt as *mut In6Rtmsg) } < 0 {
        let err = std::io::Error::last_os_error();
        let fine = (add && err.raw_os_error() == Some(libc::EEXIST))
            || (!add && err.raw_os_error() == Some(libc::ESRCH));
        if !fine {
            return Err(err).with_context(|| format!("the IPv6 route {dst}/{prefix} on {dev}"));
        }
    }
    Ok(())
}

/// The halves of the IPv4 and the IPv6 address space.
const HALVES4: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(0, 0, 0, 0), 1),
    (Ipv4Addr::new(128, 0, 0, 0), 1),
];
const HALVES6: [(Ipv6Addr, u16); 2] = [
    (Ipv6Addr::UNSPECIFIED, 1),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

/// What `Routes` changed in the resolver.
#[derive(Debug)]
enum Dns {
    Resolved,
    File {
        backup: String,
        link: Option<PathBuf>,
    },
}

const RESOLV: &str = "/etc/resolv.conf";

/// The routes and the resolver of `--default-route`; dropped, it puts each
/// change back.
#[derive(Debug)]
pub struct Routes {
    tun: String,
    exempt: Vec<Ipv4Addr>,
    gateway: Option<Gateway>,
    ipv6: bool,
    dns: Option<Dns>,
    up: bool,
}

impl Routes {
    /// Add the host routes of `exempt` through the default gateway, and set
    /// the resolver. The default routes come with [`Routes::up`].
    pub fn setup(tun: &str, exempt: Vec<Ipv4Addr>, ipv6: bool) -> Result<Self> {
        let gateway = default_gateway();
        let mut routes = Self {
            tun: tun.to_string(),
            exempt: Vec::new(),
            gateway: gateway.clone(),
            ipv6,
            dns: None,
            up: false,
        };
        if !exempt.is_empty() {
            let gw = gateway.context(
                "no IPv4 default route: cfrs cannot keep the MASQUE connection outside the tunnel",
            )?;
            for ip in exempt {
                if ip.is_loopback() {
                    continue;
                }
                route4(true, ip, 32, Some(gw.gateway), &gw.dev)?;
                routes.exempt.push(ip);
            }
        }
        routes.dns = Some(set_dns(tun)?);
        Ok(routes)
    }

    /// The default routes on the TUN (the session is up).
    pub fn up(&mut self) -> Result<()> {
        for (dst, prefix) in HALVES4 {
            route4(true, dst, prefix, None, &self.tun)?;
        }
        if self.ipv6 {
            for (dst, prefix) in HALVES6 {
                if let Err(err) = route6(true, dst, prefix, &self.tun) {
                    tracing::warn!(error = %format!("{err:#}"), "no IPv6 default route on the TUN");
                    self.ipv6 = false;
                    break;
                }
            }
        }
        self.up = true;
        Ok(())
    }

    /// No default routes on the TUN (the session is down: traffic fails
    /// fast).
    pub fn down(&mut self) {
        if !self.up {
            return;
        }
        for (dst, prefix) in HALVES4 {
            let _ = route4(false, dst, prefix, None, &self.tun);
        }
        if self.ipv6 {
            for (dst, prefix) in HALVES6 {
                let _ = route6(false, dst, prefix, &self.tun);
            }
        }
        self.up = false;
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        self.down();
        if let Some(gw) = &self.gateway {
            for ip in &self.exempt {
                let _ = route4(false, *ip, 32, Some(gw.gateway), &gw.dev);
            }
        }
        match self.dns.take() {
            Some(Dns::Resolved) => {
                let _ = std::process::Command::new("resolvectl")
                    .args(["revert", &self.tun])
                    .status();
            }
            Some(Dns::File { backup, link }) => {
                let _ = std::fs::remove_file(RESOLV);
                match link {
                    Some(target) => {
                        let _ = std::os::unix::fs::symlink(target, RESOLV);
                    }
                    None => {
                        let _ = std::fs::write(RESOLV, backup);
                    }
                }
            }
            None => {}
        }
        tracing::info!(tun = %self.tun, "the routes and the resolver are as before");
    }
}

/// The text of the resolv.conf of `--default-route`.
pub const RESOLV_TEXT: &str =
    "# cfrs warp tun --default-route: DNS through WARP\nnameserver 1.1.1.1\nnameserver 1.0.0.1\n";

fn set_dns(tun: &str) -> Result<Dns> {
    let resolved = std::path::Path::new("/run/systemd/resolve").is_dir()
        && std::process::Command::new("resolvectl")
            .args(["dns", tun, "1.1.1.1", "1.0.0.1"])
            .status()
            .is_ok_and(|s| s.success());
    if resolved {
        let _ = std::process::Command::new("resolvectl")
            .args(["domain", tun, "~."])
            .status();
        let _ = std::process::Command::new("resolvectl")
            .args(["default-route", tun, "yes"])
            .status();
        return Ok(Dns::Resolved);
    }
    let link = std::fs::read_link(RESOLV).ok();
    let backup = std::fs::read_to_string(RESOLV).unwrap_or_default();
    let _ = std::fs::remove_file(RESOLV);
    std::fs::write(RESOLV, RESOLV_TEXT).with_context(|| format!("writing {RESOLV}"))?;
    Ok(Dns::File { backup, link })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_gateway_of_the_route_table() {
        let table =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth1\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_route_table(table),
            Some(Gateway {
                dev: "eth1".into(),
                gateway: Ipv4Addr::new(192, 168, 1, 1)
            }),
            "the lowest metric"
        );
        assert_eq!(parse_route_table("Iface\tDestination\n"), None);
    }

    #[test]
    fn masks() {
        assert_eq!(mask(1), Ipv4Addr::new(128, 0, 0, 0));
        assert_eq!(mask(32), Ipv4Addr::BROADCAST);
        assert_eq!(mask(0), Ipv4Addr::UNSPECIFIED);
    }
}
