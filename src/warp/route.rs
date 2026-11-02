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

/// A route of `/proc/net/route` (an UP route; REJECT routes are skipped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub dev: String,
    pub dest: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub metric: u32,
}

/// The UP routes of `/proc/net/route`.
pub fn parse_entries(text: &str) -> Vec<Entry> {
    let hex = |f: &str| {
        u32::from_str_radix(f, 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_le_bytes()))
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            if flags & 0x1 == 0 || flags & 0x200 != 0 {
                return None;
            }
            Some(Entry {
                dev: f[0].to_string(),
                dest: hex(f[1])?,
                gateway: hex(f[2])?,
                metric: f[6].parse().unwrap_or(u32::MAX),
                mask: hex(f[7])?,
            })
        })
        .collect()
}

/// What an address of the MASQUE connection needs so that the default
/// routes of the TUN (`0/1` and `128/1`) do not capture it (issue 105).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exempt {
    /// Nothing: a loopback address, or a route more specific than /1 (an
    /// on-link subnet, for example) wins over the TUN.
    No,
    /// A host route through this device (and gateway).
    Via {
        dev: String,
        gateway: Option<Ipv4Addr>,
    },
    /// No route at all: the address cannot be kept outside the tunnel.
    Unreachable,
}

/// The plan for `ip` with the routes `entries`, not counting the routes of
/// the TUN `tun`.
pub fn plan_exempt(ip: Ipv4Addr, entries: &[Entry], tun: &str) -> Exempt {
    if ip.is_loopback() {
        return Exempt::No;
    }
    let best = entries
        .iter()
        .filter(|e| e.dev != tun && u32::from(ip) & u32::from(e.mask) == u32::from(e.dest))
        .max_by_key(|e| (u32::from(e.mask).count_ones(), std::cmp::Reverse(e.metric)));
    match best {
        None => Exempt::Unreachable,
        Some(e) if u32::from(e.mask).count_ones() >= 2 => Exempt::No,
        Some(e) => Exempt::Via {
            dev: e.dev.clone(),
            gateway: (!e.gateway.is_unspecified()).then_some(e.gateway),
        },
    }
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
    /// The host routes that keep the MASQUE connection outside the tunnel.
    exempt: Vec<(Ipv4Addr, Option<Ipv4Addr>, String)>,
    ipv6: bool,
    dns: Option<Dns>,
    up: bool,
}

impl Routes {
    /// Add a host route for each address of `exempt` that the default
    /// routes of the TUN would capture, and set the resolver. The default
    /// routes come with [`Routes::up`]. A host with no default route works
    /// when the MASQUE connection goes through a proxy on loopback or on a
    /// connected subnet (issue 105).
    pub fn setup(tun: &str, exempt: Vec<Ipv4Addr>, ipv6: bool) -> Result<Self> {
        let entries =
            parse_entries(&std::fs::read_to_string("/proc/net/route").unwrap_or_default());
        let mut routes = Self {
            tun: tun.to_string(),
            exempt: Vec::new(),
            ipv6,
            dns: None,
            up: false,
        };
        for ip in exempt {
            match plan_exempt(ip, &entries, tun) {
                Exempt::No => {}
                Exempt::Via { dev, gateway } => {
                    route4(true, ip, 32, gateway, &dev)?;
                    routes.exempt.push((ip, gateway, dev));
                }
                Exempt::Unreachable => bail!(
                    "no route to {ip}, an address of the MASQUE connection: cfrs cannot keep it outside the tunnel (use a proxy on a reachable address, or run without --default-route)"
                ),
            }
        }
        routes.dns = Some(set_dns(tun)?);
        Ok(routes)
    }

    /// The addresses that have a host route outside the tunnel.
    pub fn exempted(&self) -> Vec<Ipv4Addr> {
        self.exempt.iter().map(|(ip, _, _)| *ip).collect()
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
        for (ip, gateway, dev) in &self.exempt {
            let _ = route4(false, *ip, 32, *gateway, dev);
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

    /// A /proc/net/route table: 192.0.2.0/24 on eth0, and optionally the
    /// default route via 192.0.2.1 and a /1 of the TUN.
    fn table(default: bool) -> Vec<Entry> {
        let mut text = String::from(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
             cfrs0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\n",
        );
        if default {
            text.push_str("eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\n");
        }
        parse_entries(&text)
    }

    /// Issue 105: with no default route, a proxy on loopback or on the
    /// connected subnet needs no host route; an address with no route is
    /// refused with a precise error; with a default route, a far address
    /// gets a host route through it.
    #[test]
    fn the_plan_of_each_masque_address() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let none = table(false);
        assert_eq!(parse_route_table("Iface\n"), None);
        assert_eq!(plan_exempt(ip("127.0.0.1"), &none, "cfrs0"), Exempt::No);
        assert_eq!(plan_exempt(ip("192.0.2.10"), &none, "cfrs0"), Exempt::No);
        assert_eq!(
            plan_exempt(ip("198.51.100.7"), &none, "cfrs0"),
            Exempt::Unreachable
        );
        let with = table(true);
        assert_eq!(
            plan_exempt(ip("198.51.100.7"), &with, "cfrs0"),
            Exempt::Via {
                dev: "eth0".into(),
                gateway: Some(ip("192.0.2.1"))
            }
        );
        assert_eq!(plan_exempt(ip("192.0.2.10"), &with, "cfrs0"), Exempt::No);
    }

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
