//! The routes and the resolver of `podnet warp tun --default-route` (issue
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

/// A route of `/proc/net/ipv6_route` (an UP route; REJECT routes are
/// skipped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry6 {
    pub dev: String,
    pub dest: Ipv6Addr,
    pub prefix: u8,
    pub gateway: Ipv6Addr,
    pub metric: u32,
}

/// The UP routes of `/proc/net/ipv6_route`: dest, dest length, source,
/// source length, next hop, metric, refcount, use, flags, device.
pub fn parse_entries6(text: &str) -> Vec<Entry6> {
    let addr = |f: &str| {
        u128::from_str_radix(f, 16)
            .ok()
            .filter(|_| f.len() == 32)
            .map(Ipv6Addr::from)
    };
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let flags = u32::from_str_radix(f[8], 16).ok()?;
            if flags & 0x1 == 0 || flags & 0x200 != 0 {
                return None;
            }
            Some(Entry6 {
                dest: addr(f[0])?,
                prefix: u8::from_str_radix(f[1], 16).ok()?,
                gateway: addr(f[4])?,
                metric: u32::from_str_radix(f[5], 16).unwrap_or(u32::MAX),
                dev: f[9].to_string(),
            })
        })
        .collect()
}

/// [`Exempt`] for an IPv6 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exempt6 {
    No,
    Via {
        dev: String,
        gateway: Option<Ipv6Addr>,
    },
    Unreachable,
}

/// What an IPv6 address of the MASQUE connection needs, as
/// [`plan_exempt`] (the IPv6-only kit, 0001: before, only IPv4 addresses
/// were kept outside the TUN).
pub fn plan_exempt6(ip: Ipv6Addr, entries: &[Entry6], tun: &str) -> Exempt6 {
    if ip.is_loopback() {
        return Exempt6::No;
    }
    let bits = u128::from(ip);
    let best = entries
        .iter()
        .filter(|e| e.dev != tun && e.dev != "lo")
        .filter(|e| {
            let mask = if e.prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(e.prefix.min(128)))
            };
            bits & mask == u128::from(e.dest) & mask
        })
        .max_by_key(|e| (e.prefix, std::cmp::Reverse(e.metric)));
    match best {
        None => Exempt6::Unreachable,
        Some(e) if e.prefix >= 2 => Exempt6::No,
        Some(e) => Exempt6::Via {
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

/// Add or delete an IPv6 route on `dev`, through `via` when it is given.
fn route6(add: bool, dst: Ipv6Addr, prefix: u16, via: Option<Ipv6Addr>, dev: &str) -> Result<()> {
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
    if prefix == 128 {
        rt.flags |= libc::RTF_HOST as u32;
    }
    if let Some(gw) = via {
        rt.gateway = libc::in6_addr {
            s6_addr: gw.octets(),
        };
        rt.flags |= libc::RTF_GATEWAY as u32;
    }
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
    /// The IPv6 host routes of the same.
    exempt6: Vec<(Ipv6Addr, Option<Ipv6Addr>, String)>,
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
    ///
    /// An address of `required` (the front door or the proxy of the
    /// session) with no route is an error. An address of `optional` (the
    /// relay of a later session, of both families) with no route is
    /// skipped (the IPv6-only kit, 0001: an IPv4 address on a host with no
    /// IPv4 route stopped the command).
    pub fn setup(
        tun: &str,
        required: Vec<std::net::IpAddr>,
        optional: Vec<std::net::IpAddr>,
        ipv6: bool,
    ) -> Result<Self> {
        let entries =
            parse_entries(&std::fs::read_to_string("/proc/net/route").unwrap_or_default());
        let entries6 =
            parse_entries6(&std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default());
        let mut routes = Self {
            tun: tun.to_string(),
            exempt: Vec::new(),
            exempt6: Vec::new(),
            ipv6,
            dns: None,
            up: false,
        };
        let all = required
            .into_iter()
            .map(|ip| (ip, true))
            .chain(optional.into_iter().map(|ip| (ip, false)));
        for (ip, needed) in all {
            let unreachable = match ip {
                std::net::IpAddr::V4(ip) => match plan_exempt(ip, &entries, tun) {
                    Exempt::No => false,
                    Exempt::Via { dev, gateway } => {
                        route4(true, ip, 32, gateway, &dev)?;
                        routes.exempt.push((ip, gateway, dev));
                        false
                    }
                    Exempt::Unreachable => true,
                },
                std::net::IpAddr::V6(ip) => match plan_exempt6(ip, &entries6, tun) {
                    Exempt6::No => false,
                    Exempt6::Via { dev, gateway } => {
                        route6(true, ip, 128, gateway, &dev)?;
                        routes.exempt6.push((ip, gateway, dev));
                        false
                    }
                    Exempt6::Unreachable => true,
                },
            };
            if unreachable && needed {
                bail!(
                    "no route to {ip}, an address of the MASQUE connection: podnet cannot keep it outside the tunnel (use a proxy on a reachable address, or run without --default-route)"
                );
            }
            if unreachable {
                tracing::debug!(%ip, "no route: this address of the relay is not kept outside the tunnel");
            }
        }
        routes.dns = Some(set_dns(tun)?);
        Ok(routes)
    }

    /// The addresses that have a host route outside the tunnel.
    pub fn exempted(&self) -> Vec<std::net::IpAddr> {
        self.exempt
            .iter()
            .map(|(ip, _, _)| std::net::IpAddr::V4(*ip))
            .chain(
                self.exempt6
                    .iter()
                    .map(|(ip, _, _)| std::net::IpAddr::V6(*ip)),
            )
            .collect()
    }

    /// The default routes on the TUN (the session is up).
    pub fn up(&mut self) -> Result<()> {
        // #278: a failure after one half removes the half that is in; the
        // host never runs with half of the default routes on the TUN.
        let tun = self.tun.clone();
        install_all(&HALVES4, |(dst, prefix), add| {
            route4(add, *dst, *prefix, None, &tun)
        })?;
        if self.ipv6 {
            for (dst, prefix) in HALVES6 {
                if let Err(err) = route6(true, dst, prefix, None, &self.tun) {
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
                let _ = route6(false, dst, prefix, None, &self.tun);
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
        for (ip, gateway, dev) in &self.exempt6 {
            let _ = route6(false, *ip, 128, *gateway, dev);
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

/// The nameservers of `--default-route`: the UDP resolvers of `--resolver`
/// on port 53 (at most 3; issue 145), else 1.1.1.1 and 1.0.0.1. A program
/// of the host speaks plain DNS, so a tls:// resolver is not one of them.
pub fn nameservers() -> Vec<std::net::IpAddr> {
    let set: Vec<std::net::IpAddr> = super::proxy::resolvers()
        .iter()
        .filter_map(|r| match r {
            super::proxy::Resolver::Udp(a) if a.port() == 53 => Some(a.ip()),
            _ => None,
        })
        .take(3)
        .collect();
    if super::proxy::resolvers_set() && !set.is_empty() {
        set
    } else {
        vec![[1, 1, 1, 1].into(), [1, 0, 0, 1].into()]
    }
}

/// The text of a resolv.conf with `servers`.
pub fn resolv_text(servers: &[std::net::IpAddr]) -> String {
    let mut text = String::from("# podnet warp tun --default-route: DNS through WARP\n");
    for s in servers {
        text.push_str(&format!("nameserver {s}\n"));
    }
    text
}

fn set_dns(tun: &str) -> Result<Dns> {
    let servers: Vec<String> = nameservers().iter().map(|s| s.to_string()).collect();
    let resolved = std::path::Path::new("/run/systemd/resolve").is_dir()
        && std::process::Command::new("resolvectl")
            .arg("dns")
            .arg(tun)
            .args(&servers)
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
    replace_file(std::path::Path::new(RESOLV), &resolv_text(&nameservers()))?;
    Ok(Dns::File { backup, link })
}

/// Add each item with `apply(item, true)`. When one fails, remove the
/// items that are in (`apply(item, false)`, in the reverse order) and
/// give the error.
fn install_all<T>(items: &[T], mut apply: impl FnMut(&T, bool) -> Result<()>) -> Result<()> {
    for (i, item) in items.iter().enumerate() {
        if let Err(err) = apply(item, true) {
            for done in items[..i].iter().rev() {
                let _ = apply(done, false);
            }
            return Err(err);
        }
    }
    Ok(())
}

/// Write `text` as the file `path` (#278). A new file in the same
/// directory is renamed over the old one: a failure keeps the old file,
/// and a symbolic link is replaced, not written through. Where a rename
/// over the file is not possible (a bind mount: EBUSY, EXDEV), the file is
/// written in place.
fn replace_file(path: &std::path::Path, text: &str) -> Result<()> {
    let temp = path.with_extension(format!("podnet-{}", std::process::id()));
    std::fs::write(&temp, text).with_context(|| format!("writing {}", temp.display()))?;
    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&temp);
            tracing::debug!(error = %err, path = %path.display(), "no rename over the file; it is written in place");
            std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #278: a failed second route removes the first; no half stays.
    #[test]
    fn a_failed_route_removes_the_routes_before_it() {
        let mut log = Vec::new();
        let err = install_all(&[1, 2, 3], |item, add| {
            log.push((*item, add));
            if *item == 2 && add {
                anyhow::bail!("no route");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("no route"));
        assert_eq!(log, [(1, true), (2, true), (1, false)]);
    }

    /// #278: the file is replaced by a rename: a link is replaced, not
    /// written through, and a failed write keeps the old file.
    #[test]
    fn the_resolv_conf_is_replaced_and_never_removed_first() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("stub.conf");
        std::fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        let path = dir.path().join("resolv.conf");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        replace_file(&path, "nameserver 1.1.1.1\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "nameserver 1.1.1.1\n"
        );
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "nameserver 127.0.0.53\n"
        );
        // A directory that can not take the new file: the old file stays.
        let missing = dir.path().join("no-such-dir").join("resolv.conf");
        assert!(replace_file(&missing, "x").is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "nameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn the_resolv_conf_text() {
        let text = resolv_text(&[
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ]);
        assert!(
            text.ends_with("nameserver 192.0.2.53\nnameserver 2001:db8::53\n"),
            "{text}"
        );
    }

    /// A /proc/net/route table: 192.0.2.0/24 on eth0, and optionally the
    /// default route via 192.0.2.1 and a /1 of the TUN.
    fn table(default: bool) -> Vec<Entry> {
        let mut text = String::from(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
             podnet0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\n",
        );
        if default {
            text.push_str("eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\n");
        }
        parse_entries(&text)
    }

    /// A /proc/net/ipv6_route table: fd00:77::/64 on eth0, ::1 on lo, a /1
    /// of the TUN, and optionally the default route via fd00:77::1.
    fn table6(default: bool) -> Vec<Entry6> {
        let mut text = String::from(
            "fd000077000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n\
             00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo\n\
             00000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000001    podnet0\n",
        );
        if default {
            text.push_str("00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000077000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n");
        }
        parse_entries6(&text)
    }

    /// The IPv6-only kit, 0001: an IPv6 front door gets a host route
    /// through the IPv6 default route; an address on a connected prefix
    /// needs none; with no IPv6 route it is unreachable.
    #[test]
    fn the_plan_of_each_ipv6_masque_address() {
        let ip = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let with = table6(true);
        assert_eq!(with.len(), 4);
        assert_eq!(
            plan_exempt6(ip("2606:4700:103::2"), &with, "podnet0"),
            Exempt6::Via {
                dev: "eth0".into(),
                gateway: Some(ip("fd00:77::1")),
            }
        );
        assert_eq!(
            plan_exempt6(ip("fd00:77::9"), &with, "podnet0"),
            Exempt6::No
        );
        assert_eq!(plan_exempt6(ip("::1"), &with, "podnet0"), Exempt6::No);
        let none = table6(false);
        assert_eq!(
            plan_exempt6(ip("2606:4700:103::2"), &none, "podnet0"),
            Exempt6::Unreachable
        );
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
        assert_eq!(plan_exempt(ip("127.0.0.1"), &none, "podnet0"), Exempt::No);
        assert_eq!(plan_exempt(ip("192.0.2.10"), &none, "podnet0"), Exempt::No);
        assert_eq!(
            plan_exempt(ip("198.51.100.7"), &none, "podnet0"),
            Exempt::Unreachable
        );
        let with = table(true);
        assert_eq!(
            plan_exempt(ip("198.51.100.7"), &with, "podnet0"),
            Exempt::Via {
                dev: "eth0".into(),
                gateway: Some(ip("192.0.2.1"))
            }
        );
        assert_eq!(plan_exempt(ip("192.0.2.10"), &with, "podnet0"), Exempt::No);
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
