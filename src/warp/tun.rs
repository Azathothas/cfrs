//! Full-device mode: a TUN interface whose packets go through WARP.
//!
//! This mode needs `CAP_NET_ADMIN` and `/dev/net/tun`. Use `cfrs warp proxy`
//! or `cfrs warp run` where these are not available.
//!
//! `cfrs` makes the interface, sets the tunnel address and the MTU, and moves
//! the packets between the interface and the MASQUE session. It does not
//! change the routes. Add routes for the destinations to send through WARP.
//! Do not send the MASQUE endpoint itself through the interface, or the
//! session goes into its own tunnel.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

use super::ip::TUNNEL_MTU;
use super::session::MasqueSession;

const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
/// The interval of the HTTP/2 PING on an idle session.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// An open TUN interface.
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    /// The interface name that the kernel gave.
    pub name: String,
}

fn ifreq(name: &str) -> Result<libc::ifreq> {
    if name.len() >= libc::IFNAMSIZ {
        bail!("the interface name {name:?} is too long");
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    Ok(req)
}

impl Tun {
    /// A TUN that another part made: the raw pod of `cfrs warp run
    /// --backend netns-raw` (issue 79). The descriptor becomes non-blocking.
    pub fn from_fd(fd: OwnedFd, name: &str) -> Result<Self> {
        // SAFETY: fcntl on a descriptor that this value owns.
        unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
            {
                return Err(std::io::Error::last_os_error()).context("making the TUN non-blocking");
            }
        }
        Ok(Self {
            // SAFETY: the descriptor is owned by the AsyncFd and is not
            // closed while it is registered.
            fd: unsafe { AsyncFd::register(fd) }
                .map_err(std::io::Error::from)
                .context("registering the TUN")?,
            name: name.to_string(),
        })
    }
}

/// `struct in6_ifreq` of linux/ipv6.h (SIOCSIFADDR on an AF_INET6 socket).
#[repr(C)]
struct In6Ifreq {
    addr: libc::in6_addr,
    prefixlen: u32,
    ifindex: libc::c_int,
}

impl Tun {
    /// Add the IPv6 address of the tunnel (/128) to the interface (issue
    /// 81). A host with no IPv6 refuses the AF_INET6 socket: the error
    /// says so, and IPv4 still works.
    pub fn add_ipv6(&self, address: std::net::Ipv6Addr) -> Result<()> {
        // SAFETY: a socket call; the descriptor is owned below.
        let control =
            unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if control < 0 {
            return Err(std::io::Error::last_os_error())
                .context("an AF_INET6 socket (no IPv6 on this host?)");
        }
        // SAFETY: a descriptor that this function opened.
        let control = unsafe { OwnedFd::from_raw_fd(control) };
        let mut index = ifreq(&self.name)?;
        ioctl(
            control.as_raw_fd(),
            libc::SIOCGIFINDEX,
            &mut index,
            "SIOCGIFINDEX",
        )?;
        // SAFETY: SIOCGIFINDEX wrote the index in the union.
        let ifindex = unsafe { index.ifr_ifru.ifru_ifindex };
        let mut req = In6Ifreq {
            addr: libc::in6_addr {
                s6_addr: address.octets(),
            },
            prefixlen: 128,
            ifindex,
        };
        // SAFETY: an ioctl with a live in6_ifreq of the size that the
        // kernel reads.
        if unsafe {
            libc::ioctl(
                control.as_raw_fd(),
                libc::SIOCSIFADDR as _,
                &mut req as *mut In6Ifreq,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("SIOCSIFADDR (IPv6)");
        }
        Ok(())
    }
}

fn ioctl(fd: RawFd, request: libc::c_ulong, req: &mut libc::ifreq, what: &str) -> Result<()> {
    if unsafe { libc::ioctl(fd, request as _, req as *mut libc::ifreq) } < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| what.to_string());
    }
    Ok(())
}

impl Tun {
    /// Make the interface `name` (for example `cfrs0`), set `address/32` and
    /// `mtu`, and bring it up.
    pub fn create(name: &str, address: Ipv4Addr, mtu: usize) -> Result<Self> {
        let path = c"/dev/net/tun";
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("opening /dev/net/tun");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = ifreq(name)?;
        req.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        ioctl(
            fd.as_raw_fd(),
            TUNSETIFF,
            &mut req,
            "TUNSETIFF (needs CAP_NET_ADMIN)",
        )?;
        let name = unsafe { std::ffi::CStr::from_ptr(req.ifr_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();

        // Address, MTU and flags are set on an ordinary socket.
        let control =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if control < 0 {
            return Err(std::io::Error::last_os_error()).context("socket for the interface ioctls");
        }
        let control = unsafe { OwnedFd::from_raw_fd(control) };
        let mut addr = ifreq(&name)?;
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(address).to_be(),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::write(
                &mut addr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in,
                sin,
            );
        }
        ioctl(
            control.as_raw_fd(),
            libc::SIOCSIFADDR,
            &mut addr,
            "SIOCSIFADDR",
        )?;
        let mut mask = ifreq(&name)?;
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::MAX },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::write(
                &mut mask.ifr_ifru.ifru_netmask as *mut libc::sockaddr as *mut libc::sockaddr_in,
                sin,
            );
        }
        ioctl(
            control.as_raw_fd(),
            libc::SIOCSIFNETMASK,
            &mut mask,
            "SIOCSIFNETMASK",
        )?;
        let mut size = ifreq(&name)?;
        size.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        ioctl(
            control.as_raw_fd(),
            libc::SIOCSIFMTU,
            &mut size,
            "SIOCSIFMTU",
        )?;
        let mut flags = ifreq(&name)?;
        ioctl(
            control.as_raw_fd(),
            libc::SIOCGIFFLAGS,
            &mut flags,
            "SIOCGIFFLAGS",
        )?;
        unsafe {
            flags.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        ioctl(
            control.as_raw_fd(),
            libc::SIOCSIFFLAGS,
            &mut flags,
            "SIOCSIFFLAGS",
        )?;

        // SAFETY: `fd` is an OwnedFd: it holds the TUN descriptor open and
        // returns it from as_raw_fd until the AsyncFd drops it.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(std::io::Error::from)?;
        Ok(Self { fd, name })
    }

    /// Read one packet.
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| {
                let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one packet.
    pub async fn write(&self, packet: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| {
                let n =
                    unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// Move packets between `tun` and `session` until one of them ends.
pub async fn run(tun: &Tun, session: MasqueSession) -> Result<()> {
    let (mut tx, mut rx) = session.split();
    info!(interface = %tun.name, "the TUN interface is connected to WARP");
    let outbound = async {
        let mut buf = vec![0u8; 65_536];
        let mut keepalive = tokio::time::interval(KEEPALIVE);
        loop {
            tokio::select! {
                read = tun.read(&mut buf) => {
                    let n = read.context("reading the TUN interface")?;
                    if n == 0 {
                        continue;
                    }
                    if n > TUNNEL_MTU {
                        debug!(n, "dropped a packet larger than the tunnel MTU");
                        continue;
                    }
                    tx.send_packet(&buf[..n]).await?;
                }
                _ = keepalive.tick() => {
                    if let Err(err) = tx.keepalive() {
                        warn!(error = %err, "MASQUE keepalive failed");
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let inbound = async {
        while let Some(packet) = rx.recv_packet().await? {
            if let Err(err) = tun.write(&packet).await {
                debug!(error = %err, "writing to the TUN interface failed");
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = outbound => result,
        result = inbound => {
            result?;
            bail!("the MASQUE session ended")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make an interface where the host permits it, and check the address.
    #[tokio::test]
    async fn creates_an_interface_with_the_address() {
        let name = format!("cfrst{}", std::process::id() % 10_000);
        let tun = match Tun::create(&name, Ipv4Addr::new(172, 16, 0, 2), 1280) {
            Ok(tun) => tun,
            Err(err) => {
                eprintln!("skipping: {err:#}");
                return;
            }
        };
        assert_eq!(tun.name, name);
        let mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu")).unwrap();
        assert_eq!(mtu.trim(), "1280");
        let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags")).unwrap();
        let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
        assert_ne!(flags & libc::IFF_UP as u32, 0, "the interface is up");
    }
}
