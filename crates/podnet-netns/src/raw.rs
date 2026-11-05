//! The raw IP pod (issue 79): a user and network namespace whose TUN is
//! given to the caller as a file descriptor of raw IP packets. `podnet warp
//! run --backend netns-raw` moves these packets through WARP, so the program
//! has TCP, UDP, ICMP and IPv6 with no userspace TCP stack and no root.
//!
//! In the namespace: the TUN `eth0` with the WARP addresses (IPv4 /32, and
//! IPv6 /128 when given), a default route on the device for each family,
//! `lo` up, and a resolv.conf with `nameserver` (a bind mount in a private
//! mount namespace).
//!
//! The caller can be a multi-threaded process: everything that allocates
//! is made before `fork()`. The child only does system calls until
//! `execvpe`.

#[allow(unused_imports)]
use crate::prelude::*;
use std::ffi::CString;
use std::net::Ipv6Addr;
use std::os::fd::FromRawFd as _;

use crate::netns::{
    read_exact_fd, recv_fd, socketpair, write_all_fd, write_id_maps, IFF_NO_PI, IFF_TUN, TUNSETIFF,
};

/// What the raw pod runs, and its addresses.
#[derive(Clone, Debug)]
pub struct RawOptions {
    pub program: Vec<String>,
    pub keep_proxy_env: bool,
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
    pub mtu: usize,
    pub nameserver: IpAddr,
}

/// The program of the pod cannot be run (`execvpe` failed: not in PATH,
/// not executable). The caller exits 3, as the netns backend does (issue
/// 251: the child exited 127 with no message).
#[derive(Debug)]
pub struct ExecError {
    pub program: String,
    pub error: std::io::Error,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "execvpe {}: {}", self.program, self.error)
    }
}

impl std::error::Error for ExecError {}

/// A running raw pod: the TUN of its namespace and the pid of the program.
#[derive(Debug)]
pub struct RawPod {
    pub tun: std::os::fd::OwnedFd,
    pub pid: i32,
}

/// Whether this host can make the namespace and the TUN, with no root.
pub fn available() -> bool {
    std::path::Path::new("/dev/net/tun").exists()
        && (crate::doctor::probe_unshare(libc::CLONE_NEWNET).ok
            || crate::doctor::probe_unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET).ok)
}

/// The exit code of `pid` when it ended, with no wait.
pub fn try_wait(pid: i32) -> Option<i32> {
    let mut status = 0;
    // SAFETY: waitpid on a child of this process.
    let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    (r == pid).then(|| {
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        }
    })
}

/// Everything that the child needs, made before `fork()`.
struct Prepared {
    path: CString,
    argv: Vec<CString>,
    env: Vec<CString>,
    name: CString,
    resolv_source: CString,
    resolv_target: CString,
    root: CString,
    v4: Ipv4Addr,
    v6: Option<Ipv6Addr>,
    mtu: usize,
}

/// Start the program in a raw pod. The child exits with 3 when the
/// namespace or the TUN cannot be made; the caller gets the error of the
/// TUN fd that does not come.
pub fn spawn(opts: &RawOptions) -> Result<RawPod> {
    let program = opts.program.first().context("no program to run")?;
    let resolv = std::env::temp_dir().join(format!(
        "podnet-netns-raw-resolv-{}.conf",
        std::process::id()
    ));
    std::fs::write(
        &resolv,
        format!("nameserver {}\noptions ndots:0\n", opts.nameserver),
    )
    .context("writing the resolv.conf of the pod")?;
    let prepared = Prepared {
        path: CString::new(program.as_bytes())?,
        argv: opts
            .program
            .iter()
            .map(|a| CString::new(a.as_bytes()))
            .collect::<std::result::Result<_, _>>()?,
        env: crate::child_env(opts.keep_proxy_env),
        name: CString::new("eth0")?,
        resolv_source: CString::new(resolv.as_os_str().as_encoded_bytes())?,
        resolv_target: CString::new("/etc/resolv.conf")?,
        root: CString::new("/")?,
        v4: opts.v4,
        v6: opts.v6,
        mtu: opts.mtu,
    };
    let argv: Vec<*const libc::c_char> = prepared
        .argv
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp: Vec<*const libc::c_char> = prepared
        .env
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let (parent, child) = socketpair()?;
    // SAFETY: the child only does system calls on memory made above, then
    // execvpe or _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let _ = std::fs::remove_file(&resolv);
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::close(parent);
            let code = child_main(child, &prepared, &argv, &envp);
            libc::_exit(code);
        }
    }
    // SAFETY: our end of the pair.
    unsafe { libc::close(child) };
    let result = (|| {
        let mut kind = [0u8; 1];
        if read_exact_fd(parent, &mut kind)? == 0 {
            bail!("the namespace could not be made (unshare refused)");
        }
        if kind[0] == b'u' {
            write_id_maps(pid as u32).context("writing the uid and gid maps")?;
            write_all_fd(parent, b"a")?;
        }
        let fd = recv_fd(parent).context("the TUN of the namespace did not come (no /dev/net/tun, or the namespace cannot bring up its interfaces)")?;
        // The end of the child has FD_CLOEXEC: a good execvpe closes it
        // (no byte), and a failed one sends its errno.
        let mut errno = [0u8; 4];
        let n = read_exact_fd(parent, &mut errno);
        if let Ok(4) = n {
            // SAFETY: the TUN that recv_fd gave; nobody else has it.
            unsafe { libc::close(fd) };
            return Err(anyhow::Error::new(ExecError {
                program: program.clone(),
                error: std::io::Error::from_raw_os_error(i32::from_ne_bytes(errno)),
            }));
        }
        Ok(fd)
    })();
    // SAFETY: our end of the pair.
    unsafe { libc::close(parent) };
    // The child has the file open (bind mount) or ended.
    let _ = std::fs::remove_file(&resolv);
    match result {
        Ok(fd) => Ok(RawPod {
            // SAFETY: a descriptor that recv_fd gave to this process.
            tun: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            pid,
        }),
        Err(err) => {
            let mut status = 0;
            // SAFETY: waitpid on our child.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            Err(err)
        }
    }
}

/// The child: system calls only. Gives the exit code on a failure.
unsafe fn child_main(
    sock: RawFd,
    p: &Prepared,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> i32 {
    const NO_BACKEND: i32 = 3;
    let userns = if libc::unshare(libc::CLONE_NEWNET) == 0 {
        false
    } else if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0 {
        true
    } else {
        return NO_BACKEND;
    };
    let kind: &[u8] = if userns { b"u" } else { b"n" };
    if libc::write(sock, kind.as_ptr().cast(), 1) != 1 {
        return NO_BACKEND;
    }
    if userns {
        let mut ack = 0u8;
        if libc::read(sock, (&mut ack as *mut u8).cast(), 1) != 1 {
            return NO_BACKEND;
        }
    }
    let ctl = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if ctl < 0 {
        return NO_BACKEND;
    }
    // lo up.
    let mut lo: libc::ifreq = std::mem::zeroed();
    lo.ifr_name[0] = b'l' as libc::c_char;
    lo.ifr_name[1] = b'o' as libc::c_char;
    lo.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    if libc::ioctl(ctl, libc::SIOCSIFFLAGS as _, &lo as *const _) < 0 {
        return NO_BACKEND;
    }
    // The TUN.
    let tun = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
    if tun < 0 {
        return NO_BACKEND;
    }
    let mut ifr: libc::ifreq = std::mem::zeroed();
    for (i, b) in p
        .name
        .as_bytes()
        .iter()
        .enumerate()
        .take(libc::IF_NAMESIZE - 1)
    {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let named = ifr;
    ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
    if libc::ioctl(tun, TUNSETIFF as _, &mut ifr as *mut libc::ifreq) < 0 {
        return NO_BACKEND;
    }
    let mut req = named;
    req.ifr_ifru.ifru_mtu = p.mtu as libc::c_int;
    if libc::ioctl(ctl, libc::SIOCSIFMTU as _, &req as *const _) < 0 {
        return NO_BACKEND;
    }
    let mut req = named;
    {
        let sin = &mut req.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as u16;
        (*sin).sin_addr.s_addr = u32::from_ne_bytes(p.v4.octets());
    }
    if libc::ioctl(ctl, libc::SIOCSIFADDR as _, &req as *const _) < 0 {
        return NO_BACKEND;
    }
    let mut req = named;
    {
        let sin = &mut req.ifr_ifru.ifru_netmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as u16;
        (*sin).sin_addr.s_addr = u32::MAX;
    }
    if libc::ioctl(ctl, libc::SIOCSIFNETMASK as _, &req as *const _) < 0 {
        return NO_BACKEND;
    }
    let mut req = named;
    req.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    if libc::ioctl(ctl, libc::SIOCSIFFLAGS as _, &req as *const _) < 0 {
        return NO_BACKEND;
    }
    // The default IPv4 route on the device (point to point: no gateway).
    let mut route: libc::rtentry = std::mem::zeroed();
    (*(&mut route.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in)).sin_family =
        libc::AF_INET as u16;
    (*(&mut route.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in)).sin_family =
        libc::AF_INET as u16;
    route.rt_flags = libc::RTF_UP;
    route.rt_dev = p.name.as_ptr() as *mut libc::c_char;
    if libc::ioctl(ctl, libc::SIOCADDRT as _, &route as *const _) < 0 {
        return NO_BACKEND;
    }
    // IPv6: the address and the default route, when they can be set (a
    // host with no IPv6 keeps IPv4).
    if let Some(v6) = p.v6 {
        add_ipv6(&named, v6);
    }
    // The resolver.
    if libc::unshare(libc::CLONE_NEWNS) == 0
        && libc::mount(
            std::ptr::null(),
            p.root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) == 0
    {
        libc::mount(
            p.resolv_source.as_ptr(),
            p.resolv_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        );
    }
    // The TUN to the parent.
    if crate::netns::send_fd_raw(sock, tun) != 0 {
        return NO_BACKEND;
    }
    libc::close(ctl);
    // `sock` has FD_CLOEXEC: execvpe closes it. When execvpe fails, the
    // parent gets the errno.
    libc::execvpe(p.path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    let errno = (*libc::__errno_location()).to_ne_bytes();
    libc::write(sock, errno.as_ptr().cast(), errno.len());
    127
}

/// `struct in6_ifreq` of linux/ipv6.h.
#[repr(C)]
struct In6Ifreq {
    addr: libc::in6_addr,
    prefixlen: u32,
    ifindex: libc::c_int,
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

unsafe fn add_ipv6(named: &libc::ifreq, v6: Ipv6Addr) {
    let ctl6 = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if ctl6 < 0 {
        return;
    }
    let mut index = *named;
    if libc::ioctl(
        ctl6,
        libc::SIOCGIFINDEX as _,
        &mut index as *mut libc::ifreq,
    ) < 0
    {
        libc::close(ctl6);
        return;
    }
    let ifindex = index.ifr_ifru.ifru_ifindex;
    let mut req = In6Ifreq {
        addr: libc::in6_addr {
            s6_addr: v6.octets(),
        },
        prefixlen: 128,
        ifindex,
    };
    if libc::ioctl(ctl6, libc::SIOCSIFADDR as _, &mut req as *mut In6Ifreq) == 0 {
        let mut rt: In6Rtmsg = std::mem::zeroed();
        rt.dst_len = 0;
        rt.metric = 1;
        rt.flags = libc::RTF_UP as u32;
        rt.ifindex = ifindex;
        libc::ioctl(ctl6, libc::SIOCADDRT as _, &mut rt as *mut In6Rtmsg);
    }
    libc::close(ctl6);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Issue 251: a program that cannot be run is an error that names it
    // (before: Ok, and the child exited 127 with no message).
    #[test]
    fn a_program_that_cannot_run_is_an_error() {
        if !available() {
            eprintln!("skip: this host cannot make the namespace");
            return;
        }
        let err = spawn(&RawOptions {
            program: vec!["/nonexistent/prog".into()],
            keep_proxy_env: false,
            v4: Ipv4Addr::new(172, 16, 0, 2),
            v6: None,
            mtu: 1280,
            nameserver: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        })
        .expect_err("a missing program");
        let exec = err.downcast_ref::<ExecError>().expect("an ExecError");
        assert_eq!(exec.error.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("/nonexistent/prog"), "{err}");
    }

    #[test]
    fn a_program_that_runs_gives_the_pod() {
        if !available() {
            eprintln!("skip: this host cannot make the namespace");
            return;
        }
        let pod = spawn(&RawOptions {
            program: vec!["true".into()],
            keep_proxy_env: false,
            v4: Ipv4Addr::new(172, 16, 0, 2),
            v6: None,
            mtu: 1280,
            nameserver: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        })
        .unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let code = loop {
            if let Some(code) = try_wait(pod.pid) {
                break code;
            }
            assert!(std::time::Instant::now() < until, "true did not end");
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(code, 0);
    }
}
