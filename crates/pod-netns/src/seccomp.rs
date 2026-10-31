#[allow(unused_imports)]
use crate::prelude::*;

// ── seccomp user-notification backend ───────────────────────────────────────
//
// Where a network namespace is denied, a seccomp filter that returns
// `SECCOMP_RET_USER_NOTIF` still lets a supervisor mediate syscalls without any
// `LD_PRELOAD`. This backend intercepts `socket(2)` and hands the child a
// socketpair end with `SECCOMP_IOCTL_NOTIF_ADDFD`; the child's own `connect(2)`
// is then answered by the supervisor, which dials the proxy and splices. Only
// `socket` and `connect` need emulating for TCP, because the socketpair carries
// the bytes natively. UDP port 53 is answered from the fake-IP pool.

pub(crate) const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub(crate) const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
pub(crate) const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub(crate) const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
pub(crate) const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;
pub(crate) const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub(crate) const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SeccompData {
    pub(crate) nr: i32,
    pub(crate) arch: u32,
    pub(crate) instruction_pointer: u64,
    pub(crate) args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SeccompNotif {
    pub(crate) id: u64,
    pub(crate) pid: u32,
    pub(crate) flags: u32,
    pub(crate) data: SeccompData,
}

#[repr(C)]
pub(crate) struct SeccompNotifResp {
    pub(crate) id: u64,
    pub(crate) val: i64,
    pub(crate) error: i32,
    pub(crate) flags: u32,
}

#[repr(C)]
pub(crate) struct SeccompNotifAddfd {
    pub(crate) id: u64,
    pub(crate) flags: u32,
    pub(crate) srcfd: u32,
    pub(crate) newfd: u32,
    pub(crate) newfd_flags: u32,
}

/// The syscalls the filter stops. Everything else is allowed untouched.
pub(crate) fn intercepted_syscalls() -> [libc::c_long; 17] {
    [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_bind,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_io_uring_setup,
        libc::SYS_close,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

/// Find `name` as `execvp` does: a name with a `/` is used as it is; another
/// name is looked up in the directories of `PATH`.
pub(crate) fn resolve_program(name: &str) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if name.contains('/') {
        return Ok(std::path::PathBuf::from(name));
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if let Ok(meta) = std::fs::metadata(&candidate) {
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                return Ok(candidate);
            }
        }
    }
    bail!("the program {name:?} is not in PATH")
}

/// The audit arch value of this build target.
#[cfg(target_arch = "x86_64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
#[cfg(target_arch = "riscv64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_00F3;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
compile_error!("pod-netns: add the AUDIT_ARCH value for this target");

/// The x32 system-call bit on x86_64. Zero on other targets.
#[cfg(target_arch = "x86_64")]
pub(crate) const X32_SYSCALL_BIT: u32 = 0x4000_0000;
#[cfg(not(target_arch = "x86_64"))]
pub(crate) const X32_SYSCALL_BIT: u32 = 0;

pub(crate) fn install_notif_filter() -> Result<RawFd> {
    const BPF_LD_ABS_W: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    // seccomp_data: nr at offset 0, arch at offset 4.
    const OFFSET_ARCH: u32 = 4;

    // An unprivileged task can install a filter only with no_new_privs set.
    // The flag is inherited by the child and kept across execve.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NO_NEW_PRIVS)");
    }

    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    // A system call from a different ABI (i386 on x86_64, for example) has
    // different numbers and would pass the list below. Refuse it.
    let mut filter = vec![
        stmt(BPF_LD_ABS_W, OFFSET_ARCH),
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_NATIVE,
        },
        stmt(BPF_RET_K, RET_ERRNO | libc::ENOSYS as u32),
        stmt(BPF_LD_ABS_W, 0),
    ];
    if X32_SYSCALL_BIT != 0 {
        // x32 system calls use the native arch value with this bit set.
        filter.push(libc::sock_filter {
            code: BPF_JGE_K,
            jt: 0,
            jf: 1,
            k: X32_SYSCALL_BIT,
        });
        filter.push(stmt(BPF_RET_K, RET_ERRNO | libc::ENOSYS as u32));
    }
    for syscall in intercepted_syscalls() {
        filter.push(libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: RET_USER_NOTIF,
        });
    }
    filter.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    });

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("seccomp(NEW_LISTENER)");
    }
    Ok(r as RawFd)
}

/// Read `len` bytes from the child at `addr`.
pub(crate) fn read_mem(mem: RawFd, addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        let n = unsafe {
            libc::pread(
                mem,
                buf[off..].as_mut_ptr() as *mut _,
                len - off,
                (addr as i64) + off as i64,
            )
        };
        if n <= 0 {
            bail!("pread(/proc/pid/mem): {}", std::io::Error::last_os_error());
        }
        off += n as usize;
    }
    Ok(buf)
}

/// Write `data` into the child at `addr`.
pub(crate) fn write_mem(mem: RawFd, addr: u64, data: &[u8]) -> Result<()> {
    let mut off = 0;
    while off < data.len() {
        let n = unsafe {
            libc::pwrite(
                mem,
                data[off..].as_ptr() as *const _,
                data.len() - off,
                (addr as i64) + off as i64,
            )
        };
        if n <= 0 {
            bail!("pwrite(/proc/pid/mem): {}", std::io::Error::last_os_error());
        }
        off += n as usize;
    }
    Ok(())
}

pub(crate) fn sockaddr_in(family: u16, ip: IpAddr, port: u16) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&family.to_ne_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[4..8].copy_from_slice(&v4.octets());
            b
        }
        IpAddr::V6(v6) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&family.to_ne_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[8..24].copy_from_slice(&v6.octets());
            b
        }
    }
}

pub(crate) fn parse_sockaddr(bytes: &[u8]) -> Option<(u16, IpAddr, u16)> {
    if bytes.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family as i32 {
        libc::AF_INET if bytes.len() >= 8 => Some((
            family,
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port,
        )),
        libc::AF_INET6 if bytes.len() >= 24 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&bytes[8..24]);
            Some((family, IpAddr::V6(o.into()), port))
        }
        _ => None,
    }
}

pub(crate) fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        bail!("fcntl(F_GETFL): {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        bail!("fcntl(F_SETFL): {}", std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn notif_addfd_send(lfd: RawFd, id: u64, srcfd: RawFd, newfd_flags: u32) -> Result<i32> {
    let req = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: srcfd as u32,
        newfd: 0,
        newfd_flags,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD as _, &req) };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("NOTIF_ADDFD");
    }
    Ok(r)
}

pub(crate) fn notif_respond(lfd: RawFd, id: u64, val: i64, error: i32) -> Result<()> {
    let resp = SeccompNotifResp {
        id,
        val,
        error,
        flags: 0,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        // ENOENT means the target died or the syscall was interrupted.
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(e).context("NOTIF_SEND");
    }
    Ok(())
}

pub(crate) fn notif_continue(lfd: RawFd, id: u64) -> Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(e).context("NOTIF_SEND(CONTINUE)");
    }
    Ok(())
}

/// A live SOCKS5 UDP association: the relay socket, its address, and the TCP
/// control connection that must stay open for the association to live.
pub(crate) struct UdpRelay {
    pub(crate) udp: Arc<tokio::net::UdpSocket>,
    pub(crate) relay_addr: SocketAddr,
    pub(crate) _control: Upstream,
}

/// A listening socket inside the sandbox. Connections arrive on a unix
/// listener (the only bind a sealed host permits) and are handed to the child's
/// `accept` as injected socketpair ends.
pub(crate) struct Inbound {
    pub(crate) rx: tokio::sync::mpsc::UnboundedReceiver<tokio::net::UnixStream>,
}

pub(crate) enum Sock {
    Stream {
        pair: tokio::net::UnixStream,
        bound: Option<(IpAddr, u16)>,
        inbound: Option<Inbound>,
    },
    Datagram {
        pair: Arc<tokio::net::UnixDatagram>,
        dest: Option<(IpAddr, u16)>,
        relay: Option<UdpRelay>,
    },
}

pub(crate) fn run_seccomp(args: Args) -> Result<i32> {
    if args.proxies.is_empty() {
        bail!("the seccomp backend needs -x (there is no direct mode)");
    }
    // A seccomp filter is per-thread unless TSYNC is used. Install it on a
    // helper thread and fork there: the child inherits the filter, and the
    // listener fd stays in this process's fd table, so no SCM_RIGHTS handshake
    // is needed (the child's own sendmsg is itself intercepted).
    let program = args.program.clone();
    // execv does not search PATH, and the child must not allocate after the
    // fork: find the program here.
    let resolved = resolve_program(&program[0])?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("pod-netns-filter".into())
        .spawn(move || {
            // Built before fork so the child allocates nothing.
            let path = match CString::new(resolved.into_os_string().into_encoded_bytes()) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!("program path: {e}")));
                    return;
                }
            };
            let argv: Vec<CString> = match program
                .iter()
                .map(|a| CString::new(a.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!("argv: {e}")));
                    return;
                }
            };
            let ptrs: Vec<*const libc::c_char> = argv
                .iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            let lfd = match install_notif_filter() {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                let _ = tx.send(Err(anyhow::anyhow!(
                    "fork: {}",
                    std::io::Error::last_os_error()
                )));
                return;
            }
            if pid == 0 {
                // Child: the filter is inherited. execv with no allocation.
                unsafe { libc::execv(path.as_ptr(), ptrs.as_ptr()) };
                unsafe { libc::_exit(127) };
            }
            let _ = tx.send(Ok((lfd, pid)));
        })?;
    let (lfd, pid) = rx.recv().context("filter thread died")??;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(supervise_seccomp(
        lfd,
        pid,
        args.proxies,
        args.rules,
        args.maps,
        args.verbose,
        args.inbound_dir,
    ))
}

pub(crate) async fn supervise_seccomp(
    lfd: RawFd,
    pid: i32,
    proxies: Vec<Proxy>,
    rules: Vec<Rule>,
    maps: Vec<(String, IpAddr)>,
    verbose: bool,
    inbound_dir: std::path::PathBuf,
) -> Result<i32> {
    // NOTIF_RECV is non-blocking so the shutdown flag is observed; the fd is
    // also pollable, so the loop sleeps on readiness rather than spinning.
    unsafe { libc::fcntl(lfd, libc::F_SETFL, libc::O_NONBLOCK) };
    let dup = unsafe { OwnedFd::from_raw_fd(libc::dup(lfd)) };
    let async_fd = tokio::io::unix::AsyncFd::with_interest(dup, tokio::io::Interest::READABLE)?;

    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = shutdown.clone();
        tokio::spawn(async move {
            loop {
                let mut status = 0;
                let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if r == pid {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
    }

    let mut map: HashMap<i32, Sock> = HashMap::new();
    let mut dns = FakeDns::new();
    for (name, ip) in &maps {
        dns.pin(name, *ip);
    }

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        // NOTIF_RECV blocks even on an O_NONBLOCK descriptor, so call it only
        // when poll(2) reports a pending notification.
        let guard = tokio::select! {
            guard = async_fd.readable() => guard,
            _ = tokio::time::sleep(Duration::from_millis(50)) => continue,
        };
        let mut guard = guard?;
        let mut pfd = libc::pollfd {
            fd: lfd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, 0) };
        if pfd.revents & libc::POLLIN == 0 {
            guard.clear_ready();
            if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                // No task uses the filter any more.
                break;
            }
            continue;
        }
        let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut req) };
        if r < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                // ENOENT: the child left the system call before it was read.
                Some(libc::EAGAIN) | Some(libc::EINTR) | Some(libc::ENOENT) => continue,
                _ => break,
            }
        }
        let id = req.id;
        let nr = req.data.nr;
        let a = req.data.args;

        // Open the memory of the task that made this call, for each call. A
        // descriptor opened before the child's execve keeps the old address
        // space and reads 0 bytes. A forked grandchild has a different pid.
        let (mem, mem_writable) = open_mem(req.pid);
        // The pid can be reused after the task exits. NOTIF_ID_VALID makes
        // sure the task that made this call is still alive after the open.
        if mem >= 0 && !notif_id_valid(lfd, id) {
            unsafe { libc::close(mem) };
            continue;
        }

        let outcome = if nr == libc::SYS_socket as i32 {
            handle_socket(lfd, id, a, &mut map)
        } else if nr == libc::SYS_connect as i32 {
            handle_connect(
                lfd, id, a, mem, &mut map, &mut dns, &proxies, &rules, verbose,
            )
            .await
        } else if nr == libc::SYS_sendto as i32 {
            handle_sendto(lfd, id, a, mem, &mut map, &mut dns, &proxies).await
        } else if nr == libc::SYS_sendmsg as i32 {
            handle_sendmsg(lfd, id, a, mem, &mut map, &mut dns, &proxies).await
        } else if nr == libc::SYS_sendmmsg as i32 {
            handle_sendmmsg(lfd, id, a, mem, mem_writable, &mut map, &mut dns, &proxies).await
        } else if nr == libc::SYS_setsockopt as i32 {
            // An AF_UNIX socketpair rejects IP-level options, which makes
            // glibc's resolver give up before it ever sends. Pretend.
            if map.contains_key(&(a[0] as i32)) {
                notif_respond(lfd, id, 0, 0)
            } else {
                notif_continue(lfd, id)
            }
        } else if nr == libc::SYS_getsockopt as i32 {
            handle_getsockopt(lfd, id, a, mem, mem_writable, &mut map)
        } else if nr == libc::SYS_close as i32 {
            // Drop the supervisor's end when the child closes an injected fd,
            // or the table and its socketpairs grow for the process lifetime.
            map.remove(&(a[0] as i32));
            notif_continue(lfd, id)
        } else if nr == libc::SYS_io_uring_setup as i32 {
            // io_uring submits network operations without the intercepted
            // syscalls, which would bypass this filter entirely. Refuse it.
            notif_respond(lfd, id, -1, libc::EPERM)
        } else if nr == libc::SYS_bind as i32 {
            handle_bind(lfd, id, a, mem, &mut map)
        } else if nr == libc::SYS_listen as i32 {
            handle_listen(lfd, id, a, &mut map, &inbound_dir).await
        } else if nr == libc::SYS_accept as i32 || nr == libc::SYS_accept4 as i32 {
            handle_accept(lfd, id, a, &mut map, nr == libc::SYS_accept4 as i32).await
        } else if nr == libc::SYS_getsockname as i32 || nr == libc::SYS_getpeername as i32 {
            handle_sockname(lfd, id, a, mem, mem_writable, &mut map)
        } else {
            notif_continue(lfd, id)
        };
        if let Err(e) = outcome {
            if verbose {
                eprintln!("pod-netns: notif {nr}: {e:#}");
            }
            // A handler that fails before it answers must not leave the child
            // blocked. If the handler answered already, the kernel refuses
            // this second answer with ENOENT, which is correct.
            let errno = if nr == libc::SYS_connect as i32 {
                libc::ECONNREFUSED
            } else {
                libc::EIO
            };
            let _ = notif_respond(lfd, id, -1, errno);
        }
        if mem >= 0 {
            unsafe { libc::close(mem) };
        }
    }

    // The child can exit while a relay still carries its last bytes (a server
    // that writes a reply and exits). Let the relays finish, for a short time.
    drain_relays(RELAY_DRAIN).await;

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    Ok(if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    })
}

/// `SECCOMP_IOCTL_NOTIF_ID_VALID`: `_IOW('!', 2, __u64)`.
pub(crate) const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

/// Open `/proc/<pid>/mem`. Try read-write first, because some calls write a
/// result into the child. Return the descriptor (or -1) and whether it is
/// writable.
pub(crate) fn open_mem(pid: u32) -> (RawFd, bool) {
    let Ok(path) = CString::new(format!("/proc/{pid}/mem")) else {
        return (-1, false);
    };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd >= 0 {
        return (fd, true);
    }
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    (fd, false)
}

/// Return true while the notification `id` is still pending.
pub(crate) fn notif_id_valid(lfd: RawFd, id: u64) -> bool {
    let mut id = id;
    unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &mut id) == 0 }
}

/// The number of byte relays that are in progress.
static ACTIVE_RELAYS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The longest time to wait for relays after the child exits.
pub(crate) const RELAY_DRAIN: Duration = Duration::from_secs(3);

/// Spawn a relay task and count it until it ends.
pub(crate) fn spawn_relay<F>(relay: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    use std::sync::atomic::Ordering;
    ACTIVE_RELAYS.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        relay.await;
        ACTIVE_RELAYS.fetch_sub(1, Ordering::SeqCst);
    });
}

/// Wait until no relay is in progress, or until `limit` elapses.
pub(crate) async fn drain_relays(limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    while ACTIVE_RELAYS.load(std::sync::atomic::Ordering::SeqCst) > 0
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Above this many tracked descriptors the child is refused more, so a program
/// that leaks sockets cannot grow the supervisor without bound.
pub(crate) const MAX_TRACKED_FDS: usize = 4096;

pub(crate) fn handle_socket(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    if map.len() >= MAX_TRACKED_FDS {
        return notif_respond(lfd, id, -1, libc::EMFILE);
    }
    let domain = a[0] as i32;
    let ty = a[1] as i32;
    let kind = ty & 0xf; // SOCK_STREAM=1, SOCK_DGRAM=2
    let inet = domain == libc::AF_INET || domain == libc::AF_INET6;
    if !inet || (kind != libc::SOCK_STREAM && kind != libc::SOCK_DGRAM) {
        return notif_continue(lfd, id);
    }
    // ADDFD only accepts O_CLOEXEC in newfd_flags on older kernels, so
    // SOCK_NONBLOCK is applied to the shared description instead: the child's
    // fd is a dup of `theirs`, so the flag is inherited.
    let mut newfd_flags = 0u32;
    if ty & libc::SOCK_CLOEXEC != 0 {
        newfd_flags |= libc::O_CLOEXEC as u32;
    }
    let nonblocking = ty & libc::SOCK_NONBLOCK != 0;
    if kind == libc::SOCK_STREAM {
        // A std pair is blocking on both ends; only the supervisor's end is
        // made non-blocking, so the child gets a blocking socket unless it
        // asked for SOCK_NONBLOCK.
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        set_nonblocking(ours.as_raw_fd())?;
        if nonblocking {
            set_nonblocking(theirs.as_raw_fd())?;
        }
        let child_fd = notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
        drop(theirs);
        map.insert(
            child_fd,
            Sock::Stream {
                pair: tokio::net::UnixStream::from_std(ours)?,
                bound: None,
                inbound: None,
            },
        );
    } else {
        let (ours, theirs) = std::os::unix::net::UnixDatagram::pair()?;
        set_nonblocking(ours.as_raw_fd())?;
        if nonblocking {
            set_nonblocking(theirs.as_raw_fd())?;
        }
        let child_fd = notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
        drop(theirs);
        map.insert(
            child_fd,
            Sock::Datagram {
                pair: Arc::new(tokio::net::UnixDatagram::from_std(ours)?),
                dest: None,
                relay: None,
            },
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connect(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
    rules: &[Rule],
    verbose: bool,
) -> Result<()> {
    let fd = a[0] as i32;
    let is_datagram = matches!(map.get(&fd), Some(Sock::Datagram { .. }));
    if !map.contains_key(&fd) {
        return notif_continue(lfd, id);
    }
    let addr = read_mem(mem, a[1], (a[2] as usize).min(128))?;
    let Some((_family, ip, port)) = parse_sockaddr(&addr) else {
        return notif_respond(lfd, id, -1, libc::EAFNOSUPPORT);
    };
    if is_datagram {
        if let Some(Sock::Datagram { dest, .. }) = map.get_mut(&fd) {
            *dest = Some((ip, port));
        }
        return notif_respond(lfd, id, 0, 0);
    }
    let target = match ip {
        IpAddr::V4(v4) => match dns.name_for(v4) {
            Some(name) => format!("{name}:{port}"),
            None => format!("{v4}:{port}"),
        },
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    let chain = select_chain(rules, proxies, &target);
    if verbose {
        eprintln!("pod-netns: connect {target} via {}", chain[0].endpoint());
    }
    match within_timeout("upstream connect", connect_upstream_async(chain, &target)).await {
        Ok(mut upstream) => {
            notif_respond(lfd, id, 0, 0)?;
            if let Some(Sock::Stream { mut pair, .. }) = map.remove(&fd) {
                spawn_relay(async move {
                    let _ = tokio::io::copy_bidirectional(&mut pair, &mut upstream).await;
                });
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("pod-netns: upstream for {target} failed: {e:#}");
            }
            notif_respond(lfd, id, -1, libc::ECONNREFUSED)?;
        }
    }
    Ok(())
}

pub(crate) async fn handle_sendto(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    let fd = a[0] as i32;
    let buf = a[1];
    let len = a[2] as usize;
    let name = a[4];
    let namelen = a[5] as usize;
    let (recorded, pair) = match map.get(&fd) {
        Some(Sock::Datagram { dest, pair, .. }) => (*dest, pair.clone()),
        _ => return notif_continue(lfd, id),
    };
    let target = if name != 0 && namelen >= 4 {
        parse_sockaddr(&read_mem(mem, name, namelen.min(128))?)
            .map(|(_, ip, port)| (ip, port))
            .or(recorded)
    } else {
        recorded
    };
    let Some((ip, port)) = target else {
        return notif_respond(lfd, id, -1, libc::EDESTADDRREQ);
    };
    if port == DNS_PORT {
        let query = read_mem(mem, buf, len)?;
        let Ok(parsed) = crate::dns::ParsedQuery::parse(&query) else {
            return notif_respond(lfd, id, -1, libc::EINVAL);
        };
        let reply = dns.answer(&parsed);
        let _ = pair.send(&reply).await;
        return notif_respond(lfd, id, len as i64, 0);
    }
    let payload = read_mem(mem, buf, len)?;
    match relay_datagram(map, fd, &proxies[0], pair, &payload, ip, port).await {
        Ok(()) => notif_respond(lfd, id, len as i64, 0),
        Err(e) => {
            let _ = notif_respond(lfd, id, -1, libc::ENETUNREACH);
            Err(e)
        }
    }
}

/// `sendmmsg` is what the glibc resolver uses: a vector of `mmsghdr`, for
/// example the A and the AAAA query in one call.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_sendmmsg(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    mem_writable: bool,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    // struct mmsghdr is a struct msghdr (56 bytes), a u32 msg_len and padding.
    const MMSGHDR_SIZE: u64 = 64;
    const MSG_LEN_OFFSET: u64 = 56;
    let fd = a[0] as i32;
    let msgvec = a[1];
    let vlen = (a[2] as usize).min(64);
    if !map.contains_key(&fd) {
        return notif_continue(lfd, id);
    }
    if vlen == 0 {
        return notif_respond(lfd, id, 0, 0);
    }
    // Without write access to the child, msg_len cannot be set. Send one
    // message and report 1: the caller (glibc's resolver, for example) then
    // sends the remaining messages with separate calls.
    let count = if mem_writable { vlen } else { 1 };
    let mut sent = 0usize;
    for index in 0..count {
        let entry = msgvec + index as u64 * MMSGHDR_SIZE;
        match send_msghdr(fd, entry, mem, map, dns, proxies).await? {
            None => return notif_continue(lfd, id),
            Some(Ok(bytes)) => {
                if mem_writable {
                    write_mem(mem, entry + MSG_LEN_OFFSET, &(bytes as u32).to_ne_bytes())?;
                }
                sent += 1;
            }
            Some(Err(errno)) => {
                if sent == 0 {
                    return notif_respond(lfd, id, -1, errno);
                }
                break;
            }
        }
    }
    notif_respond(lfd, id, sent as i64, 0)
}

pub(crate) async fn handle_sendmsg(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    match send_msghdr(a[0] as i32, a[1], mem, map, dns, proxies).await? {
        None => notif_continue(lfd, id),
        Some(Ok(bytes)) => notif_respond(lfd, id, bytes as i64, 0),
        Some(Err(errno)) => notif_respond(lfd, id, -1, errno),
    }
}

/// Send one `struct msghdr` for the child. Return the byte count, or the
/// errno to give the child. `Ok(None)` means: not a socket of ours.
pub(crate) async fn send_msghdr(
    fd: i32,
    msg_ptr: u64,
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<Option<std::result::Result<usize, i32>>> {
    let (recorded, pair) = match map.get(&fd) {
        Some(Sock::Datagram { dest, pair, .. }) => (*dest, pair.clone()),
        _ => return Ok(None),
    };
    // struct msghdr on x86_64: name, namelen, iov, iovlen, control, controllen, flags.
    let hdr = read_mem(mem, msg_ptr, 56)?;
    let name_ptr = u64::from_ne_bytes(hdr[0..8].try_into().unwrap());
    let name_len = u32::from_ne_bytes(hdr[8..12].try_into().unwrap()) as usize;
    let iov_ptr = u64::from_ne_bytes(hdr[16..24].try_into().unwrap());
    let iov_len = u64::from_ne_bytes(hdr[24..32].try_into().unwrap()) as usize;
    let target = if name_ptr != 0 && name_len >= 4 {
        parse_sockaddr(&read_mem(mem, name_ptr, name_len.min(128))?)
            .map(|(_, ip, port)| (ip, port))
            .or(recorded)
    } else {
        recorded
    };
    let Some((ip, port)) = target else {
        return Ok(Some(Err(libc::EDESTADDRREQ)));
    };
    let mut payload = Vec::new();
    for i in 0..iov_len.min(8) {
        let iov = read_mem(mem, iov_ptr + (i as u64) * 16, 16)?;
        let base = u64::from_ne_bytes(iov[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(iov[8..16].try_into().unwrap()) as usize;
        if len == 0 {
            continue;
        }
        payload.extend_from_slice(&read_mem(mem, base, len.min(65536))?);
    }
    if port == DNS_PORT {
        let Ok(parsed) = crate::dns::ParsedQuery::parse(&payload) else {
            return Ok(Some(Err(libc::EINVAL)));
        };
        let reply = dns.answer(&parsed);
        let _ = pair.send(&reply).await;
        return Ok(Some(Ok(payload.len())));
    }
    match relay_datagram(map, fd, &proxies[0], pair, &payload, ip, port).await {
        Ok(()) => Ok(Some(Ok(payload.len()))),
        Err(_) => Ok(Some(Err(libc::ENETUNREACH))),
    }
}

pub(crate) async fn ensure_udp_relay(
    map: &mut HashMap<i32, Sock>,
    fd: i32,
    proxy: &Proxy,
    pair: Arc<tokio::net::UnixDatagram>,
) -> Result<()> {
    if matches!(map.get(&fd), Some(Sock::Datagram { relay: Some(_), .. })) {
        return Ok(());
    }
    if proxy.kind != ProxyKind::Socks5 {
        bail!("UDP relay needs a SOCKS5 proxy");
    }
    let control = within_timeout("udp associate dial", dial_proxy(proxy)).await?;
    let (control, relay_addr) =
        within_timeout("udp associate", socks5_udp_associate(control, proxy)).await?;
    let udp = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    let reader = udp.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, _)) = reader.recv_from(&mut buf).await else {
                break;
            };
            if n < 4 {
                continue;
            }
            let off = match buf[3] {
                0x01 => 10,
                0x03 => 4 + 1 + buf[4] as usize + 2,
                0x04 => 22,
                _ => continue,
            };
            if n < off {
                continue;
            }
            let _ = pair.send(&buf[off..n]).await;
        }
    });
    if let Some(Sock::Datagram { relay, .. }) = map.get_mut(&fd) {
        *relay = Some(UdpRelay {
            udp,
            relay_addr,
            _control: control,
        });
    }
    Ok(())
}

/// Wrap a datagram in a SOCKS5 UDP request header and send it to the relay.
pub(crate) async fn relay_datagram(
    map: &mut HashMap<i32, Sock>,
    fd: i32,
    proxy: &Proxy,
    pair: Arc<tokio::net::UnixDatagram>,
    payload: &[u8],
    ip: IpAddr,
    port: u16,
) -> Result<()> {
    ensure_udp_relay(map, fd, proxy, pair).await?;
    let wrapped = wrap_udp(payload, ip, port);
    if let Some(Sock::Datagram { relay: Some(r), .. }) = map.get(&fd) {
        r.udp.send_to(&wrapped, r.relay_addr).await?;
    }
    Ok(())
}

pub(crate) fn handle_bind(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    let fd = a[0] as i32;
    match map.get_mut(&fd) {
        Some(Sock::Stream { bound, .. }) => {
            if a[1] != 0 && a[2] >= 4 {
                if let Some((_, ip, port)) =
                    parse_sockaddr(&read_mem(mem, a[1], (a[2] as usize).min(128))?)
                {
                    *bound = Some((ip, port));
                }
            }
            notif_respond(lfd, id, 0, 0)
        }
        // A datagram socket that binds a local port is a socketpair here.
        Some(Sock::Datagram { .. }) => notif_respond(lfd, id, 0, 0),
        None => notif_continue(lfd, id),
    }
}

/// `listen` creates the real listener the sandbox can have: a unix socket named
/// after the port. A reader task turns accepted connections into a queue that
/// `accept` draws from.
pub(crate) async fn handle_listen(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    map: &mut HashMap<i32, Sock>,
    inbound_dir: &std::path::Path,
) -> Result<()> {
    let fd = a[0] as i32;
    let Some(Sock::Stream {
        bound: Some((_, port)),
        ..
    }) = map.get(&fd)
    else {
        return notif_continue(lfd, id);
    };
    let port = *port;
    std::fs::create_dir_all(inbound_dir)?;
    let path = inbound_dir.join(format!("{port}.sock"));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("bind inbound listener {}", path.display()))?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            if tx.send(conn).is_err() {
                break;
            }
        }
    });
    if let Some(Sock::Stream { inbound, .. }) = map.get_mut(&fd) {
        *inbound = Some(Inbound { rx });
    }
    notif_respond(lfd, id, 0, 0)?;
    // The listener is a real unix socket; say where it is.
    eprintln!(
        "pod-netns: listening on unix:{} (port {port})",
        path.display()
    );
    Ok(())
}

pub(crate) async fn handle_accept(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    map: &mut HashMap<i32, Sock>,
    accept4: bool,
) -> Result<()> {
    let fd = a[0] as i32;
    // The caller's flags are on accept4 only; ADDFD takes just O_CLOEXEC.
    let flags = if accept4 { a[3] as i32 } else { 0 };
    let mut newfd_flags = 0u32;
    if flags & libc::SOCK_CLOEXEC != 0 {
        newfd_flags |= libc::O_CLOEXEC as u32;
    }
    let conn = {
        let Some(Sock::Stream {
            inbound: Some(inc), ..
        }) = map.get_mut(&fd)
        else {
            return notif_continue(lfd, id);
        };
        match inc.rx.recv().await {
            Some(c) => c,
            None => return notif_respond(lfd, id, -1, libc::EINVAL),
        }
    };
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    set_nonblocking(ours.as_raw_fd())?;
    if flags & libc::SOCK_NONBLOCK != 0 {
        set_nonblocking(theirs.as_raw_fd())?;
    }
    // ADDFD with SEND already answers the syscall with the installed fd.
    notif_addfd_send(lfd, id, theirs.as_raw_fd(), newfd_flags)?;
    drop(theirs);
    let mut ours = tokio::net::UnixStream::from_std(ours)?;
    let mut conn = conn;
    spawn_relay(async move {
        let _ = tokio::io::copy_bidirectional(&mut ours, &mut conn).await;
    });
    Ok(())
}

pub(crate) fn handle_getsockopt(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    let fd = a[0] as i32;
    let level = a[1] as i32;
    let optname = a[2] as i32;
    let optval = a[3];
    let optlen_ptr = a[4];
    let Some(entry) = map.get(&fd) else {
        return notif_continue(lfd, id);
    };
    if !writable || optval == 0 || optlen_ptr == 0 {
        return notif_continue(lfd, id);
    }
    let len = read_mem(mem, optlen_ptr, 4)?;
    let len = u32::from_ne_bytes(len[..4].try_into().unwrap()) as usize;
    if len == 0 || len > 256 {
        return notif_continue(lfd, id);
    }
    let mut val = vec![0u8; len];
    if level == libc::SOL_SOCKET && optname == libc::SO_TYPE {
        let ty = match entry {
            Sock::Stream { .. } => libc::SOCK_STREAM,
            Sock::Datagram { .. } => libc::SOCK_DGRAM,
        };
        let b = (ty as u32).to_ne_bytes();
        val[..4].copy_from_slice(&b);
    }
    write_mem(mem, optval, &val)?;
    notif_respond(lfd, id, 0, 0)
}

pub(crate) fn handle_sockname(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    writable: bool,
    map: &mut HashMap<i32, Sock>,
) -> Result<()> {
    let fd = a[0] as i32;
    let Some(entry) = map.get(&fd) else {
        return notif_continue(lfd, id);
    };
    if !writable {
        // Cannot rewrite the caller's sockaddr; let the kernel answer (it will
        // report the AF_UNIX socketpair).
        return notif_continue(lfd, id);
    }
    // Answer with a plausible INET address so a program that checks it does not
    // see an AF_UNIX socketpair.
    let (ip, port) = match entry {
        Sock::Stream { bound, .. } => bound.unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        Sock::Datagram { dest, .. } => dest.unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    };
    let family = if ip.is_ipv4() {
        libc::AF_INET as u16
    } else {
        libc::AF_INET6 as u16
    };
    let bytes = sockaddr_in(family, ip, port);
    let out_len = (bytes.len() as u64).to_ne_bytes();
    write_mem(mem, a[2], &out_len)?;
    if a[1] != 0 {
        write_mem(mem, a[1], &bytes)?;
    }
    notif_respond(lfd, id, 0, 0)
}
