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
/// `SECCOMP_ADDFD_FLAG_SETFD`: install the fd at the number in `newfd`,
/// in place of the fd that has that number.
pub(crate) const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;

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
pub(crate) fn intercepted_syscalls() -> [libc::c_long; 20] {
    [
        libc::SYS_socket,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
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
        SYS_ACCEPT,
        libc::SYS_accept4,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

/// Read a pointer-sized word (a pointer or a `size_t`) of the child at
/// `offset` of `bytes`.
pub(crate) fn read_word(bytes: &[u8], offset: usize) -> u64 {
    const WORD: usize = std::mem::size_of::<usize>();
    let mut buf = [0u8; WORD];
    buf.copy_from_slice(&bytes[offset..offset + WORD]);
    usize::from_ne_bytes(buf) as u64
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

/// accept(2). i386 has no direct accept system call (only accept4, and
/// accept through socketcall), so the entry is accept4 there.
#[cfg(not(target_arch = "x86"))]
const SYS_ACCEPT: libc::c_long = libc::SYS_accept;
#[cfg(target_arch = "x86")]
const SYS_ACCEPT: libc::c_long = libc::SYS_accept4;

/// The audit arch value of this build target.
#[cfg(target_arch = "x86_64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
#[cfg(target_arch = "arm")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0x4000_0028;
#[cfg(target_arch = "riscv64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_00F3;
#[cfg(target_arch = "x86")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0x4000_0003;
#[cfg(target_arch = "loongarch64")]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_0102;
#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
pub(crate) const AUDIT_ARCH_NATIVE: u32 = 0xC000_0015;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
    target_arch = "x86",
    target_arch = "loongarch64",
    all(target_arch = "powerpc64", target_endian = "little")
)))]
compile_error!("podnet-netns: add the AUDIT_ARCH value for this target");

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
    // seccomp_data: args[] (u64 each) at offset 16.
    const OFFSET_ARG4: u32 = 16 + 4 * 8;

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
    // socketcall(2) multiplexes the socket calls on i386 and powerpc64. The
    // list below names the direct calls only, so socketcall fails: a program
    // then cannot pass around the proxy (the C libraries use the direct
    // calls on the kernels that have them).
    #[cfg(any(target_arch = "x86", target_arch = "powerpc64"))]
    {
        filter.push(libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_socketcall as u32,
        });
        filter.push(stmt(BPF_RET_K, RET_ERRNO | libc::ENOSYS as u32));
    }
    for syscall in intercepted_syscalls() {
        if syscall == libc::SYS_recvfrom {
            // A recvfrom with no source buffer (recv(2), the reads of a TCP
            // program) needs no source address: the kernel runs it, as a
            // read(2). The inbox keeps the order of the sources across such
            // a read (issue 305). The pointer is args[4]; the targets are
            // little-endian, so its low word is first.
            filter.push(libc::sock_filter {
                code: BPF_JEQ_K,
                jt: 0,
                jf: 6,
                k: syscall as u32,
            });
            filter.push(stmt(BPF_LD_ABS_W, OFFSET_ARG4));
            filter.push(libc::sock_filter {
                code: BPF_JEQ_K,
                jt: 0,
                jf: 3,
                k: 0,
            });
            filter.push(stmt(BPF_LD_ABS_W, OFFSET_ARG4 + 4));
            filter.push(libc::sock_filter {
                code: BPF_JEQ_K,
                jt: 0,
                jf: 1,
                k: 0,
            });
            filter.push(stmt(BPF_RET_K, RET_ALLOW));
            filter.push(stmt(BPF_RET_K, RET_USER_NOTIF));
            continue;
        }
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
/// The pid of the notification of now: [`open_mem`] sets it, and
/// [`write_mem`] uses it for `process_vm_writev`. The supervisor handles one
/// notification at a time.
static MEM_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Write `data` at `addr` in the memory of the task of the notification:
/// through `mem` (`/proc/<pid>/mem` opened for writing), else with
/// `process_vm_writev` (issue 98: a host can refuse the write open of the
/// file and allow the system call).
pub(crate) fn write_mem(mem: RawFd, addr: u64, data: &[u8]) -> Result<()> {
    write_mem_to(
        mem,
        MEM_PID.load(std::sync::atomic::Ordering::Relaxed),
        addr,
        data,
    )
}

/// [`write_mem`] for the task `pid`: for a write from a task that does not
/// handle the notification of now (a blocking read).
pub(crate) fn write_mem_to(mem: RawFd, pid: u32, addr: u64, data: &[u8]) -> Result<()> {
    let mut off = 0;
    while off < data.len() {
        let n = if mem >= 0 {
            unsafe {
                libc::pwrite(
                    mem,
                    data[off..].as_ptr() as *const _,
                    data.len() - off,
                    (addr as i64) + off as i64,
                )
            }
        } else {
            -1
        };
        let n = if n > 0 {
            n
        } else {
            let local = libc::iovec {
                iov_base: data[off..].as_ptr() as *mut _,
                iov_len: data.len() - off,
            };
            let remote = libc::iovec {
                iov_base: (addr as usize + off) as *mut _,
                iov_len: data.len() - off,
            };
            // SAFETY: the local buffer is valid for iov_len bytes; the kernel
            // checks the remote range in the other process.
            unsafe { libc::process_vm_writev(pid as i32, &local, 1, &remote, 1, 0) }
        };
        if n <= 0 {
            bail!(
                "writing the memory of the program: {}",
                std::io::Error::last_os_error()
            );
        }
        off += n as usize;
    }
    Ok(())
}

/// Whether `process_vm_writev` to `pid` passes the permission check: a
/// write of one byte to address 1 (never mapped) gives EFAULT when the
/// check passes.
pub(crate) fn process_vm_writable(pid: u32) -> bool {
    let byte = [0u8; 1];
    let local = libc::iovec {
        iov_base: byte.as_ptr() as *mut _,
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: std::ptr::dangling_mut::<u8>() as *mut _,
        iov_len: 1,
    };
    // SAFETY: a one-byte local buffer; the remote address is never mapped.
    let n = unsafe { libc::process_vm_writev(pid as i32, &local, 1, &remote, 1, 0) };
    n >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EFAULT)
}

/// The test hook of the memory path (issue 98): `no-fd` skips the write open
/// of `/proc/<pid>/mem`; `none` also skips `process_vm_writev`.
fn mem_test_hook() -> &'static str {
    static HOOK: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOOK.get_or_init(|| std::env::var("PODNET_NETNS_TEST_MEM").unwrap_or_default())
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

/// Install `srcfd` in the child at the number `target`, in place of the fd
/// that has that number (the syscall is not answered).
pub(crate) fn notif_addfd_setfd(
    lfd: RawFd,
    id: u64,
    srcfd: RawFd,
    target: i32,
    newfd_flags: u32,
) -> Result<i32> {
    let req = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SETFD,
        srcfd: srcfd as u32,
        newfd: target as u32,
        newfd_flags,
    };
    let r = unsafe { libc::ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD as _, &req) };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("NOTIF_ADDFD (SETFD)");
    }
    Ok(r)
}

/// The file status flags of the fd `fd` of the task `pid`
/// (`/proc/<pid>/fdinfo/<fd>`, the line `flags:` in octal).
pub(crate) fn child_fd_flags(pid: u32, fd: i32) -> Option<i32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok()?;
    let value = text.lines().find_map(|l| l.strip_prefix("flags:"))?;
    i32::from_str_radix(value.trim(), 8).ok()
}

/// Answer the notification `id`: the system call returns `val`, or fails
/// with the errno `error` (a positive errno, for example `libc::EPERM`).
pub(crate) fn notif_respond(lfd: RawFd, id: u64, val: i64, error: i32) -> Result<()> {
    let resp = SeccompNotifResp {
        id,
        val,
        // The kernel takes a nonzero error as the return value of the system
        // call, so it must be the negative errno. Before (issue 98), a
        // positive errno was a positive return: getpeername returned 95
        // (EOPNOTSUPP), connect returned 111 (ECONNREFUSED), as successes.
        error: -error.abs(),
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

/// A live SOCKS5 UDP association.
pub(crate) enum UdpRelay {
    /// `UDP ASSOCIATE`: the relay socket, its address, and the control
    /// connection that must stay open for the association to live.
    Socket {
        udp: Arc<tokio::net::UdpSocket>,
        relay_addr: SocketAddr,
        _control: Upstream,
    },
    /// The datagrams go as frames on the control connection (issue 84):
    /// no kernel UDP socket. A writer task owns the write half.
    Stream {
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    },
}

/// A listening socket inside the sandbox. Connections arrive on a unix
/// listener (the only bind a sealed host permits) and are handed to the child's
/// `accept` as injected socketpair ends.
/// The queue of a listener of the child. The child's listener fd is one end
/// of a socketpair: for each queued connection the reader task writes one
/// byte to the other end, so poll, select and epoll on the listener wake.
/// Each accept takes one byte back through `drain` (a copy of the child's
/// end), so the listener is readable while a connection waits, and only
/// then.
pub(crate) struct Inbound {
    pub(crate) rx:
        Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<tokio::net::UnixStream>>>,
    pub(crate) drain: Arc<std::os::unix::net::UnixStream>,
}

pub(crate) enum Sock {
    Stream {
        pair: tokio::net::UnixStream,
        bound: Option<(IpAddr, u16)>,
        inbound: Option<Inbound>,
        /// The pending error of the socket (`SO_ERROR`): the errno of the
        /// last failed connect, 0 when none. A read of `SO_ERROR` clears it.
        error: i32,
        options: crate::sockopt::Options,
    },
    /// A connected TCP socket (T-063): the relay task has its socketpair.
    Connected(crate::sockopt::Connected),
    Datagram {
        pair: Arc<tokio::net::UnixDatagram>,
        dest: Option<(IpAddr, u16)>,
        relay: Option<UdpRelay>,
        /// The receive side: the sources of the datagrams (issue 305).
        inbox: Arc<crate::inbox::Inbox>,
    },
    /// An ICMP datagram socket (T-066): the pod answers an echo to its gateway.
    Icmp(crate::icmp::Icmp),
}

pub(crate) fn run_seccomp(args: Args) -> Result<i32> {
    if args.proxies.is_empty() {
        bail!("the seccomp backend needs -x (there is no direct mode)");
    }
    // Issue 306: the inbound directory is private before the program runs.
    crate::listen::private_dir(&args.inbound_dir)?;
    // A seccomp filter is per-thread unless TSYNC is used. Install it on a
    // helper thread and fork there: the child inherits the filter, and the
    // listener fd stays in this process's fd table, so no SCM_RIGHTS handshake
    // is needed (the child's own sendmsg is itself intercepted).
    let program = args.program.clone();
    // execv does not search PATH, and the child must not allocate after the
    // fork: find the program here.
    let resolved = resolve_program(&program[0])?;
    let mut env = crate::child_env(args.keep_proxy_env);
    crate::with_single_request(&mut env);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("podnet-netns-filter".into())
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
            let envp: Vec<*const libc::c_char> = env
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
                unsafe { libc::execve(path.as_ptr(), ptrs.as_ptr(), envp.as_ptr()) };
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
    let async_fd = crate::readable_copy(lfd)?;

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

    let mut map = crate::fdtable::Table::new(pid);
    let mut dns = FakeDns::new();
    let mut dials = crate::connect::Dials::new();
    let route = crate::connect::Route {
        proxies: &proxies,
        rules: &rules,
        inbound_dir: &inbound_dir,
        verbose,
    };
    dns.v6 = true;
    for (name, ip) in &maps {
        dns.pin(name, *ip);
    }

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        // NOTIF_RECV blocks even on an O_NONBLOCK descriptor, so call it only
        // when poll(2) reports a pending notification.
        // T-067: a dial that ended gets its answer here.
        let guard = tokio::select! {
            guard = async_fd.readable() => guard,
            Some(done) = dials.next() => {
                crate::connect::finish(lfd, done, &mut map, &mut dials, verbose);
                continue;
            }
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
        // T-064: the entry of a socket follows the socket, not the number.
        let key = match nr == libc::SYS_socket as i32 {
            true => 0,
            false => map.key_of(req.pid, a[0] as i32),
        };

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

        let icmp = crate::icmp::handle(lfd, id, nr, a, (mem, mem_writable), (&mut map, key));
        let outcome = if let Some(outcome) = icmp.await {
            outcome
        } else if nr == libc::SYS_socket as i32 {
            crate::socket::handle_socket(lfd, id, a, &mut map, verbose)
        } else if nr == libc::SYS_connect as i32 {
            let entry = (&mut *map, key);
            crate::connect::handle_connect(lfd, id, a, mem, entry, &mut dns, &mut dials, &route)
        } else if nr == libc::SYS_sendto as i32 {
            handle_sendto(lfd, id, a, mem, (&mut map, key), &mut dns, &proxies).await
        } else if nr == libc::SYS_sendmsg as i32 {
            handle_sendmsg(lfd, id, a, mem, (&mut map, key), &mut dns, &proxies).await
        } else if nr == libc::SYS_sendmmsg as i32 {
            handle_sendmmsg(
                lfd,
                id,
                a,
                (mem, mem_writable),
                (&mut map, key),
                &mut dns,
                &proxies,
            )
            .await
        } else if nr == libc::SYS_setsockopt as i32 {
            crate::sockopt::handle_setsockopt(lfd, id, a, mem, (&mut map, key), verbose)
        } else if nr == libc::SYS_getsockopt as i32 {
            crate::sockopt::handle_getsockopt(lfd, id, a, mem, mem_writable, (&mut map, key))
        } else if nr == libc::SYS_close as i32 {
            // Drop the entry when the last copy of the socket closes.
            crate::fdtable::handle_close(lfd, id, a[0] as i32, key, req.pid, &mut map)
        } else if nr == libc::SYS_io_uring_setup as i32 {
            // io_uring submits network operations without the intercepted
            // syscalls, which would bypass this filter entirely. Refuse it.
            notif_respond(lfd, id, -1, libc::EPERM)
        } else if nr == libc::SYS_bind as i32 {
            handle_bind(lfd, id, a, mem, (&mut map, key))
        } else if nr == libc::SYS_listen as i32 {
            handle_listen(lfd, id, a, (&mut map, key), &inbound_dir, req.pid).await
        } else if nr == SYS_ACCEPT as i32 || nr == libc::SYS_accept4 as i32 {
            handle_accept(
                lfd,
                id,
                a,
                (&mut map, key),
                nr == libc::SYS_accept4 as i32,
                req.pid,
            )
            .await
        } else if crate::inbox::is_recv(nr) {
            crate::inbox::handle_recv(lfd, id, a, (mem, mem_writable), &map, key, nr, req.pid)
        } else if nr == libc::SYS_getsockname as i32 || nr == libc::SYS_getpeername as i32 {
            let peer = nr == libc::SYS_getpeername as i32;
            crate::sockopt::handle_sockname(lfd, id, a, mem, mem_writable, (&mut map, key), peer)
        } else {
            notif_continue(lfd, id)
        };
        if let Err(e) = outcome {
            if verbose {
                eprintln!("podnet-netns: notif {nr}: {e:#}");
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
    MEM_PID.store(pid, std::sync::atomic::Ordering::Relaxed);
    let (fd, writable) = open_mem_of(pid);
    if !writable {
        warn_no_mem_write();
    }
    (fd, writable)
}

/// [`open_mem`] with no change of the pid of now and no warning.
pub(crate) fn open_mem_of(pid: u32) -> (RawFd, bool) {
    let Ok(path) = CString::new(format!("/proc/{pid}/mem")) else {
        return (-1, false);
    };
    let hook = mem_test_hook();
    if hook.is_empty() {
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            return (fd, true);
        }
    }
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    // A read-only descriptor: writes go through process_vm_writev, when the
    // host allows it (issue 98).
    let writable = hook != "none" && process_vm_writable(pid);
    (fd, writable)
}

/// Once: the memory of the program cannot be written.
fn warn_no_mem_write() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        crate::warn(
            "warning: this host refuses writes to the memory of the program; \
             getsockname and getpeername fail with EOPNOTSUPP: QUIC clients (curl --http3) fail, and a program \
             that reads its own address can crash (for example a Go program); use --backend netns where it works",
        );
    });
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

pub(crate) async fn handle_sendto(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    (map, fd): (&mut HashMap<Key, Sock>, Key),
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    let buf = a[1];
    let len = a[2] as usize;
    let name = a[4];
    let namelen = a[5] as usize;
    let (recorded, pair, inbox) = match map.get(&fd) {
        Some(Sock::Datagram {
            dest, pair, inbox, ..
        }) => (*dest, pair.clone(), inbox.clone()),
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
    // The length comes from the program: check it before the read.
    if len > MAX_DATAGRAM {
        return notif_respond(lfd, id, -1, libc::EMSGSIZE);
    }
    let Ok(payload) = read_mem(mem, buf, len) else {
        return notif_respond(lfd, id, -1, libc::EFAULT);
    };
    if port == DNS_PORT {
        let Ok(parsed) = crate::dns::ParsedQuery::parse(&payload) else {
            return notif_respond(lfd, id, -1, libc::EINVAL);
        };
        let reply = dns.answer(&parsed);
        let source = crate::inbox::WireSource::Ip(SocketAddr::new(ip, port));
        inbox.deliver(&pair, source, &reply).await;
        return notif_respond(lfd, id, len as i64, 0);
    }
    let name = dns.name_for_ip(ip).map(str::to_string);
    if let Err(errno) = crate::dgram::fits_relay(len, ip, name.as_deref()) {
        return notif_respond(lfd, id, -1, errno);
    }
    match relay_datagram(
        map,
        fd,
        &proxies[0],
        (pair, inbox),
        &payload,
        ip,
        name,
        port,
    )
    .await
    {
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
    (mem, mem_writable): (RawFd, bool),
    (map, fd): (&mut HashMap<Key, Sock>, Key),
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    // struct mmsghdr is a struct msghdr (56 bytes), a u32 msg_len and padding.
    // The layouts of the child are those of this target: same ABI.
    const MMSGHDR_SIZE: u64 = std::mem::size_of::<libc::mmsghdr>() as u64;
    const MSG_LEN_OFFSET: u64 = std::mem::offset_of!(libc::mmsghdr, msg_len) as u64;
    let msgvec = a[1];
    let vlen = (a[2] as usize).min(64);
    if !map.contains_key(&fd) {
        return notif_continue(lfd, id);
    }
    if vlen == 0 {
        return notif_respond(lfd, id, 0, 0);
    }
    // Without write access to the child, msg_len cannot be set. Send one
    // message and report 1. glibc's resolver does not send the others: it
    // reads the msg_len of 0 as a failure. The pod therefore sets
    // RES_OPTIONS=single-request (issue 113), and glibc sends one query in
    // each call.
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
    (map, fd): (&mut HashMap<Key, Sock>, Key),
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<()> {
    match send_msghdr(fd, a[1], mem, map, dns, proxies).await? {
        None => notif_continue(lfd, id),
        Some(Ok(bytes)) => notif_respond(lfd, id, bytes as i64, 0),
        Some(Err(errno)) => notif_respond(lfd, id, -1, errno),
    }
}

/// Send one `struct msghdr` for the child. Return the byte count, or the
/// errno to give the child. `Ok(None)` means: not a socket of ours.
pub(crate) async fn send_msghdr(
    fd: Key,
    msg_ptr: u64,
    mem: RawFd,
    map: &mut HashMap<Key, Sock>,
    dns: &mut FakeDns,
    proxies: &[Proxy],
) -> Result<Option<std::result::Result<usize, i32>>> {
    let (recorded, pair, inbox) = match map.get(&fd) {
        Some(Sock::Datagram {
            dest, pair, inbox, ..
        }) => (*dest, pair.clone(), inbox.clone()),
        _ => return Ok(None),
    };
    // struct msghdr on x86_64: name, namelen, iov, iovlen, control, controllen, flags.
    // struct msghdr of this target (the child has the same ABI).
    let hdr = read_mem(mem, msg_ptr, std::mem::size_of::<libc::msghdr>())?;
    let name_ptr = read_word(&hdr, std::mem::offset_of!(libc::msghdr, msg_name));
    let name_len = u32::from_ne_bytes(
        hdr[std::mem::offset_of!(libc::msghdr, msg_namelen)..][..4]
            .try_into()
            .unwrap(),
    ) as usize;
    let iov_ptr = read_word(&hdr, std::mem::offset_of!(libc::msghdr, msg_iov));
    let iov_len = read_word(&hdr, std::mem::offset_of!(libc::msghdr, msg_iovlen)) as usize;
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
    // The lengths come from the program: check the count of the iovecs and
    // the sum of their lengths before a read (issue 303). Before, only the
    // first 8 iovecs were read, each up to 64 KiB.
    if iov_len > crate::inbox::UIO_MAXIOV {
        return Ok(Some(Err(libc::EMSGSIZE)));
    }
    let size = std::mem::size_of::<libc::iovec>();
    let Ok(iovs) = read_mem(mem, iov_ptr, iov_len * size) else {
        return Ok(Some(Err(libc::EFAULT)));
    };
    let parts: Vec<(u64, usize)> = iovs
        .chunks_exact(size)
        .map(|iov| {
            (
                read_word(iov, std::mem::offset_of!(libc::iovec, iov_base)),
                read_word(iov, std::mem::offset_of!(libc::iovec, iov_len)) as usize,
            )
        })
        .collect();
    let total = parts
        .iter()
        .fold(0usize, |sum, (_, len)| sum.saturating_add(*len));
    if total > MAX_DATAGRAM {
        return Ok(Some(Err(libc::EMSGSIZE)));
    }
    let mut payload = Vec::with_capacity(total);
    for (base, len) in parts {
        if len == 0 {
            continue;
        }
        let Ok(part) = read_mem(mem, base, len) else {
            return Ok(Some(Err(libc::EFAULT)));
        };
        payload.extend_from_slice(&part);
    }
    if port == DNS_PORT {
        let Ok(parsed) = crate::dns::ParsedQuery::parse(&payload) else {
            return Ok(Some(Err(libc::EINVAL)));
        };
        let reply = dns.answer(&parsed);
        let source = crate::inbox::WireSource::Ip(SocketAddr::new(ip, port));
        inbox.deliver(&pair, source, &reply).await;
        return Ok(Some(Ok(payload.len())));
    }
    let name = dns.name_for_ip(ip).map(str::to_string);
    if let Err(errno) = crate::dgram::fits_relay(payload.len(), ip, name.as_deref()) {
        return Ok(Some(Err(errno)));
    }
    match relay_datagram(
        map,
        fd,
        &proxies[0],
        (pair, inbox),
        &payload,
        ip,
        name,
        port,
    )
    .await
    {
        Ok(()) => Ok(Some(Ok(payload.len()))),
        Err(_) => Ok(Some(Err(libc::ENETUNREACH))),
    }
}

pub(crate) async fn ensure_udp_relay(
    map: &mut HashMap<Key, Sock>,
    fd: Key,
    proxy: &Proxy,
    pair: Arc<tokio::net::UnixDatagram>,
    inbox: Arc<crate::inbox::Inbox>,
) -> Result<()> {
    if matches!(map.get(&fd), Some(Sock::Datagram { relay: Some(_), .. })) {
        return Ok(());
    }
    if proxy.kind != ProxyKind::Socks5 {
        bail!("UDP relay needs a SOCKS5 proxy");
    }
    // Issue 84: a proxy on a unix socket (warp proxy, a pod front door)
    // carries the datagrams on the control connection, so no kernel UDP
    // socket is necessary. A server that does not know the command gets
    // UDP ASSOCIATE.
    if proxy.is_unix() {
        let control = within_timeout("udp in the stream dial", dial_proxy(proxy)).await?;
        // On an error (0x07, or a server that closes on a command that it
        // does not know): UDP ASSOCIATE below.
        if let Ok(control) = within_timeout(
            "udp in the stream",
            crate::upstream::socks5_udp_in_stream(control, proxy),
        )
        .await
        {
            {
                let (mut read, mut write) = tokio::io::split(control);
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                tokio::spawn(async move {
                    while let Some(datagram) = rx.recv().await {
                        if crate::upstream::write_udp_frame(&mut write, &datagram)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    while let Ok(Some(datagram)) = crate::upstream::read_udp_frame(&mut read).await
                    {
                        if let Some((source, off)) = crate::inbox::udp_source(&datagram) {
                            inbox.deliver(&pair, source, &datagram[off..]).await;
                        }
                    }
                });
                if let Some(Sock::Datagram { relay, .. }) = map.get_mut(&fd) {
                    *relay = Some(UdpRelay::Stream { tx });
                }
                return Ok(());
            }
        }
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
            if let Some((source, off)) = crate::inbox::udp_source(&buf[..n]) {
                inbox.deliver(&pair, source, &buf[off..n]).await;
            }
        }
    });
    if let Some(Sock::Datagram { relay, .. }) = map.get_mut(&fd) {
        *relay = Some(UdpRelay::Socket {
            udp,
            relay_addr,
            _control: control,
        });
    }
    Ok(())
}

/// Wrap a datagram in a SOCKS5 UDP request header and send it to the relay.
/// Send one datagram of the program through the UDP relay. A fake IP of the
/// pod goes to the proxy as its name (ATYP 3, issue 113): before, the
/// proxy got the fake IP, which no host has.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_datagram(
    map: &mut HashMap<Key, Sock>,
    fd: Key,
    proxy: &Proxy,
    (pair, inbox): (Arc<tokio::net::UnixDatagram>, Arc<crate::inbox::Inbox>),
    payload: &[u8],
    ip: IpAddr,
    name: Option<String>,
    port: u16,
) -> Result<()> {
    ensure_udp_relay(map, fd, proxy, pair, inbox.clone()).await?;
    let wrapped = match name {
        Some(name) => {
            let wire = crate::inbox::WireSource::Name(name.clone(), port);
            inbox.remember(wire, ip, port);
            crate::upstream::wrap_udp_name(payload, &name, port)
        }
        None => {
            let wire = crate::inbox::WireSource::Ip(SocketAddr::new(ip, port));
            inbox.remember(wire, ip, port);
            wrap_udp(payload, ip, port)
        }
    };
    match map.get(&fd) {
        Some(Sock::Datagram {
            relay: Some(UdpRelay::Socket {
                udp, relay_addr, ..
            }),
            ..
        }) => {
            udp.send_to(&wrapped, *relay_addr).await?;
        }
        Some(Sock::Datagram {
            relay: Some(UdpRelay::Stream { tx }),
            ..
        }) if tx.send(wrapped).is_err() => {
            // The association ended: the next datagram opens a new one.
            if let Some(Sock::Datagram { relay, .. }) = map.get_mut(&fd) {
                *relay = None;
            }
            bail!("the UDP association in the stream ended");
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn handle_bind(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    (map, fd): (&mut HashMap<Key, Sock>, Key),
) -> Result<()> {
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
        Some(Sock::Datagram { .. } | Sock::Icmp(_)) => notif_respond(lfd, id, 0, 0),
        // A connected socket is bound already, as in the kernel.
        Some(Sock::Connected(_)) => notif_respond(lfd, id, -1, libc::EINVAL),
        None => notif_continue(lfd, id),
    }
}

/// `listen` creates the real listener the sandbox can have: a unix socket named
/// after the port. A reader task turns accepted connections into a queue that
/// `accept` draws from, and makes the child's listener fd readable while a
/// connection waits (see [`Inbound`]).
pub(crate) async fn handle_listen(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    (map, key): (&mut HashMap<Key, Sock>, Key),
    inbound_dir: &std::path::Path,
    pid: u32,
) -> Result<()> {
    let fd = a[0] as i32;
    let Some(Sock::Stream {
        bound: Some((_, port)),
        ..
    }) = map.get(&key)
    else {
        return notif_continue(lfd, id);
    };
    let port = *port;
    crate::listen::private_dir(inbound_dir)?;
    let path = inbound_dir.join(format!("{port}.sock"));
    let _ = std::fs::remove_file(&path);
    let listener = crate::listen::bind_private(&path)
        .with_context(|| format!("bind inbound listener {}", path.display()))?;

    // The new listener fd of the child: one end of a socketpair, with the
    // O_NONBLOCK and close-on-exec of the old fd.
    let flags = child_fd_flags(pid, fd).unwrap_or(0);
    let (signal, child_end) = std::os::unix::net::UnixStream::pair()?;
    if flags & libc::O_NONBLOCK != 0 {
        set_nonblocking(child_end.as_raw_fd())?;
    }
    let drain = child_end.try_clone()?;
    let newfd_flags = if flags & libc::O_CLOEXEC != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    // The new end is a new socket: the entry moves to its key.
    let new_key = crate::fdtable::inode_of(child_end.as_raw_fd())?;
    notif_addfd_setfd(lfd, id, child_end.as_raw_fd(), fd, newfd_flags)?;
    drop(child_end);
    if let Some(entry) = map.remove(&key) {
        map.insert(new_key, entry);
    }
    set_nonblocking(signal.as_raw_fd())?;
    let mut signal = tokio::net::UnixStream::from_std(signal)?;

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            // The byte first: when accept finds the connection, its byte is
            // there to take.
            if tokio::io::AsyncWriteExt::write_all(&mut signal, &[1])
                .await
                .is_err()
            {
                break;
            }
            if tx.send(conn).is_err() {
                break;
            }
        }
    });
    if let Some(Sock::Stream { inbound, .. }) = map.get_mut(&new_key) {
        *inbound = Some(Inbound {
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            drain: Arc::new(drain),
        });
    }
    notif_respond(lfd, id, 0, 0)?;
    // The listener is a real unix socket; say where it is.
    eprintln!(
        "podnet-netns: listening on unix:{} (port {port})",
        path.display()
    );
    Ok(())
}

/// Take the byte of one queued connection from the child's listener.
fn drain_one(drain: &std::os::unix::net::UnixStream) {
    let mut byte = [0u8; 1];
    unsafe {
        libc::recv(
            drain.as_raw_fd(),
            byte.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_DONTWAIT,
        )
    };
}

/// Give the connection `conn` to the child as the answer of `accept`.
fn install_accepted(
    lfd: RawFd,
    id: u64,
    conn: tokio::net::UnixStream,
    nonblocking: bool,
    newfd_flags: u32,
) -> Result<()> {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    set_nonblocking(ours.as_raw_fd())?;
    if nonblocking {
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

/// `accept` takes a queued connection at once. With none queued, a
/// non-blocking listener gets EAGAIN, and a blocking accept waits in its own
/// task: the other system calls of the child go on (before, one accept that
/// waited stopped each other call of the child).
pub(crate) async fn handle_accept(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    (map, key): (&mut HashMap<Key, Sock>, Key),
    accept4: bool,
    pid: u32,
) -> Result<()> {
    let fd = a[0] as i32;
    // The caller's flags are on accept4 only; ADDFD takes just O_CLOEXEC.
    let flags = if accept4 { a[3] as i32 } else { 0 };
    let mut newfd_flags = 0u32;
    if flags & libc::SOCK_CLOEXEC != 0 {
        newfd_flags |= libc::O_CLOEXEC as u32;
    }
    let nonblocking_conn = flags & libc::SOCK_NONBLOCK != 0;
    let (rx, drain) = {
        let Some(Sock::Stream {
            inbound: Some(inc), ..
        }) = map.get(&key)
        else {
            return notif_continue(lfd, id);
        };
        (inc.rx.clone(), inc.drain.clone())
    };
    let queued = rx.try_lock().ok().and_then(|mut rx| rx.try_recv().ok());
    if let Some(conn) = queued {
        drain_one(&drain);
        return install_accepted(lfd, id, conn, nonblocking_conn, newfd_flags);
    }
    let listener_nonblocking = child_fd_flags(pid, fd).is_some_and(|f| f & libc::O_NONBLOCK != 0);
    if listener_nonblocking {
        return notif_respond(lfd, id, -1, libc::EAGAIN);
    }
    tokio::spawn(async move {
        let conn = rx.lock().await.recv().await;
        match conn {
            Some(conn) => {
                drain_one(&drain);
                // ENOENT: the child left the accept (a signal); the
                // connection is closed.
                let _ = install_accepted(lfd, id, conn, nonblocking_conn, newfd_flags);
            }
            None => {
                let _ = notif_respond(lfd, id, -1, libc::EINVAL);
            }
        }
    });
    Ok(())
}
