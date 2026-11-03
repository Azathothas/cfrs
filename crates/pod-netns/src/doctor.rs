#[allow(unused_imports)]
use crate::prelude::*;

// ── capability probes ───────────────────────────────────────────────────────

pub(crate) struct Probe {
    pub(crate) name: &'static str,
    pub(crate) ok: bool,
    pub(crate) detail: String,
}

pub(crate) fn probe_unshare(flags: libc::c_int) -> Probe {
    // Probe in a forked child: a successful unshare would otherwise take the
    // probe process out of the host's network namespace permanently.
    //
    // A successful unshare is not sufficient. A security module (for example
    // the AppArmor setting `apparmor_restrict_unprivileged_userns`) can remove
    // the capabilities in the new user namespace. Thus the child also does
    // what the backend does: bring up `lo` and make a TUN device.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::unshare(flags) };
        let code = if r != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(1)
        } else if bringup_loopback().is_err() {
            PROBE_NO_LOOPBACK
        } else if create_tun("pnprobe0").is_err() {
            PROBE_NO_TUN
        } else {
            0
        };
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let name = if flags == libc::CLONE_NEWNET {
        "unshare(CLONE_NEWNET)"
    } else {
        "unshare(NEWUSER|NEWNET)"
    };
    if code == 0 {
        Probe {
            name,
            ok: true,
            detail: "ok".into(),
        }
    } else {
        let detail = match code {
            PROBE_NO_LOOPBACK => "unshare ok, but lo cannot be set up (no capability)".to_string(),
            PROBE_NO_TUN => "unshare ok, but no TUN device in the namespace".to_string(),
            code => format!("{}", std::io::Error::from_raw_os_error(code)),
        };
        Probe {
            name,
            ok: false,
            detail,
        }
    }
}

/// Child exit codes of [`probe_unshare`] after a successful `unshare`.
const PROBE_NO_LOOPBACK: i32 = 200;
const PROBE_NO_TUN: i32 = 201;

pub(crate) fn probe_tun() -> Probe {
    let path = c"/dev/net/tun";
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Probe {
            name: "open(/dev/net/tun)",
            ok: false,
            detail: format!("{e}"),
        };
    }
    unsafe { libc::close(fd) };
    Probe {
        name: "open(/dev/net/tun)",
        ok: true,
        detail: "ok".into(),
    }
}

pub(crate) fn probe_ptrace() -> Probe {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
        if r != 0 {
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::raise(libc::SIGSTOP) };
        unsafe { libc::_exit(0) };
    }
    // The child is our tracer's child, so its SIGSTOP is a ptrace-stop; use
    // WUNTRACED so a plain stop is still reported if TRACEME failed silently.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    let stopped = libc::WIFSTOPPED(status);
    let detail = if stopped {
        "descendant ptrace allowed".to_string()
    } else {
        "ptrace not permitted".to_string()
    };
    unsafe {
        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
    Probe {
        name: "PTRACE_TRACEME (not a backend)",
        ok: stopped,
        detail,
    }
}

/// Can a seccomp filter that returns `SECCOMP_RET_USER_NOTIF` be installed and
/// handed a listener fd? That is the only `LD_PRELOAD`-free interception left
/// when namespaces and ptrace are both denied.
pub(crate) fn probe_seccomp_notif() -> Probe {
    pub(crate) const BPF_LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    pub(crate) const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    pub(crate) const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
    pub(crate) const RET_USER_NOTIF: u32 = 0x7fc0_0000;
    pub(crate) const RET_ALLOW: u32 = 0x7fff_0000;
    pub(crate) const SET_MODE_FILTER: libc::c_uint = 1;
    pub(crate) const FLAG_NEW_LISTENER: libc::c_uint = 8;

    let filter = [
        libc::sock_filter {
            code: BPF_LD_ABS_W,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_getpid as u32,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: RET_USER_NOTIF,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: RET_ALLOW,
        },
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SET_MODE_FILTER,
            FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        return Probe {
            name: "seccomp(SECCOMP_RET_USER_NOTIF)",
            ok: false,
            detail: format!("{}", std::io::Error::last_os_error()),
        };
    }
    let fd = r as RawFd;
    unsafe { libc::close(fd) };
    Probe {
        name: "seccomp(SECCOMP_RET_USER_NOTIF)",
        ok: true,
        detail: "listener installed".into(),
    }
}

/// Can the supervisor write a child's memory? That is what faking
/// `getsockname`/`getpeername`/`accept` addresses needs.
pub(crate) fn probe_mem_write() -> Probe {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut b = [0u8; 1];
        unsafe { libc::read(0, b.as_mut_ptr() as *mut _, 0) };
        unsafe { libc::_exit(0) };
    }
    let path = CString::new(format!("/proc/{pid}/mem")).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    // Issue 98: process_vm_writev is the second path of the supervisor.
    let (ok, detail) = if fd >= 0 {
        unsafe { libc::close(fd) };
        (true, "O_RDWR on /proc/<pid>/mem".to_string())
    } else {
        let open_error = std::io::Error::last_os_error();
        if crate::seccomp::process_vm_writable(pid as u32) {
            (
                true,
                format!("process_vm_writev (the open gave: {open_error})"),
            )
        } else {
            (
                false,
                format!("{open_error}; process_vm_writev is refused too: getsockname and getpeername fail with EOPNOTSUPP, QUIC clients fail"),
            )
        }
    };
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    Probe {
        name: "write program memory",
        ok,
        detail,
    }
}

pub(crate) fn doctor(json: bool) -> i32 {
    let probes = [
        probe_unshare(libc::CLONE_NEWNET),
        probe_unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET),
        probe_tun(),
        probe_ptrace(),
        probe_seccomp_notif(),
        probe_mem_write(),
    ];
    let netns_available = (probes[0].ok || probes[1].ok) && probes[2].ok;
    let seccomp_available = probes[4].ok;
    let any = netns_available || seccomp_available;

    if json {
        let mut root = serde_json::Map::new();
        let capabilities: serde_json::Map<String, serde_json::Value> = probes
            .iter()
            .map(|p| {
                (
                    p.name.to_string(),
                    serde_json::json!({ "ok": p.ok, "detail": p.detail }),
                )
            })
            .collect();
        root.insert("capabilities".into(), capabilities.into());
        root.insert("backend_netns".into(), netns_available.into());
        root.insert("backend_seccomp".into(), seccomp_available.into());
        root.insert("backend_available".into(), any.into());
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(root))
                .unwrap_or_else(|_| "{}".to_string())
        );
        return if any { 0 } else { EXIT_NO_BACKEND };
    }

    println!("pod-netns: capability report");
    for p in &probes {
        println!(
            "  {:<34} {:<5} {}",
            p.name,
            if p.ok { "ok" } else { "no" },
            p.detail
        );
    }
    println!(
        "pod-netns: backend netns:   {}",
        if netns_available {
            "available"
        } else {
            "unavailable"
        }
    );
    println!(
        "pod-netns: backend seccomp: {}",
        if !seccomp_available {
            "unavailable"
        } else if probes[5].ok {
            "available"
        } else {
            "available (getsockname/getpeername: unavailable)"
        }
    );
    println!("pod-netns: the host conditions that cfrs handles: https://github.com/Azathothas/cfrs/blob/main/docs/target-environment.md");
    if any {
        0
    } else {
        EXIT_NO_BACKEND
    }
}
