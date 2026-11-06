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
///
/// The probe does what the backend does (`install_notif_filter`): it sets
/// `no_new_privs` first, because an unprivileged task cannot install a filter
/// without it (`EACCES`). It runs in a forked child, so the flag and the
/// filter do not stay on the doctor process.
pub(crate) fn probe_seccomp_notif() -> Probe {
    const BPF_LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const SET_MODE_FILTER: libc::c_uint = 1;
    const FLAG_NEW_LISTENER: libc::c_uint = 8;
    const NAME: &str = "seccomp(SECCOMP_RET_USER_NOTIF)";

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
    // The child does no allocation: the doctor process can have threads.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Probe {
            name: NAME,
            ok: false,
            detail: format!("fork: {}", std::io::Error::last_os_error()),
        };
    }
    if pid == 0 {
        let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            unsafe { libc::_exit(PROBE_NO_NNP_BASE + errno().clamp(1, 50)) };
        }
        let r = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SET_MODE_FILTER,
                FLAG_NEW_LISTENER,
                &prog as *const libc::sock_fprog,
            )
        };
        let code = if r < 0 { errno().clamp(1, 199) } else { 0 };
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    match code {
        0 => Probe {
            name: NAME,
            ok: true,
            detail: "listener installed".into(),
        },
        code if code > PROBE_NO_NNP_BASE => Probe {
            name: NAME,
            ok: false,
            detail: format!(
                "prctl(PR_SET_NO_NEW_PRIVS): {}",
                std::io::Error::from_raw_os_error(code - PROBE_NO_NNP_BASE)
            ),
        },
        -1 => Probe {
            name: NAME,
            ok: false,
            detail: "the probe process was killed".into(),
        },
        code => Probe {
            name: NAME,
            ok: false,
            detail: format!("{}", std::io::Error::from_raw_os_error(code)),
        },
    }
}

/// Child exit codes of [`probe_seccomp_notif`] above this value: `prctl`
/// failed with the errno `code - PROBE_NO_NNP_BASE`.
const PROBE_NO_NNP_BASE: i32 = 200;

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
                format!("{open_error}; process_vm_writev is refused too: getsockname and getpeername fail with EOPNOTSUPP, QUIC clients fail, and a program that reads its own address can crash (a Go program); use --backend netns"),
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
                    serde_json::json!({ "ok": p.ok, "verdict": verdict(p.ok), "detail": p.detail }),
                )
            })
            .collect();
        // T-078: the schema and the verdict words of podnet doctor.
        root.insert("schema".into(), SCHEMA.into());
        root.insert("capabilities".into(), capabilities.into());
        root.insert(
            "verdicts".into(),
            serde_json::json!({
                "netns": verdict(netns_available),
                "seccomp": verdict(seccomp_available),
                "any": verdict(any),
            }),
        );
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

    println!("podnet-netns: capability report");
    for p in &probes {
        println!("  {:<34} {:<5} {}", p.name, verdict(p.ok), p.detail);
    }
    println!(
        "podnet-netns: backend netns:   {}",
        verdict(netns_available)
    );
    println!(
        "podnet-netns: backend seccomp: {}",
        if !seccomp_available {
            "fail"
        } else if probes[5].ok {
            "ok"
        } else {
            "ok (getsockname/getpeername: fail)"
        }
    );
    println!("podnet-netns: the host conditions that podnet handles: https://github.com/PodUtils/podnet/blob/main/docs/target-environment.md");
    if any {
        0
    } else {
        EXIT_NO_BACKEND
    }
}

/// The version of the JSON form of `pod doctor` (T-078).
pub const SCHEMA: u32 = 1;

/// The verdict word of `podnet doctor` for a probe that passed or failed.
pub fn verdict(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "fail"
    }
}

#[cfg(test)]
mod tests {
    /// Issue 299: the probe must agree with the filter of the backend. A
    /// task with no `CAP_SYS_ADMIN` and `no_new_privs` clear (an unprivileged
    /// user) can install the filter of the backend, because the backend sets
    /// `no_new_privs`. Before, the probe did not set it and said `no`
    /// (`EACCES`). The test drops root in a child to make that task.
    #[test]
    fn the_seccomp_probe_agrees_with_the_backend_filter() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            if unsafe { libc::geteuid() } == 0 {
                // nobody: no capabilities after the change of the uid.
                unsafe {
                    libc::setresgid(65534, 65534, 65534);
                    libc::setresuid(65534, 65534, 65534);
                }
            }
            let probe = super::probe_seccomp_notif().ok;
            let backend = crate::seccomp::install_notif_filter().is_ok();
            unsafe { libc::_exit(i32::from(probe) | (i32::from(backend) << 1)) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child did not exit");
        let code = libc::WEXITSTATUS(status);
        let probe = code & 1 != 0;
        let backend = code & 2 != 0;
        assert_eq!(
            probe, backend,
            "probe_seccomp_notif says {probe}, install_notif_filter says {backend}"
        );
    }
}
