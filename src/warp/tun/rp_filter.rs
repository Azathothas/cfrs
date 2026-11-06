//! The reverse path filter of the TUN of `warp tun` (T-072).
//!
//! On a host with systemd, each new interface can get `rp_filter` 2 (loose)
//! from systemd-sysctl. When the only egress is a loopback proxy and the
//! WAN routes are in their own tables, the filter drops the replies that
//! come in on the TUN. `warp tun` writes 0 for its interface after the
//! create, again 2 s later (udev can run after podnet), and at each new
//! session. The kernel uses the larger value of `conf.all` and
//! `conf.<interface>`: a warning names a value that stays above 0.
//! `--keep-rp-filter` keeps the value of the host.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::warn;

static KEEP: AtomicBool = AtomicBool::new(false);

/// `--keep-rp-filter`: do not write `rp_filter`.
pub fn set_keep(keep: bool) {
    KEEP.store(keep, Ordering::SeqCst);
}

/// The value that the kernel uses: the larger of `conf.all` and
/// `conf.<interface>`.
pub fn effective(all: u32, interface: u32) -> u32 {
    all.max(interface)
}

fn file(root: &Path, conf: &str) -> PathBuf {
    root.join(conf).join("rp_filter")
}

fn read(root: &Path, conf: &str) -> Option<u32> {
    std::fs::read_to_string(file(root, conf))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Write 0 for `interface` (unless `--keep-rp-filter`), and give the value
/// that the kernel uses, with a warning when it is not 0.
pub fn apply(interface: &str) -> Option<u32> {
    apply_in(
        Path::new("/proc/sys/net/ipv4/conf"),
        interface,
        KEEP.load(Ordering::SeqCst),
    )
}

fn apply_in(root: &Path, interface: &str, keep: bool) -> Option<u32> {
    if !keep && read(root, interface) != Some(0) {
        if let Err(err) = std::fs::write(file(root, interface), "0\n") {
            warn!(interface, error = %err, "warp tun cannot set rp_filter to 0 for its interface");
        }
    }
    let all = read(root, "all")?;
    let own = read(root, interface)?;
    let value = effective(all, own);
    if value != 0 {
        warn!(
            interface,
            all,
            own,
            value,
            "the reverse path filter of the TUN is on: the kernel can drop the replies; write 0 to net.ipv4.conf.all.rp_filter{}",
            if keep { " (--keep-rp-filter keeps the value of the interface)" } else { "" }
        );
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_effective_rp_filter_is_the_larger_value() {
        assert_eq!(effective(0, 0), 0);
        assert_eq!(effective(0, 2), 2);
        assert_eq!(effective(1, 0), 1);
        assert_eq!(effective(2, 1), 2);
    }

    #[test]
    fn warp_tun_writes_0_unless_it_keeps_the_value() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (conf, value) in [("all", "0"), ("podnet0", "2")] {
            std::fs::create_dir_all(root.join(conf)).unwrap();
            std::fs::write(file(root, conf), value).unwrap();
        }
        assert_eq!(apply_in(root, "podnet0", true), Some(2));
        assert_eq!(read(root, "podnet0"), Some(2));
        assert_eq!(apply_in(root, "podnet0", false), Some(0));
        assert_eq!(read(root, "podnet0"), Some(0));
        // conf.all wins over the interface.
        std::fs::write(file(root, "all"), "1").unwrap();
        assert_eq!(apply_in(root, "podnet0", false), Some(1));
        // No file: no value.
        assert_eq!(apply_in(root, "none", false), None);
    }
}
