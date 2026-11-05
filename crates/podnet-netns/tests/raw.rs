//! The raw IP pod (issue 79), with no network: the program sends one UDP
//! datagram with the text of its /etc/resolv.conf; the test reads the IP
//! packet from the TUN of the pod and checks its addresses and its text.

use std::io::Read as _;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::time::{Duration, Instant};

fn python() -> Option<String> {
    ["python3", "python"]
        .iter()
        .find(|p| {
            std::process::Command::new(p)
                .arg("-c")
                .arg("pass")
                .status()
                .is_ok_and(|s| s.success())
        })
        .map(|p| p.to_string())
}

#[test]
fn a_raw_pod_gives_the_ip_packets_of_its_program() {
    if !podnet_netns::raw::available() {
        eprintln!("skipping: no user namespace or no /dev/net/tun");
        return;
    }
    let Some(python) = python() else {
        eprintln!("skipping: no python");
        return;
    };
    let v4 = Ipv4Addr::new(172, 16, 0, 2);
    let opts = podnet_netns::raw::RawOptions {
        program: vec![
            python,
            "-c".into(),
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(open('/etc/resolv.conf','rb').read(), ('1.2.3.4', 9))".into(),
        ],
        keep_proxy_env: false,
        v4,
        v6: None,
        mtu: 1280,
        nameserver: "1.1.1.1".parse().unwrap(),
    };
    let pod = match podnet_netns::raw::spawn(&opts) {
        Ok(pod) => pod,
        Err(err) => {
            // A host where the namespace cannot bring up its interfaces
            // (AppArmor on GitHub runners) cannot run this backend.
            eprintln!("skipping: {err:#}");
            return;
        }
    };
    // SAFETY: a duplicate of the TUN descriptor that the pod gave.
    let mut tun = unsafe { std::fs::File::from_raw_fd(libc::dup(pod.tun.as_raw_fd())) };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = vec![0u8; 2048];
    loop {
        assert!(Instant::now() < deadline, "no UDP packet from the pod");
        let n = tun.read(&mut buf).unwrap();
        let packet = &buf[..n];
        // IPv4, UDP, to 1.2.3.4:9.
        if n < 28 || packet[0] >> 4 != 4 || packet[9] != 17 || packet[16..20] != [1, 2, 3, 4] {
            continue;
        }
        assert_eq!(
            &packet[12..16],
            &v4.octets(),
            "the source is the address of the pod"
        );
        let ihl = (packet[0] & 0x0f) as usize * 4;
        assert_eq!(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]), 9);
        let payload = String::from_utf8_lossy(&packet[ihl + 8..]);
        assert!(payload.contains("nameserver 1.1.1.1"), "{payload}");
        break;
    }
    let until = Instant::now() + Duration::from_secs(10);
    let code = loop {
        if let Some(code) = podnet_netns::raw::try_wait(pod.pid) {
            break code;
        }
        assert!(Instant::now() < until, "the program did not end");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(code, 0);
}
