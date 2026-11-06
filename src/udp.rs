//! UDP egress: does a datagram leave the host and come back?
//!
//! A bind of a UDP socket does not show that a datagram can leave. The probe
//! sends one QUIC packet with a reserved version (RFC 9000 section 15) to an
//! edge address on port 7844. A QUIC server answers it with a Version
//! Negotiation packet. The result is one of three:
//!
//! * answered: a datagram came back;
//! * refused: the send failed, or the host or the network refused the
//!   datagram (an ICMP error on the connected socket);
//! * unknown: no answer before the deadline. A firewall that drops UDP gives
//!   this result, and so does a lost packet.
//!
//! `PODNET_UDP` selects what a tunnel does with UDP: `off` (no QUIC on UDP
//! 7844), `on` (no probe), or `probe` (the default: a short probe; the
//! `quic` leg of `--protocol auto` is skipped only when the result is
//! refused).

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

/// The deadline of the probe of `podnet net doctor`.
pub const DOCTOR_DEADLINE: Duration = Duration::from_secs(3);

/// The deadline of the probe at the start of a tunnel. A local refusal (a
/// firewall rule on this host) comes back in less than this.
pub const START_DEADLINE: Duration = Duration::from_millis(150);

/// The edge address of the probe when `PODNET_EDGE` is not set: an anycast
/// address of the edge, so the probe needs no DNS (the fact `probe-address`
/// of the edge of `pod-services`, on the port of the role `h2`).
pub fn default_probe_target() -> SocketAddr {
    let address = crate::services::text(crate::services::EDGE, "probe-address");
    let ip: std::net::IpAddr = address
        .parse()
        .expect("the probe address of pod-services is an address");
    SocketAddr::new(ip, crate::services::edge_port())
}

/// The result of a probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Egress {
    Answered(String),
    Refused(String),
    Unknown(String),
}

impl Egress {
    pub fn name(&self) -> &'static str {
        match self {
            Egress::Answered(_) => "answered",
            Egress::Refused(_) => "refused",
            Egress::Unknown(_) => "unknown",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Egress::Answered(d) | Egress::Refused(d) | Egress::Unknown(d) => d,
        }
    }
}

/// What a tunnel does with UDP (`PODNET_UDP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// No QUIC on UDP 7844.
    Off,
    /// No probe: the legs keep their order.
    On,
    /// A probe; `--protocol auto` skips QUIC on UDP 7844 when it is refused.
    Probe,
}

impl Choice {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "no" => Ok(Choice::Off),
            "on" | "1" | "yes" => Ok(Choice::On),
            "probe" | "" => Ok(Choice::Probe),
            other => bail!("PODNET_UDP={other:?}: give off, on or probe"),
        }
    }

    /// The choice of `PODNET_UDP`; `probe` when it is not set.
    pub fn from_env() -> Result<Self> {
        match std::env::var("PODNET_UDP") {
            Ok(value) => {
                Self::parse(&value).map_err(|e| crate::exit::fault(crate::exit::Fault::Config, e))
            }
            Err(_) => Ok(Choice::Probe),
        }
    }
}

/// Check `PODNET_EDGE` as `tunnel` does: each entry must be ip:port. The
/// doctors call it, so a bad value is exit 78 there too (issue 66).
pub fn check_edge_env() -> Result<()> {
    let Ok(list) = std::env::var("PODNET_EDGE") else {
        return Ok(());
    };
    for item in list.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        if item.parse::<SocketAddr>().is_err() {
            return Err(crate::exit::fault(
                crate::exit::Fault::Config,
                anyhow::anyhow!("PODNET_EDGE entry {item:?} is not ip:port"),
            ));
        }
    }
    Ok(())
}

/// The target of the probe: the first address of `PODNET_EDGE`, else
/// [`default_probe_target`].
pub fn probe_target() -> SocketAddr {
    std::env::var("PODNET_EDGE")
        .ok()
        .and_then(|list| {
            list.split(',')
                .map(str::trim)
                .find_map(|item| item.parse().ok())
        })
        .unwrap_or_else(default_probe_target)
}

/// One QUIC long-header packet with the reserved version 0x?a?a?a?a and a
/// random connection id, padded to 1200 bytes (a server answers only a
/// packet of at least 1200 bytes).
pub fn packet() -> Vec<u8> {
    let mut dcid = [0u8; 8];
    let _ = getrandom::fill(&mut dcid);
    let mut p = Vec::with_capacity(1200);
    p.push(0xc0);
    p.extend_from_slice(&[0x1a, 0x2a, 0x3a, 0x4a]);
    p.push(dcid.len() as u8);
    p.extend_from_slice(&dcid);
    p.push(0); // no source connection id
    p.resize(1200, 0);
    p
}

/// Send one packet to `target` and wait at most `deadline` for an answer.
/// This blocks: call it from a blocking thread.
pub fn probe(target: SocketAddr, deadline: Duration) -> Egress {
    let local: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = match UdpSocket::bind(local) {
        Ok(s) => s,
        Err(e) => return Egress::Refused(format!("bind: {e}")),
    };
    // A connected socket gets the ICMP errors of the path.
    if let Err(e) = socket.connect(target) {
        return Egress::Refused(format!("connect {target}: {e}"));
    }
    if let Err(e) = socket.send(&packet()) {
        return Egress::Refused(format!("send to {target}: {e}"));
    }
    let end = Instant::now() + deadline;
    let mut buf = [0u8; 1500];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Egress::Unknown(format!(
                "no answer from {target} in {} ms",
                deadline.as_millis()
            ));
        }
        let _ = socket.set_read_timeout(Some(left));
        match socket.recv(&mut buf) {
            Ok(n) => {
                let what = if n >= 5 && buf[0] & 0x80 != 0 && buf[1..5] == [0, 0, 0, 0] {
                    "a QUIC version negotiation"
                } else {
                    "a datagram"
                };
                return Egress::Answered(format!("{what} of {n} bytes from {target}"));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Egress::Refused(format!("{target}: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_peer_is_unknown_not_answered() {
        crate::test_host::need_loopback!();
        // A bound socket that never answers: a bind alone is not an answer.
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let got = probe(silent.local_addr().unwrap(), Duration::from_millis(200));
        assert!(matches!(got, Egress::Unknown(_)), "{got:?}");
        // The packet did leave.
        let mut buf = [0u8; 1500];
        silent.set_nonblocking(true).unwrap();
        let n = silent.recv(&mut buf).unwrap();
        assert_eq!(n, 1200);
        assert_eq!(&buf[1..5], &[0x1a, 0x2a, 0x3a, 0x4a]);
    }

    #[test]
    fn an_answer_is_answered() {
        crate::test_host::need_loopback!();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        let echo = std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (_, from) = peer.recv_from(&mut buf).unwrap();
            // A version negotiation: long header, version 0.
            peer.send_to(&[0x80, 0, 0, 0, 0, 0, 0], from).unwrap();
        });
        let got = probe(addr, Duration::from_secs(2));
        echo.join().unwrap();
        assert!(
            matches!(&got, Egress::Answered(d) if d.contains("version negotiation")),
            "{got:?}"
        );
    }

    #[test]
    fn a_closed_port_is_refused() {
        crate::test_host::need_loopback!();
        let addr = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let got = probe(addr, Duration::from_secs(2));
        assert!(matches!(got, Egress::Refused(_)), "{got:?}");
    }

    #[test]
    fn the_choices() {
        assert_eq!(Choice::parse("off").unwrap(), Choice::Off);
        assert_eq!(Choice::parse("ON").unwrap(), Choice::On);
        assert_eq!(Choice::parse("probe").unwrap(), Choice::Probe);
        assert!(Choice::parse("maybe").is_err());
    }
}
