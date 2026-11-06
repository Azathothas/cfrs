//! `podnet warp export --check` (T-074): a test of the data path of the
//! exported device.
//!
//! WARP reads the three reserved bytes of each WireGuard message (bytes 1
//! to 3): the `client_id` of the device. Kernel WireGuard and wg-quick send
//! zeros there. A device that needs the bytes then has fresh handshakes and
//! no data path. The check runs the WireGuard leg of podnet two times, with
//! the reserved bytes and with zeros, and connects to the TCP probe target
//! through each.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};

use crate::warp::ip::{StackConfig, WarpStack};
use crate::warp::session::MasqueSession;
use crate::warp::wg::Peer;

/// The result of the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// TCP goes with zeros: the device works in kernel WireGuard.
    Ok,
    /// TCP goes only with the reserved bytes.
    NeedsReserved,
    /// TCP goes in neither leg.
    Dead,
}

impl Verdict {
    /// The verdict of the two legs.
    pub fn of(reserved: bool, zeros: bool) -> Self {
        match (reserved, zeros) {
            (_, true) => Verdict::Ok,
            (true, false) => Verdict::NeedsReserved,
            (false, false) => Verdict::Dead,
        }
    }

    /// The line of the verdict.
    pub fn text(self) -> &'static str {
        match self {
            Verdict::Ok => "device ok",
            Verdict::NeedsReserved => "needs reserved bytes",
            Verdict::Dead => "device data path dead, use --new",
        }
    }
}

/// The peer of `peer` with zero reserved bytes, as kernel WireGuard sends.
pub fn zeroed(peer: &Peer) -> Peer {
    let mut zero = peer.clone();
    zero.keys.reserved = [0; 3];
    zero
}

/// One leg: the handshake with `peer`, then a TCP connect to `target`
/// through a stack on the leg, in `limit`. The time of the connect.
pub async fn probe(peer: &Peer, target: SocketAddr, limit: Duration) -> Result<Duration> {
    let session = MasqueSession::connect_wg(peer)
        .await
        .context("the WireGuard handshake")?;
    let local = peer
        .v4
        .map(IpAddr::V4)
        .or(peer.v6.map(IpAddr::V6))
        .context("the WireGuard device has no address")?;
    let (tx, rx) = session.split();
    let stack = WarpStack::start(tx, rx, StackConfig::new(local).with_ipv6(peer.v6))?;
    let start = Instant::now();
    let result = tokio::time::timeout(limit, stack.tcp_connect(target)).await;
    stack.close_session("warp export --check");
    match result {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(err)) => Err(err.context(format!("TCP to {target}"))),
        Err(_) => bail!(
            "the handshake is done, and TCP to {target} got no answer in {} ms",
            limit.as_millis()
        ),
    }
}

/// The two legs and the verdict.
pub struct Report {
    /// The leg with the reserved bytes; `None` when the device has none.
    pub reserved: Option<Result<Duration>>,
    /// The leg with zeros.
    pub zeros: Result<Duration>,
    pub verdict: Verdict,
}

/// Run the check of `peer` against `target`.
pub async fn run(peer: &Peer, target: SocketAddr, limit: Duration) -> Report {
    let reserved = if peer.keys.reserved == [0; 3] {
        None
    } else {
        Some(probe(peer, target, limit).await)
    };
    let zeros = probe(&zeroed(peer), target, limit).await;
    let verdict = Verdict::of(reserved.as_ref().is_some_and(|r| r.is_ok()), zeros.is_ok());
    Report {
        reserved,
        zeros,
        verdict,
    }
}

impl Report {
    /// One line for each leg, then the verdict. No line holds a key or the
    /// reserved bytes.
    pub fn lines(&self, target: SocketAddr) -> Vec<String> {
        let leg = |name: &str, r: &Result<Duration>| match r {
            Ok(took) => format!("{name}: TCP to {target} in {} ms", took.as_millis()),
            Err(err) => format!("{name}: {err:#}"),
        };
        let mut out = Vec::new();
        match &self.reserved {
            Some(r) => out.push(leg("with the reserved bytes", r)),
            None => out.push("with the reserved bytes: the device has none".into()),
        }
        out.push(leg("with zeros (kernel WireGuard, wg-quick)", &self.zeros));
        out.push(self.verdict.text().into());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warp::wg::standin::{self, DataPath};

    /// T-074: the leg with zeros changes bytes 1 to 3 of each message, and
    /// no other byte. The AEAD does not cover them, so the peer opens both.
    #[test]
    fn a_seal_with_zero_reserved_differs_in_three_bytes() {
        let (keys, _) = standin::keys([1, 2, 3]);
        let peer = Peer {
            keys,
            endpoint: "127.0.0.1:2408".parse().unwrap(),
            v4: None,
            v6: None,
        };
        let zero = zeroed(&peer);
        assert_eq!(zero.keys.reserved, [0; 3]);
        assert_eq!(zero.keys.private, peer.keys.private);
        let mut packet = vec![0x45, 0, 0, 28];
        packet.resize(28, 9);
        let key = [5u8; 32];
        let with = standin::session(key).seal(&peer.keys.reserved, &packet);
        let without = standin::session(key).seal(&zero.keys.reserved, &packet);
        assert_eq!(with.len(), without.len());
        let differ: Vec<usize> = (0..with.len()).filter(|&i| with[i] != without[i]).collect();
        assert_eq!(differ, vec![1, 2, 3]);
        assert_eq!(&without[1..4], &[0, 0, 0]);
        let mut back = standin::session(key);
        (back.local, back.remote) = (2, 1);
        assert_eq!(back.open(&with).unwrap(), packet);
        let mut back = standin::session(key);
        (back.local, back.remote) = (2, 1);
        assert_eq!(back.open(&without).unwrap(), packet);
    }

    #[test]
    fn the_verdict_of_the_two_legs() {
        assert_eq!(Verdict::of(true, true), Verdict::Ok);
        assert_eq!(Verdict::of(false, true), Verdict::Ok);
        assert_eq!(Verdict::of(true, false), Verdict::NeedsReserved);
        assert_eq!(Verdict::of(false, false), Verdict::Dead);
        assert_eq!(Verdict::Dead.text(), "device data path dead, use --new");
    }

    /// The check against the stand-in of the front door: a device that
    /// works, one that needs the reserved bytes, and a dead one.
    #[tokio::test]
    async fn export_check_tells_the_three_states() {
        crate::test_host::need_loopback!();
        let target: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let limit = Duration::from_millis(500);
        for (path, verdict) in [
            (DataPath::All, Verdict::Ok),
            (DataPath::NeedsReserved, Verdict::NeedsReserved),
            (DataPath::Dead, Verdict::Dead),
        ] {
            let peer = standin::start([1, 2, 3], path).await;
            let report = run(&peer, target, limit).await;
            let lines = report.lines(target);
            assert_eq!(report.verdict, verdict, "{path:?}: {lines:?}");
            assert_eq!(lines.last().unwrap(), verdict.text());
            assert!(lines.iter().all(|l| !l.contains("1,2,3")), "{lines:?}");
        }
    }
}
