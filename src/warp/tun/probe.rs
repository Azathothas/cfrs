//! The TCP probe of the data path of `warp tun` (T-069).
//!
//! The TUN carries the packets of the host, so the probe of T-068 cannot
//! open a socket of a userspace stack here. In its place, `warp tun` puts
//! one TCP SYN into the session: from the address of the tunnel and the
//! reserved port [`PROBE_PORT`] to the probe target. The answer (a SYN-ACK
//! or a RST) to that port does not go to the TUN: [`TunProbe::take`] takes
//! it out, and gives a RST for a SYN-ACK, so that the far end frees its
//! state. After [`crate::warp::live::Probe::misses`] probes with no answer in a
//! row, the session carries no TCP, and `tun::run` ends it.

use std::net::{Ipv4Addr, SocketAddrV4};

/// The source port of the probe. The kernel of the host does not give it:
/// it is above the ephemeral range of Linux (32768 to 60999).
pub const PROBE_PORT: u16 = 61999;

/// The state of the probe of one session.
#[derive(Debug)]
pub struct TunProbe {
    source: Ipv4Addr,
    target: SocketAddrV4,
    misses: u32,
    limit: u32,
    seq: u32,
    waiting: bool,
}

impl TunProbe {
    /// A probe from `source` (the address of the tunnel) to `target`. It
    /// ends the session after `limit` probes with no answer.
    pub fn new(source: Ipv4Addr, target: SocketAddrV4, limit: u32) -> Self {
        TunProbe {
            source,
            target,
            misses: 0,
            limit: limit.max(1),
            seq: 0x5eed_0001,
            waiting: false,
        }
    }

    /// The tick of the probe: the SYN to send, or `Err` when `limit`
    /// probes in a row got no answer.
    pub fn tick(&mut self) -> Result<Vec<u8>, u32> {
        if self.waiting {
            self.misses += 1;
            if self.misses >= self.limit {
                return Err(self.misses);
            }
        }
        self.waiting = true;
        self.seq = self.seq.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        Ok(tcp_packet(
            self.source,
            self.target.ip().to_owned(),
            PROBE_PORT,
            self.target.port(),
            self.seq,
            0,
            SYN,
        ))
    }

    /// When `packet` (from the session) is the answer to the probe: take
    /// it out (it does not go to the TUN), and give the RST to send for a
    /// SYN-ACK (`Some(None)` for a RST). `None`: another packet.
    pub fn take(&mut self, packet: &[u8]) -> Option<Option<Vec<u8>>> {
        let tcp = parse(packet)?;
        if tcp.src != *self.target.ip()
            || tcp.dst != self.source
            || tcp.sport != self.target.port()
            || tcp.dport != PROBE_PORT
        {
            return None;
        }
        self.waiting = false;
        self.misses = 0;
        if tcp.flags & SYN != 0 && tcp.flags & ACK != 0 {
            return Some(Some(tcp_packet(
                self.source,
                tcp.src,
                PROBE_PORT,
                tcp.sport,
                tcp.ack,
                0,
                RST,
            )));
        }
        Some(None)
    }
}

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

struct Tcp {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    ack: u32,
    flags: u8,
}

/// The TCP header of an IPv4 packet with no fragment.
fn parse(p: &[u8]) -> Option<Tcp> {
    if p.len() < 20 || p[0] >> 4 != 4 || p[9] != 6 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    // A fragment after the first has no TCP header.
    if u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 || p.len() < ihl + 20 {
        return None;
    }
    let t = &p[ihl..];
    Some(Tcp {
        src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
        sport: u16::from_be_bytes([t[0], t[1]]),
        dport: u16::from_be_bytes([t[2], t[3]]),
        ack: u32::from_be_bytes([t[8], t[9], t[10], t[11]]),
        flags: t[13],
    })
}

/// An IPv4 packet with a TCP header of 20 bytes and no data.
fn tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(0, &p[..20]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let t = &mut p[20..];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&64240u16.to_be_bytes());
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
    let sum = checksum(sum_of(0, &pseudo), t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    p
}

fn sum_of(mut acc: u32, data: &[u8]) -> u32 {
    for pair in data.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        acc += u32::from(word);
    }
    acc
}

fn checksum(acc: u32, data: &[u8]) -> u16 {
    let mut acc = sum_of(acc, data);
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> TunProbe {
        TunProbe::new(
            Ipv4Addr::new(172, 16, 0, 2),
            SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443),
            3,
        )
    }

    #[test]
    fn the_syn_of_the_probe_is_a_valid_packet() {
        let syn = probe().tick().unwrap();
        let tcp = parse(&syn).unwrap();
        assert_eq!(tcp.src, Ipv4Addr::new(172, 16, 0, 2));
        assert_eq!(tcp.dst, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!((tcp.sport, tcp.dport, tcp.flags), (PROBE_PORT, 443, SYN));
        // A valid checksum sums to 0 with the field in place.
        assert_eq!(checksum(0, &syn[..20]), 0);
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&syn[12..16]);
        pseudo[4..8].copy_from_slice(&syn[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(checksum(sum_of(0, &pseudo), &syn[20..]), 0);
    }

    #[test]
    fn warp_tun_probe_takes_its_answer_out() {
        let mut p = probe();
        let syn = p.tick().unwrap();
        let seq = u32::from_be_bytes([syn[24], syn[25], syn[26], syn[27]]);
        let from = Ipv4Addr::new(1, 1, 1, 1);
        let to = Ipv4Addr::new(172, 16, 0, 2);
        let synack = tcp_packet(from, to, 443, PROBE_PORT, 7, seq + 1, SYN | ACK);
        // The SYN-ACK does not go to the TUN; a RST goes back.
        let rst = p.take(&synack).unwrap().unwrap();
        let rst = parse(&rst).unwrap();
        assert_eq!((rst.sport, rst.dport, rst.flags), (PROBE_PORT, 443, RST));
        // A RST from the target is an answer too, with nothing to send.
        assert_eq!(
            p.take(&tcp_packet(from, to, 443, PROBE_PORT, 0, 0, RST | ACK)),
            Some(None)
        );
        // Another flow of the host goes to the TUN.
        assert!(p
            .take(&tcp_packet(from, to, 443, 40000, 7, 1, SYN | ACK))
            .is_none());
        let other = Ipv4Addr::new(9, 9, 9, 9);
        assert!(p
            .take(&tcp_packet(other, to, 443, PROBE_PORT, 7, 1, SYN | ACK))
            .is_none());
        let mut udp = tcp_packet(from, to, 443, PROBE_PORT, 7, 1, SYN | ACK);
        udp[9] = 17;
        assert!(p.take(&udp).is_none());
        assert!(p.take(&[0x60; 40]).is_none(), "an IPv6 packet");
    }

    #[test]
    fn warp_tun_probe_ends_a_dead_session() {
        let mut p = probe();
        // Answered probes keep the session.
        for _ in 0..5 {
            let syn = p.tick().unwrap();
            let seq = u32::from_be_bytes([syn[24], syn[25], syn[26], syn[27]]);
            let synack = tcp_packet(
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(172, 16, 0, 2),
                443,
                PROBE_PORT,
                1,
                seq + 1,
                SYN | ACK,
            );
            assert!(p.take(&synack).is_some());
        }
        // Three probes with no answer: the third tick after them ends it.
        assert!(p.tick().is_ok());
        assert!(p.tick().is_ok());
        assert!(p.tick().is_ok());
        assert_eq!(p.tick(), Err(3));
    }
}
