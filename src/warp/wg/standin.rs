//! A stand-in of the WireGuard front door of WARP, for the tests (T-074).
//! It answers each handshake. It takes the data messages as [`DataPath`]
//! says: a TCP SYN gets a SYN-ACK, and each other packet comes back.

use super::*;

/// What the stand-in does with the data messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataPath {
    /// It takes each message.
    All,
    /// It drops a message with zero reserved bytes (bytes 1 to 3).
    NeedsReserved,
    /// It drops each message: the handshakes stay fresh, and no data goes.
    Dead,
}

/// The responder of the handshake: it checks the initiation and answers as
/// a WireGuard peer does. It gives the response, the send key, the receive
/// key and the index of the responder.
pub fn respond(
    peer_private: &[u8; 32],
    initiator_public: &[u8; 32],
    init: &[u8],
) -> (Vec<u8>, [u8; 32], [u8; 32], u32) {
    let peer_public = x25519_base(peer_private);
    assert_eq!(init.len(), INITIATION_LEN);
    assert_eq!(mac1(&peer_public, &init[..116]), init[116..132]);
    let mut c = hash(&[CONSTRUCTION]);
    let mut h = hash(&[&c, IDENTIFIER]);
    h = hash(&[&h, &peer_public]);
    let e_pub: [u8; 32] = init[8..40].try_into().unwrap();
    [c] = kdf::<1>(&c, &e_pub);
    h = hash(&[&h, &e_pub]);
    let [c2, k] = kdf::<2>(&c, &x25519(peer_private, &e_pub));
    c = c2;
    let s_pub = open(&k, 0, &init[40..88], &h).unwrap();
    assert_eq!(s_pub, initiator_public);
    h = hash(&[&h, &init[40..88]]);
    let [c3, k] = kdf::<2>(&c, &x25519(peer_private, initiator_public));
    c = c3;
    let time = open(&k, 0, &init[88..116], &h).unwrap();
    assert_eq!(time.len(), 12);
    h = hash(&[&h, &init[88..116]]);
    let e_priv = random::<32>();
    let e_r = x25519_base(&e_priv);
    [c] = kdf::<1>(&c, &e_r);
    h = hash(&[&h, &e_r]);
    [c] = kdf::<1>(&c, &x25519(&e_priv, &e_pub));
    [c] = kdf::<1>(&c, &x25519(&e_priv, initiator_public));
    let [c4, tau, k] = kdf::<3>(&c, &[0u8; 32]);
    c = c4;
    h = hash(&[&h, &tau]);
    let empty = seal(&k, 0, &[], &h);
    let sender = 77u32;
    let mut m = vec![MSG_RESPONSE, 0, 0, 0];
    m.extend_from_slice(&sender.to_le_bytes());
    m.extend_from_slice(&init[4..8]);
    m.extend_from_slice(&e_r);
    m.extend_from_slice(&empty);
    let mac = mac1(initiator_public, &m);
    m.extend_from_slice(&mac);
    m.extend_from_slice(&[0; 16]);
    let [recv_key, send_key] = kdf::<2>(&c, &[]);
    (m, send_key, recv_key, sender)
}

/// A session with `key` in both directions, for a test of [`Session::seal`].
pub fn session(key: [u8; 32]) -> Session {
    Session {
        send_key: key,
        recv_key: key,
        local: 1,
        remote: 2,
        send_counter: 0,
        created: Instant::now(),
        replay: Replay::default(),
    }
}

/// The keys of a client and of the stand-in: (client keys, private key of
/// the stand-in).
pub fn keys(reserved: [u8; 3]) -> (Keys, [u8; 32]) {
    let peer_private = random::<32>();
    let keys = Keys {
        private: random::<32>(),
        peer_public: x25519_base(&peer_private),
        reserved,
    };
    (keys, peer_private)
}

/// Start the stand-in on the loopback for the client of `keys`. It gives
/// the peer of the client (the device address 172.16.0.2).
pub async fn start(reserved: [u8; 3], path: DataPath) -> Peer {
    let (keys, peer_private) = self::keys(reserved);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = sock.local_addr().unwrap();
    tokio::spawn(serve(sock, peer_private, keys.public(), path));
    Peer {
        keys,
        endpoint,
        v4: Some("172.16.0.2".parse().unwrap()),
        v6: None,
    }
}

/// Serve the client of `client_public` on `sock`.
pub async fn serve(
    sock: tokio::net::UdpSocket,
    peer_private: [u8; 32],
    client_public: [u8; 32],
    path: DataPath,
) {
    // For each client address: the send key, the receive key, the index
    // of the client and the send counter.
    let mut sessions = std::collections::HashMap::new();
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            return;
        };
        let m = &buf[..n];
        if m[0] == MSG_INITIATION && n == INITIATION_LEN {
            let (response, send, recv, _) = respond(&peer_private, &client_public, m);
            let receiver: [u8; 4] = m[4..8].try_into().unwrap();
            sessions.insert(from, (send, recv, receiver, 0u64));
            let _ = sock.send_to(&response, from).await;
            continue;
        }
        let dropped = match path {
            DataPath::All => false,
            DataPath::NeedsReserved => m.get(1..4) == Some(&[0, 0, 0][..]),
            DataPath::Dead => true,
        };
        if m[0] != MSG_DATA || n < 32 || dropped {
            continue;
        }
        let Some((send, recv, receiver, counter)) = sessions.get_mut(&from) else {
            continue;
        };
        let c = u64::from_le_bytes(m[8..16].try_into().unwrap());
        let Ok(plain) = open(recv, c, &m[16..], &[]) else {
            continue;
        };
        if plain.is_empty() {
            continue;
        }
        let back = syn_ack(&plain).unwrap_or(plain);
        let mut out = vec![MSG_DATA, 0, 0, 0];
        out.extend_from_slice(&receiver[..]);
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&seal(send, *counter, &back, &[]));
        *counter += 1;
        let _ = sock.send_to(&out, from).await;
    }
}

/// The SYN-ACK for an IPv4 TCP SYN (the far end of the TCP probe).
fn syn_ack(p: &[u8]) -> Option<Vec<u8>> {
    if p.len() < 40 || p[0] != 0x45 || p[9] != 6 || p[33] != 0x02 {
        return None;
    }
    let ip = |at: usize| std::net::Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]);
    let port = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
    let seq = u32::from_be_bytes(p[24..28].try_into().unwrap());
    Some(crate::warp::tun::probe::tcp_packet(
        ip(16),
        ip(12),
        port(22),
        port(20),
        0x0bad_cafe,
        seq.wrapping_add(1),
        0x12,
    ))
}

/// A tunnel over the stand-in carries packets both ways.
#[tokio::test]
async fn a_tunnel_over_udp_carries_packets_both_ways() {
    crate::test_host::need_loopback!();
    let peer = start([7, 8, 9], DataPath::NeedsReserved).await;
    let (mut tx, mut rx, _keepalive) = connect(&peer).await.unwrap();
    let mut packet = vec![0x45, 0, 0, 40];
    packet.resize(40, 3);
    tx.send_packets(&[packet.clone()]).await.unwrap();
    let back = tokio::time::timeout(Duration::from_secs(5), rx.recv_packet())
        .await
        .expect("a packet back")
        .unwrap()
        .unwrap();
    assert_eq!(back.to_vec(), packet);
}

/// T-074: the WireGuard leg of `--transport wireguard` has fresh
/// handshakes and no data path. `WgKeepalive` sees no fault; the TCP probe
/// of T-068 on the stack of the leg renews the session.
#[tokio::test]
async fn wireguard_probe_renews_a_dead_leg() {
    use crate::warp::ip::{StackConfig, WarpStack};
    use crate::warp::live::{Connect, Live, Probe};
    crate::test_host::need_loopback!();
    let peer = start([1, 2, 3], DataPath::Dead).await;
    let open = |peer: Peer| async move {
        let session = crate::warp::session::MasqueSession::connect_wg(&peer).await?;
        let (tx, rx) = session.split();
        WarpStack::start(tx, rx, StackConfig::new("172.16.0.2".parse().unwrap()))
    };
    let first = open(peer.clone()).await.unwrap();
    let opens = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let connect: Connect<WarpStack> = {
        let opens = opens.clone();
        Box::new(move || {
            opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(open(peer.clone()))
        })
    };
    let probe = Probe {
        target: "1.1.1.1:443".parse().unwrap(),
        every: Duration::from_millis(200),
        limit: Duration::from_millis(300),
        misses: 3,
    };
    let live = Live::start_with(
        first,
        connect,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .probed(Some(probe));
    let old = live.get().await.unwrap();
    let started = Instant::now();
    while live.reconnects() == 0 {
        assert!(started.elapsed() < Duration::from_secs(10), "no renewal");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The handshakes are fresh: the old leg is open, and drains.
    assert!(!old.is_closed(), "{:?}", old.close_reason());
    assert!(opens.load(std::sync::atomic::Ordering::SeqCst) >= 1);
}
