//! WireGuard for the WARP tunnel (issue 152): the Noise IKpsk2 handshake
//! and the transport messages (the WireGuard paper, section 5.4, and
//! wireguard.com/protocol).
//!
//! The device is a WireGuard device of the WARP service (`warp export`):
//! its X25519 key, the key of the peer, and the three `reserved` bytes of
//! `client_id`, which WARP reads in bytes 1 to 3 of each message.

use anyhow::{bail, Context as _, Result};
use ring::aead;

// ── BLAKE2s (RFC 7693) ────────────────────────────────────────────────────

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2s with an output of `out_len` bytes (1 to 32) and a key of at most
/// 32 bytes, over the parts of `data` in order.
pub fn blake2s(out_len: usize, key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    assert!((1..=32).contains(&out_len) && key.len() <= 32);
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ out_len as u32;
    let mut buf = Vec::with_capacity(64 + data.iter().map(|d| d.len()).sum::<usize>());
    if !key.is_empty() {
        let mut block = [0u8; 64];
        block[..key.len()].copy_from_slice(key);
        buf.extend_from_slice(&block);
    }
    for d in data {
        buf.extend_from_slice(d);
    }
    let mut t: u64 = 0;
    let mut chunks = buf.chunks(64).peekable();
    if chunks.peek().is_none() {
        compress(&mut h, &[0u8; 64], 0, true);
    }
    while let Some(chunk) = chunks.next() {
        let mut block = [0u8; 64];
        block[..chunk.len()].copy_from_slice(chunk);
        t += chunk.len() as u64;
        compress(&mut h, &block, t, chunks.peek().is_none());
    }
    let mut out = Vec::with_capacity(32);
    for w in h {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.truncate(out_len);
    out
}

fn hash(data: &[&[u8]]) -> [u8; 32] {
    blake2s(32, &[], data).try_into().expect("32 bytes")
}

/// HMAC with BLAKE2s-256 (a block of 64 bytes).
fn hmac(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&hash(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut parts: Vec<&[u8]> = vec![&ipad];
    parts.extend_from_slice(data);
    let inner = hash(&parts);
    hash(&[&opad, &inner])
}

/// The KDF of WireGuard: `n` keys of 32 bytes from a chaining key and an
/// input.
fn kdf<const N: usize>(key: &[u8; 32], input: &[u8]) -> [[u8; 32]; N] {
    let t0 = hmac(key, &[input]);
    let mut out = [[0u8; 32]; N];
    let mut prev: Vec<u8> = Vec::new();
    for (i, o) in out.iter_mut().enumerate() {
        let t = hmac(&t0, &[&prev, &[i as u8 + 1]]);
        *o = t;
        prev = t.to_vec();
    }
    out
}

// ── The other primitives ──────────────────────────────────────────────────

fn x25519(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::MontgomeryPoint(*public)
        .mul_clamped(*private)
        .to_bytes()
}

fn x25519_base(private: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::MontgomeryPoint::mul_base_clamped(*private).to_bytes()
}

fn nonce(counter: u64) -> aead::Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    aead::Nonce::assume_unique_for_key(n)
}

fn seal(key: &[u8; 32], counter: u64, plain: &[u8], ad: &[u8]) -> Vec<u8> {
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).expect("a key of 32 bytes"),
    );
    let mut out = plain.to_vec();
    key.seal_in_place_append_tag(nonce(counter), aead::Aad::from(ad), &mut out)
        .expect("ChaCha20-Poly1305 seals");
    out
}

fn open(key: &[u8; 32], counter: u64, sealed: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).expect("a key of 32 bytes"),
    );
    let mut buf = sealed.to_vec();
    let plain = key
        .open_in_place(nonce(counter), aead::Aad::from(ad), &mut buf)
        .map_err(|_| anyhow::anyhow!("a WireGuard message that does not authenticate"))?;
    Ok(plain.to_vec())
}

/// The TAI64N of now.
fn tai64n() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(now.as_secs() + (1u64 << 62) + 10).to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS entropy");
    b
}

// ── The handshake ─────────────────────────────────────────────────────────

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE: u8 = 3;
pub const MSG_DATA: u8 = 4;

/// The length of an initiation and of a response.
pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;

/// The keys of a device and of its peer.
#[derive(Clone)]
pub struct Keys {
    pub private: [u8; 32],
    pub peer_public: [u8; 32],
    /// Bytes 1 to 3 of each message (WARP: the `client_id`).
    pub reserved: [u8; 3],
}

impl Keys {
    pub fn public(&self) -> [u8; 32] {
        x25519_base(&self.private)
    }
}

/// An initiation that waits for its response.
pub struct Initiation {
    chaining: [u8; 32],
    hash: [u8; 32],
    ephemeral: [u8; 32],
    sender: u32,
    /// The message to send.
    pub message: Vec<u8>,
}

/// The keys of a session: one way each.
pub struct Session {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    /// The index of this side (the receiver of the messages to it).
    pub local: u32,
    /// The index of the peer (the receiver of the messages to the peer).
    pub remote: u32,
    pub send_counter: u64,
    pub created: std::time::Instant,
    replay: Replay,
}

fn mac1(peer_public: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let key = hash(&[LABEL_MAC1, peer_public]);
    blake2s(16, &key, &[message])
}

/// Make the initiation of a handshake.
pub fn initiate(keys: &Keys) -> Initiation {
    initiate_with(
        keys,
        random::<32>(),
        u32::from_le_bytes(random::<4>()),
        tai64n(),
    )
}

fn initiate_with(keys: &Keys, ephemeral: [u8; 32], sender: u32, timestamp: [u8; 12]) -> Initiation {
    let mut c = hash(&[CONSTRUCTION]);
    let mut h = hash(&[&c, IDENTIFIER]);
    h = hash(&[&h, &keys.peer_public]);
    let e_pub = x25519_base(&ephemeral);
    [c] = kdf::<1>(&c, &e_pub);
    h = hash(&[&h, &e_pub]);
    let [c2, k] = kdf::<2>(&c, &x25519(&ephemeral, &keys.peer_public));
    c = c2;
    let enc_static = seal(&k, 0, &keys.public(), &h);
    h = hash(&[&h, &enc_static]);
    let [c3, k] = kdf::<2>(&c, &x25519(&keys.private, &keys.peer_public));
    c = c3;
    let enc_time = seal(&k, 0, &timestamp, &h);
    h = hash(&[&h, &enc_time]);
    let mut m = Vec::with_capacity(INITIATION_LEN);
    m.push(MSG_INITIATION);
    m.extend_from_slice(&keys.reserved);
    m.extend_from_slice(&sender.to_le_bytes());
    m.extend_from_slice(&e_pub);
    m.extend_from_slice(&enc_static);
    m.extend_from_slice(&enc_time);
    let mac = mac1(&keys.peer_public, &m);
    m.extend_from_slice(&mac);
    m.extend_from_slice(&[0u8; 16]); // mac2: no cookie
    Initiation {
        chaining: c,
        hash: h,
        ephemeral,
        sender,
        message: m,
    }
}

impl Initiation {
    /// The session of the response of the peer.
    pub fn finish(&self, keys: &Keys, response: &[u8]) -> Result<Session> {
        if response.len() != RESPONSE_LEN || response[0] != MSG_RESPONSE {
            bail!("not a WireGuard handshake response");
        }
        let remote = u32::from_le_bytes(response[4..8].try_into().expect("4 bytes"));
        let receiver = u32::from_le_bytes(response[8..12].try_into().expect("4 bytes"));
        if receiver != self.sender {
            bail!("a WireGuard response to another handshake");
        }
        if mac1(&keys.public(), &response[..60]) != response[60..76] {
            bail!("the mac1 of the WireGuard response is wrong");
        }
        let e_pub: [u8; 32] = response[12..44].try_into().expect("32 bytes");
        let empty = &response[44..60];
        let mut c = self.chaining;
        let mut h = self.hash;
        [c] = kdf::<1>(&c, &e_pub);
        h = hash(&[&h, &e_pub]);
        [c] = kdf::<1>(&c, &x25519(&self.ephemeral, &e_pub));
        [c] = kdf::<1>(&c, &x25519(&keys.private, &e_pub));
        let [c4, tau, k] = kdf::<3>(&c, &[0u8; 32]);
        c = c4;
        h = hash(&[&h, &tau]);
        open(&k, 0, empty, &h).context("the WireGuard handshake response")?;
        let [send_key, recv_key] = kdf::<2>(&c, &[]);
        Ok(Session {
            send_key,
            recv_key,
            local: self.sender,
            remote,
            send_counter: 0,
            created: std::time::Instant::now(),
            replay: Replay::default(),
        })
    }
}

impl Session {
    /// A transport message with `packet` (padded to 16 bytes; an empty
    /// packet is a keepalive).
    pub fn seal(&mut self, reserved: &[u8; 3], packet: &[u8]) -> Vec<u8> {
        let counter = self.send_counter;
        self.send_counter += 1;
        let mut plain = packet.to_vec();
        plain.resize(packet.len().div_ceil(16) * 16, 0);
        let mut m = Vec::with_capacity(16 + plain.len() + 16);
        m.push(MSG_DATA);
        m.extend_from_slice(reserved);
        m.extend_from_slice(&self.remote.to_le_bytes());
        m.extend_from_slice(&counter.to_le_bytes());
        m.extend_from_slice(&seal(&self.send_key, counter, &plain, &[]));
        m
    }

    /// The IP packet of a transport message to this session: the padding is
    /// cut by the length in the IP header. An empty vector is a keepalive.
    pub fn open(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() < 32 || message[0] != MSG_DATA {
            bail!("not a WireGuard transport message");
        }
        let receiver = u32::from_le_bytes(message[4..8].try_into().expect("4 bytes"));
        if receiver != self.local {
            bail!("a WireGuard message for another session");
        }
        let counter = u64::from_le_bytes(message[8..16].try_into().expect("8 bytes"));
        if !self.replay.check(counter) {
            bail!("a WireGuard message that came before (counter {counter})");
        }
        let mut plain = open(&self.recv_key, counter, &message[16..], &[])?;
        self.replay.mark(counter);
        let len = match plain.first().map(|b| b >> 4) {
            Some(4) if plain.len() >= 20 => u16::from_be_bytes([plain[2], plain[3]]) as usize,
            Some(6) if plain.len() >= 40 => 40 + u16::from_be_bytes([plain[4], plain[5]]) as usize,
            _ => 0,
        };
        plain.truncate(len.min(plain.len()));
        Ok(plain)
    }

    /// The receiver index of a message: to find its session.
    pub fn receiver_of(message: &[u8]) -> Option<u32> {
        Some(u32::from_le_bytes(message.get(4..8)?.try_into().ok()?))
    }
}

/// A sliding window of the counters that came (RFC 6479 shape, 2048 bits).
#[derive(Default)]
struct Replay {
    top: u64,
    bits: [u64; 32],
    any: bool,
}

impl Replay {
    const WINDOW: u64 = 2048 - 64;

    fn check(&self, n: u64) -> bool {
        if !self.any || n > self.top {
            return true;
        }
        if self.top - n >= Self::WINDOW {
            return false;
        }
        let bit = n % 2048;
        self.bits[(bit / 64) as usize] & (1 << (bit % 64)) == 0
    }

    fn mark(&mut self, n: u64) {
        if !self.any || n > self.top {
            let from = if self.any { self.top + 1 } else { n };
            if n - from >= 2048 {
                self.bits = [0; 32];
            } else {
                for i in from..=n {
                    let bit = i % 2048;
                    self.bits[(bit / 64) as usize] &= !(1 << (bit % 64));
                }
            }
            self.top = n;
            self.any = true;
        }
        let bit = n % 2048;
        self.bits[(bit / 64) as usize] |= 1 << (bit % 64);
    }
}

// ── The transport of the tunnel ───────────────────────────────────────────

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A new session after this time (REKEY_AFTER_TIME).
pub const REKEY_AFTER: Duration = Duration::from_secs(120);
/// A handshake with no answer is sent again after this time (REKEY_TIMEOUT).
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// A handshake with no answer in this time: the path is dead.
pub const HANDSHAKE_DEAD: Duration = Duration::from_secs(20);
/// The persistent keepalive.
pub const KEEPALIVE: Duration = Duration::from_secs(25);

/// A WireGuard peer of the WARP service: the keys, the front door and the
/// addresses of the device.
#[derive(Clone)]
pub struct Peer {
    pub keys: Keys,
    pub endpoint: SocketAddr,
    pub v4: Option<std::net::Ipv4Addr>,
    pub v6: Option<std::net::Ipv6Addr>,
}

impl Peer {
    /// The peer of a device of `warp export` (issue 148). `endpoint`
    /// replaces the IPv4 address of the record on port 2408.
    pub fn from_exported(
        exported: &super::export::Exported,
        endpoint: Option<SocketAddr>,
    ) -> Result<Self> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let device = &exported.device;
        let private: [u8; 32] = b64
            .decode(&exported.private_key)
            .ok()
            .and_then(|k| k.try_into().ok())
            .context("the private key of the WireGuard device")?;
        let peer = device
            .config
            .peers
            .first()
            .context("the WireGuard device has no peer")?;
        let peer_public: [u8; 32] = b64
            .decode(&peer.public_key)
            .ok()
            .and_then(|k| k.try_into().ok())
            .context("the key of the WireGuard peer")?;
        let endpoint = match endpoint {
            Some(e) => e,
            None => {
                let v4 = peer.endpoint.v4.trim();
                let ip = v4.rsplit_once(':').map_or(v4, |(ip, _)| ip);
                let ip: std::net::Ipv4Addr = ip.parse().context(
                    "the WireGuard peer has no IPv4 endpoint; give --wireguard-endpoint",
                )?;
                SocketAddr::new(ip.into(), super::export::WG_PORT)
            }
        };
        Ok(Peer {
            keys: Keys {
                private,
                peer_public,
                reserved: device.reserved().unwrap_or([0; 3]),
            },
            endpoint,
            v4: device.config.interface.addresses.v4.parse().ok(),
            v6: device.config.interface.addresses.v6.parse().ok(),
        })
    }
}

struct State {
    keys: Keys,
    current: Session,
    previous: Option<Session>,
    pending: Option<(Initiation, Instant, Instant)>,
    last_send: Instant,
}

impl State {
    /// A new initiation, or the one that waits when it is new enough. The
    /// message to send, if any.
    fn rekey(&mut self, now: Instant) -> Result<Option<Vec<u8>>> {
        match &self.pending {
            Some((_, first, _)) if now.duration_since(*first) > HANDSHAKE_DEAD => {
                bail!(
                    "no WireGuard handshake answer in {} s",
                    HANDSHAKE_DEAD.as_secs()
                )
            }
            Some((_, first, sent)) if now.duration_since(*sent) > REKEY_TIMEOUT => {
                let first = *first;
                let init = initiate(&self.keys);
                let m = init.message.clone();
                self.pending = Some((init, first, now));
                Ok(Some(m))
            }
            Some(_) => Ok(None),
            None if self.current.created.elapsed() > REKEY_AFTER => {
                let init = initiate(&self.keys);
                let m = init.message.clone();
                self.pending = Some((init, now, now));
                Ok(Some(m))
            }
            None => Ok(None),
        }
    }
}

/// The write half of a WireGuard transport.
pub struct WgTx {
    sock: Arc<tokio::net::UdpSocket>,
    state: Arc<Mutex<State>>,
}

/// The read half of a WireGuard transport.
pub struct WgRx {
    sock: Arc<tokio::net::UdpSocket>,
    state: Arc<Mutex<State>>,
    buf: Vec<u8>,
}

/// The liveness check: keepalives, the rekey, and a dead path.
pub struct WgKeepalive {
    sock: Arc<tokio::net::UdpSocket>,
    state: Arc<Mutex<State>>,
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// The handshake with `peer` on UDP: three tries, [`REKEY_TIMEOUT`] apart.
pub async fn connect(peer: &Peer) -> Result<(WgTx, WgRx, WgKeepalive)> {
    let bind: SocketAddr = if peer.endpoint.is_ipv4() {
        "0.0.0.0:0".parse().expect("an address")
    } else {
        "[::]:0".parse().expect("an address")
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .context("a UDP socket for WireGuard")?;
    sock.connect(peer.endpoint)
        .await
        .with_context(|| format!("UDP to the WireGuard front door {}", peer.endpoint))?;
    let mut buf = vec![0u8; 2048];
    let mut last_err = None;
    for _ in 0..3 {
        let init = initiate(&peer.keys);
        sock.send(&init.message)
            .await
            .with_context(|| format!("UDP to the WireGuard front door {}", peer.endpoint))?;
        let deadline = tokio::time::Instant::now() + REKEY_TIMEOUT;
        loop {
            let n = match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Err(_) => break,
                Ok(Err(err)) => {
                    last_err =
                        Some(anyhow::Error::new(err).context("UDP from the WireGuard front door"));
                    break;
                }
                Ok(Ok(n)) => n,
            };
            match buf[0] {
                MSG_RESPONSE => match init.finish(&peer.keys, &buf[..n]) {
                    Ok(session) => {
                        let now = Instant::now();
                        let state = Arc::new(Mutex::new(State {
                            keys: peer.keys.clone(),
                            current: session,
                            previous: None,
                            pending: None,
                            last_send: now,
                        }));
                        let sock = Arc::new(sock);
                        tracing::debug!(endpoint = %peer.endpoint, "the WireGuard handshake is done");
                        return Ok((
                            WgTx {
                                sock: sock.clone(),
                                state: state.clone(),
                            },
                            WgRx {
                                sock: sock.clone(),
                                state: state.clone(),
                                buf: vec![0u8; 2048],
                            },
                            WgKeepalive { sock, state },
                        ));
                    }
                    Err(err) => last_err = Some(err),
                },
                MSG_COOKIE => {
                    last_err = Some(anyhow::anyhow!(
                        "the WireGuard front door is under load (a cookie reply)"
                    ))
                }
                _ => {}
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "no WireGuard handshake answer from {} (UDP) in {} s",
            peer.endpoint,
            3 * REKEY_TIMEOUT.as_secs()
        )
    }))
}

impl WgTx {
    /// Seal and send each packet.
    pub async fn send_packets<P: AsRef<[u8]>>(&mut self, packets: &[P]) -> Result<()> {
        let (messages, handshake) = {
            let mut state = lock(&self.state);
            let handshake = state.rekey(Instant::now())?;
            let reserved = state.keys.reserved;
            let messages: Vec<Vec<u8>> = packets
                .iter()
                .map(|p| state.current.seal(&reserved, p.as_ref()))
                .collect();
            state.last_send = Instant::now();
            (messages, handshake)
        };
        if let Some(m) = handshake {
            self.sock.send(&m).await.context("a WireGuard handshake")?;
        }
        for m in messages {
            self.sock.send(&m).await.context("a WireGuard message")?;
        }
        Ok(())
    }
}

impl WgRx {
    /// The next IP packet; a handshake response, a keepalive and a message
    /// that does not authenticate are taken and not returned.
    pub async fn recv_packet(&mut self) -> Result<Option<bytes::Bytes>> {
        loop {
            let n = self
                .sock
                .recv(&mut self.buf)
                .await
                .context("UDP from the WireGuard front door")?;
            let message = &self.buf[..n];
            let mut state = lock(&self.state);
            match message.first() {
                Some(&MSG_DATA) => {
                    let receiver = Session::receiver_of(message);
                    let session = if receiver == Some(state.current.local) {
                        Some(&mut state.current)
                    } else {
                        state
                            .previous
                            .as_mut()
                            .filter(|s| Some(s.local) == receiver)
                    };
                    let Some(session) = session else { continue };
                    match session.open(message) {
                        Ok(packet) if packet.is_empty() => continue,
                        Ok(packet) => return Ok(Some(packet.into())),
                        Err(err) => {
                            tracing::debug!(error = %err, "a WireGuard message is dropped");
                            continue;
                        }
                    }
                }
                Some(&MSG_RESPONSE) => {
                    let Some((init, _, _)) = state.pending.take() else {
                        continue;
                    };
                    let keys = state.keys.clone();
                    match init.finish(&keys, message) {
                        Ok(session) => {
                            let old = std::mem::replace(&mut state.current, session);
                            state.previous = Some(old);
                            tracing::debug!("a new WireGuard session (rekey)");
                        }
                        Err(err) => {
                            tracing::debug!(error = %err, "a WireGuard response is dropped");
                            state.pending = Some((init, Instant::now(), Instant::now()));
                        }
                    }
                }
                _ => continue,
            }
        }
    }
}

impl WgKeepalive {
    /// Ready with an error when the path is dead: a handshake had no answer
    /// in [`HANDSHAKE_DEAD`]. Sends a keepalive when nothing went out for
    /// [`KEEPALIVE`], and the handshake of the rekey.
    pub async fn run(self) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let (handshake, keepalive) = {
                let mut state = lock(&self.state);
                let now = Instant::now();
                let handshake = state.rekey(now)?;
                let keepalive = if now.duration_since(state.last_send) >= KEEPALIVE {
                    state.last_send = now;
                    let reserved = state.keys.reserved;
                    Some(state.current.seal(&reserved, &[]))
                } else {
                    None
                };
                (handshake, keepalive)
            };
            for m in handshake.iter().chain(keepalive.iter()) {
                let _ = self.sock.send(m).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn blake2s_vectors() {
        // RFC 7693, appendix B.
        assert_eq!(
            blake2s(32, &[], &[b"abc"]),
            hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
        // The keyed vector of the BLAKE2 reference (key 00..1f, no input).
        let key: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            blake2s(32, &key, &[]),
            hex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
        );
        // ... and with the input 00..3f (64 bytes: one whole block).
        let input: Vec<u8> = (0u8..64).collect();
        assert_eq!(
            blake2s(32, &key, &[&input]),
            hex("8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4")
        );
        // The parts are one input.
        assert_eq!(
            blake2s(32, &[], &[b"a", b"bc"]),
            blake2s(32, &[], &[b"abc"])
        );
    }

    /// HMAC-BLAKE2s, the KDF, a long input and a keyed MAC of 16 bytes, as
    /// Python's hashlib and hmac compute them.
    #[test]
    fn hmac_and_kdf_vectors() {
        let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let t0 = hmac(&key, &[b"WireGuard"]);
        assert_eq!(
            t0.to_vec(),
            hex("5415924543576b3f5ee867c94e1aab70586d33b32fae3fccd2c635b3e1d7198d")
        );
        let [k1, k2, k3] = kdf::<3>(&key, b"WireGuard");
        assert_eq!(
            k1.to_vec(),
            hex("7e615ce2573f4139b960d562ec463daf7164bd86a0a64c0adc374ff2655769f3")
        );
        assert_eq!(
            k2.to_vec(),
            hex("42dbbd4438e101cd2c2ea8d05ed6716bf87489aea47ece2f06358835670130bf")
        );
        assert_eq!(
            k3.to_vec(),
            hex("5c58c1d9808a5bfdf8f38f6487248985c04f4b6d0fe427516935a0f6903b0157")
        );
        let long: Vec<u8> = (0..768).map(|i| i as u8).collect();
        assert_eq!(
            blake2s(32, &[], &[&long]),
            hex("b928a17862e211e99759ba8819280803a914cd3dee7c5d711a3b5185aa96a7b3")
        );
        assert_eq!(
            blake2s(16, &[0u8; 32], &[b"mac1 input"]),
            hex("e3df99b695c09da1151bb0fd6cd4ea5b")
        );
    }

    /// The responder of the handshake, for the test: it checks the
    /// initiation and answers as a WireGuard peer does.
    fn respond(
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

    #[test]
    fn a_handshake_and_transport_messages() {
        let peer_private = random::<32>();
        let keys = Keys {
            private: random::<32>(),
            peer_public: x25519_base(&peer_private),
            reserved: [1, 2, 3],
        };
        let init = initiate(&keys);
        assert_eq!(init.message.len(), INITIATION_LEN);
        assert_eq!(&init.message[..4], &[MSG_INITIATION, 1, 2, 3]);
        let (response, peer_send, peer_recv, peer_index) =
            respond(&peer_private, &keys.public(), &init.message);
        assert_eq!(response.len(), RESPONSE_LEN);
        let mut session = init.finish(&keys, &response).unwrap();
        assert_eq!(session.remote, peer_index);
        assert_eq!(session.send_key, peer_recv);
        assert_eq!(session.recv_key, peer_send);
        // A packet out: an IPv4 header of 28 bytes, padded to 32.
        let mut packet = vec![0x45, 0, 0, 28];
        packet.resize(28, 9);
        let m = session.seal(&keys.reserved, &packet);
        assert_eq!(&m[..4], &[MSG_DATA, 1, 2, 3]);
        assert_eq!(m.len(), 16 + 32 + 16);
        let plain = open(&peer_recv, 0, &m[16..], &[]).unwrap();
        assert_eq!(&plain[..28], &packet[..]);
        // A packet in, then the same message again (a replay).
        let mut back = vec![MSG_DATA, 0, 0, 0];
        back.extend_from_slice(&session.local.to_le_bytes());
        back.extend_from_slice(&5u64.to_le_bytes());
        back.extend_from_slice(&seal(&peer_send, 5, &plain, &[]));
        assert_eq!(session.open(&back).unwrap(), packet);
        assert!(session.open(&back).is_err());
        // A changed byte does not authenticate.
        let mut bad = back.clone();
        bad[8] = 6;
        bad[20] ^= 1;
        assert!(session.open(&bad).is_err());
        // A wrong response key: refused.
        let other = Keys {
            private: random::<32>(),
            ..keys.clone()
        };
        assert!(init.finish(&other, &response).is_err());
    }

    /// A WireGuard peer on the loopback: it answers the handshake and sends
    /// each packet back.
    #[tokio::test]
    async fn a_tunnel_over_udp_carries_packets_both_ways() {
        let peer_private = random::<32>();
        let keys = Keys {
            private: random::<32>(),
            peer_public: x25519_base(&peer_private),
            reserved: [7, 8, 9],
        };
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = sock.local_addr().unwrap();
        let client_public = keys.public();
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..4], &[MSG_INITIATION, 7, 8, 9]);
            let (response, send_key, recv_key, _) =
                respond(&peer_private, &client_public, &buf[..n]);
            let receiver: [u8; 4] = buf[4..8].try_into().unwrap();
            sock.send_to(&response, from).await.unwrap();
            let mut counter = 0u64;
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                if buf[0] != MSG_DATA {
                    continue;
                }
                let c = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                let plain = open(&recv_key, c, &buf[16..n], &[]).unwrap();
                if plain.is_empty() {
                    continue;
                }
                let mut m = vec![MSG_DATA, 0, 0, 0];
                m.extend_from_slice(&receiver);
                m.extend_from_slice(&counter.to_le_bytes());
                m.extend_from_slice(&seal(&send_key, counter, &plain, &[]));
                counter += 1;
                sock.send_to(&m, from).await.unwrap();
            }
        });
        let peer = Peer {
            keys,
            endpoint,
            v4: Some("172.16.0.2".parse().unwrap()),
            v6: None,
        };
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
        server.abort();
    }

    #[tokio::test]
    async fn no_answer_is_an_error_that_names_the_door() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = Peer {
            keys: Keys {
                private: random::<32>(),
                peer_public: random::<32>(),
                reserved: [0; 3],
            },
            endpoint: sock.local_addr().unwrap(),
            v4: None,
            v6: None,
        };
        tokio::time::pause();
        let task =
            tokio::spawn(async move { connect(&peer).await.err().map(|e| format!("{e:#}")) });
        let err = task.await.unwrap().expect("no answer fails");
        assert!(err.contains("no WireGuard handshake answer"), "{err}");
        drop(sock);
    }

    #[test]
    fn the_replay_window() {
        let mut r = Replay::default();
        for n in [0u64, 1, 5, 3] {
            assert!(r.check(n), "{n}");
            r.mark(n);
            assert!(!r.check(n), "{n} again");
        }
        assert!(r.check(4));
        r.mark(5000);
        assert!(!r.check(5));
        assert!(r.check(4999));
    }
}
