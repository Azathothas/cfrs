//! Cloudflare WARP, spoken directly: anonymous registration, MASQUE CONNECT-IP
//! over HTTP/2 on TCP 443, and a userspace IP stack on top of it.
//!
//! Two things this buys you that `cloudflared` cannot do from a locked-down
//! host:
//!
//! * **A tunnel whose only egress is TCP 443.** The registration API and the
//!   MASQUE front door are both reachable on 443, so a host that permits
//!   nothing else still gets a working WARP tunnel.
//! * **A destination the host's firewall refuses.** Packets are built by
//!   `smoltcp` and carried inside the tunnel, so the host never issues a
//!   `connect()` to the real address. That is how a Cloudflare tunnel edge on
//!   port 7844 becomes reachable on a host where 7844 is filtered.
//!
//! Everything is in-crate: no `wgcf`, no `warp-cli`, no `cloudflared`, no
//! external tunnel binary. The registration is two HTTP calls
//! ([`register`]), the tunnel is one HTTP/2 CONNECT ([`session`]), and the
//! routing is `smoltcp` ([`ip`]).
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use cfrs::warp::WarpClient;
//!
//! // Register anonymously and enrol a MASQUE identity in one call.
//! let client = WarpClient::register().await?;
//! // Open the tunnel; only TCP 443 is needed.
//! let stack = client.connect().await?;
//! // Reach anything, including ports the host blocks.
//! let conn = stack.tcp_connect("198.41.192.27:7844".parse()?).await?;
//! # let _ = conn;
//! # Ok(())
//! # }
//! ```

pub mod capsule;
pub mod exit;
pub mod export;
pub mod forward;
pub mod h3;
pub mod identity;
pub mod ip;
pub mod l4;
pub mod live;
pub mod nc;
pub mod proxy;
pub mod quic;
pub mod register;
pub mod route;
pub mod rules;
pub mod session;
pub mod ssh_config;
#[cfg(target_os = "linux")]
pub mod tun;
pub mod up;
pub mod wg;

pub use identity::Identity;
pub use ip::{check_cc, check_tcp_burst, StackConfig, TcpConn, UdpConn, WarpStack};
pub use live::{Closable, Live};
pub use register::Device;
pub use session::Dial;
pub use session::{MasqueRx, MasqueSession, MasqueTx};

use anyhow::{bail, Context, Result};

use crate::egress::Proxy;

/// A registered WARP device with a MASQUE identity ready to dial.
pub struct WarpClient {
    device: Device,
    identity: Identity,
    proxy: Option<Proxy>,
    masque: MasqueOptions,
    /// The relay of the fallback, made on first use.
    relay: std::sync::OnceLock<Option<std::sync::Arc<crate::ws_relay::Relay>>>,
    /// The last session went through the relay: try it first next time.
    relay_first: std::sync::atomic::AtomicBool,
    /// The file that keeps the leg that worked between two runs (issue
    /// 126), next to the identity file.
    leg_file: Option<std::path::PathBuf>,
    /// The leg file was read.
    leg_read: std::sync::Once,
    /// The address of the front door that worked last (issue 124).
    endpoint_won: std::sync::Mutex<Option<std::net::SocketAddr>>,
    /// The address of a front door whose session carried no packet (issue
    /// 133): it goes last.
    door_bad: std::sync::Mutex<Option<std::net::SocketAddr>>,
    /// WireGuard in place of MASQUE (issue 152): the peer of the device
    /// of `warp export`.
    wireguard: Option<wg::Peer>,
    /// A second device on WireGuard inside the first session (issues 154
    /// and 155): the stack of the tools is the stack of this one.
    carry: Option<wg::Peer>,
}

/// The order of the front door addresses: the one that worked last first,
/// then the others; IPv6 only with an IPv6 route (or a proxy or a relay,
/// which reach it for cfrs).
fn endpoint_order(
    all: Vec<std::net::SocketAddr>,
    won: Option<std::net::SocketAddr>,
    bad: Option<std::net::SocketAddr>,
    ipv6: bool,
) -> Vec<std::net::SocketAddr> {
    let mut out: Vec<std::net::SocketAddr> =
        all.into_iter().filter(|a| a.is_ipv4() || ipv6).collect();
    if let Some(won) = won.filter(|w| Some(*w) != bad) {
        if let Some(i) = out.iter().position(|a| *a == won) {
            out.swap(0, i);
        }
    }
    // Issue 133: a door that carried no packet goes last.
    if let Some(bad) = bad {
        if let Some(i) = out.iter().position(|a| *a == bad) {
            let door = out.remove(i);
            out.push(door);
        }
    }
    out
}

/// The door file of an identity file: `warp.json` gives `warp-door.json`.
fn door_file_of(identity: &std::path::Path) -> std::path::PathBuf {
    let stem = identity
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "warp".into());
    identity.with_file_name(format!("{stem}-door.json"))
}

/// The MTU of the stack of a carried device (issues 154 and 155): 1280 of
/// the outer stack, less the IPv4 and UDP headers (28), the header and the
/// tag of WireGuard (32), and its padding (at most 15).
pub const CARRY_MTU: usize = 1200;

/// A door in the door file is used for this time.
const DOOR_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// The door of the text of a door file, when it is recent (less than
/// [`DOOR_TTL`] before `now`) and one of `candidates` (issue 133).
fn door_from(
    text: &str,
    now: u64,
    candidates: &[std::net::SocketAddr],
) -> Option<std::net::SocketAddr> {
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    if doc["schema"] != 1 {
        return None;
    }
    let at = doc["at"].as_u64()?;
    if at > now || now - at >= DOOR_TTL.as_secs() {
        return None;
    }
    let door: std::net::SocketAddr = doc["door"].as_str()?.parse().ok()?;
    candidates.contains(&door).then_some(door)
}

/// The delay of the relay after the start of the direct path.
const RELAY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);
/// The delay of the relay when the relay worked last: a direct path that
/// works opens in less.
const RELAY_DELAY_KNOWN: std::time::Duration = std::time::Duration::from_millis(500);

/// A leg in the leg file is used for this time.
const LEG_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// The leg file of an identity file: `warp.json` gives `warp-leg.json`.
fn leg_file_of(identity: &std::path::Path) -> std::path::PathBuf {
    let stem = identity
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "warp".into());
    identity.with_file_name(format!("{stem}-leg.json"))
}

/// True when the text of a leg file says that the relay `relay` worked
/// less than [`LEG_TTL`] before `now` (unix seconds).
fn relay_first_from(text: &str, now: u64, relay: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    doc["leg"] == "relay"
        && doc["relay"] == relay
        && doc["at"]
            .as_u64()
            .is_some_and(|at| at <= now && now - at < LEG_TTL.as_secs())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How cfrs reaches the MASQUE front door (issue 76).
#[derive(Clone, Debug, Default)]
pub struct MasqueOptions {
    /// No WebSocket relay when the direct path fails.
    pub no_relay: bool,
    /// The front door in place of the one of the device record.
    pub endpoint: Option<std::net::SocketAddr>,
    /// The TLS name in place of `consumer-masque.cloudflareclient.com`.
    pub sni: Option<String>,
    /// HTTP/3 on UDP 443 in place of HTTP/2 on TCP 443 (issue 157). No
    /// relay and no proxy: they carry TCP only.
    pub h3: bool,
}

impl WarpClient {
    /// Register anonymously and enrol the MASQUE identity.
    ///
    /// This is the whole of the "self registration" step: a `POST` that creates
    /// the device, a `PATCH` that swaps its key for a P-256 one and switches it
    /// to MASQUE, and a locally generated keypair. No account, no token, no
    /// external tool.
    pub async fn register() -> Result<Self> {
        Self::register_with(None).await
    }

    /// Register through a specific proxy, or directly when `proxy` is `None`.
    pub async fn register_with(proxy: Option<Proxy>) -> Result<Self> {
        let identity = Identity::generate().context("generating the MASQUE identity")?;
        let device = register::create_device(proxy.as_ref())
            .await
            .context("creating an anonymous WARP device")?;
        if device.token.is_empty() {
            bail!("the registration response carried no token");
        }
        let mut enrolled = register::enrol_masque(
            &device.id,
            &device.token,
            identity.spki_b64(),
            proxy.as_ref(),
        )
        .await
        .context("enrolling the MASQUE identity")?;
        // Only the registration answer has the token. Keep it: the account
        // calls and the key rotation need it.
        enrolled.token = device.token;
        if enrolled.tunnel_type != "masque" {
            bail!(
                "the API kept tunnel_type {:?} instead of masque",
                enrolled.tunnel_type
            );
        }
        Ok(Self {
            device: enrolled,
            identity,
            proxy,
            masque: MasqueOptions::default(),
            relay: std::sync::OnceLock::new(),
            relay_first: std::sync::atomic::AtomicBool::new(false),
            leg_file: None,
            leg_read: std::sync::Once::new(),
            endpoint_won: std::sync::Mutex::new(None),
            door_bad: std::sync::Mutex::new(None),
            wireguard: None,
            carry: None,
        })
    }

    /// Build a client from an already-enrolled device and identity, for callers
    /// that persist them.
    pub fn from_parts(device: Device, identity: Identity) -> Self {
        Self {
            device,
            identity,
            proxy: None,
            masque: MasqueOptions::default(),
            relay: std::sync::OnceLock::new(),
            relay_first: std::sync::atomic::AtomicBool::new(false),
            leg_file: None,
            leg_read: std::sync::Once::new(),
            endpoint_won: std::sync::Mutex::new(None),
            door_bad: std::sync::Mutex::new(None),
            wireguard: None,
            carry: None,
        }
    }

    /// How to reach the MASQUE front door: the relay fallback and the
    /// overrides of the endpoint and the TLS name.
    pub fn with_masque(mut self, masque: MasqueOptions) -> Self {
        self.masque = masque;
        self
    }

    /// Carry the tunnel on WireGuard with `peer` (issue 152), in place of
    /// MASQUE.
    pub fn with_wireguard(mut self, peer: Option<wg::Peer>) -> Self {
        self.wireguard = peer;
        self
    }

    /// The L4 door of `warp proxy --l4` (issue 140): the front door of the
    /// device (or `--masque-endpoint`), the TLS name `sni`, the client
    /// certificate and the pinned key.
    pub fn l4(&self, sni: &str) -> Result<l4::L4> {
        let (endpoint, pinned) = Self::endpoint_and_pin(&self.device)?;
        let endpoint = self.masque.endpoint.unwrap_or(endpoint);
        let tls = session::tls_config_alpn(&self.identity, pinned, h3::ALPN)?;
        Ok(l4::L4::new(endpoint, tls, sni))
    }

    /// Carry a second WireGuard device inside the session (issues 154 and
    /// 155).
    pub fn with_carry(mut self, peer: Option<wg::Peer>) -> Self {
        self.carry = peer;
        self
    }

    /// True when the tunnel goes on WireGuard.
    pub fn is_wireguard(&self) -> bool {
        self.wireguard.is_some()
    }

    /// The relay of the fallback: the relay of `--transport relay` when it
    /// is set, else the relay of `CFRS_RELAY` or the default relay. None
    /// with `--no-relay`.
    fn relay(&self) -> Option<std::sync::Arc<crate::ws_relay::Relay>> {
        if self.masque.no_relay {
            return None;
        }
        self.relay
            .get_or_init(|| match crate::ws_relay::Relay::from_env(None) {
                Ok(relay) => Some(std::sync::Arc::new(relay)),
                Err(err) => {
                    tracing::warn!(error = %format!("{err:#}"), "no WebSocket relay for MASQUE");
                    None
                }
            })
            .clone()
    }

    /// Use this proxy for the registration calls and the MASQUE dial, or none
    /// for a direct connection.
    pub fn with_proxy(mut self, proxy: Option<Proxy>) -> Self {
        self.proxy = proxy;
        self
    }

    /// The proxy in use, if any.
    pub fn proxy(&self) -> Option<&Proxy> {
        self.proxy.as_ref()
    }

    /// Write the device and the identity to one JSON file, so a later run can
    /// resume the tunnel without registering a second device.
    ///
    /// The file holds the private key. It is written with mode 0600 and the
    /// caller owns where it goes.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        #[derive(serde::Serialize)]
        struct Stored<'a> {
            device: &'a Device,
            cert_pem: String,
            key_pem: String,
        }
        let (cert_pem, key_pem) = self.identity.to_pem()?;
        let text = serde_json::to_string_pretty(&Stored {
            device: &self.device,
            cert_pem,
            key_pem,
        })
        .context("serialising the WARP identity")?;
        write_private(path, text.as_bytes())
            .with_context(|| format!("writing the WARP identity to {}", path.display()))
    }

    /// Read a client written by [`WarpClient::save`].
    pub fn load(path: &std::path::Path) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Stored {
            device: Device,
            cert_pem: String,
            key_pem: String,
        }
        check_private(path)?;
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the WARP identity from {}", path.display()))?;
        let stored: Stored = serde_json::from_str(&text)
            .with_context(|| format!("parsing the WARP identity in {}", path.display()))?;
        let identity = Identity::from_pem(&stored.cert_pem, &stored.key_pem)
            .context("rebuilding the MASQUE identity")?;
        let mut client = Self::from_parts(stored.device, identity);
        client.leg_file = Some(leg_file_of(path));
        // Issue 133: the door that carried data last goes first.
        if let Ok(text) = std::fs::read_to_string(door_file_of(path)) {
            let door = door_from(&text, unix_now(), &client.device.masque_endpoints());
            *client
                .endpoint_won
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = door;
        }
        Ok(client)
    }

    /// Read the leg file once: a relay that worked in the last hours goes
    /// first (issue 126: a restart started with the direct path, which can
    /// time out for a long time on a blocked front door).
    fn read_leg(&self, relay: &crate::ws_relay::Relay) {
        self.leg_read.call_once(|| {
            let Some(path) = &self.leg_file else { return };
            let Ok(text) = std::fs::read_to_string(path) else {
                return;
            };
            if relay_first_from(&text, unix_now(), &relay.url()) {
                tracing::debug!("the last run used the relay; it goes first");
                self.relay_first
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }

    /// Keep the door that carried data (issue 133). A failure to write is
    /// not an error; the file is written only when the door changed.
    fn write_door(&self) {
        let Some(leg) = &self.leg_file else { return };
        let Some(door) = *self.endpoint_won.lock().unwrap_or_else(|e| e.into_inner()) else {
            return;
        };
        let path = leg.with_file_name(
            leg.file_name()
                .map(|n| n.to_string_lossy().replace("-leg.json", "-door.json"))
                .unwrap_or_else(|| "warp-door.json".into()),
        );
        let now = unix_now();
        let old = std::fs::read_to_string(&path).ok();
        if old.and_then(|t| door_from(&t, now, &[door])).is_some() {
            return;
        }
        let text =
            serde_json::json!({"schema": 1, "door": door.to_string(), "at": now}).to_string();
        if let Err(err) = write_private(&path, text.as_bytes()) {
            tracing::debug!(error = %err, path = %path.display(), "the door file is not written");
        }
    }

    /// Keep the leg that worked. A failure to write is not an error.
    fn write_leg(&self, leg: &str, relay: &crate::ws_relay::Relay) {
        let Some(path) = &self.leg_file else { return };
        let text =
            serde_json::json!({"leg": leg, "at": unix_now(), "relay": relay.url()}).to_string();
        if let Err(err) = write_private(path, text.as_bytes()) {
            tracing::debug!(error = %err, path = %path.display(), "the leg file is not written");
        }
    }

    /// Register if `path` holds nothing yet, otherwise resume what it holds.
    ///
    /// This is the call a daemon wants: one device per installation, not one
    /// per start.
    ///
    /// A file that cannot be read, or that other users can read, is an
    /// error: cfrs does not write over it.
    pub async fn register_or_load(path: &std::path::Path) -> Result<Self> {
        if path.exists() {
            let client = Self::load(path)?;
            if client.device.tunnel_type == "masque" {
                return Ok(client);
            }
            tracing::debug!(
                tunnel_type = %client.device.tunnel_type,
                "the stored device is not enrolled for MASQUE; registering again"
            );
        } else {
            tracing::debug!(path = %path.display(), "no stored WARP identity; registering a new device");
        }
        // A failed save after the registration spends a device: check first.
        crate::state::check_file_writable(path)?;
        let client = Self::register().await?;
        client.save(path)?;
        Ok(client)
    }

    /// The default place for the saved identity: `warp.json` in the state
    /// directory of [`crate::state`], or `None` with `CFRS_STATE_DIR=none`.
    pub fn default_identity_path() -> Result<Option<std::path::PathBuf>> {
        Ok(crate::state::state_dir()?.map(|dir| dir.join("warp.json")))
    }

    /// Read the device record from the API again. Keep the token, which only
    /// the registration answer has.
    pub async fn refresh(&mut self) -> Result<()> {
        let token = self.device.token.clone();
        let mut device = register::get_device(&self.device.id, &token, self.proxy.as_ref()).await?;
        device.token = token;
        self.device = device;
        Ok(())
    }

    /// The account record: type, WARP+ state and quota. The license key is
    /// hidden (`register::redact_account`).
    pub async fn account(&self) -> Result<serde_json::Value> {
        let mut account =
            register::get_account(&self.device.id, &self.device.token, self.proxy.as_ref()).await?;
        register::redact_account(&mut account);
        Ok(account)
    }

    /// Attach a WARP+ license key, then read the device again.
    pub async fn set_license(&mut self, license: &str) -> Result<serde_json::Value> {
        let account = register::set_license(
            &self.device.id,
            &self.device.token,
            license,
            self.proxy.as_ref(),
        )
        .await?;
        self.refresh().await?;
        let mut account = account;
        register::redact_account(&mut account);
        Ok(account)
    }

    /// Make a new MASQUE key and enrol it. The old key stops working.
    pub async fn rotate_key(&mut self) -> Result<()> {
        let identity = Identity::generate().context("generating the MASQUE identity")?;
        let token = self.device.token.clone();
        let mut device = register::enrol_masque(
            &self.device.id,
            &token,
            identity.spki_b64(),
            self.proxy.as_ref(),
        )
        .await
        .context("enrolling the new MASQUE identity")?;
        device.token = token;
        self.device = device;
        self.identity = identity;
        Ok(())
    }

    /// Remove the device from the WARP service.
    pub async fn delete(&self) -> Result<()> {
        register::delete_device(&self.device.id, &self.device.token, self.proxy.as_ref()).await
    }

    /// The device record, including the assigned addresses and the pinned peer
    /// key.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// The identity presented to the front door.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The address the tunnel assigned to us.
    pub fn local_address(&self) -> Result<std::net::IpAddr> {
        if let Some(peer) = &self.wireguard {
            return peer
                .v4
                .map(std::net::IpAddr::V4)
                .or(peer.v6.map(std::net::IpAddr::V6))
                .context("the WireGuard device has no address");
        }
        self.device
            .ipv4()
            .map(std::net::IpAddr::V4)
            .or_else(|| self.device.ipv6().map(std::net::IpAddr::V6))
            .context("the tunnel assigned no address")
    }

    /// Open the MASQUE session and start the userspace stack on top of it.
    pub async fn connect(&self) -> Result<WarpStack> {
        let outer = self.connect_outer().await?;
        match &self.carry {
            None => Ok(outer),
            Some(peer) => self.connect_carried(outer, peer).await,
        }
    }

    /// The stack of a second WireGuard device inside the stack `outer`
    /// (issues 154 and 155). Its MTU leaves room for WireGuard and the
    /// headers of the outer packet; it has IPv4 only (IPv6 needs an MTU of
    /// 1280).
    async fn connect_carried(&self, outer: WarpStack, peer: &wg::Peer) -> Result<WarpStack> {
        let session = MasqueSession::connect_wg_inside(peer, &outer)
            .await
            .context("the carried WireGuard tunnel")?;
        let local = peer
            .v4
            .map(std::net::IpAddr::V4)
            .context("the carried device has no IPv4 address")?;
        let mut config = StackConfig::new(local);
        config.mtu = CARRY_MTU;
        let (tx, rx) = session.split();
        let inner = WarpStack::start(tx, rx, config)?;
        // The outer stack lives as long as the inner one.
        let watch = inner.clone();
        tokio::spawn(async move {
            while !watch.is_closed() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            drop(outer);
        });
        if std::env::var_os(proxy::NO_CHECK_VARIABLE).is_none_or(|v| v.is_empty()) {
            let took = proxy::check_data_path(&inner, true)
                .await
                .context("the carried tunnel carries no packet")?;
            tracing::info!(
                ms = took.as_millis() as u64,
                "a packet crossed the carried WireGuard tunnel"
            );
        }
        crate::decisions::count("masque", "carry");
        Ok(inner)
    }

    /// The session of this client and the stack on it.
    async fn connect_outer(&self) -> Result<WarpStack> {
        let session = self.open_session().await?;
        let local = self.local_address()?;
        let (tx, rx) = session.split();
        let stack = WarpStack::start(
            tx,
            rx,
            StackConfig::new(local).with_ipv6(match &self.wireguard {
                Some(peer) => peer.v6,
                None => self.device.ipv6(),
            }),
        )?;
        // Issue 120: the session is up when a packet crossed it.
        if std::env::var_os(proxy::NO_CHECK_VARIABLE).is_some_and(|v| !v.is_empty()) {
            tracing::debug!(
                "{} is set: no check of the data path",
                proxy::NO_CHECK_VARIABLE
            );
        } else {
            let took = match proxy::check_data_path(&stack, local.is_ipv4()).await {
                Ok(took) => took,
                Err(err) => {
                    // Issue 133: the next session tries the other door
                    // first. Before, the door that answered the handshake
                    // and carried nothing stayed first.
                    let mut won = self.endpoint_won.lock().unwrap_or_else(|e| e.into_inner());
                    *self.door_bad.lock().unwrap_or_else(|e| e.into_inner()) = won.take();
                    return Err(err);
                }
            };
            tracing::info!(
                ms = took.as_millis() as u64,
                "a packet crossed the MASQUE session"
            );
            self.write_door();
        }
        Ok(stack)
    }

    /// The address of the front door of the last session: the override of
    /// `--masque-endpoint`, else the address that worked, else the first of
    /// the device record (the IPv6-only kit, 0001).
    pub fn endpoint_in_use(&self) -> Option<std::net::SocketAddr> {
        self.masque
            .endpoint
            .or(*self.endpoint_won.lock().unwrap_or_else(|e| e.into_inner()))
            .or_else(|| self.device.masque_endpoint())
    }

    /// Open the session without the userspace stack, for callers that only want
    /// the raw packet pipe.
    pub async fn connect_raw(&self) -> Result<MasqueSession> {
        if self.carry.is_some() {
            bail!(
                "--carry is for the userspace stack (warp proxy, run, nc, probe), not for warp tun"
            );
        }
        self.open_session().await
    }

    /// The endpoint and the pinned key of a device record.
    fn endpoint_and_pin(device: &Device) -> Result<(std::net::SocketAddr, Vec<u8>)> {
        let endpoint = device
            .masque_endpoint()
            .context("the device has no MASQUE endpoint")?;
        let pinned = device
            .peer_public_key_pem()
            .context("the device has no peer key to pin; cfrs does not connect without one")
            .and_then(identity::spki_from_pem)
            .context("parsing the pinned peer key")?;
        Ok((endpoint, pinned))
    }

    /// Open the MASQUE session. When the front door shows a key that is not
    /// the pinned key (live run 41272909372, on a new device), read the
    /// device record again and try with its key and endpoint, then once
    /// more after 1 s (a new connection may reach another server). A key
    /// that the API did not give is never accepted.
    /// Open a session: direct (through the proxy of the egress), and when
    /// that fails, through the WebSocket relay (issue 76). The path that
    /// worked last goes first.
    async fn open_session(&self) -> Result<MasqueSession> {
        use std::sync::atomic::Ordering;
        // Issue 152: WireGuard on UDP, with no relay and no proxy.
        if let Some(peer) = &self.wireguard {
            let session = MasqueSession::connect_wg(peer).await?;
            crate::decisions::count("masque", "wireguard");
            return Ok(session);
        }
        // Issue 157: HTTP/3 has no relay (the relay carries TCP).
        let relay = if self.masque.h3 { None } else { self.relay() };
        let Some(relay) = relay else {
            let session = self.open_on(None).await?;
            crate::decisions::count("masque", "no_relay");
            return Ok(session);
        };
        self.read_leg(&relay);
        // The direct path goes first, each time; the relay starts after a
        // delay, and the first session that opens wins. A host where the
        // direct path works again leaves the relay (before, a relay that
        // worked once went first, also from the leg file, and the direct
        // path was not tried again). The delay is short when the relay
        // worked last.
        let relay_first = self.relay_first.load(Ordering::SeqCst);
        let delay = if relay_first {
            RELAY_DELAY_KNOWN
        } else {
            RELAY_DELAY
        };
        let direct = self.open_on(None);
        let through = async {
            tokio::time::sleep(delay).await;
            self.open_on(Some(&relay)).await
        };
        tokio::pin!(direct);
        tokio::pin!(through);
        let mut direct_err: Option<anyhow::Error> = None;
        let mut relay_err: Option<anyhow::Error> = None;
        while direct_err.is_none() || relay_err.is_none() {
            tokio::select! {
                result = &mut direct, if direct_err.is_none() => match result {
                    Ok(session) => {
                        crate::decisions::count("masque", "direct");
                        if relay_first {
                            self.relay_first.store(false, Ordering::SeqCst);
                            self.write_leg("direct", &relay);
                        }
                        return Ok(session);
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %format!("{err:#}"),
                            relay = %relay.url(),
                            "the direct MASQUE path failed; the WebSocket relay is tried (--no-relay turns this off)"
                        );
                        direct_err = Some(err);
                    }
                },
                result = &mut through, if relay_err.is_none() => match result {
                    Ok(session) => {
                        tracing::info!(relay = %relay.url(), "MASQUE goes through the WebSocket relay");
                        crate::decisions::count("masque", if relay_first { "relay_first" } else { "relay" });
                        if !relay_first {
                            self.relay_first.store(true, Ordering::SeqCst);
                            self.write_leg("relay", &relay);
                        }
                        return Ok(session);
                    }
                    Err(err) => relay_err = Some(err),
                },
            }
        }
        let (Some(direct), Some(through)) = (direct_err, relay_err) else {
            unreachable!("the loop ends when both failed");
        };
        Err(direct.context(format!(
            "and through the relay {}: {through:#}",
            relay.url()
        )))
    }

    /// Open a session on one path; a key that is not the pinned key reads
    /// the device record again (the front door changed its key).
    /// Measure each of `candidates` and the front doors of the device
    /// record (issue 139), at most 8 at the same time. The result is in
    /// the order of the total time; a failure goes last.
    pub async fn scan(
        &self,
        candidates: &[std::net::SocketAddr],
        timeout: std::time::Duration,
    ) -> Result<Vec<(std::net::SocketAddr, Result<session::DoorTimes>)>> {
        use futures::StreamExt as _;
        let (_, pinned) = Self::endpoint_and_pin(&self.device)?;
        let mut all: Vec<std::net::SocketAddr> = Vec::new();
        for a in candidates
            .iter()
            .copied()
            .chain(self.device.masque_endpoints())
        {
            if !all.contains(&a) {
                all.push(a);
            }
        }
        let dial = session::Dial {
            proxy: self.proxy.as_ref(),
            relay: None,
            sni: self.masque.sni.as_deref(),
            h3: false,
        };
        let mut out: Vec<_> = futures::stream::iter(all)
            .map(|a| {
                let pinned = pinned.clone();
                async move {
                    let r = session::probe_door(a, &self.identity, pinned, dial, timeout).await;
                    (a, r)
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;
        out.sort_by_key(|(a, r)| match r {
            Ok(t) => (0, t.total(), *a),
            Err(_) => (1, std::time::Duration::ZERO, *a),
        });
        Ok(out)
    }

    async fn open_on(&self, relay: Option<&crate::ws_relay::Relay>) -> Result<MasqueSession> {
        let dial = session::Dial {
            proxy: self.proxy.as_ref(),
            relay,
            sni: self.masque.sni.as_deref(),
            h3: self.masque.h3,
        };
        let (endpoint, pinned) = Self::endpoint_and_pin(&self.device)?;
        // Issue 124: the IPv4 and the IPv6 address of the front door, the
        // one that worked last first. An override is the only one.
        let candidates = match self.masque.endpoint {
            Some(one) => vec![one],
            None => {
                let won = *self.endpoint_won.lock().unwrap_or_else(|e| e.into_inner());
                let bad = *self.door_bad.lock().unwrap_or_else(|e| e.into_inner());
                let ipv6 = relay.is_some()
                    || self.proxy.is_some()
                    || crate::resolve::has_default_route(true);
                let order = endpoint_order(self.device.masque_endpoints(), won, bad, ipv6);
                if order.is_empty() {
                    vec![endpoint]
                } else {
                    order
                }
            }
        };
        let mut failures = Vec::new();
        let mut mismatch = None;
        for (i, endpoint) in candidates.iter().enumerate() {
            match MasqueSession::connect(*endpoint, &self.identity, pinned.clone(), dial).await {
                Ok(session) => {
                    *self.endpoint_won.lock().unwrap_or_else(|e| e.into_inner()) = Some(*endpoint);
                    return Ok(session);
                }
                Err(err) if format!("{err:#}").contains(session::PIN_MISMATCH) => {
                    mismatch = Some(err);
                    break;
                }
                Err(err) => {
                    if i + 1 < candidates.len() {
                        tracing::warn!(error = %format!("{err:#}"), "the front door {endpoint} failed; trying {}", candidates[i + 1]);
                    }
                    failures.push(err);
                }
            }
        }
        let Some(err) = mismatch else {
            let mut errs = failures.into_iter();
            let first = errs
                .next()
                .unwrap_or_else(|| anyhow::anyhow!("no front door address"));
            return Err(errs.fold(first, |acc, e| {
                acc.context(format!(
                    "the other address of the front door failed too ({e:#})"
                ))
            }));
        };
        tracing::warn!(error = %format!("{err:#}"), "the MASQUE key is not the pinned key; reading the device record again");
        let fresh = register::get_device(&self.device.id, &self.device.token, self.proxy.as_ref())
            .await
            .context("reading the device record again after a MASQUE key mismatch")?;
        let (endpoint, pinned) = Self::endpoint_and_pin(&fresh)?;
        let endpoint = self.masque.endpoint.unwrap_or(endpoint);
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            match MasqueSession::connect(endpoint, &self.identity, pinned.clone(), dial).await {
                Ok(session) => return Ok(session),
                Err(err) if attempt == 0 && format!("{err:#}").contains(session::PIN_MISMATCH) => {
                    tracing::warn!("the MASQUE key is still not the pinned key; trying once more");
                }
                Err(err) => return Err(err),
            }
        }
        unreachable!("the loop returns")
    }
}

/// Write `bytes` to `path` with mode 0600: to a new file beside it, then a
/// rename. No other user can read the file at any time, and a reader never
/// sees half a file.
pub(crate) fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the path has no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// [`write_private`] for the commands of the binary.
pub fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    write_private(path, bytes)
}

/// Refuse `path` when its owner is another user, or when its group or other
/// users may read or write it.
pub(crate) fn check_private(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading the WARP identity from {}", path.display()))?;
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        anyhow::bail!(
            "{} belongs to user {}, not to this user ({uid}); cfrs does not use it",
            path.display(),
            meta.uid()
        );
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} has mode {mode:04o}: other users may read the WARP key. Run: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod private_file_tests {
    use super::*;

    // Issue 124: the address that worked goes first; IPv6 only with a
    // route.
    #[test]
    fn the_order_of_the_front_door_addresses() {
        let v4: std::net::SocketAddr = "162.159.198.2:443".parse().unwrap();
        let v6: std::net::SocketAddr = "[2606:4700:103::2]:443".parse().unwrap();
        assert_eq!(endpoint_order(vec![v4, v6], None, None, true), [v4, v6]);
        assert_eq!(endpoint_order(vec![v4, v6], Some(v6), None, true), [v6, v4]);
        assert_eq!(endpoint_order(vec![v4, v6], None, None, false), [v4]);
        assert_eq!(endpoint_order(vec![v4, v6], Some(v6), None, false), [v4]);
        // Issue 133: a door that carried no packet goes last, also when it
        // won the handshake.
        assert_eq!(
            endpoint_order(vec![v4, v6], Some(v4), Some(v4), true),
            [v6, v4]
        );
        assert_eq!(endpoint_order(vec![v4, v6], None, Some(v4), true), [v6, v4]);
    }

    // Issue 133: the door file is used when it is recent and names a door
    // of the device.
    #[test]
    fn the_door_file() {
        let v4: std::net::SocketAddr = "162.159.198.2:443".parse().unwrap();
        let v6: std::net::SocketAddr = "[2606:4700:103::2]:443".parse().unwrap();
        let doc = |door: &str, at: u64, schema: u64| {
            serde_json::json!({"schema": schema, "door": door, "at": at}).to_string()
        };
        let now = 1_800_000_000;
        let doors = [v4, v6];
        assert_eq!(
            door_from(&doc("[2606:4700:103::2]:443", now - 60, 1), now, &doors),
            Some(v6)
        );
        assert_eq!(
            door_from(&doc("162.159.198.2:443", now - 8 * 86400, 1), now, &doors),
            None
        );
        assert_eq!(
            door_from(&doc("192.0.2.1:443", now - 60, 1), now, &doors),
            None
        );
        assert_eq!(
            door_from(&doc("162.159.198.2:443", now - 60, 2), now, &doors),
            None
        );
        assert_eq!(door_from("{", now, &doors), None);
        assert_eq!(
            door_file_of(std::path::Path::new("/s/warp.json")),
            std::path::Path::new("/s/warp-door.json")
        );
    }

    // Issue 126: a relay that worked in the last hours goes first; an old
    // entry, another relay or a bad file does not.
    #[test]
    fn the_leg_file_puts_a_recent_relay_first() {
        let relay = "https://relay.example";
        let doc = |leg: &str, at: u64, r: &str| {
            serde_json::json!({"leg": leg, "at": at, "relay": r}).to_string()
        };
        let now = 1_800_000_000;
        assert!(relay_first_from(&doc("relay", now - 60, relay), now, relay));
        assert!(!relay_first_from(
            &doc("direct", now - 60, relay),
            now,
            relay
        ));
        assert!(!relay_first_from(
            &doc("relay", now - 7 * 3600, relay),
            now,
            relay
        ));
        assert!(!relay_first_from(
            &doc("relay", now - 60, "https://other"),
            now,
            relay
        ));
        assert!(!relay_first_from(
            &doc("relay", now + 60, relay),
            now,
            relay
        ));
        assert!(!relay_first_from("not json", now, relay));
        assert_eq!(
            leg_file_of(std::path::Path::new("/s/warp.json")),
            std::path::Path::new("/s/warp-leg.json")
        );
    }
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_private_file_has_mode_0600_and_a_loose_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/cfrs/warp.json");
        write_private(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let parent = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent, 0o700);
        check_private(&path).unwrap();
        // A second write replaces the file and leaves no temporary file.
        write_private(&path, b"{\"a\":1}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}");
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_private(&path).unwrap_err().to_string();
        assert!(
            err.contains("mode 0644") && err.contains("chmod 600"),
            "{err}"
        );
        let err = WarpClient::load(&path).err().unwrap().to_string();
        assert!(err.contains("mode 0644"), "{err}");
    }
}
