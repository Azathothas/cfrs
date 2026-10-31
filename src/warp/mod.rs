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
pub mod edge;
pub mod identity;
pub mod ip;
pub mod quic;
pub mod register;
pub mod proxy;
pub mod session;

pub use edge::{start_quick_tunnel, QuickTunnelHandle};
pub use identity::Identity;
pub use ip::{StackConfig, TcpConn, UdpConn, WarpStack};
pub use register::Device;
pub use session::{MasqueRx, MasqueSession, MasqueTx};

use anyhow::{bail, Context, Result};

use crate::egress::Proxy;

/// A registered WARP device with a MASQUE identity ready to dial.
pub struct WarpClient {
    device: Device,
    identity: Identity,
    proxy: Option<Proxy>,
}

impl WarpClient {
    /// Register anonymously and enrol the MASQUE identity.
    ///
    /// This is the whole of the "self registration" step: a `POST` that creates
    /// the device, a `PATCH` that swaps its key for a P-256 one and switches it
    /// to MASQUE, and a locally generated keypair. No account, no token, no
    /// external tool.
    pub async fn register() -> Result<Self> {
        Self::register_with(Proxy::from_env()).await
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
        })
    }

    /// Build a client from an already-enrolled device and identity, for callers
    /// that persist them.
    pub fn from_parts(device: Device, identity: Identity) -> Self {
        Self {
            device,
            identity,
            proxy: Proxy::from_env(),
        }
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, text)
            .with_context(|| format!("writing the WARP identity to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(())
    }

    /// Read a client written by [`WarpClient::save`].
    pub fn load(path: &std::path::Path) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Stored {
            device: Device,
            cert_pem: String,
            key_pem: String,
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the WARP identity from {}", path.display()))?;
        let stored: Stored = serde_json::from_str(&text)
            .with_context(|| format!("parsing the WARP identity in {}", path.display()))?;
        let identity = Identity::from_pem(&stored.cert_pem, &stored.key_pem)
            .context("rebuilding the MASQUE identity")?;
        Ok(Self::from_parts(stored.device, identity))
    }

    /// Register if `path` holds nothing yet, otherwise resume what it holds.
    ///
    /// This is the call a daemon wants: one device per installation, not one
    /// per start.
    pub async fn register_or_load(path: &std::path::Path) -> Result<Self> {
        match Self::load(path) {
            Ok(client) => {
                if client.device.tunnel_type == "masque" {
                    return Ok(client);
                }
                tracing::debug!(
                    tunnel_type = %client.device.tunnel_type,
                    "the stored device is not enrolled for MASQUE; registering again"
                );
            }
            Err(err) => {
                tracing::debug!(%err, "no stored WARP identity; registering a new device");
            }
        }
        let client = Self::register().await?;
        client.save(path)?;
        Ok(client)
    }

    /// The default place for the saved identity:
    /// `$XDG_STATE_HOME/cfrs/warp.json`, else `~/.local/state/cfrs/warp.json`,
    /// else `./cfrs-warp.json`.
    pub fn default_identity_path() -> std::path::PathBuf {
        if let Some(state) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return std::path::PathBuf::from(state).join("cfrs").join("warp.json");
        }
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            return std::path::PathBuf::from(home)
                .join(".local/state/cfrs")
                .join("warp.json");
        }
        std::path::PathBuf::from("cfrs-warp.json")
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

    /// The account record: type, WARP+ state and quota.
    pub async fn account(&self) -> Result<serde_json::Value> {
        register::get_account(&self.device.id, &self.device.token, self.proxy.as_ref()).await
    }

    /// Attach a WARP+ license key, then read the device again.
    pub async fn set_license(&mut self, license: &str) -> Result<serde_json::Value> {
        let account =
            register::set_license(&self.device.id, &self.device.token, license, self.proxy.as_ref())
                .await?;
        self.refresh().await?;
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
        self.device
            .ipv4()
            .map(std::net::IpAddr::V4)
            .or_else(|| self.device.ipv6().map(std::net::IpAddr::V6))
            .context("the tunnel assigned no address")
    }

    /// Open the MASQUE session and start the userspace stack on top of it.
    pub async fn connect(&self) -> Result<WarpStack> {
        let endpoint = self
            .device
            .masque_endpoint()
            .context("the device has no MASQUE endpoint")?;
        let pinned = self
            .device
            .peer_public_key_pem()
            .map(identity::spki_from_pem)
            .transpose()
            .context("parsing the pinned peer key")?;
        let session =
            MasqueSession::connect(endpoint, &self.identity, pinned, self.proxy.as_ref()).await?;
        let local = self.local_address()?;
        let (tx, rx) = session.split();
        WarpStack::start(tx, rx, StackConfig::new(local))
    }

    /// Open the session without the userspace stack, for callers that only want
    /// the raw packet pipe.
    pub async fn connect_raw(&self) -> Result<MasqueSession> {
        let endpoint = self
            .device
            .masque_endpoint()
            .context("the device has no MASQUE endpoint")?;
        let pinned = self
            .device
            .peer_public_key_pem()
            .map(identity::spki_from_pem)
            .transpose()
            .context("parsing the pinned peer key")?;
        MasqueSession::connect(endpoint, &self.identity, pinned, self.proxy.as_ref()).await
    }
}
