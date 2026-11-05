//! `podnet warp export` (issue 148): a WireGuard device of the WARP service,
//! as a config that other clients read (wg-quick, or JSON).
//!
//! The exported device is a new device with its own X25519 key. It is not
//! the MASQUE device of `warp.json`, which this module never reads or
//! writes. Its data plane is WireGuard on UDP (port 2408 of the front door
//! by default), not MASQUE on TCP 443: on a network that permits only TCP
//! 443, the exported config does not work, and podnet itself does.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};

use super::register::{self, Device};
use crate::egress::Proxy;

/// The file name of the exported device in the state directory.
pub const FILE_NAME: &str = "warp-wg.json";
/// The UDP port of WireGuard on the front door.
pub const WG_PORT: u16 = 2408;

/// The exported device and its private key.
#[derive(Serialize, Deserialize)]
pub struct Exported {
    pub device: Device,
    /// The X25519 private key (base64).
    pub private_key: String,
}

/// An X25519 key pair: (private, public), each in base64. The private key
/// is clamped (RFC 7748), as WireGuard keeps it.
pub fn keypair() -> Result<(String, String)> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("no OS entropy: {e}"))?;
    Ok(keypair_of(secret))
}

fn keypair_of(mut secret: [u8; 32]) -> (String, String) {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(secret);
    (b64(&secret), b64(public.as_bytes()))
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// `<state dir>/warp-wg.json`; `None` with `PODNET_STATE_DIR=none`.
pub fn default_path() -> Result<Option<PathBuf>> {
    Ok(crate::state::state_dir()?.map(|dir| dir.join(FILE_NAME)))
}

/// Read an exported device.
pub fn load(path: &Path) -> Result<Exported> {
    super::check_private(path)?;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The exported device of `path`; a new one when there is none or `new`.
pub async fn load_or_register(path: &Path, new: bool, proxy: Option<&Proxy>) -> Result<Exported> {
    if crate::state::exists(path)? && !new {
        return load(path);
    }
    let (private_key, public_key) = keypair()?;
    let device = register::create_device_with_key(&public_key, proxy)
        .await
        .context("registering the WireGuard device")?;
    if device.config.peers.is_empty() {
        bail!("the WARP API gave no peer for the WireGuard device");
    }
    let exported = Exported {
        device,
        private_key,
    };
    let text = serde_json::to_string_pretty(&exported)?;
    super::write_private(path, text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(exported)
}

/// Remove the exported device from the service, and its file.
pub async fn delete(path: &Path, proxy: Option<&Proxy>) -> Result<String> {
    // Issue 178: a second --delete names the missing file (before: an
    // error of the WARP identity, exit 69).
    if !crate::state::exists(path)? {
        return Err(crate::exit::fault(
            crate::exit::Fault::Config,
            anyhow::anyhow!("no exported device at {}", path.display()),
        ));
    }
    let exported = load(path)?;
    register::delete_device(&exported.device.id, &exported.device.token, proxy).await?;
    std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    Ok(exported.device.id)
}

/// Issue 177: the output of `warp export` holds the private key. With no
/// `--out`, a terminal is refused (a usage error), so that the key is not
/// on the screen. `--out -` writes to stdout on purpose.
pub fn check_sink(out: Option<&Path>, stdout_is_terminal: bool) -> Result<()> {
    if out.is_none() && stdout_is_terminal {
        bail!(
            "stdout is a terminal, and the output holds the private key; give --out FILE, redirect stdout, or give --out - to print it"
        );
    }
    Ok(())
}

/// Issue 177: when stdout is a regular file of this user that others can
/// read (`podnet warp export > warp.conf` with a umask of 022), set its mode
/// to 0600 before the key is written. True when the mode changed.
pub fn tighten_stdout() -> bool {
    use std::os::fd::AsRawFd as _;
    let fd = std::io::stdout().as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    tighten_fd(fd, &st)
}

fn tighten_fd(fd: i32, st: &libc::stat) -> bool {
    let regular = st.st_mode & libc::S_IFMT == libc::S_IFREG;
    let mine = st.st_uid == unsafe { libc::geteuid() };
    if regular && mine && st.st_mode & 0o077 != 0 {
        return unsafe { libc::fchmod(fd, 0o600) } == 0;
    }
    false
}

/// The values of a config.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub private_key: String,
    pub peer_public_key: String,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub endpoint: String,
    pub reserved: Option<[u8; 3]>,
    pub keepalive: u16,
}

impl Config {
    /// The config of an exported device. `endpoint` replaces the endpoint
    /// of the record.
    pub fn of(exported: &Exported, endpoint: Option<&str>, keepalive: u16) -> Result<Self> {
        let device = &exported.device;
        let peer = device
            .config
            .peers
            .first()
            .context("the device record has no peer")?;
        if peer.public_key.is_empty() {
            bail!("the device record has no peer key");
        }
        let endpoint = match endpoint {
            Some(e) => e.to_string(),
            None => record_endpoint(&peer.endpoint)?,
        };
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        Ok(Config {
            private_key: exported.private_key.clone(),
            peer_public_key: peer.public_key.clone(),
            address_v4: some(&device.config.interface.addresses.v4),
            address_v6: some(&device.config.interface.addresses.v6),
            endpoint,
            reserved: device.reserved(),
            keepalive,
        })
    }

    /// The wg-quick text.
    pub fn wg_quick(&self) -> String {
        let mut addresses = Vec::new();
        if let Some(v4) = &self.address_v4 {
            addresses.push(format!("{v4}/32"));
        }
        if let Some(v6) = &self.address_v6 {
            addresses.push(format!("{v6}/128"));
        }
        let mut out = String::from(
            "# podnet warp export: a WireGuard device of WARP (UDP). podnet warp export --delete removes it.\n",
        );
        if let Some([a, b, c]) = self.reserved {
            out.push_str(&format!(
                "# Reserved = {a},{b},{c} (for the clients that send it)\n"
            ));
        }
        out.push_str(&format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001\nMTU = 1280\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}\n",
            self.private_key,
            addresses.join(", "),
            self.peer_public_key,
            self.endpoint
        ));
        if self.keepalive > 0 {
            out.push_str(&format!("PersistentKeepalive = {}\n", self.keepalive));
        }
        out
    }

    /// The JSON document.
    pub fn json(&self, device_id: &str) -> serde_json::Value {
        serde_json::json!({
            "device_id": device_id,
            "private_key": self.private_key,
            "peer_public_key": self.peer_public_key,
            "address_v4": self.address_v4,
            "address_v6": self.address_v6,
            "endpoint": self.endpoint,
            "reserved": self.reserved.map(|r| r.to_vec()),
            "mtu": 1280,
            "keepalive": self.keepalive,
        })
    }
}

/// The endpoint of the record: `host` (with port 2408 when it has none),
/// else the IPv4 address on port 2408.
fn record_endpoint(endpoint: &register::Endpoint) -> Result<String> {
    let host = endpoint.host.trim();
    if !host.is_empty() {
        let has_port = host
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && !h.ends_with(':') && p.parse::<u16>().is_ok());
        return Ok(if has_port {
            host.to_string()
        } else {
            format!("{host}:{WG_PORT}")
        });
    }
    let v4 = endpoint.v4.trim();
    let ip = v4.rsplit_once(':').map_or(v4, |(ip, _)| ip);
    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(format!("{ip}:{WG_PORT}"));
    }
    bail!("the device record has no endpoint; give --endpoint HOST:PORT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_refuses_a_terminal_without_out() {
        assert!(check_sink(None, true).is_err());
        assert!(check_sink(None, false).is_ok());
        assert!(check_sink(Some(Path::new("-")), true).is_ok());
        assert!(check_sink(Some(Path::new("w.conf")), true).is_ok());
    }

    #[test]
    fn a_redirected_file_is_tightened_to_0600() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("podnet-tighten-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("warp.conf");
        let file = std::fs::File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(file.as_raw_fd(), &mut st) }, 0);
        assert!(tighten_fd(file.as_raw_fd(), &st));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Mode 0600 already: no change.
        assert_eq!(unsafe { libc::fstat(file.as_raw_fd(), &mut st) }, 0);
        assert!(!tighten_fd(file.as_raw_fd(), &st));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_x25519_key_pair() {
        // RFC 7748, section 6.1: the key of Alice.
        let secret: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let (private, public) = keypair_of(secret);
        use base64::Engine;
        let public = base64::engine::general_purpose::STANDARD
            .decode(public)
            .unwrap();
        assert_eq!(
            public,
            hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        let private = base64::engine::general_purpose::STANDARD
            .decode(private)
            .unwrap();
        assert_eq!(private[0] & 7, 0);
        assert_eq!(private[31] & 0xc0, 0x40);
        let (a, b) = keypair().unwrap();
        assert_eq!((a.len(), b.len()), (44, 44));
    }

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn exported(host: &str, v4: &str) -> Exported {
        let device: Device = serde_json::from_value(serde_json::json!({
            "id": "dev",
            "account": {"id": "acc"},
            "token": "t",
            "config": {
                "client_id": "AQID",
                "peers": [{"public_key": "PEER=", "endpoint": {"host": host, "v4": v4}}],
                "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110::2"}},
            },
        }))
        .unwrap();
        Exported {
            device,
            private_key: "PRIV=".into(),
        }
    }

    #[test]
    fn the_wg_quick_config() {
        let config =
            Config::of(&exported("engage.cloudflareclient.com:2408", ""), None, 25).unwrap();
        assert_eq!(config.endpoint, "engage.cloudflareclient.com:2408");
        assert_eq!(config.reserved, Some([1, 2, 3]));
        let text = config.wg_quick();
        assert!(text.contains("PrivateKey = PRIV=\n"));
        assert!(text.contains("Address = 172.16.0.2/32, 2606:4700:110::2/128\n"));
        assert!(text.contains("PublicKey = PEER=\n"));
        assert!(text.contains("Endpoint = engage.cloudflareclient.com:2408\n"));
        assert!(text.contains("PersistentKeepalive = 25\n"));
        assert!(text.contains("# Reserved = 1,2,3"));
        let json = config.json("dev");
        assert_eq!(json["reserved"], serde_json::json!([1, 2, 3]));
        assert!(json.get("token").is_none());
        // No keepalive line with 0; the endpoint of the IPv4 address.
        let config = Config::of(&exported("", "162.159.192.1:0"), None, 0).unwrap();
        assert_eq!(config.endpoint, "162.159.192.1:2408");
        assert!(!config.wg_quick().contains("PersistentKeepalive"));
        let config = Config::of(
            &exported("engage.example", ""),
            Some("[2606:4700::1]:500"),
            25,
        )
        .unwrap();
        assert_eq!(config.endpoint, "[2606:4700::1]:500");
        assert_eq!(
            Config::of(&exported("engage.example", ""), None, 25)
                .unwrap()
                .endpoint,
            "engage.example:2408"
        );
        assert!(Config::of(&exported("", ""), None, 25).is_err());
    }
}
