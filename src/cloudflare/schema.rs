//! The tunnel structs of `tunnelrpc.capnp` and `quic_metadata_protocol.capnp`
//! (cloudflared). Each layout comes from the field ordinals by the Cap'n
//! Proto layout rules. Offsets are in elements of the field type: a `u8` at
//! index 1 is byte 1, a `u16` at index 1 is bytes 2 and 3.

use anyhow::{bail, Context, Result};
use uuid::Uuid;

use super::capnp::{Builder, StructReader};

/// `interface RegistrationServer`.
pub const REGISTRATION_SERVER_ID: u64 = 0xf716_95ec_7fe8_5497;
/// `RegistrationServer.registerConnection`.
pub const METHOD_REGISTER_CONNECTION: u16 = 0;
/// `RegistrationServer.unregisterConnection`.
pub const METHOD_UNREGISTER_CONNECTION: u16 = 1;

/// `struct TunnelAuth` (0 data words, 2 pointers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelAuth {
    /// `accountTag @0 :Text` (pointer 0).
    pub account_tag: String,
    /// `tunnelSecret @1 :Data` (pointer 1).
    pub tunnel_secret: Vec<u8>,
}

/// `struct ConnectionOptions` and its `struct ClientInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionOptions {
    pub client_id: [u8; 16],
    pub features: Vec<String>,
    pub version: String,
    pub arch: String,
    pub origin_local_ip: Vec<u8>,
    pub replace_existing: bool,
    pub compression_quality: u8,
    pub num_previous_attempts: u8,
}

impl ConnectionOptions {
    /// The options of a new connection. The features are the default
    /// features of cloudflared (`features/features.go`).
    pub fn default_for_quick_tunnel(version: &str) -> Self {
        Self {
            client_id: *Uuid::new_v4().as_bytes(),
            features: [
                "allow_remote_config",
                "serialized_headers",
                "support_datagram_v2",
                "support_quic_eof",
                "management_logs",
            ]
            .map(String::from)
            .to_vec(),
            version: version.to_string(),
            arch: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            origin_local_ip: Vec::new(),
            replace_existing: false,
            compression_quality: 0,
            num_previous_attempts: 0,
        }
    }
}

/// The answer to a good registration (`struct ConnectionDetails`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationDetails {
    pub uuid: Uuid,
    /// The edge location, for example `bom12`.
    pub location: String,
    pub tunnel_is_remotely_managed: bool,
}

/// The answer to a refused registration (`struct ConnectionError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionError {
    pub cause: String,
    /// Nanoseconds to wait before the next attempt.
    pub retry_after: i64,
    pub should_retry: bool,
}

/// Write `registerConnection$Params` (1 data word, 3 pointers) into pointer
/// `index` of `parent`.
pub fn write_register_params(
    b: &mut Builder,
    parent: super::capnp::StructRef,
    index: u16,
    auth: &TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &ConnectionOptions,
) {
    let params = b.init_struct(parent, index, 1, 3);
    let a = b.init_struct(params, 0, 0, 2);
    b.set_text(a, 0, &auth.account_tag);
    b.set_data(a, 1, &auth.tunnel_secret);
    b.set_data(params, 1, tunnel_id.as_bytes());
    b.set_u8(params, 0, conn_index);
    // ConnectionOptions: 1 data word, 2 pointers.
    let o = b.init_struct(params, 2, 1, 2);
    // ClientInfo: 0 data words, 4 pointers.
    let client = b.init_struct(o, 0, 0, 4);
    b.set_data(client, 0, &options.client_id);
    b.set_text_list(client, 1, &options.features);
    b.set_text(client, 2, &options.version);
    b.set_text(client, 3, &options.arch);
    b.set_data(o, 1, &options.origin_local_ip);
    b.set_bool(o, 0, options.replace_existing);
    b.set_u8(o, 1, options.compression_quality);
    b.set_u8(o, 2, options.num_previous_attempts);
}

/// Read `registerConnection$Results` (0 data words, 1 pointer: `result`,
/// a `ConnectionResponse`).
pub fn read_register_results(
    results: &StructReader<'_>,
) -> Result<std::result::Result<RegistrationDetails, ConnectionError>> {
    let response = results
        .get_struct(0)?
        .context("registerConnection returned no result")?;
    // ConnectionResponse: 1 data word, 1 pointer; union tag u16 at index 0.
    let body = response
        .get_struct(0)?
        .context("the ConnectionResponse is empty")?;
    match response.get_u16(0) {
        0 => Ok(Err(ConnectionError {
            cause: body.get_text(0)?,
            retry_after: body.get_u64(0) as i64,
            should_retry: body.get_bool(64),
        })),
        1 => {
            let raw = body.get_data(0)?;
            let uuid = Uuid::from_slice(&raw).unwrap_or_default();
            Ok(Ok(RegistrationDetails {
                uuid,
                location: body.get_text(1)?,
                tunnel_is_remotely_managed: body.get_bool(0),
            }))
        }
        other => bail!("unknown ConnectionResponse variant {other}"),
    }
}

// ── quic_metadata_protocol.capnp ────────────────────────────────────────────

/// `enum ConnectionType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Http,
    Websocket,
    Tcp,
}

impl ConnectionType {
    fn from_u16(value: u16) -> Result<Self> {
        Ok(match value {
            0 => Self::Http,
            1 => Self::Websocket,
            2 => Self::Tcp,
            other => bail!("unknown ConnectionType {other}"),
        })
    }

    fn to_u16(self) -> u16 {
        match self {
            Self::Http => 0,
            Self::Websocket => 1,
            Self::Tcp => 2,
        }
    }
}

/// `struct ConnectRequest` (1 data word, 2 pointers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// `dest @0 :Text`: a URL, or `host:port` for TCP.
    pub dest: String,
    /// `type @1 :ConnectionType` (u16 at index 0).
    pub conn_type: ConnectionType,
    /// `metadata @2 :List(Metadata)`.
    pub metadata: Vec<(String, String)>,
}

impl ConnectRequest {
    /// The value of the first metadata entry with this key.
    pub fn meta(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn write_metadata(
    b: &mut Builder,
    parent: super::capnp::StructRef,
    index: u16,
    items: &[(String, String)],
) {
    // Metadata: 0 data words, 2 pointers (key, val).
    let list = b.init_struct_list(parent, index, items.len(), 0, 2);
    for (entry, (key, val)) in list.into_iter().zip(items) {
        b.set_text(entry, 0, key);
        b.set_text(entry, 1, val);
    }
}

fn read_metadata(parent: &StructReader<'_>, index: u16) -> Result<Vec<(String, String)>> {
    parent
        .get_struct_list(index)?
        .iter()
        .map(|entry| Ok((entry.get_text(0)?, entry.get_text(1)?)))
        .collect()
}

/// Encode a `ConnectRequest` message.
pub fn encode_connect_request(request: &ConnectRequest) -> Vec<u8> {
    let mut b = Builder::new();
    let root = b.init_root(1, 2);
    b.set_text(root, 0, &request.dest);
    b.set_u16(root, 0, request.conn_type.to_u16());
    write_metadata(&mut b, root, 1, &request.metadata);
    b.to_bytes()
}

/// Decode a `ConnectRequest` root.
pub fn decode_connect_request(root: &StructReader<'_>) -> Result<ConnectRequest> {
    Ok(ConnectRequest {
        dest: root.get_text(0)?,
        conn_type: ConnectionType::from_u16(root.get_u16(0))?,
        metadata: read_metadata(root, 1)?,
    })
}

/// Encode a `ConnectResponse` message (0 data words, 2 pointers: `error`,
/// `metadata`).
pub fn encode_connect_response(error: &str, metadata: &[(String, String)]) -> Vec<u8> {
    let mut b = Builder::new();
    let root = b.init_root(0, 2);
    b.set_text(root, 0, error);
    write_metadata(&mut b, root, 1, metadata);
    b.to_bytes()
}

/// Decode a `ConnectResponse` root: the error text and the metadata.
pub fn decode_connect_response(root: &StructReader<'_>) -> Result<(String, Vec<(String, String)>)> {
    Ok((root.get_text(0)?, read_metadata(root, 1)?))
}

#[cfg(test)]
mod tests {
    use super::super::capnp::Message;
    use super::*;

    #[test]
    fn connect_request_round_trips() {
        let request = ConnectRequest {
            dest: "https://x.trycloudflare.com/a?b=c".into(),
            conn_type: ConnectionType::Websocket,
            metadata: vec![
                ("HttpMethod".into(), "GET".into()),
                ("HttpHeader:Host".into(), "x".into()),
            ],
        };
        let bytes = encode_connect_request(&request);
        let (msg, _) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(
            decode_connect_request(&msg.root().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn register_results_decode_both_variants() {
        // connectionDetails
        let mut b = Builder::new();
        let results = b.init_root(0, 1);
        let response = b.init_struct(results, 0, 1, 1);
        b.set_u16(response, 0, 1);
        let details = b.init_struct(response, 0, 1, 2);
        let uuid = Uuid::new_v4();
        b.set_data(details, 0, uuid.as_bytes());
        b.set_text(details, 1, "bom12");
        b.set_bool(details, 0, true);
        let (msg, _) = Message::parse(&b.to_bytes()).unwrap().unwrap();
        let got = read_register_results(&msg.root().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(got.uuid, uuid);
        assert_eq!(got.location, "bom12");
        assert!(got.tunnel_is_remotely_managed);

        // error
        let mut b = Builder::new();
        let results = b.init_root(0, 1);
        let response = b.init_struct(results, 0, 1, 1);
        b.set_u16(response, 0, 0);
        let error = b.init_struct(response, 0, 2, 1);
        b.set_text(error, 0, "duplicate");
        b.set_u64(error, 0, 5_000_000_000);
        b.set_bool(error, 64, true);
        let (msg, _) = Message::parse(&b.to_bytes()).unwrap().unwrap();
        let got = read_register_results(&msg.root().unwrap())
            .unwrap()
            .unwrap_err();
        assert_eq!(got.cause, "duplicate");
        assert_eq!(got.retry_after, 5_000_000_000);
        assert!(got.should_retry);
    }

    #[test]
    fn register_params_have_the_schema_layout() {
        let auth = TunnelAuth {
            account_tag: "acct".into(),
            tunnel_secret: vec![9; 32],
        };
        let options = ConnectionOptions::default_for_quick_tunnel("cfrs/test");
        let tunnel = Uuid::new_v4();
        let mut b = Builder::new();
        let holder = b.init_root(0, 1);
        write_register_params(&mut b, holder, 0, &auth, tunnel, 3, &options);
        let (msg, _) = Message::parse(&b.to_bytes()).unwrap().unwrap();
        let params = msg.root().unwrap().get_struct(0).unwrap().unwrap();
        let a = params.get_struct(0).unwrap().unwrap();
        assert_eq!(a.get_text(0).unwrap(), "acct");
        assert_eq!(a.get_data(1).unwrap(), vec![9; 32]);
        assert_eq!(params.get_data(1).unwrap(), tunnel.as_bytes());
        assert_eq!(params.get_u8(0), 3);
        let o = params.get_struct(2).unwrap().unwrap();
        let client = o.get_struct(0).unwrap().unwrap();
        assert_eq!(client.get_data(0).unwrap(), options.client_id);
        assert_eq!(client.get_text_list(1).unwrap(), options.features);
        assert_eq!(client.get_text(2).unwrap(), "cfrs/test");
    }
}
