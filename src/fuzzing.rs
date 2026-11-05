//! Entry points for the fuzz targets of `fuzz/` (cargo-fuzz). Each function
//! takes untrusted bytes, runs one parser of podnet on them, and must not
//! panic, hang or allocate much more than the input. The functions give no
//! result: a parse error is a correct answer to bad bytes.
//!
//! [`TARGETS`] is the list of the targets, and [`seeds`] gives the seed
//! inputs of each. A unit test runs each target on its seeds and on
//! deterministic mutations of them, so that the stable test suite also
//! catches a panic.

use crate::cloudflare::capnp::{Message, StructReader};

/// One fuzz target: it takes untrusted bytes.
pub type Target = fn(&[u8]);

/// The name and the function of each target.
pub const TARGETS: &[(&str, Target)] = &[
    ("capnp_message", capnp_message),
    ("rpc_message", rpc_message),
    ("register_response", register_response),
    ("connect_request", connect_request),
    ("capsule", capsule),
    ("proxy_url", proxy_url),
    ("no_proxy", no_proxy),
    ("connect_response_head", connect_response_head),
    ("srv_record", srv_record),
    ("doh_json", doh_json),
    ("acl_rule", acl_rule),
    ("ingress_rule", ingress_rule),
    ("config_yaml", config_yaml),
    ("h2_header_block", h2_header_block),
    ("vnet_frame", vnet_frame),
    ("request_head", request_head),
];

/// Visit each pointer of a struct, to the depth `depth`.
fn walk(s: &StructReader<'_>, depth: u32) {
    if depth == 0 {
        return;
    }
    for i in 0..8u16 {
        let _ = s.get_u64(i as usize);
        if let Ok(Some(child)) = s.get_struct(i) {
            walk(&child, depth - 1);
        }
        let _ = s.get_text(i);
        let _ = s.get_data(i);
        let _ = s.get_capability(i);
        let _ = s.get_text_list(i);
        if let Ok(list) = s.get_struct_list(i) {
            for item in list.iter().take(16) {
                walk(item, depth - 1);
            }
        }
    }
}

/// A Cap'n Proto message: the framing and a walk of each pointer.
pub fn capnp_message(data: &[u8]) {
    if let Ok(Some((message, used))) = Message::parse(data) {
        assert!(used <= data.len());
        if let Ok(root) = message.root() {
            walk(&root, 8);
        }
    }
}

/// An RPC message of the edge: the readers of the RPC session.
pub fn rpc_message(data: &[u8]) {
    use crate::cloudflare::rpc;
    if let Ok(Some((message, _))) = Message::parse(data) {
        let _ = rpc::payload(&message);
        let _ = rpc::results_struct(&message);
        let _ = rpc::imported_capability(&message);
        if let Ok(root) = message.root() {
            let _ = rpc::exception_reason(&root);
        }
    }
}

/// The results of `registerConnection`.
pub fn register_response(data: &[u8]) {
    if let Ok(Some((message, _))) = Message::parse(data) {
        if let Ok(root) = message.root() {
            let _ = crate::cloudflare::schema::read_register_results(&root);
        }
    }
}

/// The `ConnectRequest` and `ConnectResponse` of a visitor stream.
pub fn connect_request(data: &[u8]) {
    if let Ok(Some((message, _))) = Message::parse(data) {
        if let Ok(root) = message.root() {
            let _ = crate::cloudflare::schema::decode_connect_request(&root);
            let _ = crate::cloudflare::schema::decode_connect_response(&root);
        }
    }
}

/// MASQUE capsules, in two chunks.
pub fn capsule(data: &[u8]) {
    let mut decoder = crate::warp::capsule::CapsuleDecoder::new();
    let half = data.len() / 2;
    decoder.push(&data[..half]);
    while decoder.next_packet().is_some() {}
    decoder.push(&data[half..]);
    let mut total = 0;
    while let Some(packet) = decoder.next_packet() {
        total += packet.len();
    }
    assert!(total <= data.len());
}

fn text(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(data).ok()
}

/// A proxy URL (`--proxy`, `HTTPS_PROXY`). A parsed proxy prints with no
/// password.
pub fn proxy_url(data: &[u8]) {
    let Some(spec) = text(data) else { return };
    if let Ok(proxy) = crate::egress::Proxy::parse(spec) {
        let shown = proxy.to_string();
        assert!(!shown.contains('@'), "{shown}");
    }
}

/// A `NO_PROXY` list.
pub fn no_proxy(data: &[u8]) {
    let Some(list) = text(data) else { return };
    let rules = crate::egress::NoProxy::parse(list);
    let _ = rules.matches("api.trycloudflare.com", 443);
    let _ = rules.matches("198.41.192.167", 7844);
    let _ = rules.matches("::1", 80);
}

/// The status line of a proxy answer to `CONNECT`.
pub fn connect_response_head(data: &[u8]) {
    let _ = crate::egress::parse_status(data);
}

/// The `data` field of an SRV record of DoH.
pub fn srv_record(data: &[u8]) {
    if let Some(text) = text(data) {
        let _ = crate::edge_discovery::parse_srv(text);
    }
}

/// A DoH JSON answer.
pub fn doh_json(data: &[u8]) {
    if let Ok(answer) = serde_json::from_slice::<crate::resolve::DohAnswer>(data) {
        for record in answer.answer.iter().take(64) {
            let _ = record.data.parse::<std::net::IpAddr>();
            let _ = crate::edge_discovery::parse_srv(&record.data);
        }
    }
}

/// An ACL rule of `podnet net`.
pub fn acl_rule(data: &[u8]) {
    if let Some(line) = text(data) {
        let _ = crate::vnet::policy::AclRule::parse(line);
    }
}

/// An ingress service and a forward target.
pub fn ingress_rule(data: &[u8]) {
    if let Some(value) = text(data) {
        let _ = crate::ingress::Service::parse(value);
        let _ = crate::ingress::ForwardTarget::parse(value);
        let _ = crate::ws::LocalSpec::parse(value);
    }
}

/// A YAML config file.
pub fn config_yaml(data: &[u8]) {
    if let Some(value) = text(data) {
        let _ = crate::yaml::parse(value);
    }
}

/// The serialized response headers of the HTTP/2 leg.
pub fn h2_header_block(data: &[u8]) {
    if let Some(value) = text(data) {
        let headers = crate::cloudflare::http2::decode_headers(value);
        let _ = crate::cloudflare::http2::decode_origin_response(&headers);
    }
}

/// The HTTP/1.1 head to the origin, from the fields of a `ConnectRequest`
/// of the edge (issue 272): the fields are split at the 0 bytes (the
/// method, the destination, the host, then header names and values). A
/// head that is built has one empty line, at its end, and each line ends
/// with CR LF.
pub fn request_head(data: &[u8]) {
    use crate::cloudflare::stream::{HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY};
    let fields: Vec<String> = data
        .split(|b| *b == 0)
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .collect();
    let field = |i: usize| fields.get(i).cloned().unwrap_or_default();
    let mut metadata = vec![
        (HTTP_METHOD_KEY.to_string(), field(0)),
        (HTTP_HOST_KEY.to_string(), field(2)),
    ];
    for pair in fields.get(3..).unwrap_or_default().chunks(2) {
        let value = pair.get(1).cloned().unwrap_or_default();
        metadata.push((format!("{HTTP_HEADER_KEY}:{}", pair[0]), value));
    }
    let request = crate::cloudflare::stream::ConnectRequest {
        dest: field(1),
        conn_type: crate::cloudflare::stream::ConnectionType::Http,
        metadata,
    };
    let options = crate::ingress::OriginOptions::default();
    for upgrade in [false, true] {
        if let Ok(head) = crate::proxy::build_request_head(&request, &options, upgrade) {
            assert!(head.ends_with("\r\n\r\n"), "{head:?}");
            assert_eq!(head.matches("\r\n\r\n").count(), 1, "{head:?}");
            let crlf = head.matches("\r\n").count();
            assert_eq!(head.matches('\r').count(), crlf, "{head:?}");
            assert_eq!(head.matches('\n').count(), crlf, "{head:?}");
            // Each header line is a pair of the input, or a line that podnet
            // writes: no field makes a line of its own.
            let pairs: Vec<String> = fields
                .get(3..)
                .unwrap_or_default()
                .chunks(2)
                .map(|p| format!("{}: {}", p[0], p.get(1).cloned().unwrap_or_default()))
                .collect();
            for line in head.trim_end().split("\r\n").skip(1) {
                assert!(
                    pairs.iter().any(|p| p == line)
                        || ["Host: ", "Connection: ", "Upgrade: "]
                            .iter()
                            .any(|own| line.starts_with(own)),
                    "{line:?} in {head:?}"
                );
            }
        }
    }
}

/// A frame of the virtual network.
pub fn vnet_frame(data: &[u8]) {
    let mut reader = data;
    let mut packet = Vec::new();
    for _ in 0..64 {
        match futures::executor::block_on(crate::vnet::framing::read_frame(
            &mut reader,
            &mut packet,
        )) {
            Ok(Some(n)) => assert!(n <= data.len()),
            _ => break,
        }
    }
}

/// The seed inputs of `target`.
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    use crate::cloudflare::schema::{
        encode_connect_request, encode_connect_response, ConnectRequest, ConnectionType,
    };
    let s = |items: &[&str]| items.iter().map(|i| i.as_bytes().to_vec()).collect();
    match target {
        "capnp_message" | "rpc_message" | "register_response" | "connect_request" => vec![
            encode_connect_request(&ConnectRequest {
                dest: "http://localhost/".into(),
                conn_type: ConnectionType::Http,
                metadata: vec![("HttpMethod".into(), "GET".into())],
            }),
            encode_connect_response("", &[("HttpStatus".into(), "200".into())]),
            crate::cloudflare::rpc::our_bootstrap_return(1).to_bytes(),
            crate::cloudflare::rpc::exception_return(2, "refused").to_bytes(),
        ],
        "capsule" => vec![vec![0x00, 0x04, 0x45, 0x00, 0x00, 0x04], vec![0x01, 0x01, 0x00]],
        "proxy_url" => s(&[
            "http://127.0.0.1:3128",
            "http://user:pass@proxy:8080",
            "socks5h://[::1]:1080",
            "https://p",
        ]),
        "no_proxy" => s(&["localhost,.example.com,10.0.0.0/8", "*", "[::1]:80,api.x"]),
        "connect_response_head" => s(&[
            "HTTP/1.1 200 Connection established\r\n\r\n",
            "HTTP/1.0 407 Proxy Authentication Required\r\n",
        ]),
        "srv_record" => s(&["1 1 7844 region1.v2.argotunnel.com."]),
        "doh_json" => s(&[
            r#"{"Status":0,"Answer":[{"name":"x.","type":1,"TTL":60,"data":"1.2.3.4"}]}"#,
            r#"{"Status":0,"Answer":[{"type":33,"data":"1 1 7844 region2.v2.argotunnel.com."}]}"#,
        ]),
        "acl_rule" => s(&["allow 10.66.0.0/24:80-90", "deny *", "deny [fd00::1]:22"]),
        "ingress_rule" => s(&[
            "http://127.0.0.1:8080",
            "unix:/run/app.sock",
            "tcp://host:22",
            "http_status:404",
            "spa:./site",
        ]),
        "config_yaml" => s(&[
            "tunnel: x\ncredentials-file: /c.json\ningress:\n  - hostname: a.example.com\n    service: http://localhost:1\n  - service: http_status:404\n",
        ]),
        "h2_header_block" => s(&["Q29udGVudC1UeXBl:dGV4dC9wbGFpbg;WC1B:Yg"]),
        "vnet_frame" => vec![vec![0x00, 0x03, 1, 2, 3], vec![0x80, 0x01, 9]],
        "request_head" => s(&[
            "GET\0https://x.example/a?b=1\0x.example\0Accept\0*/*\0Cookie\0a=b",
            "POST\0https://x/u\0x\0Transfer-Encoding\0chunked\0Connection\0close, X-Hop\0X-Hop\0one",
            "GET\0https://x/ws\0x\0Upgrade\0websocket\0X-A\0a\r\nInjected: 1",
        ]),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each target on its seeds and on 2000 mutations of them (a fixed
    /// xorshift sequence): no panic. This is the stable part of `fuzz/`.
    #[test]
    fn each_target_survives_mutations() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (name, target) in TARGETS {
            let seeds = seeds(name);
            assert!(!seeds.is_empty(), "{name} has no seed");
            for seed in &seeds {
                target(seed);
            }
            for _ in 0..2000 {
                let mut input = seeds[(next() % seeds.len() as u64) as usize].clone();
                for _ in 0..(1 + next() % 4) {
                    let r = next();
                    match r % 4 {
                        0 if !input.is_empty() => {
                            let i = (r >> 8) as usize % input.len();
                            input[i] ^= (r >> 16) as u8;
                        }
                        1 if !input.is_empty() => {
                            let i = (r >> 8) as usize % input.len();
                            input[i] = [0, 0xff, 0x7f, 0x80][(r >> 16) as usize % 4];
                        }
                        2 => {
                            let i = (r >> 8) as usize % (input.len() + 1);
                            input.insert(i, (r >> 16) as u8);
                        }
                        _ => {
                            let keep = (r >> 8) as usize % (input.len() + 1);
                            input.truncate(keep);
                        }
                    }
                }
                target(&input);
            }
        }
    }
}
