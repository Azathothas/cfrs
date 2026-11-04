//! `cfrs doctor` against a local test proxy that refuses, carries nothing,
//! or terminates TLS with its own CA (issue 11). No test uses the network.

mod test_host;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// What the test proxy does with one CONNECT.
#[derive(Clone, Copy)]
enum Action {
    /// 403 with a body.
    Refuse,
    /// 200, then no byte.
    Silent,
    /// 200, then TLS with the certificate of the test CA.
    Terminate,
}

const PASSWORD: &str = "doctor-secret-pw";

fn tls_config() -> Arc<rustls::ServerConfig> {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cfrs doctor test CA");
    let issuer = rcgen::Issuer::new(params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["api.trycloudflare.com".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// A CONNECT proxy on a local port; `rule` chooses the action for each
/// authority. Gives the port.
fn proxy(rule: fn(&str) -> Action) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = tls_config();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || handle(stream, rule, config));
        }
    });
    port
}

fn handle(mut stream: TcpStream, rule: fn(&str) -> Action, config: Arc<rustls::ServerConfig>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let text = String::from_utf8_lossy(&head);
    let authority = text
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("")
        .to_string();
    match rule(&authority) {
        Action::Refuse => {
            let body = "port not on the allowlist";
            let _ = write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
        Action::Silent => {
            let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            std::thread::sleep(Duration::from_secs(5));
        }
        Action::Terminate => {
            let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
        }
    }
}

/// Run `cfrs doctor --json` through the proxy on `port`. Gives the exit code,
/// the JSON document and all the output.
fn doctor(port: u16) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cfrs"));
    cmd.args([
        "--proxy",
        &format!("http://tester:{PASSWORD}@127.0.0.1:{port}"),
        "doctor",
        "--json",
        "--samples",
        "2",
        "--timeout",
        "1",
    ])
    // A TEST-NET address: no answer, and no proxy rule exempts it.
    .env("CFRS_EDGE", "192.0.2.1:7844")
    .env_remove("CFRS_ERROR_PROGRAM")
    .env_remove("SSL_CERT_FILE");
    for key in ["NO_PROXY", "no_proxy"] {
        cmd.env_remove(key);
    }
    let out = cmd.output().unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !all.contains(PASSWORD),
        "the proxy password is in the output"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({e}):\n{all}"));
    (out.status.code(), doc, all)
}

fn leg<'a>(doc: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    doc["legs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["leg"] == name)
        .unwrap()
}

fn path<'a>(doc: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    doc["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .unwrap()
}

#[test]
fn a_proxy_that_refuses_7844_and_terminates_tls() {
    test_host::need_loopback!();
    let port = proxy(|authority| {
        if authority.ends_with(":7844") {
            Action::Refuse
        } else {
            Action::Terminate
        }
    });
    let (code, doc, all) = doctor(port);
    assert_eq!(code, Some(1), "{all}");
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["proxy"]["credentials"], true);
    let http2 = leg(&doc, "http2");
    assert_eq!(http2["verdict"], "fail", "{all}");
    assert_eq!(http2["status"], "fail", "{all}");
    assert!(
        http2["reason"].as_str().unwrap().contains("proxy 403"),
        "{all}"
    );
    assert_eq!(leg(&doc, "quic")["verdict"], "fail");
    // The TLS issuer of the proxy is named.
    let api = path(&doc, "api");
    assert_eq!(api["verdict"], "ok", "{all}");
    assert_eq!(api["tls"]["verdict"], "fail", "{all}");
    assert!(api["tls"]["issuer"]
        .as_str()
        .unwrap()
        .contains("cfrs doctor test CA"));
    assert!(api["tls"]["detail"]
        .as_str()
        .unwrap()
        .contains("a proxy terminates TLS"));
    // Samples: a refusal is an answer, not a loss.
    let edge = path(&doc, "edge-address");
    assert_eq!(edge["samples"]["loss"], 0.0, "{all}");
    assert!(edge["samples"]["best_ms"].is_number());
    // UDP to an address that does not answer is never ok.
    assert_ne!(doc["udp"]["verdict"], "answered");
}

#[test]
fn a_proxy_that_allows_names_and_refuses_addresses() {
    test_host::need_loopback!();
    let port = proxy(|authority| {
        let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
        if host.parse::<std::net::IpAddr>().is_ok() {
            Action::Refuse
        } else {
            Action::Terminate
        }
    });
    let (_, doc, all) = doctor(port);
    assert_eq!(
        doc["names"],
        "the proxy allows names and refuses IP addresses; the edge legs dial addresses",
        "{all}"
    );
    assert_eq!(path(&doc, "edge-name")["verdict"], "ok");
    assert_eq!(path(&doc, "edge-address")["verdict"], "fail");
}

#[test]
fn a_proxy_that_answers_200_and_carries_nothing() {
    test_host::need_loopback!();
    let port = proxy(|_| Action::Silent);
    let (code, doc, all) = doctor(port);
    assert_eq!(code, Some(1));
    let api = path(&doc, "api");
    assert_eq!(api["verdict"], "ok", "{all}");
    assert!(
        api["tls"]["detail"]
            .as_str()
            .unwrap()
            .contains("the proxy answers and carries nothing"),
        "{all}"
    );
}
