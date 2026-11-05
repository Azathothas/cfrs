//! The TLS roots of podnet, end to end: a local HTTPS server with a private CA
//! stands in for the quick-tunnel API (as a TLS-inspecting proxy would).

mod test_host;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;

struct Ca {
    pem: String,
    leaf_der: Vec<u8>,
    key_der: Vec<u8>,
}

/// A private CA and a certificate for `localhost` that it signs. With
/// `expired`, the certificate ended in 2021.
fn ca(expired: bool) -> Ca {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "podnet test CA");
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(params, ca_key);

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    if expired {
        leaf.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf.not_after = rcgen::date_time_ymd(2021, 1, 1);
    }
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
    Ca {
        pem: ca_cert.pem(),
        leaf_der: leaf_cert.der().to_vec(),
        key_der: leaf_key.serialize_der(),
    }
}

/// Serve HTTPS on a local port: each request gets `403` and a short body.
/// Gives the port.
fn serve(ca: &Ca) -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(ca.leaf_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(ca.key_der.clone().into()),
        )
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let body = "private CA reached";
                let _ = write!(
                    tls,
                    "HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

/// Run `podnet tunnel` with the quick-tunnel API at `https://localhost:port`.
fn tunnel(port: u16, env: &[(&str, &str)], args: &[&str]) -> String {
    let url = format!("https://localhost:{port}");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podnet"));
    cmd.args(["tunnel", "--hello-world", "--service-url", &url])
        .args(args)
        .env("PODNET_EDGE", "127.0.0.1:9")
        .env_remove("SSL_CERT_FILE")
        .env_remove("PODNET_ERROR_PROGRAM");
    for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_private_ca_is_trusted_only_when_it_is_given() {
    test_host::need_loopback!();
    let ca = ca(false);
    let port = serve(&ca);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ca.pem");
    std::fs::write(&file, &ca.pem).unwrap();
    let file = file.to_str().unwrap();

    // Without the CA: a certificate error.
    let text = tunnel(port, &[], &[]);
    assert!(
        text.contains("UnknownIssuer") || text.contains("unknown issuer"),
        "{text}"
    );

    // With SSL_CERT_FILE: the TLS connection works, and the server answers.
    let text = tunnel(port, &[("SSL_CERT_FILE", file)], &[]);
    assert!(text.contains("HTTP 403"), "{text}");
    assert!(!text.to_lowercase().contains("issuer"), "{text}");

    // With --ca-file: the same.
    let text = tunnel(port, &[], &["--ca-file", file]);
    assert!(text.contains("HTTP 403"), "{text}");

    // An explicit file is used alone: a file with another CA does not
    // widen to the system roots, and the server is refused.
    let other = dir.path().join("other.pem");
    std::fs::write(&other, ca_other()).unwrap();
    let text = tunnel(port, &[("SSL_CERT_FILE", other.to_str().unwrap())], &[]);
    assert!(text.contains("invalid peer certificate"), "{text}");
    assert!(!text.contains("HTTP 403"), "{text}");
}

fn ca_other() -> String {
    ca(false).pem
}

#[test]
fn an_expired_certificate_names_the_host_clock() {
    test_host::need_loopback!();
    let ca = ca(true);
    let port = serve(&ca);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ca.pem");
    std::fs::write(&file, &ca.pem).unwrap();
    let text = tunnel(port, &[("SSL_CERT_FILE", file.to_str().unwrap())], &[]);
    assert!(
        text.contains("Expired") || text.contains("expired"),
        "{text}"
    );
    assert!(
        text.contains("certificates are checked against the clock of this host, which reads "),
        "{text}"
    );
    assert!(text.trim_end().ends_with("GMT"), "{text}");
}

/// Issue 127: a reset of the connection during the TLS handshake names the
/// network and the destination; the hint is not the CA or the clock.
#[test]
fn a_reset_in_the_tls_handshake_names_the_network() {
    test_host::need_loopback!();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { break };
            // The ClientHello stays unread: the close sends a reset.
            std::thread::sleep(std::time::Duration::from_millis(200));
            drop(conn);
        }
    });
    let text = tunnel(port, &[], &[]);
    assert!(
        text.contains("reset during the TLS handshake")
            || text.contains("closed during the TLS handshake"),
        "{text}"
    );
    assert!(text.contains(&format!("localhost:{port}")), "{text}");
    assert!(text.contains("allow-list"), "{text}");
    assert!(!text.contains("--ca-file"), "{text}");
}
