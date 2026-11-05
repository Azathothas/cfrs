//! End-to-end check of the documented `podnet net proxy --forward` path.
//!
//! `docs/virtual-network.md` section 5.2 describes a SOCKS5 front door on a
//! unix socket that forwards a virtual endpoint to a real one. The unit test in
//! `src/vnet/proxy.rs` covers the same shape with an in-process echo; this one
//! uses a real `AF_UNIX` client so the whole documented path is exercised:
//! client socket, SOCKS handshake, stack connect, forward, real destination and
//! the reply back to the client.

#![cfg(unix)]

use std::time::Duration;

use podnet::vnet::proxy::{serve, ProxyListen};
use podnet::vnet::{NetStack, VirtAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A "real" service that reads one request and answers it, then closes.
async fn real_service(stream: tokio::io::DuplexStream) {
    let (mut read, mut write) = tokio::io::split(stream);
    let mut request = vec![0u8; 512];
    let n = read.read(&mut request).await.unwrap_or(0);
    let body = format!("real-service saw {n} bytes");
    let response = format!(
        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = write.write_all(response.as_bytes()).await;
    let _ = write.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_documented_forward_path_carries_a_reply_back_to_the_client() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socks_path = dir.path().join("socks.sock");
    let net = std::sync::Arc::new(NetStack::loopback());
    let virt: VirtAddr = "10.66.0.2:8080".parse().unwrap();

    let mut proxy = serve(
        net.clone(),
        ProxyListen::Unix(socks_path.clone()),
        Default::default(),
        80,
    )
    .await
    .expect("starting the proxy");
    proxy.spawn_forwards(net.clone(), virt, || async {
        let (ours, theirs) = tokio::io::duplex(4096);
        tokio::spawn(real_service(theirs));
        Ok(ours)
    });

    // The listener binds asynchronously; give it a moment.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = tokio::net::UnixStream::connect(&socks_path)
        .await
        .expect("connecting to the SOCKS front door");

    // SOCKS5, no auth, IPv4 destination 10.66.0.2:8080.
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0], "SOCKS greeting");

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&[10, 66, 0, 2]);
    request.extend_from_slice(&8080u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS connect should succeed");

    client
        .write_all(b"GET /hello HTTP/1.0\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => panic!("reading the reply: {err}"),
        Err(_) => panic!(
            "the reply never reached the client; got {} bytes so far: {:?}",
            response.len(),
            String::from_utf8_lossy(&response)
        ),
    }
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("real-service saw 23 bytes"),
        "unexpected reply: {text:?}"
    );
}
