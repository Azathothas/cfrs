use super::*;
use crate::vnet::addr::VirtAddr;
use crate::vnet::stack::StackConfig;
use std::net::Ipv4Addr;

#[test]
fn the_same_seed_gives_the_same_faults() {
    let faults = Faults {
        drop: 0.2,
        duplicate: 0.1,
        reorder: 0.1,
        seed: 7,
    };
    let run = || {
        let mut injector = FaultInjector::new(faults);
        (0u8..200)
            .flat_map(|i| injector.apply(vec![i]))
            .map(|p| p[0])
            .collect::<Vec<u8>>()
    };
    let first = run();
    assert_eq!(first, run());
    assert!(first.len() < 200 + 40, "some packets dropped");
    assert_ne!(first, (0u8..200).collect::<Vec<u8>>());
}

#[test]
fn no_faults_keep_the_sequence() {
    let mut injector = FaultInjector::new(Faults::default());
    let out: Vec<Vec<u8>> = (0u8..50).flat_map(|i| injector.apply(vec![i])).collect();
    assert_eq!(out, (0u8..50).map(|i| vec![i]).collect::<Vec<_>>());
}

#[test]
fn reads_packet_addresses() {
    let mut v4 = vec![0u8; 20];
    v4[0] = 0x45;
    v4[12..16].copy_from_slice(&[10, 66, 0, 2]);
    v4[16..20].copy_from_slice(&[10, 66, 0, 3]);
    assert_eq!(
        packet_addresses(&v4),
        Some((
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 3))
        ))
    );
    assert_eq!(packet_addresses(&[0x45, 0]), None);
}

fn config(last: u8) -> StackConfig {
    StackConfig {
        local_v4: Ipv4Addr::new(10, 66, 0, last),
        ..StackConfig::default()
    }
}

const PAYLOAD_LEN: usize = 64 * 1024;

/// Two stacks on one switch, with a lossy link that also duplicates and
/// reorders: TCP still carries every byte in order.
#[tokio::test]
async fn two_stacks_talk_through_a_lossy_switch() {
    let dir = tempfile::tempdir().unwrap();
    let listen = ProxyListen::Unix(dir.path().join("switch.sock"));
    let switch = serve(listen.clone(), None).await.unwrap();

    let server = NetStack::over_link(config(2));
    let client = NetStack::over_link(config(3));
    let faults = Faults {
        drop: 0.1,
        duplicate: 0.05,
        reorder: 0.05,
        seed: 42,
    };
    let _a = attach(&server, &listen, faults, None).await.unwrap();
    let _b = attach(&client, &listen, faults, None).await.unwrap();

    let address = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 8080);
    let mut listener = server.listen(address).await.unwrap();
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let accept = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        let mut got = Vec::new();
        conn.read_to_end(&mut got).await.unwrap();
        got
    });
    let mut conn =
        tokio::time::timeout(std::time::Duration::from_secs(20), client.connect(address))
            .await
            .expect("connect in time")
            .unwrap();
    conn.write_all(&payload).await.unwrap();
    AsyncWriteExt::shutdown(&mut conn).await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(60), accept)
        .await
        .expect("transfer in time")
        .unwrap();
    assert_eq!(got.len(), expected.len());
    assert!(got == expected, "the bytes arrived changed");
    switch.abort();
}

fn v4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet
}

/// Issue 309: a packet with the source address of another peer is
/// dropped and counted, and the replies to that address still go to
/// its owner.
#[test]
fn a_spoofed_source_address_is_dropped() {
    let mut table = Table::default();
    let mut queues = Vec::new();
    for id in 1..=3u64 {
        let (tx, rx) = mpsc::channel(16);
        table.peers.insert(id, tx);
        queues.push(rx);
    }
    // Peer 1 is 10.66.0.2, peer 2 is 10.66.0.3.
    table.forward(1, v4_packet([10, 66, 0, 2], [10, 66, 0, 3]));
    table.forward(2, v4_packet([10, 66, 0, 3], [10, 66, 0, 2]));
    for rx in &mut queues {
        while rx.try_recv().is_ok() {}
    }
    // Peer 3 sends with the source address of peer 1.
    table.forward(3, v4_packet([10, 66, 0, 2], [10, 66, 0, 3]));
    assert_eq!(table.spoofed, 1);
    assert!(queues[1].try_recv().is_err(), "the spoofed packet arrived");
    // A reply to 10.66.0.2 goes to peer 1, not to peer 3.
    table.forward(2, v4_packet([10, 66, 0, 3], [10, 66, 0, 2]));
    assert!(queues[0].try_recv().is_ok(), "peer 1 lost its reply");
    assert!(queues[2].try_recv().is_err(), "peer 3 got the reply");
    // When peer 1 leaves, another peer can take the address.
    table.remove(1);
    table.forward(3, v4_packet([10, 66, 0, 2], [10, 66, 0, 3]));
    assert_eq!(table.spoofed, 1);
}

/// Issue 309: a TCP switch needs a token. A peer with a wrong first line
/// gets "refused" and no packet; two stacks with the token talk.
#[tokio::test]
async fn a_tcp_switch_takes_peers_with_its_token_only() {
    crate::test_host::need_loopback!();
    let listen = ProxyListen::parse("tcp://127.0.0.1:0").unwrap();
    let err = serve(listen.clone(), None).await.err().expect("no token");
    assert!(err.to_string().contains("token"), "{err}");

    let switch = serve(listen, Some("test-switch-token".into()))
        .await
        .unwrap();
    let tcp = switch.listen.clone();
    let ProxyListen::Tcp(addr) = tcp else {
        unreachable!()
    };

    let server = NetStack::over_link(config(2));
    let client = NetStack::over_link(config(3));
    assert!(attach(&server, &tcp, Faults::default(), None)
        .await
        .is_err());
    let wrong = attach(&server, &tcp, Faults::default(), Some("wrong"))
        .await
        .expect_err("a wrong token");
    assert!(
        format!("{wrong:#}").contains("refused the token"),
        "{wrong:#}"
    );
    let _a = attach(&server, &tcp, Faults::default(), Some("test-switch-token"))
        .await
        .unwrap();
    let _b = attach(&client, &tcp, Faults::default(), Some("test-switch-token"))
        .await
        .unwrap();

    // A peer that sends a packet and no token gets no packet back.
    let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut frame = FrameEncoder::encode(&v4_packet([10, 66, 0, 9], [10, 66, 0, 99])).unwrap();
    frame.push(b'\n');
    raw.write_all(&frame).await.unwrap();

    let address = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 8080);
    let mut listener = server.listen(address).await.unwrap();
    let accept = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.write_all(b"pong").await.unwrap();
        AsyncWriteExt::shutdown(&mut conn).await.unwrap();
    });
    let mut conn =
        tokio::time::timeout(std::time::Duration::from_secs(10), client.connect(address))
            .await
            .expect("connect in time")
            .unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        conn.read_to_end(&mut got),
    )
    .await
    .expect("reply in time")
    .unwrap();
    assert_eq!(got, b"pong");
    accept.await.unwrap();

    // The switch answers "refused" and closes. A reset (the switch did
    // not read the rest of the frame) can drop the answer.
    let mut seen = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        raw.read_to_end(&mut seen),
    )
    .await
    .expect("the switch keeps a peer with no token");
    assert!(b"refused\n".starts_with(&seen), "{seen:?}");
    switch.abort();
}

/// Issue 65: a stack on a switch reaches its own listener, at its own
/// address and at another address that a forward binds. Before, the
/// packet went to the switch, which drops a packet back to its sender.
#[tokio::test]
async fn a_stack_reaches_its_own_listener_through_a_switch() {
    let dir = tempfile::tempdir().unwrap();
    let listen = ProxyListen::Unix(dir.path().join("switch.sock"));
    let switch = serve(listen.clone(), None).await.unwrap();
    let stack = NetStack::over_link(config(3));
    let _a = attach(&stack, &listen, Faults::default(), None)
        .await
        .unwrap();
    for ip in [Ipv4Addr::new(10, 66, 0, 3), Ipv4Addr::new(10, 66, 0, 9)] {
        let address = VirtAddr::new(IpAddr::V4(ip), 8080);
        let mut listener = stack.listen(address).await.unwrap();
        let accept = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            conn.write_all(b"self").await.unwrap();
            AsyncWriteExt::shutdown(&mut conn).await.unwrap();
        });
        let mut conn =
            tokio::time::timeout(std::time::Duration::from_secs(5), stack.connect(address))
                .await
                .expect("connect in time")
                .unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_to_end(&mut got),
        )
        .await
        .unwrap_or_else(|_| panic!("no answer from {address} in 5 s"))
        .unwrap();
        assert_eq!(got, b"self");
        accept.await.unwrap();
    }
    switch.abort();
}

/// Issue 308: the control socket drops a `RegisterBind` of another
/// user, and takes the one of its own user.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_control_datagram_of_another_user_is_dropped() {
    use crate::vnet::control::ControlMessage;
    use std::os::linux::net::SocketAddrExt;
    let stack = Arc::new(NetStack::over_link(config(2)));
    let send = |name: &str, addr: VirtAddr| {
        let to = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let socket = std::os::unix::net::UnixDatagram::unbound().unwrap();
        socket.connect_addr(&to).unwrap();
        socket
            .send(&ControlMessage::RegisterBind { id: 1, addr }.encode())
            .unwrap();
    };
    let pid = std::process::id();
    let foreign = format!("podnet-vnet/test-ctl/{pid}/foreign");
    let own = format!("podnet-vnet/test-ctl/{pid}/own");
    let a = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 8081);
    let b = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 8082);
    let _foreign = serve_control_for(stack.clone(), &foreign, own_uid().wrapping_add(1)).unwrap();
    let _own = serve_control_for(stack.clone(), &own, own_uid()).unwrap();
    send(&foreign, a);
    send(&own, b);
    // An exported address is bound in the stack: a second listen fails.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        stack.listen(a).await.is_ok(),
        "a datagram of another user exported {a}"
    );
    assert!(
        stack.listen(b).await.is_err(),
        "a datagram of the same user did not export {b}"
    );
}

/// Issue 308: the unix listener of the switch closes a peer of another
/// user at once.
#[tokio::test]
async fn a_switch_peer_of_another_user_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let listen = ProxyListen::Unix(dir.path().join("switch.sock"));
    let switch = serve_for(listen.clone(), None, own_uid().wrapping_add(1))
        .await
        .unwrap();
    let ProxyListen::Unix(path) = &listen else {
        unreachable!()
    };
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("the switch keeps a peer of another user");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    switch.abort();
}

/// A program on host A listens on an abstract name (as the shim does); a
/// program on host B connects to the imported name. The bytes go through
/// two stacks and a switch.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn exported_and_imported_names_meet_through_the_switch() {
    let dir = tempfile::tempdir().unwrap();
    let listen = ProxyListen::Unix(dir.path().join("switch.sock"));
    let switch = serve(listen.clone(), None).await.unwrap();
    let a = Arc::new(NetStack::over_link(config(2)));
    let b = Arc::new(NetStack::over_link(config(3)));
    let _la = attach(&a, &listen, Faults::default(), None).await.unwrap();
    let _lb = attach(&b, &listen, Faults::default(), None).await.unwrap();

    // Both "hosts" share one abstract namespace in this test. Thus B
    // connects through its stack directly, which is what an imported name
    // does for each client. A port from the pid keeps parallel runs apart.
    let port = 7000 + (std::process::id() % 1000) as u16;
    let addr = VirtAddr::new(IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), port);
    let program = abstract_listener(&addr.abstract_name().unwrap()).unwrap();
    export(a.clone(), addr).await.unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = program.accept().await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        conn.write_all(b"pong").await.unwrap();
    });

    let mut conn = b.connect(addr).await.unwrap();
    conn.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        conn.read_exact(&mut reply),
    )
    .await
    .expect("reply in time")
    .unwrap();
    assert_eq!(&reply, b"pong");
    switch.abort();
}
