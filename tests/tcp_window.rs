//! A download through the tunnel device must fill a 512 KiB window at an RTT
//! of 40 ms (issue 100). The test runs two smoltcp stacks over two tunnel
//! devices with a link of 20 ms in each direction, on a virtual clock.

use std::collections::VecDeque;

use podnet::vnet::device::LinkDevice;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

const MTU: usize = 1280;
const BUFFER: usize = 512 * 1024;
const ONE_WAY_US: i64 = 20_000;

struct Node {
    device: LinkDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
}

fn node(addr: [u8; 4]) -> Node {
    let mut device = LinkDevice::tunnel(MTU);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 7;
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::from(addr)), 24))
            .ok();
    });
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER]),
        tcp::SocketBuffer::new(vec![0; BUFFER]),
    ));
    Node {
        device,
        iface,
        sockets,
        handle,
    }
}

/// Move the packets a node sent onto the link, with their arrival time.
fn pump(from: &Node, link: &mut VecDeque<(i64, Vec<u8>)>, now: i64) {
    while let Some(packet) = from.device.outbound().pop() {
        link.push_back((now + ONE_WAY_US, packet));
    }
}

fn deliver(link: &mut VecDeque<(i64, Vec<u8>)>, to: &Node, now: i64) {
    while matches!(link.front(), Some((at, _)) if *at <= now) {
        let (_, packet) = link.pop_front().unwrap();
        to.device.inbound().push(packet);
    }
}

/// The rate of a download of `total` bytes, in MB/s of virtual time.
fn download_rate(total: usize) -> f64 {
    let mut client = node([10, 0, 0, 1]);
    let mut server = node([10, 0, 0, 2]);
    server
        .sockets
        .get_mut::<tcp::Socket>(server.handle)
        .listen(80)
        .unwrap();
    {
        let cx = client.iface.context();
        client
            .sockets
            .get_mut::<tcp::Socket>(client.handle)
            .connect(
                cx,
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 80),
                (IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 40_000),
            )
            .unwrap();
    }
    let (mut to_server, mut to_client) = (VecDeque::new(), VecDeque::new());
    let chunk = vec![0xabu8; 64 * 1024];
    let mut buf = vec![0u8; 64 * 1024];
    let (mut sent, mut got) = (0usize, 0usize);
    let mut started = None;
    let mut now: i64 = 0;
    while got < total {
        assert!(now < 600_000_000, "the download stalled at {got} bytes");
        for _ in 0..1000 {
            let ts = Instant::from_micros(now);
            deliver(&mut to_client, &client, now);
            deliver(&mut to_server, &server, now);
            client
                .iface
                .poll(ts, &mut client.device, &mut client.sockets);
            server
                .iface
                .poll(ts, &mut server.device, &mut server.sockets);
            pump(&client, &mut to_server, now);
            pump(&server, &mut to_client, now);
            let mut moved = false;
            let s = server.sockets.get_mut::<tcp::Socket>(server.handle);
            if s.can_send() && sent < total {
                let n = chunk.len().min(total - sent);
                let w = s.send_slice(&chunk[..n]).unwrap();
                sent += w;
                moved |= w > 0;
                started.get_or_insert(now);
            }
            let c = client.sockets.get_mut::<tcp::Socket>(client.handle);
            if c.can_recv() {
                let r = c.recv_slice(&mut buf).unwrap();
                got += r;
                moved |= r > 0;
            }
            if !moved {
                break;
            }
        }
        let ts = Instant::from_micros(now);
        let mut next = i64::MAX;
        for n in [&mut client, &mut server] {
            if let Some(at) = n.iface.poll_at(ts, &n.sockets) {
                next = next.min(at.total_micros().max(now + 1));
            }
        }
        for link in [&to_server, &to_client] {
            if let Some((at, _)) = link.front() {
                next = next.min((*at).max(now + 1));
            }
        }
        assert!(next != i64::MAX, "the download stalled at {got} bytes");
        now = next;
    }
    let seconds = (now - started.unwrap()) as f64 / 1e6;
    got as f64 / seconds / 1e6
}

#[test]
fn download_fills_the_window_at_40_ms() {
    let rate = download_rate(8 * 1024 * 1024);
    eprintln!("download rate: {rate:.2} MB/s");
    // The window of 512 KiB over 41 ms allows 12.6 MB/s. A window of one
    // segment (the old burst limit) allows 0.5 MB/s.
    assert!(rate > 8.0, "download rate {rate:.2} MB/s");
}
