#[allow(unused_imports)]
use crate::prelude::*;

// ── front door: pod-netns as a proxy for others ─────────────────────────────

pub(crate) enum FrontListener {
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

impl FrontListener {
    pub(crate) async fn accept(&self) -> std::io::Result<Upstream> {
        match self {
            FrontListener::Unix(l) => Ok(Box::new(l.accept().await?.0)),
            FrontListener::Tcp(l) => Ok(Box::new(l.accept().await?.0)),
        }
    }
}

/// Serve SOCKS5 and HTTP `CONNECT`, forwarding each request through the
/// configured upstream chain. This makes an instance a hop for another, and a
/// drop-in replacement for a shim's front door.
pub(crate) async fn serve_front_door(
    listen: crate::listen::ProxyListen,
    chain: Vec<Proxy>,
    rules: Vec<Rule>,
    verbose: bool,
) -> Result<()> {
    use crate::listen::ProxyListen;
    let listener = match &listen {
        ProxyListen::Unix(path) => {
            let _ = std::fs::remove_file(path);
            FrontListener::Unix(tokio::net::UnixListener::bind(path)?)
        }
        ProxyListen::Tcp(addr) => FrontListener::Tcp(tokio::net::TcpListener::bind(addr).await?),
    };
    eprintln!(
        "pod-netns: serving {} ({} upstream)",
        listen_str(&listen),
        chain.len()
    );
    loop {
        let conn = listener.accept().await?;
        let chain = chain.clone();
        let rules = rules.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(conn, &chain, &rules, verbose).await {
                if verbose {
                    eprintln!("pod-netns: front door: {e:#}");
                }
            }
        });
    }
}

pub(crate) fn listen_str(listen: &crate::listen::ProxyListen) -> String {
    match listen {
        crate::listen::ProxyListen::Unix(p) => format!("unix:{}", p.display()),
        crate::listen::ProxyListen::Tcp(a) => format!("tcp://{a}"),
    }
}

pub(crate) async fn serve_one(conn: Upstream, chain: &[Proxy], rules: &[Rule], verbose: bool) -> Result<()> {
    use crate::socks;
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::new(conn);
    let first = {
        let buf = reader.fill_buf().await?;
        buf.first().copied()
    };
    match first {
        Some(5) => {
            let (cmd, request) = read_socks5_command(&mut reader).await?;
            if cmd == 0x03 {
                return serve_udp_associate(reader, chain, verbose).await;
            }
            let target = format!("{}:{}", request.host, request.port);
            let selected = select_chain(rules, chain, &target);
            if verbose {
                eprintln!(
                    "pod-netns: front door {target} via {}",
                    selected[0].endpoint()
                );
            }
            let mut upstream = match within_timeout(
                "front door connect",
                connect_upstream_async(selected, &target),
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    let _ = socks::socks5_reply(
                        &mut reader,
                        socks::socks5_code_for_error(&e.to_string()),
                        None,
                    )
                    .await;
                    return Err(e);
                }
            };
            socks::socks5_reply(&mut reader, 0x00, None).await?;
            let _ = tokio::io::copy_bidirectional(&mut reader, &mut upstream).await;
            Ok(())
        }
        Some(_) => {
            let request = socks::http_read_connect(&mut reader).await?;
            let target = format!("{}:{}", request.host, request.port);
            let selected = select_chain(rules, chain, &target);
            let mut upstream = match within_timeout(
                "front door connect",
                connect_upstream_async(selected, &target),
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    let _ = socks::http_connect_reply(&mut reader, 502, "Bad Gateway").await;
                    return Err(e);
                }
            };
            socks::http_connect_ok(&mut reader).await?;
            let _ = tokio::io::copy_bidirectional(&mut reader, &mut upstream).await;
            Ok(())
        }
        None => Ok(()),
    }
}

/// Read a SOCKS5 greeting and request, accepting any command so
/// `UDP ASSOCIATE` is not rejected before it can be served.
pub(crate) async fn read_socks5_command<S>(stream: &mut S) -> Result<(u8, crate::socks::ProxyRequest)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::socks::ProxyHost;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut intro = [0u8; 2];
    stream
        .read_exact(&mut intro)
        .await
        .context("SOCKS5 greeting")?;
    if intro[0] != 0x05 {
        bail!("SOCKS5 version {} is not 5", intro[0]);
    }
    let mut methods = vec![0u8; intro[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("SOCKS5 request")?;
    if header[0] != 0x05 {
        bail!("SOCKS5 request version {} is not 5", header[0]);
    }
    let host = match header[3] {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            ProxyHost::Ip(IpAddr::V4(Ipv4Addr::from(a)))
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut h = vec![0u8; l[0] as usize];
            stream.read_exact(&mut h).await?;
            ProxyHost::Domain(String::from_utf8_lossy(&h).to_string())
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            ProxyHost::Ip(IpAddr::V6(std::net::Ipv6Addr::from(a)))
        }
        other => bail!("SOCKS5 address type {other} is not supported"),
    };
    let mut p = [0u8; 2];
    stream.read_exact(&mut p).await?;
    Ok((
        header[1],
        crate::socks::ProxyRequest {
            host,
            port: u16::from_be_bytes(p),
        },
    ))
}

/// Answer `UDP ASSOCIATE` by relaying through the first upstream proxy's own
/// association, so a UDP relay can chain through this instance.
pub(crate) async fn serve_udp_associate(
    mut control: tokio::io::BufReader<Upstream>,
    chain: &[Proxy],
    verbose: bool,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let proxy = chain.first().context("no upstream for UDP ASSOCIATE")?;
    if proxy.kind != ProxyKind::Socks5 {
        let _ = control
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        bail!("UDP ASSOCIATE needs a SOCKS5 upstream");
    }
    // Our own relay socket, advertised to the client.
    let relay = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    let addr = relay.local_addr()?;
    let mut bnd = vec![0x05u8, 0x00, 0x00];
    match addr {
        SocketAddr::V4(a) => {
            bnd.push(0x01);
            bnd.extend_from_slice(&a.ip().octets());
            bnd.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            bnd.push(0x04);
            bnd.extend_from_slice(&a.ip().octets());
            bnd.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    control.write_all(&bnd).await?;
    control.flush().await?;

    // The upstream's relay, reached over its own association.
    let up_control = dial_proxy(proxy).await?;
    let (_up_control, up_addr) = socks5_udp_associate(up_control, proxy).await?;
    let up = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    if verbose {
        eprintln!("pod-netns: front door UDP relay {addr} -> {up_addr}");
    }

    let client: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    // client -> upstream
    let to_upstream = {
        let relay = relay.clone();
        let up = up.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = relay.recv_from(&mut buf).await {
                *client.lock().await = Some(from);
                if n < 4 {
                    continue;
                }
                let _ = up.send_to(&buf[..n], up_addr).await;
            }
        })
    };
    // upstream -> client
    let to_client = {
        let relay = relay.clone();
        let up = up.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, _)) = up.recv_from(&mut buf).await {
                if let Some(to) = *client.lock().await {
                    let _ = relay.send_to(&buf[..n], to).await;
                }
            }
        })
    };
    // Hold the control connection until the client closes it, then stop the
    // relay tasks rather than leaving them holding the sockets.
    let mut byte = [0u8; 1];
    while control.read(&mut byte).await.unwrap_or(0) == 1 {}
    to_upstream.abort();
    to_client.abort();
    Ok(())
}
