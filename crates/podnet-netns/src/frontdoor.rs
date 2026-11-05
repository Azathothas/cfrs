#[allow(unused_imports)]
use crate::prelude::*;

// ── front door: podnet-netns as a proxy for others ─────────────────────────────

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
    let (listener, bound) = bind_front_door(&listen).await?;
    // Issue 300: the bound address, so a TCP port 0 shows the port that
    // the kernel chose.
    eprintln!("podnet-netns: serving {bound} ({} upstream)", chain.len());
    loop {
        let conn = listener.accept().await?;
        let chain = chain.clone();
        let rules = rules.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(conn, &chain, &rules, verbose).await {
                if verbose {
                    eprintln!("podnet-netns: front door: {e:#}");
                }
            }
        });
    }
}

/// Bind the listener of the front door. Return it with the bound address:
/// for TCP, the port that the kernel chose for port 0.
pub(crate) async fn bind_front_door(
    listen: &crate::listen::ProxyListen,
) -> Result<(FrontListener, crate::listen::ProxyListen)> {
    use crate::listen::ProxyListen;
    Ok(match listen {
        ProxyListen::Unix(path) => {
            let _ = std::fs::remove_file(path);
            (
                FrontListener::Unix(crate::listen::bind_private(path)?),
                listen.clone(),
            )
        }
        ProxyListen::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let actual = listener.local_addr()?;
            (FrontListener::Tcp(listener), ProxyListen::Tcp(actual))
        }
    })
}

pub(crate) async fn serve_one(
    conn: Upstream,
    chain: &[Proxy],
    rules: &[Rule],
    verbose: bool,
) -> Result<()> {
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
            if cmd == crate::upstream::CMD_UDP_IN_STREAM {
                return serve_udp_in_stream(reader, chain).await;
            }
            let target = format!("{}:{}", request.host, request.port);
            let selected = select_chain(rules, chain, &target);
            if verbose {
                eprintln!(
                    "podnet-netns: front door {target} via {}",
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
pub(crate) async fn read_socks5_command<S>(
    stream: &mut S,
) -> Result<(u8, crate::socks::ProxyRequest)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    crate::socks::socks5_read_command(stream).await
}

/// Answer a UDP association in the stream (issue 84) with the same
/// association of the first upstream: the frames are the same on both
/// connections, so the bytes are copied. An upstream that does not know the
/// command gives 0x07 to the client, which then can use `UDP ASSOCIATE`.
pub(crate) async fn serve_udp_in_stream(
    mut control: tokio::io::BufReader<Upstream>,
    chain: &[Proxy],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let refuse = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let proxy = match chain.first() {
        Some(proxy) if proxy.kind == ProxyKind::Socks5 => proxy,
        _ => {
            control.write_all(&refuse).await?;
            bail!("UDP in the stream needs a SOCKS5 upstream");
        }
    };
    let upstream = async {
        let up = dial_proxy(proxy).await?;
        crate::upstream::socks5_udp_in_stream(up, proxy).await
    };
    let mut up = match within_timeout("udp in the stream", upstream).await {
        Ok(up) => up,
        Err(err) => {
            let _ = control.write_all(&refuse).await;
            return Err(err);
        }
    };
    control
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    control.flush().await?;
    let _ = tokio::io::copy_bidirectional(&mut control, &mut up).await;
    Ok(())
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
        eprintln!("podnet-netns: front door UDP relay {addr} -> {up_addr}");
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
