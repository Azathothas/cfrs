//! `podnet warp nc HOST PORT` and `podnet warp ssh-config` (issue 85): a byte
//! pipe from stdin and stdout to HOST:PORT, for `ssh -o ProxyCommand` and
//! git over SSH on a network that refuses port 22.
//!
//! The pipe goes through the running `podnet warp up` (SOCKS5 on its unix
//! socket), else through a WARP session of this process, else (with
//! `--via-relay`) through the WebSocket relay straight to HOST:PORT. SSH
//! checks the host key of the server as on a direct connection.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncWriteExt as _, BufReader};

use crate::net::BoxedIo;

/// `host:port` for a SOCKS5 request (`[v6]:port` for IPv6).
pub fn target(host: &str, port: u16) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

/// Through the running `podnet warp up`, if its socket answers.
pub async fn via_running(at: &super::find::At, host: &str, port: u16) -> Result<Option<BoxedIo>> {
    let Ok(socket) = super::find::running(at) else {
        return Ok(None);
    };
    let proxy = podnet_netns::Proxy::parse(&format!("socks5://unix:{}", socket.display()))?;
    let upstream = podnet_netns::upstream::connect_upstream_async(&[proxy], &target(host, port))
        .await
        .with_context(|| format!("{host}:{port} through podnet warp up"))?;
    Ok(Some(Box::new(upstream)))
}

/// Through the WebSocket relay, with no WARP: TCP to an IPv4 address of
/// `host`.
pub async fn via_relay(relay: &crate::ws_relay::Relay, host: &str, port: u16) -> Result<BoxedIo> {
    let addrs = crate::resolve::resolve(host)
        .await
        .with_context(|| format!("resolving {host}"))?;
    let ip = addrs
        .into_iter()
        .find(|a| a.is_ipv4())
        .with_context(|| format!("{host} has no IPv4 address (the relay has IPv4 egress only)"))?;
    relay
        .connect(
            SocketAddr::new(ip, port),
            std::time::Duration::from_secs(20),
        )
        .await
}

/// When the TCP pipe of `podnet warp nc` sends its FIN, and when it ends.
#[derive(Clone, Copy, Debug)]
pub struct PipeEnd {
    /// `-N`: send the FIN at the end of the input, then wait for the far
    /// end to close.
    pub shutdown: bool,
    /// With no `-N`: after the end of the input, end (and send the FIN)
    /// when no data came for this time.
    pub idle: std::time::Duration,
}

/// The default `--idle` of the TCP pipe, as `relay connect` (issue 109).
pub const TCP_IDLE: std::time::Duration = std::time::Duration::from_secs(5);

/// Copy stdin to `io` and `io` to stdout, until the far end closes; then
/// end the process (a read of stdin blocks a thread, and the runtime would
/// wait for it).
pub async fn pipe(io: BoxedIo, end: PipeEnd) -> Result<()> {
    pipe_with(io, tokio::io::stdin(), tokio::io::stdout(), end).await?;
    std::process::exit(0);
}

/// Copy `input` to `io` and `io` to `output`, until the far end closes.
///
/// Issue 188: at the end of the input, no FIN goes to the far end (as
/// OpenBSD nc with no -N). Some servers drop a connection that is half
/// closed before they answer, and the answer was lost. The pipe ends when
/// the far end closes, or `end.idle` after the last data. With
/// `end.shutdown` (-N), the FIN goes at the end of the input.
///
/// An error of the far end is returned; before, the pipe exited 0.
pub async fn pipe_with<R, W>(io: BoxedIo, input: R, mut output: W, end: PipeEnd) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let (mut from, mut to) = tokio::io::split(io);
    let upload = async move {
        let mut input = BufReader::new(input);
        let sent = tokio::io::copy(&mut input, &mut to).await;
        if end.shutdown {
            let _ = to.shutdown().await;
        }
        (to, sent)
    };
    let mut upload = std::pin::pin!(upload);
    let mut writer = None;
    let mut buf = vec![0u8; 16 * 1024];
    let mut received = 0u64;
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            (to, sent) = &mut upload, if writer.is_none() => {
                tracing::debug!(sent = ?sent.as_ref().ok(), "warp nc: the end of the input");
                writer = Some(to);
                last = tokio::time::Instant::now();
            }
            read = from.read(&mut buf) => match read {
                Ok(0) => break,
                Ok(n) => {
                    received += n as u64;
                    last = tokio::time::Instant::now();
                    output.write_all(&buf[..n]).await.context("writing the output")?;
                    output.flush().await.context("writing the output")?;
                }
                Err(err) => {
                    let _ = output.flush().await;
                    tracing::debug!(received, "warp nc: the far end failed");
                    return Err(err).context("reading from the far end");
                }
            },
            _ = tokio::time::sleep_until(last + end.idle), if writer.is_some() && !end.shutdown => {
                tracing::debug!(received, "warp nc: no data after the end of the input");
                if let Some(mut to) = writer.take() {
                    let _ = to.shutdown().await;
                }
                break;
            }
        }
    }
    tracing::debug!(received, "warp nc: the far end closed");
    output.flush().await.context("writing the output")?;
    Ok(())
}

/// `podnet warp nc -u` (issue 115): each read of `input` is one datagram to
/// the far end (`out`); each datagram that comes back (`back`) goes to
/// `output`. After the end of the input, the pipe ends when no datagram
/// came for `idle`.
pub async fn udp_pipe_with<R, W>(
    out: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut back: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut input: R,
    mut output: W,
    idle: std::time::Duration,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut buf = vec![0u8; 65_507];
    let mut input_open = true;
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            read = input.read(&mut buf), if input_open => match read {
                Ok(0) | Err(_) => {
                    input_open = false;
                    last = tokio::time::Instant::now();
                }
                Ok(n) => {
                    if out.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            },
            datagram = back.recv() => match datagram {
                Some(d) => {
                    last = tokio::time::Instant::now();
                    output.write_all(&d).await?;
                    output.flush().await?;
                }
                None => break,
            },
            _ = tokio::time::sleep_until(last + idle), if !input_open => break,
        }
    }
    Ok(())
}

/// The payload of a SOCKS5 UDP datagram (after its header).
fn udp_payload(datagram: &[u8]) -> Option<&[u8]> {
    let off = match *datagram.get(3)? {
        0x01 => 10,
        0x03 => 7 + *datagram.get(4)? as usize,
        0x04 => 22,
        _ => return None,
    };
    datagram.get(off..)
}

/// The two channels of a UDP pipe through the running `podnet warp up` (the
/// association in the stream, 0x83, on its unix socket), or `None` when it
/// does not run.
pub async fn udp_via_running(
    at: &super::find::At,
    host: &str,
    port: u16,
) -> Result<
    Option<(
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    )>,
> {
    use podnet_netns::upstream::{read_udp_frame, wrap_udp, wrap_udp_name, write_udp_frame};
    let Ok(socket) = super::find::running(at) else {
        return Ok(None);
    };
    let proxy = podnet_netns::Proxy::parse(&format!("socks5://unix:{}", socket.display()))?;
    let stream = podnet_netns::upstream::dial_proxy(&proxy).await?;
    let stream = podnet_netns::upstream::socks5_udp_in_stream(stream, &proxy)
        .await
        .context("a UDP association through podnet warp up")?;
    let (mut read, mut write) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (back_tx, back_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let host = host.to_string();
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            let framed = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => wrap_udp(&payload, ip, port),
                Err(_) => wrap_udp_name(&payload, &host, port),
            };
            if write_udp_frame(&mut write, &framed).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok(Some(datagram)) = read_udp_frame(&mut read).await {
            if let Some(payload) = udp_payload(&datagram) {
                if back_tx.send(payload.to_vec()).await.is_err() {
                    return;
                }
            }
        }
    });
    Ok(Some((out_tx, back_rx)))
}

/// The two channels of a UDP pipe through a WARP session of this process.
pub async fn udp_via_stack(
    stack: std::sync::Arc<super::WarpStack>,
    host: &str,
    port: u16,
) -> Result<(
    tokio::sync::mpsc::Sender<Vec<u8>>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
)> {
    let ip = super::proxy::resolve(&stack, host).await?;
    let udp = stack.udp_bind().await?;
    let to = SocketAddr::new(ip, port);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (back_tx, back_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let sender = udp.clone();
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            if sender.send_to(payload, to).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok((data, from)) = udp.recv_from(65_536).await {
            if from == to && back_tx.send(data).await.is_err() {
                return;
            }
        }
    });
    Ok((out_tx, back_rx))
}

/// An SSH config block and `GIT_SSH_COMMAND` that use `podnet warp nc`.
pub fn ssh_config(exe: &Path, host: &str) -> String {
    let exe = exe.display();
    format!(
        "# podnet warp ssh-config: SSH through WARP (podnet warp nc)\n\
Host {host}\n    ProxyCommand {exe} warp nc %h %p\n\n\
# For git over SSH with no SSH config:\n\
# export GIT_SSH_COMMAND='ssh -o ProxyCommand=\"{exe} warp nc %h %p\"'\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(target("github.com", 22), "github.com:22");
        assert_eq!(target("10.0.0.1", 22), "10.0.0.1:22");
        assert_eq!(target("2001:db8::1", 22), "[2001:db8::1]:22");
    }

    // Issue 115: nc -u: each read is a datagram; the answers come back;
    // the pipe ends after the idle time when the input ended.
    #[tokio::test]
    async fn a_udp_pipe_sends_each_read_and_prints_each_answer() {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(8);
        let (back_tx, back_rx) = tokio::sync::mpsc::channel(8);
        let echo = tokio::spawn(async move {
            while let Some(d) = out_rx.recv().await {
                let mut answer = b"ECHO:".to_vec();
                answer.extend(d);
                if back_tx.send(answer).await.is_err() {
                    return;
                }
            }
        });
        let mut output = Vec::new();
        let start = std::time::Instant::now();
        udp_pipe_with(
            out_tx,
            back_rx,
            &b"PING"[..],
            &mut output,
            std::time::Duration::from_millis(200),
        )
        .await
        .unwrap();
        assert_eq!(output, b"ECHO:PING");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        echo.abort();
        assert_eq!(
            udp_payload(&[0, 0, 0, 1, 1, 1, 1, 1, 0, 53, b'x']),
            Some(&b"x"[..])
        );
        assert_eq!(
            udp_payload(&[0, 0, 0, 3, 1, b'a', 0, 53, b'y']),
            Some(&b"y"[..])
        );
    }

    #[test]
    fn the_ssh_config_uses_warp_nc() {
        let text = ssh_config(Path::new("/b/podnet"), "github.com");
        assert!(text.contains("Host github.com\n    ProxyCommand /b/podnet warp nc %h %p\n"));
        assert!(text.contains("GIT_SSH_COMMAND"));
    }

    /// The pipe carries both directions and ends when the far end closes.
    #[tokio::test]
    async fn the_pipe_ends_when_the_far_end_closes() {
        use tokio::io::AsyncReadExt as _;
        let (ours, mut theirs) = tokio::io::duplex(1024);
        // The input stays open (as the stdin of ssh does).
        let (_input_keep, input) = tokio::io::duplex(64);
        let (output, mut shown) = tokio::io::duplex(1024);
        let far = tokio::spawn(async move {
            theirs.write_all(b"SSH-2.0-test\r\n").await.unwrap();
            drop(theirs);
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipe_with(Box::new(ours), input, output, DEFAULT_END),
        )
        .await
        .expect("the pipe ends")
        .unwrap();
        far.await.unwrap();
        let mut got = Vec::new();
        shown.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"SSH-2.0-test\r\n");
    }

    const DEFAULT_END: PipeEnd = PipeEnd {
        shutdown: false,
        idle: TCP_IDLE,
    };

    /// A far end that reads the request, waits, and answers only if it saw
    /// no FIN (as a server that drops a half-closed connection).
    async fn picky_server(mut theirs: tokio::io::DuplexStream) -> bool {
        use tokio::io::AsyncReadExt as _;
        let mut buf = [0u8; 64];
        let n = theirs.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"GET");
        let fin = matches!(
            tokio::time::timeout(std::time::Duration::from_millis(300), theirs.read(&mut buf))
                .await,
            Ok(Ok(0))
        );
        if !fin {
            theirs.write_all(b"REPLY").await.unwrap();
        }
        drop(theirs);
        fin
    }

    // Issue 188: an input that ends at once does not lose the reply.
    #[tokio::test]
    async fn the_reply_survives_an_input_that_ends_at_once() {
        use tokio::io::AsyncReadExt as _;
        let (ours, theirs) = tokio::io::duplex(1024);
        let (output, mut shown) = tokio::io::duplex(1024);
        let far = tokio::spawn(picky_server(theirs));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipe_with(Box::new(ours), &b"GET"[..], output, DEFAULT_END),
        )
        .await
        .expect("the pipe ends")
        .unwrap();
        assert!(!far.await.unwrap(), "no FIN before the reply");
        let mut got = Vec::new();
        shown.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"REPLY");
    }

    // Issue 188: -N sends the FIN at the end of the input.
    #[tokio::test]
    async fn with_n_the_far_end_sees_the_eof() {
        let (ours, theirs) = tokio::io::duplex(1024);
        let (output, _shown) = tokio::io::duplex(1024);
        let far = tokio::spawn(picky_server(theirs));
        let end = PipeEnd {
            shutdown: true,
            idle: TCP_IDLE,
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipe_with(Box::new(ours), &b"GET"[..], output, end),
        )
        .await
        .expect("the pipe ends")
        .unwrap();
        assert!(far.await.unwrap(), "the far end saw the FIN");
    }

    // Issue 188: after the end of the input, no data for the idle time
    // ends the pipe, and the far end then gets the FIN.
    #[tokio::test]
    async fn the_pipe_ends_after_idle_with_no_reply() {
        use tokio::io::AsyncReadExt as _;
        let (ours, mut theirs) = tokio::io::duplex(1024);
        let (output, _shown) = tokio::io::duplex(1024);
        let end = PipeEnd {
            shutdown: false,
            idle: std::time::Duration::from_millis(200),
        };
        let started = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipe_with(Box::new(ours), &b"x"[..], output, end),
        )
        .await
        .expect("the pipe ends")
        .unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let mut got = Vec::new();
        theirs.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"x");
    }
}
