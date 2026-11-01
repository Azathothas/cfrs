//! `cfrs warp nc HOST PORT` and `cfrs warp ssh-config` (issue 85): a byte
//! pipe from stdin and stdout to HOST:PORT, for `ssh -o ProxyCommand` and
//! git over SSH on a network that refuses port 22.
//!
//! The pipe goes through the running `cfrs warp up` (SOCKS5 on its unix
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

/// Through the running `cfrs warp up`, if its socket answers.
pub async fn via_running(host: &str, port: u16) -> Result<Option<BoxedIo>> {
    let socket = super::up::socket_path()?;
    if std::os::unix::net::UnixStream::connect(&socket).is_err() {
        return Ok(None);
    }
    let proxy = pod_netns::Proxy::parse(&format!("socks5://unix:{}", socket.display()))?;
    let upstream = pod_netns::upstream::connect_upstream_async(&[proxy], &target(host, port))
        .await
        .with_context(|| format!("{host}:{port} through cfrs warp up"))?;
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

/// Copy stdin to `io` and `io` to stdout, until the far end closes; then
/// end the process (a read of stdin blocks a thread, and the runtime would
/// wait for it).
pub async fn pipe(io: BoxedIo) -> Result<()> {
    pipe_with(io, tokio::io::stdin(), tokio::io::stdout()).await?;
    std::process::exit(0);
}

/// Copy `input` to `io` and `io` to `output`, until the far end closes.
pub async fn pipe_with<R, W>(io: BoxedIo, input: R, mut output: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (mut from, mut to) = tokio::io::split(io);
    let upload = async move {
        let mut input = BufReader::new(input);
        let _ = tokio::io::copy(&mut input, &mut to).await;
        let _ = to.shutdown().await;
    };
    let download = async move {
        let _ = tokio::io::copy(&mut from, &mut output).await;
        let _ = output.flush().await;
    };
    // The far end closes: the pipe ends, also while the input stays open.
    tokio::select! {
        _ = download => {}
        _ = async { upload.await; std::future::pending::<()>().await } => {}
    }
    Ok(())
}

/// An SSH config block and `GIT_SSH_COMMAND` that use `cfrs warp nc`.
pub fn ssh_config(exe: &Path, host: &str) -> String {
    let exe = exe.display();
    format!(
        "# cfrs warp ssh-config: SSH through WARP (cfrs warp nc)\n\
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

    #[test]
    fn the_ssh_config_uses_warp_nc() {
        let text = ssh_config(Path::new("/b/cfrs"), "github.com");
        assert!(text.contains("Host github.com\n    ProxyCommand /b/cfrs warp nc %h %p\n"));
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
            pipe_with(Box::new(ours), input, output),
        )
        .await
        .expect("the pipe ends")
        .unwrap();
        far.await.unwrap();
        let mut got = Vec::new();
        shown.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"SSH-2.0-test\r\n");
    }
}
