//! `podnet connect`: local listeners to a `--forward` tunnel.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;

use podnet::exit::{Fault, ResultExt};
use podnet::net::BoxedIo;
use podnet::ws::{self, LocalSpec};

use crate::cli::opts::DetachArgs;
use crate::cli::signals::sleep_or_signal;

#[derive(Args, Debug)]
pub(crate) struct ConnectArgs {
    /// Public WebSocket URL, e.g. wss://<host>/__podnet/ws.
    remote: String,
    /// Local listeners, repeatable: tcp://[bind:]port or unix:///path. In
    /// podnet pod with the netns backend, a TCP listener is in the network of
    /// the pod: use unix:///path to reach it from outside.
    #[arg(short = 'L', long = "local", required = true)]
    locals: Vec<String>,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
    /// Start with no check of the remote. By default, connect opens one
    /// WebSocket to the remote at start and exits 69 when it fails (the
    /// origin then dials its forward target once).
    #[arg(long)]
    no_check: bool,
    /// The user for a tunnel with --auth-user (HTTP Basic in the
    /// WebSocket upgrade), with the password of --auth-password-file.
    #[arg(
        long,
        value_name = "USER",
        env = "PODNET_AUTH_USER",
        hide_env_values = true,
        requires = "auth_password_file"
    )]
    auth_user: Option<String>,
    /// The file with the password of --auth-user on its first line (mode
    /// 0600).
    #[arg(
        long,
        value_name = "FILE",
        env = "PODNET_AUTH_PASSWORD_FILE",
        hide_env_values = true,
        requires = "auth_user"
    )]
    auth_password_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) detach: DetachArgs,
}

pub(crate) async fn connect(args: ConnectArgs) -> Result<()> {
    podnet::init_crypto();
    if !(args.remote.starts_with("wss://") || args.remote.starts_with("ws://")) {
        return Err(podnet::exit::fault(
            Fault::Usage,
            anyhow::anyhow!(
                "the remote {} is not a WebSocket URL: give wss://<host>/__podnet/ws",
                args.remote
            ),
        ));
    }
    let mut locals = Vec::new();
    for raw in &args.locals {
        // Issue 249: a bad --local was exit 1.
        locals.push(
            LocalSpec::parse(raw)
                .with_context(|| format!("--local {raw}"))
                .fault(Fault::Usage)?,
        );
    }
    // Issue 205: the credential of a tunnel with --auth-user.
    let auth: Option<Arc<str>> = match (&args.auth_user, &args.auth_password_file) {
        (Some(user), Some(file)) => Some(Arc::from(
            podnet::ingress::credentials(user, file)
                .context("--auth-password-file")
                .fault(Fault::Config)?
                .basic_header(),
        )),
        _ => None,
    };
    let mut tcp = Vec::new();
    #[cfg(unix)]
    let mut unix = Vec::new();
    // Issue 202: each socket file of this run is removed at the end.
    #[cfg(unix)]
    let mut files = Vec::new();
    for local in &locals {
        match local {
            LocalSpec::Tcp { bind, port } => {
                let listener = tokio::net::TcpListener::bind((bind.as_str(), *port))
                    .await
                    .with_context(|| format!("binding {bind}:{port}"))?;
                tcp.push((local.describe(), listener));
            }
            LocalSpec::Unix(path) => {
                #[cfg(unix)]
                {
                    let (listener, file) = unix_listener(path, args.detach.replace)?;
                    files.push(file);
                    unix.push((local.describe(), listener));
                }
                #[cfg(not(unix))]
                bail!(
                    "unix sockets are not supported on this platform: {}",
                    path.display()
                );
            }
        }
    }
    // Issue 207: one WebSocket at start shows that the remote answers.
    // Before, the listeners came up, and each client got a reset.
    if !args.no_check {
        let ws = ws::dial(&args.remote, ws::DIAL_TIMEOUT, auth.as_deref())
            .await
            .map_err(|err| {
                podnet::exit::fault(
                    Fault::Unavailable,
                    err.context(format!(
                        "the remote {} does not answer (--no-check starts without this check)",
                        args.remote
                    )),
                )
            })?;
        let mut ws = ws;
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.close(None)).await;
    }
    let mut tasks = Vec::new();
    let mut listens: Vec<String> = tcp.iter().map(|(name, _)| name.clone()).collect();
    #[cfg(unix)]
    listens.extend(unix.iter().map(|(name, _)| name.clone()));
    for (name, listener) in tcp {
        println!("podnet: {name} -> {}", args.remote);
        tasks.push(tokio::spawn(accept_loop(
            listener,
            args.remote.clone(),
            auth.clone(),
        )));
    }
    #[cfg(unix)]
    for (name, listener) in unix {
        println!("podnet: {name} -> {}", args.remote);
        tasks.push(tokio::spawn(accept_unix(
            listener,
            args.remote.clone(),
            auth.clone(),
        )));
    }
    // Issue 207: the ready document of --detach and --name.
    podnet::detach::ready(serde_json::json!({
        "remote": args.remote,
        "listen": listens.join(", "),
        "listeners": listens,
    }));
    sleep_or_signal(args.run_for).await;
    for task in tasks {
        task.abort();
    }
    #[cfg(unix)]
    drop(files);
    Ok(())
}

async fn accept_loop(listener: tokio::net::TcpListener, remote: String, auth: Option<Arc<str>>) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let remote = remote.clone();
                let auth = auth.clone();
                // Issue 206: no Nagle delay on the local side.
                let _ = stream.set_nodelay(true);
                tokio::spawn(async move {
                    let io: BoxedIo = Box::new(stream);
                    if let Err(err) = ws::connect_bridge(&remote, io, auth.as_deref()).await {
                        tracing::warn!(error = %format!("{err:#}"), "forward connection failed");
                    }
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "accept failed");
                return;
            }
        }
    }
}

/// A socket file that this run made. Drop removes it, but only while the
/// file is still the one of this run: a later `--replace` run owns its own.
#[cfg(unix)]
pub(crate) struct SocketFile {
    path: std::path::PathBuf,
    id: Option<(u64, u64)>,
}

#[cfg(unix)]
fn file_id(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

#[cfg(unix)]
impl Drop for SocketFile {
    fn drop(&mut self) {
        if self.id.is_some() && file_id(&self.path) == self.id {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bind a unix listener at `path` (issue 202). A socket that answers
/// belongs to another process and is refused, unless `replace`. A stale
/// socket file is removed. Another kind of file is never removed.
#[cfg(unix)]
pub(crate) fn unix_listener(
    path: &std::path::Path,
    replace: bool,
) -> Result<(tokio::net::UnixListener, SocketFile)> {
    podnet::net::claim_socket_path(path, replace)?;
    let listener = podnet_netns::listen::bind_private(path)
        .with_context(|| format!("binding unix:{}", path.display()))?;
    let file = SocketFile {
        path: path.to_path_buf(),
        id: file_id(path),
    };
    Ok((listener, file))
}

#[cfg(unix)]
async fn accept_unix(listener: tokio::net::UnixListener, remote: String, auth: Option<Arc<str>>) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let remote = remote.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    let io: BoxedIo = Box::new(stream);
                    if let Err(err) = ws::connect_bridge(&remote, io, auth.as_deref()).await {
                        tracing::warn!(error = %format!("{err:#}"), "forward connection failed");
                    }
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "accept failed");
                return;
            }
        }
    }
}
