//! `podnet serve`, `podnet share` and `podnet demo`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};

use podnet::config::Config;
use podnet::exit::{Fault, ResultExt};
use podnet::gate::Gate;
use podnet::ingress::{Ingress, Service};
use podnet::share::ShareConfig;

use crate::cli::cmd::connect::unix_listener;
use crate::cli::cmd::run::{run_demo, run_share, run_tunnel};
use crate::cli::cmd::tunnel::preflight;
use crate::cli::opts::TunnelOpts;
use crate::cli::signals::sleep_or_signal;

#[derive(Args, Debug)]
pub(crate) struct ServeArgs {
    #[command(flatten)]
    pub(crate) common: TunnelOpts,
    /// Directory to serve.
    #[arg(long, value_name = "DIR")]
    dir: PathBuf,
    /// Single-page-app fallback to index.html.
    #[arg(long)]
    spa: bool,
    /// Serve the files on this local listener and make no tunnel:
    /// HOST:PORT (or tcp://HOST:PORT), or unix:PATH (mode 0600). Port 0
    /// takes a free port; podnet prints the bound address. A unix socket
    /// that answers is refused (exit 69, --replace takes it over), a
    /// stale socket is removed, a file that is not a socket is refused
    /// (exit 64). The tunnel flags have no effect.
    #[arg(long, value_name = "ADDR", conflicts_with = "check")]
    local: Option<String>,
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN or
    /// --token-file: other users of the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Read the named-tunnel token from this file (for example a secret
    /// of a container). The token is not on the command line.
    #[arg(
        long,
        value_name = "PATH",
        env = "TUNNEL_TOKEN_FILE",
        hide_env_values = true
    )]
    token_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ModeArg {
    Upload,
    Download,
    Proxy,
}

#[derive(Args, Debug)]
pub(crate) struct ShareArgs {
    #[command(flatten)]
    pub(crate) common: TunnelOpts,
    /// Session mode. With no --mode: download with --file, proxy with
    /// --port or --unix, upload with --dir. With none of these flags,
    /// podnet refuses to start: give --mode upload for the default upload
    /// directory.
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    /// Directory that receives uploads.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// File to share (download mode).
    #[arg(long)]
    file: Option<PathBuf>,
    /// Local HTTP port to share (proxy mode).
    #[arg(long, conflicts_with = "unix", value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
    /// A unix socket of a local HTTP server to share (proxy mode), for a
    /// host with no TCP listener.
    #[arg(long, value_name = "PATH")]
    unix: Option<PathBuf>,
    /// Require a 6-digit PIN (always on for proxy mode).
    #[arg(long)]
    password: bool,
    /// Stop the tunnel after the first successful transfer.
    #[arg(long)]
    stop_after: bool,
    /// Stop after this many idle seconds (0 disables).
    #[arg(long, default_value_t = 900)]
    idle_secs: u64,
    /// Upload mode: the most bytes of one upload request. A larger request
    /// gets 413 and saves nothing (podnet drops its body). The Cloudflare
    /// edge accepts at most 100 MB in one request.
    #[arg(long, value_name = "BYTES", default_value_t = podnet::share::MAX_REQUEST, value_parser = clap::value_parser!(u64).range(1..))]
    max_request: u64,
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN or
    /// --token-file: other users of the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Read the named-tunnel token from this file (for example a secret
    /// of a container). The token is not on the command line.
    #[arg(
        long,
        value_name = "PATH",
        env = "TUNNEL_TOKEN_FILE",
        hide_env_values = true
    )]
    token_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct DemoArgs {
    #[command(flatten)]
    pub(crate) common: TunnelOpts,
    /// Exit as soon as the public URL has been fetched.
    #[arg(long)]
    exit_on_verify: bool,
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN or
    /// --token-file: other users of the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Read the named-tunnel token from this file (for example a secret
    /// of a container). The token is not on the command line.
    #[arg(
        long,
        value_name = "PATH",
        env = "TUNNEL_TOKEN_FILE",
        hide_env_values = true
    )]
    token_file: Option<PathBuf>,
}

pub(crate) async fn serve(args: ServeArgs) -> Result<()> {
    if let Some(local) = &args.local {
        return serve_local(&args, local).await;
    }
    let mut config = Config::default();
    if let Some(token) = &args.token {
        podnet::report::hide(token);
        config.credentials = podnet::config::parse_token(token).fault(Fault::Config)?;
    }
    config.ingress = Ingress::new().catch_all(Service::Static {
        root: args.dir.clone(),
        spa: args.spa,
    });
    config = args.common.apply(config)?;
    if args.common.check {
        return preflight(&config, args.common.show()).await;
    }
    run_tunnel(config, args.common.show(), args.common.run_for, vec![]).await
}

/// `serve --local ADDR` (issue 307): serve the static files on a local
/// listener, with the router of the tunnel, and provision no tunnel.
async fn serve_local(args: &ServeArgs, local: &str) -> Result<()> {
    let usage = |msg: String| podnet::exit::fault(Fault::Usage, anyhow::anyhow!(msg));
    if args.common.auth_user.is_some() {
        return Err(usage(
            "serve --local: --auth-user works only through a tunnel; a local listener checks no visitor"
                .to_string(),
        ));
    }
    let router = podnet::service::static_router(&args.dir, args.spa)?;
    let show = args.common.show();
    let (url, listen, server, _file) = if local.starts_with("unix:") {
        #[cfg(unix)]
        {
            let path = match podnet::vnet::proxy::ProxyListen::parse(local) {
                Ok(podnet::vnet::proxy::ProxyListen::Unix(path)) => path,
                Ok(_) => unreachable!("a unix: address is a unix socket"),
                Err(err) => return Err(usage(format!("--local {local}: {err:#}"))),
            };
            let (listener, file) = unix_listener(&path, args.common.detach.replace)?;
            let name = format!("unix:{}", path.display());
            let server = tokio::spawn(async move { axum::serve(listener, router).await });
            (name.clone(), name, server, Some(file))
        }
        #[cfg(not(unix))]
        bail!("unix sockets are not supported on this platform: {local}");
    } else {
        let addr = local.strip_prefix("tcp://").unwrap_or(local);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) if !addr.contains(':') || err.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(usage(format!(
                    "--local {local}: give HOST:PORT (for example 127.0.0.1:8080) or unix:PATH ({err})"
                )));
            }
            // An address in use, or an address of no interface: exit 69.
            Err(err) => {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("--local {local}: binding {addr}: {err}"),
                ));
            }
        };
        let bound = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        (
            format!("http://{bound}/"),
            format!("tcp://{bound}"),
            server,
            None,
        )
    };
    podnet::detach::arm_stop();
    if show.json {
        let doc = serde_json::json!({
            "event": "ready",
            "url": url,
            "listen": listen,
            "dir": args.dir.display().to_string(),
        });
        println!("{}", podnet::status::stamped(doc));
    } else {
        println!(
            "podnet: serve  {}  on {url}  (local, no tunnel)",
            args.dir.display()
        );
    }
    // A QR code of a unix socket has no use.
    if show.qr && url.starts_with("http://") {
        print!("{}", podnet::qr::render_terminal(&url)?);
    }
    podnet::detach::ready(serde_json::json!({ "url": url, "listen": listen }));
    tokio::select! {
        _ = sleep_or_signal(args.common.run_for) => {}
        ended = server => {
            ended
                .context("the local server stopped")?
                .context("the local server stopped")?;
        }
    }
    Ok(())
}

/// The mode of `share` (issue 118): `--mode`, else the mode of the flags
/// (`--file`: download, `--port`: proxy, else upload). Flags of two modes,
/// or a flag of another mode than `--mode`, are a usage error (exit 64).
/// Before, `--file` with no `--mode` started an upload session.
pub(crate) fn share_mode(args: &ShareArgs) -> Result<ModeArg> {
    let mut wanted = Vec::new();
    if args.file.is_some() {
        wanted.push(("--file", ModeArg::Download));
    }
    if args.port.is_some() {
        wanted.push(("--port", ModeArg::Proxy));
    }
    if args.unix.is_some() {
        wanted.push(("--unix", ModeArg::Proxy));
    }
    if args.dir.is_some() {
        wanted.push(("--dir", ModeArg::Upload));
    }
    let usage = |msg: String| podnet::exit::fault(Fault::Usage, anyhow::anyhow!(msg));
    if let [(a, _), (b, _), ..] = wanted[..] {
        return Err(usage(format!(
            "share: {a} and {b} are flags of two modes; give one"
        )));
    }
    let name = |m: ModeArg| format!("{m:?}").to_lowercase();
    match (args.mode, wanted.first()) {
        (Some(mode), Some((flag, other))) if mode != *other => Err(usage(format!(
            "share: {flag} is a flag of --mode {}, not of --mode {}",
            name(*other),
            name(mode)
        ))),
        (Some(mode), _) => Ok(mode),
        (None, Some((_, mode))) => Ok(*mode),
        // Issue 250: a bare `podnet share` does not open a public upload
        // session.
        (None, None) => Err(usage(
            "share: give a mode: --mode upload (or --dir DIR) to receive files, \
             --file FILE to send one file, --port PORT or --unix PATH to share a local server"
                .to_string(),
        )),
    }
}

pub(crate) async fn share(args: ShareArgs) -> Result<()> {
    let mode = share_mode(&args)?;
    let mut share_config = match mode {
        ModeArg::Upload => {
            let dir = args.dir.clone().unwrap_or_else(default_upload_dir);
            ShareConfig::upload(dir)
        }
        ModeArg::Download => {
            let file = args
                .file
                .clone()
                .context("download mode needs --file")
                .fault(Fault::Usage)?;
            ShareConfig::download(file)
        }
        // Issue 204: --unix gives a unix socket origin.
        ModeArg::Proxy if args.unix.is_some() => {
            let path = args.unix.clone().expect("matched above");
            use std::os::unix::fs::FileTypeExt as _;
            match std::fs::metadata(&path) {
                Ok(meta) if meta.file_type().is_socket() => {}
                Ok(_) => {
                    return Err(podnet::exit::fault(
                        Fault::Usage,
                        anyhow::anyhow!("--unix {}: not a unix socket", path.display()),
                    ))
                }
                Err(err) => {
                    return Err(podnet::exit::fault(
                        Fault::Unavailable,
                        anyhow::anyhow!("--unix {}: {err}", path.display()),
                    ))
                }
            }
            ShareConfig::proxy(format!("unix:{}", path.display()))
        }
        ModeArg::Proxy => {
            let port = args
                .port
                .context("proxy mode needs --port or --unix")
                .fault(Fault::Usage)?;
            // A check sends no request to the origin: it only connects.
            if !args.common.check {
                podnet::ports::confirm_local_http(port).await?;
            }
            ShareConfig::proxy(format!("127.0.0.1:{port}"))
        }
    };
    if args.password || matches!(mode, ModeArg::Proxy) {
        share_config.gate = Gate::pin();
    }
    share_config.stop_after = args.stop_after;
    if matches!(mode, ModeArg::Upload) {
        share_config.max_request = args.max_request;
    }

    let mut config = Config::default();
    if let Some(token) = &args.token {
        podnet::report::hide(token);
        config.credentials = podnet::config::parse_token(token).fault(Fault::Config)?;
    }
    config.ingress = Ingress::new().catch_all(Service::Share(share_config.clone()));
    config = args.common.apply(config)?;
    if args.common.check {
        return preflight(&config, args.common.show()).await;
    }

    let pin = share_config.gate.pin_display().map(str::to_string);
    let path = share_config.url_path();
    let controls_hint = args.idle_secs;
    run_share(
        config,
        args.common.show(),
        args.common.run_for,
        pin,
        path,
        controls_hint,
    )
    .await
}

pub(crate) async fn demo(args: DemoArgs) -> Result<()> {
    let mut config = Config::default();
    if let Some(token) = &args.token {
        podnet::report::hide(token);
        config.credentials = podnet::config::parse_token(token).fault(Fault::Config)?;
    }
    config.ingress = Ingress::new().catch_all(Service::HelloWorld);
    config = args.common.apply(config)?;
    if args.common.check {
        return preflight(&config, args.common.show()).await;
    }
    let exit_on_verify = args.exit_on_verify;
    run_demo(
        config,
        args.common.show(),
        args.common.run_for,
        exit_on_verify,
    )
    .await
}

fn default_upload_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let downloads = home.join("Downloads");
    if downloads.is_dir() {
        downloads.join("podnet")
    } else {
        home.join("podnet-uploads")
    }
}
