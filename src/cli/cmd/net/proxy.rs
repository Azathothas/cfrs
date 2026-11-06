//! `podnet net proxy`: a SOCKS5 and HTTP CONNECT proxy into the virtual
//! network, and the real targets of its forwards.

use std::sync::Arc;

use anyhow::{bail, Context, Result};

use podnet::exit::{Fault, ResultExt};
use podnet::vnet::VirtAddr;

use super::ProxyArgs;
use crate::cli::signals::sleep_or_signal;
use crate::listen_doc;

/// A probability from 0.0 to 1.0 (issue 196).
pub(crate) fn probability(value: &str) -> std::result::Result<f64, String> {
    let p: f64 = value
        .parse()
        .map_err(|_| format!("{value} is not a number"))?;
    if !(0.0..=1.0).contains(&p) {
        return Err(format!("{value} is not from 0.0 to 1.0"));
    }
    Ok(p)
}

pub(crate) async fn net_proxy(args: ProxyArgs) -> Result<()> {
    use podnet::vnet::proxy::{ProxyListen, Resolver};

    let mut _link = None;
    let net = match &args.switch {
        None => Arc::new(podnet::vnet::NetStack::loopback()),
        Some(switch) => {
            let address = args
                .address
                .context("--switch needs --address, the address of this stack")
                .fault(Fault::Usage)?;
            let config = podnet::vnet::StackConfig {
                local_v4: address,
                ..podnet::vnet::StackConfig::default()
            };
            let net = Arc::new(podnet::vnet::NetStack::over_link(config));
            let faults = podnet::vnet::switch::Faults {
                drop: args.drop,
                duplicate: args.duplicate,
                reorder: args.reorder,
                seed: args.seed,
            };
            let switch = ProxyListen::parse(switch)
                .context("--switch")
                .fault(Fault::Usage)?;
            // Issue 309: a TCP switch needs its shared token.
            let token = podnet::vnet::switch::token(args.switch_token_file.as_deref())
                .fault(Fault::Usage)?;
            if let Some(token) = &token {
                podnet::report::hide(token);
            }
            if matches!(switch, ProxyListen::Tcp(_)) && token.is_none() {
                return Err(anyhow::anyhow!(
                    "a TCP switch needs its token: set {}, or give --switch-token-file",
                    podnet::vnet::switch::TOKEN_VARIABLE
                ))
                .fault(Fault::Usage);
            }
            _link = Some(
                podnet::vnet::switch::attach(&net, &switch, faults, token.as_deref())
                    .await
                    .fault(Fault::Unavailable)?,
            );
            #[cfg(target_os = "linux")]
            {
                if let Some(name) = &args.control {
                    podnet::vnet::switch::serve_control(net.clone(), name)?;
                    println!("podnet: control  \\0{name}  (PODNET_VNET_CONTROL={name})");
                }
                for spec in &args.imports {
                    let virt: VirtAddr = spec.trim().parse()?;
                    podnet::vnet::switch::import(net.clone(), virt)?;
                    println!("podnet: import   {virt}");
                }
            }
            match &switch {
                ProxyListen::Unix(path) => {
                    println!("podnet: switch   unix:{} as {address}", path.display())
                }
                ProxyListen::Tcp(addr) => println!("podnet: switch   tcp://{addr} as {address}"),
            }
            net
        }
    };
    let mut resolver = Resolver::new();
    for entry in &args.maps {
        let (name, address) = entry
            .split_once('=')
            .with_context(|| format!("--map wants NAME=ADDRESS, got {entry:?}"))?;
        resolver.insert(
            name.trim().to_ascii_lowercase(),
            address
                .trim()
                .parse()
                .with_context(|| format!("bad address in {entry:?}"))?,
        );
    }
    let listen = ProxyListen::parse(&args.listen)?;
    let mut proxy = podnet::vnet::proxy::serve(net.clone(), listen, resolver, args.port).await?;
    for spec in &args.forwards {
        let (virt, real) = spec
            .split_once('=')
            .with_context(|| format!("--forward wants VIRT=REAL, got {spec:?}"))?;
        let virt: VirtAddr = virt.trim().parse()?;
        let real = RealTarget::parse(real.trim())?;
        let dial_real = real.clone();
        proxy.spawn_forwards(net.clone(), virt, move || {
            let real = dial_real.clone();
            async move { real.dial().await }
        });
        println!("podnet: forward  {virt} -> {}", real.describe());
    }
    // Issue 300: the bound address (a TCP port 0 gives the port).
    println!("podnet: proxy    {}", proxy.listen);
    podnet::detach::ready(listen_doc(&proxy.listen));
    sleep_or_signal(args.run_for).await;
    proxy.abort();
    Ok(())
}

/// A real destination a virtual forward bridges to.
#[derive(Clone, Debug)]
pub(crate) enum RealTarget {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl RealTarget {
    fn parse(value: &str) -> Result<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                if path.is_empty() {
                    bail!("unix: real destination has no path");
                }
                return Ok(Self::Unix(std::path::PathBuf::from(path)));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                bail!("unix destinations are not supported on this platform");
            }
        }
        Ok(Self::Tcp(
            value
                .parse()
                .with_context(|| format!("bad real address {value:?}"))?,
        ))
    }

    fn describe(&self) -> String {
        match self {
            Self::Tcp(addr) => addr.to_string(),
            #[cfg(unix)]
            Self::Unix(path) => format!("unix:{}", path.display()),
        }
    }

    /// Open a real connection, type-erased so the forward is generic.
    async fn dial(&self) -> std::io::Result<Box<dyn DialStream>> {
        match self {
            Self::Tcp(addr) => Ok(Box::new(tokio::net::TcpStream::connect(addr).await?)),
            #[cfg(unix)]
            Self::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
        }
    }
}

/// The bounds a forwarded connection must satisfy. A single local trait lets
/// the real destination be either a TCP or a unix stream.
pub(crate) trait DialStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin
{
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> DialStream for T {}
