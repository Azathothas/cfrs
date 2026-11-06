//! `podnet tunnel`: the arguments, the origin and the `--check` report.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use podnet::config::{load_file, Config};
use podnet::exit::{Fault, ResultExt};
use podnet::ingress::{ForwardTarget, Ingress, IngressRule, OriginOptions, Service};

use crate::cli::cmd::run::run_tunnel;
use crate::cli::opts::{Show, TunnelOpts};

#[derive(Args, Debug)]
pub(crate) struct TunnelArgs {
    #[command(flatten)]
    pub(crate) common: TunnelOpts,
    /// HTTP or HTTPS origin.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    url: Option<String>,
    /// HTTP origin on a unix socket.
    #[arg(long)]
    unix: Option<PathBuf>,
    /// HTTP origin on 127.0.0.1:<PORT>.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
    /// Raw TCP origin.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    tcp: Option<String>,
    /// Expose a raw stream over a WebSocket endpoint (tcp://host:port or unix:/path).
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    forward: Option<String>,
    /// cloudflared's built-in hello world.
    #[arg(long)]
    hello_world: bool,
    /// cloudflared-style YAML config with ingress rules.
    #[arg(long)]
    config: Option<PathBuf>,
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
    /// cloudflared credentials JSON file.
    #[arg(long)]
    credentials_file: Option<PathBuf>,
    /// Skip TLS verification of the origin.
    #[arg(long)]
    no_tls_verify: bool,
    /// Override the Host header sent to the origin.
    #[arg(long)]
    http_host_header: Option<String>,
    /// Drop Accept-Encoding so the origin cannot compress a streaming response.
    #[arg(long)]
    strip_accept_encoding: bool,
}

pub(crate) async fn tunnel(args: TunnelArgs) -> Result<()> {
    let mut config = if let Some(path) = &args.config {
        load_file(path).fault(Fault::Config)?
    } else {
        Config::default()
    };
    // Issue 172: a token of the command line and --credentials-file are a
    // conflict; a token of TUNNEL_TOKEN gives way to the flag.
    let token = match (&args.token, &args.credentials_file) {
        (Some(token), Some(path)) => {
            if std::env::var("TUNNEL_TOKEN").ok().as_deref() != Some(token.as_str()) {
                return Err(podnet::exit::fault(
                    Fault::Usage,
                    anyhow::anyhow!("give --token or --credentials-file, not both"),
                ));
            }
            tracing::warn!(
                "TUNNEL_TOKEN is set; --credentials-file {} is used",
                path.display()
            );
            None
        }
        (token, _) => token.as_ref(),
    };
    if let Some(token) = token {
        podnet::report::hide(token);
        config.credentials = podnet::config::parse_token(token).fault(Fault::Config)?;
    } else if let Some(path) = &args.credentials_file {
        config.credentials = podnet::config::parse_credentials_file(path).fault(Fault::Config)?;
    }

    if args.config.is_none() {
        let mut ingress = Ingress::new();
        if let Some(forward) = &args.forward {
            let target = ForwardTarget::parse(forward).fault(Fault::Usage)?;
            ingress = ingress.rule_with(IngressRule {
                hostname: None,
                path: Some(podnet::ingress::PathPattern::prefix(
                    podnet::ws::DEFAULT_PATH,
                )),
                service: Service::Forward(target),
                origin: OriginOptions::default(),
            });
        }
        if let Some(service) = pick_optional_service(&args).fault(Fault::Usage)? {
            let origin = OriginOptions {
                no_tls_verify: args.no_tls_verify,
                http_host_header: args.http_host_header.clone(),
                strip_accept_encoding: args.strip_accept_encoding,
                ..OriginOptions::default()
            };
            ingress = ingress.rule_with(IngressRule {
                hostname: None,
                path: None,
                service,
                origin,
            });
        }
        if ingress.is_empty() {
            return Err(podnet::exit::fault(
                Fault::Usage,
                anyhow::anyhow!(
                    "choose an origin (--url, --unix, --port, --tcp, --hello-world) or --forward"
                ),
            ));
        }
        config.ingress = ingress;
    }
    config = args.common.apply(config)?;
    // A forward-only tunnel has no HTTP origin to verify; the root is expected
    // to answer 503. A raw TCP origin answers HTTP with 501 (issue 199).
    if !config
        .ingress
        .rules
        .iter()
        .any(|rule| !matches!(rule.service, Service::Forward(_) | Service::Tcp(_)))
    {
        if config
            .ingress
            .rules
            .iter()
            .any(|rule| matches!(rule.service, Service::Tcp(_)))
            && config.verify
        {
            tracing::info!("a raw TCP origin does not answer HTTP: no verify of the public URL");
        }
        config.verify = false;
    }

    if args.common.check {
        return preflight(&config, args.common.show()).await;
    }
    run_tunnel(config, args.common.show(), args.common.run_for, vec![]).await
}

/// `--check`: print the report of the check, and fail when a check failed.
pub(crate) async fn preflight(config: &Config, show: Show) -> Result<()> {
    let report = podnet::preflight::check(config).await;
    if show.json {
        println!("{}", podnet::status::stamped(report.to_json()));
    } else {
        print!("{}", report.text());
    }
    let failed = report
        .checks
        .iter()
        .filter(|c| c.status == podnet::preflight::Status::Fail)
        .count();
    if failed > 0 {
        let err = anyhow::anyhow!(
            "the check failed ({failed} of {}); nothing was started",
            report.checks.len()
        );
        // Issue 173: a failed check of the configuration gives its code
        // (78), as a run does. A failed origin or network check gives 1.
        return Err(match report.fault() {
            Some(class) => podnet::exit::fault(class, err),
            None => err,
        });
    }
    Ok(())
}

/// Split `host:port`, `[v6]:port` or `ip:port` into the host and the port.
pub(crate) fn split_host_port(spec: &str) -> Result<(String, u16)> {
    let (host, port) = spec
        .rsplit_once(':')
        .with_context(|| format!("{spec}: give host:port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .with_context(|| format!("{spec}: the port must be 1 to 65535"))?;
    if host.is_empty() || host.contains(['/', ' ']) {
        bail!("{spec}: give host:port");
    }
    Ok((host.to_string(), port))
}

fn pick_optional_service(args: &TunnelArgs) -> Result<Option<Service>> {
    let mut choices = 0;
    let mut service = None;
    if let Some(url) = &args.url {
        choices += 1;
        if url
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .is_some_and(|a| a.ends_with(":0"))
        {
            bail!("--url {url}: the port 0 is not a port");
        }
        service = Some(Service::parse(url).with_context(|| format!("--url {url}"))?);
    }
    if let Some(path) = &args.unix {
        choices += 1;
        use std::os::unix::fs::FileTypeExt;
        match std::fs::metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {}
            Ok(_) => bail!("--unix {}: not a Unix socket", path.display()),
            Err(err) => bail!("--unix {}: {err}", path.display()),
        }
        service = Some(Service::Unix(path.clone()));
    }
    if let Some(port) = args.port {
        choices += 1;
        service = Some(Service::Http(format!("http://127.0.0.1:{port}")));
    }
    if let Some(addr) = &args.tcp {
        choices += 1;
        // Issue 199: tcp://host:port is accepted; another scheme is not.
        let addr = &addr.strip_prefix("tcp://").unwrap_or(addr).to_string();
        if addr.contains("://") {
            bail!("--tcp {addr}: give host:port or tcp://host:port");
        }
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("--tcp {addr}: give host:port"))?;
        if host.is_empty() || port.parse::<u16>().map_or(true, |p| p == 0) {
            bail!("--tcp {addr}: give host:port with a port from 1 to 65535");
        }
        service = Some(Service::Tcp(addr.clone()));
    }
    if args.hello_world {
        choices += 1;
        service = Some(Service::HelloWorld);
    }
    if choices > 1 {
        bail!("choose at most one origin: --url, --unix, --port, --tcp, --hello-world");
    }
    Ok(service)
}
