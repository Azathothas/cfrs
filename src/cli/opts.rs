//! The options that more than one command shares: the tunnel options, the
//! output form, the options of `--detach` and the global network options.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use podnet::config::Config;
use podnet::exit::{Fault, ResultExt};
use podnet::ingress::Service;
use podnet::{Protocol, Transport};

use crate::cli::cmd::net::NetCommand;
use crate::cli::cmd::relay::RelayCommand;
use crate::cli::cmd::warp::WarpCommand;
use crate::cli::{Cli, Command};

#[derive(Args, Clone, Debug)]
pub(crate) struct TunnelOpts {
    #[command(flatten)]
    pub(crate) detach: DetachArgs,
    /// Quick-tunnel provisioning endpoint.
    #[arg(long, default_value = "https://api.trycloudflare.com", global = true)]
    pub(crate) service_url: String,
    /// User-Agent sent when provisioning.
    #[arg(long, global = true)]
    pub(crate) user_agent: Option<String>,
    /// Edge connections (1-8), for redundancy: when one is lost, the others
    /// carry the visitors. The edge chooses the connection of each request,
    /// and one request uses one connection, so more connections do not make
    /// one transfer faster. Default: ha-connections of --config, else 2.
    #[arg(long, global = true, value_parser = clap::value_parser!(u8).range(1..=8))]
    pub(crate) ha_connections: Option<u8>,
    /// Edge protocol: quic (UDP 7844), http2 or h2 (TCP 7844), or auto
    /// (quic, then http2). Default: protocol of --config, else auto.
    #[arg(long, global = true, value_parser = ["auto", "quic", "http2", "h2"])]
    pub(crate) protocol: Option<String>,
    /// How to reach the edge: auto (try 7844, fall back to WARP on 443),
    /// direct (port 7844), warp (carried on TCP 443) or relay (HTTP/2 in a
    /// WebSocket to the relay of --relay, on TCP 443).
    #[arg(long, default_value = "auto", global = true, value_parser = ["auto", "direct", "warp", "relay"])]
    pub(crate) transport: String,
    /// The WebSocket-to-TCP relay of --transport relay: a URL, or a comma
    /// list of hosts of one deployment. The variable PODNET_RELAY_TOKEN (not
    /// PODNET_RELAY) gives a token; without it, podnet mints one.
    #[arg(long, value_name = "URL", global = true, env = "PODNET_RELAY", hide_env_values = true, default_value = podnet::ws_relay::default_relay())]
    pub(crate) relay: String,
    /// Keep the WARP device and MASQUE key here and resume them next run.
    /// Without it, every run registers a new anonymous device.
    #[arg(long, value_name = "PATH", global = true)]
    pub(crate) warp_identity: Option<PathBuf>,
    /// How the next edge leg starts: staggered (when the leg before has not
    /// registered in 2 s, or at once when it fails) or serial (only after the
    /// leg before failed).
    #[arg(long, global = true, default_value = "staggered", env = "PODNET_LEG_FAILOVER", hide_env_values = true, value_parser = ["staggered", "serial"])]
    pub(crate) leg_failover: String,
    /// Do not fetch the public URL to prove reachability.
    #[arg(long, global = true)]
    pub(crate) no_verify: bool,
    /// Print a QR code for the public URL.
    #[arg(long, global = true)]
    pub(crate) qr: bool,
    /// Print the state of the tunnel as JSON lines on stdout, in place of
    /// the text lines. Each line is one object with the key "event":
    /// "ready" (url, tunnel_id, locations, and pin for share) or "verified"
    /// (url).
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Stay up for this many seconds instead of until Ctrl-C (it also ends
    /// the verify of the public URL).
    #[arg(long, global = true)]
    pub(crate) run_for: Option<u64>,
    /// Each visitor must give this user (HTTP Basic), with the password of
    /// --auth-password-file. A visitor with no right credential gets 401
    /// and reaches no origin; the origin does not get the header. For HTTP
    /// origins and --forward (podnet connect --auth-user); not for --tcp.
    #[arg(
        long,
        value_name = "USER",
        global = true,
        env = "PODNET_AUTH_USER",
        hide_env_values = true,
        requires = "auth_password_file"
    )]
    pub(crate) auth_user: Option<String>,
    /// The file with the password of --auth-user on its first line (mode
    /// 0600).
    #[arg(
        long,
        value_name = "FILE",
        global = true,
        env = "PODNET_AUTH_PASSWORD_FILE",
        hide_env_values = true,
        requires = "auth_user"
    )]
    pub(crate) auth_password_file: Option<PathBuf>,
    /// Check the plan and stop: the flags, the config file, each origin (a
    /// connection, and the TLS handshake for https, with no request), the
    /// files and the directories, and the edge legs. No Cloudflare API call,
    /// no edge connection, no file is written. Exit 0 when each check
    /// passes, 1 when a check fails. With --json, one JSON document.
    #[arg(long, global = true)]
    pub(crate) check: bool,
}

/// How a tunnel command prints its state.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Show {
    pub(crate) qr: bool,
    pub(crate) json: bool,
    /// The origin answers 404 for `/` as its normal answer: `serve` of a
    /// directory with no `index.html` (issue 119).
    pub(crate) root_404: bool,
    /// The tunnel has --auth-user: the verify gets 401 (issue 205).
    pub(crate) auth: bool,
}

impl TunnelOpts {
    pub(crate) fn show(&self) -> Show {
        Show {
            qr: self.qr,
            json: self.json,
            root_404: false,
            auth: self.auth_user.is_some(),
        }
    }

    pub(crate) fn apply(&self, mut config: Config) -> Result<Config> {
        config.service_url = self.service_url.clone();
        if let Some(user_agent) = &self.user_agent {
            config.user_agent = user_agent.clone();
        }
        // Issue 171: a flag wins over the file; with no flag, the value of
        // the file stays.
        if let Some(n) = self.ha_connections {
            config.ha_connections = n;
        }
        if let Some(protocol) = &self.protocol {
            config.protocol = Protocol::parse(protocol)?;
        }
        config.transport = Transport::parse(&self.transport)?;
        // Issue 173: a protocol that the transport cannot carry is a usage
        // error before any network call.
        podnet::tunnel::leg_plan(config.protocol, config.transport).fault(Fault::Usage)?;
        // Issue 205: the credential in front of the tunnel.
        if let (Some(user), Some(file)) = (&self.auth_user, &self.auth_password_file) {
            if config
                .ingress
                .rules
                .iter()
                .any(|rule| matches!(rule.service, Service::Tcp(_)))
            {
                return Err(podnet::exit::fault(
                    Fault::Usage,
                    anyhow::anyhow!(
                        "--auth-user is for HTTP origins and --forward, not for a raw --tcp origin"
                    ),
                ));
            }
            config.ingress.auth = Some(
                podnet::ingress::credentials(user, file)
                    .context("--auth-password-file")
                    .fault(Fault::Config)?,
            );
        }
        if config.transport == Transport::Relay {
            podnet::ws_relay::set(
                podnet::ws_relay::Relay::from_env(Some(&self.relay)).fault(Fault::Usage)?,
            );
        }
        config.warp_identity = self.warp_identity.clone();
        config.verify = !self.no_verify;
        config.failover = podnet::race::Failover::parse(&self.leg_failover)?;
        Ok(config)
    }
}

/// The options of a command that can run in the background (issue 70).
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct DetachArgs {
    /// Run in the background: podnet prints one JSON document when the
    /// command is ready (its URL or its listen address) and exits 0. The
    /// instance keeps running when the shell or the terminal closes. podnet
    /// ps, logs, wait and stop manage it.
    #[arg(long)]
    pub(crate) detach: bool,
    /// The name of the detached instance. Default: the command and a hash
    /// of its arguments. A second start with the same name and the same
    /// arguments gives the same instance. With no --detach: register this
    /// process under the name (it is not forked and not restarted); podnet
    /// ps, logs, wait and stop see it.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// With --detach: seconds to wait for the instance to be ready (else
    /// exit 124).
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    pub(crate) ready_timeout: u64,
    /// Stop a running instance of the same name that has other arguments,
    /// and start this one (needs --detach). connect: also take a unix
    /// socket of -L that another process serves (by default, a socket that
    /// answers is refused, exit 69; a stale socket file is replaced).
    #[arg(long)]
    pub(crate) replace: bool,
    /// Do not start the instance again when it ends. Without it, a
    /// supervisor starts it again with a backoff (1 s to 30 s), but not
    /// after exit 64 or 78, and not after a planned end (--stop-after,
    /// --idle-secs, --run-for). A quick tunnel gets a new URL; podnet ps
    /// shows it. With --name and no --detach, there is no supervisor.
    #[arg(long)]
    pub(crate) no_restart: bool,
}

impl DetachArgs {
    pub(crate) fn options(&self) -> podnet::detach::Options {
        podnet::detach::Options {
            name: self.name.clone(),
            ready_timeout: std::time::Duration::from_secs(self.ready_timeout.max(1)),
            replace: self.replace,
            restart: !self.no_restart,
        }
    }
}

/// The options of --detach of a command that can run in the background.
pub(crate) fn detach_of(command: &Command) -> Option<&DetachArgs> {
    match command {
        Command::Tunnel(args) => Some(&args.common.detach),
        Command::Serve(args) => Some(&args.common.detach),
        Command::Share(args) => Some(&args.common.detach),
        Command::Demo(args) => Some(&args.common.detach),
        // Issue 207: connect has --detach, --name and ps.
        Command::Connect(args) => Some(&args.detach),
        Command::Warp(args) => match &args.command {
            WarpCommand::Proxy { detach, .. } => Some(detach),
            WarpCommand::Forward { detach, .. } => Some(detach),
            WarpCommand::Tun { detach, .. } => Some(detach),
            _ => None,
        },
        Command::Relay(args) => match &args.command {
            RelayCommand::Node { detach, .. } => Some(detach),
            _ => None,
        },
        Command::Net(args) => match &args.command {
            NetCommand::Proxy(args) => Some(&args.detach),
            NetCommand::Switch(args) => Some(&args.detach),
            _ => None,
        },
        _ => None,
    }
}

/// Apply --proxy, --no-proxy and --resolve.
pub(crate) fn network_options(cli: &Cli) -> Result<()> {
    use podnet::egress::Proxy;
    // The pins first: the first dialer, of --proxy or --no-proxy, takes them.
    if let Some(list) = &cli.resolve {
        podnet::resolve::set_pins(list).context("--resolve")?;
    } else if let Ok(list) = std::env::var(podnet::resolve::PINS_VARIABLE) {
        // Issue 252: a bad PODNET_RESOLVE is an error here, not a warning at the first dial.
        podnet::resolve::parse_pins(&list)
            .context(podnet::resolve::PINS_VARIABLE)
            .fault(Fault::Config)?;
    }
    if let Some(spec) = &cli.proxy {
        // Issue 95: a value with no scheme (PODNET_PROXY=notaurl) became
        // http://notaurl:8080, and each leg then failed on a name. The
        // proxy variables of other tools keep the lenient form.
        if !spec.contains("://") && !spec.contains("+unix:") && !spec.contains("+exec:") {
            let shown = match spec.rsplit_once('@') {
                Some((_, host)) => format!("***@{host}"),
                None => spec.clone(),
            };
            bail!(
                "--proxy (or PODNET_PROXY) {shown:?} has no scheme; give http://, socks5:// or socks5h://HOST:PORT"
            );
        }
        for secret in Proxy::secret_parts(spec) {
            podnet::report::hide(&secret);
        }
        podnet::egress::set_proxy(spec).context("--proxy")?;
    } else if cli.no_proxy {
        podnet::egress::set_direct();
    }
    Ok(())
}
