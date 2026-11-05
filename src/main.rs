//! podnet command line.

/// `println!`, `print!` and `eprintln!` that drop a failed write (issue
/// 74). The std macros panic when the write fails: a detached instance
/// writes to its log, and a full disk or a closed stream must not stop it.
/// A command that only prints keeps the default action of SIGPIPE.
macro_rules! println {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stdout(), $($arg)*);
    }};
}

macro_rules! print {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::write!(::std::io::stdout(), $($arg)*);
    }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr(), $($arg)*);
    }};
}

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory as _, FromArgMatches as _, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use podnet::config::{load_file, Config};
use podnet::exit::{Fault, ResultExt};
use podnet::gate::Gate;
use podnet::ingress::{ForwardTarget, Ingress, IngressRule, OriginOptions, Service};
use podnet::net::BoxedIo;
use podnet::share::{ShareConfig, ShareControl, ShareMode};
use podnet::vnet::{VirtAddr, VirtualSubnet};
use podnet::ws::{self, LocalSpec};
use podnet::{Protocol, Transport, Tunnel};

#[derive(Parser, Debug)]
#[command(
    name = "podnet",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("PODNET_BUILD_COMMIT"), ")"),
    about = "Cloudflare tunnels and the WARP client for hosts with strong network limits"
)]
struct Cli {
    /// A file of TLS roots (PEM). podnet uses only these roots for each
    /// connection that it opens as a client. Without it, podnet reads SSL_CERT_FILE, else podnet-ca.pem
    /// beside the binary, the system bundle and the compiled-in roots.
    #[arg(long, global = true, value_name = "PATH")]
    ca_file: Option<PathBuf>,
    /// The proxy for each connection: http://, socks5:// or socks5h://
    /// [user:password@]host[:port]. A proxy on a unix socket:
    /// socks5h+unix:/PATH (or socks5h://unix:/PATH). A proxy at the stdin
    /// and stdout of a command, one for each connection (as ProxyCommand of
    /// SSH): http+exec:COMMAND or socks5h+exec:COMMAND. Without it, podnet
    /// reads HTTPS_PROXY and ALL_PROXY (no +exec: there). NO_PROXY names
    /// the targets that do not use a proxy. PODNET_PROXY gives the same
    /// value, and keeps a password out of the command line. Percent-encode
    /// / ? # @ : in the user and the password.
    #[arg(
        long,
        global = true,
        value_name = "URL",
        conflicts_with = "no_proxy",
        env = "PODNET_PROXY",
        hide_env_values = true
    )]
    proxy: Option<String>,
    /// Use no proxy, also when HTTPS_PROXY or ALL_PROXY is set.
    #[arg(long, global = true)]
    no_proxy: bool,
    /// Addresses for names, in place of DNS: HOST=IP[,HOST=IP]. PODNET_RESOLVE
    /// adds to it. TLS still checks the name of the certificate.
    #[arg(long, global = true, value_name = "HOST=IP")]
    resolve: Option<String>,
    /// Log warnings and errors only.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    /// Log more: -v for debug, -vv for trace. RUST_LOG takes priority.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Colours in the log: auto (only on a terminal, and not with NO_COLOR),
    /// always or never.
    #[arg(long, global = true, default_value = "auto", value_parser = ["auto", "always", "never"])]
    color: String,
    /// The form of the log on stderr: text, or json (one object for each
    /// line).
    #[arg(long, global = true, default_value = "text", value_parser = ["text", "json"])]
    log_format: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Expose a service (cloudflared-style).
    Tunnel(TunnelArgs),
    /// Serve a directory over a tunnel.
    Serve(ServeArgs),
    /// Share files or a local port in a session with a PIN.
    Share(ShareArgs),
    /// Bridge a local socket to a remote WebSocket forward endpoint.
    Connect(ConnectArgs),
    /// List local TCP ports that are listening.
    Ports(PortsArgs),
    /// Print a text for a bug report: the version, podnet status, the
    /// detached instances and the end of their logs, and the names of the
    /// variables that are set. Device IDs, tunnel IDs, tokens and
    /// credentials are hidden. No network unless --doctor.
    BugReport {
        /// Also run podnet doctor and add its JSON (network).
        #[arg(long)]
        doctor: bool,
    },
    /// Print a completion script for a shell: bash, zsh, fish, elvish or
    /// powershell.
    ///
    /// Bash: podnet completions bash > ~/.local/share/bash-completion/completions/podnet.
    /// Zsh: podnet completions zsh > ~/.zfunc/_podnet (with ~/.zfunc in fpath).
    /// Fish: podnet completions fish > ~/.config/fish/completions/podnet.fish.
    /// Elvish: podnet completions elvish > ~/.config/elvish/lib/podnet.elv, and
    /// use podnet in ~/.config/elvish/rc.elv.
    /// PowerShell: podnet completions powershell > ~/.config/powershell/podnet.ps1,
    /// and . ~/.config/powershell/podnet.ps1 in $PROFILE.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Replace this binary with the binary of a release, after checking its
    /// signature (cosign, release.yml at the tag) and its SHA-256.
    Update(UpdateArgs),
    /// Print a QR code for a URL.
    Qr(QrArgs),
    /// Test the full path: a built-in origin, a tunnel, a fetch of the URL.
    Demo(DemoArgs),
    /// Userspace virtual networking (no kernel interfaces).
    Net(NetArgs),
    /// Cloudflare WARP client: registration, account, proxy, run.
    Warp(Box<WarpArgs>),
    /// Inbound access to this host through the WebSocket relay (--relay):
    /// pair, run a node for a local port, connect as the operator.
    Relay(RelayArgs),
    /// Run a program with all its traffic sent through a proxy (podnet-netns).
    ///
    /// Give the podnet-netns arguments after `pod`. See `podnet pod --help`.
    /// podnet gives the line after `pod` to podnet-netns: the global options of
    /// podnet (-q, -v, --color, --log-format) do not apply to it.
    #[command(disable_help_flag = true)]
    Pod {
        /// The podnet-netns arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show the manual, generated from this binary.
    Man(ManArgs),
    /// Print one line of JSON about this host. It opens no connection.
    Status {
        /// The output is JSON; this flag is accepted for scripts.
        #[arg(long)]
        json: bool,
    },
    /// Test the path from this host to the edge: the proxy, TCP and TLS to
    /// the APIs, the edge (7844) and MASQUE (443), and UDP 7844. Exit 0 when
    /// at least one leg (quic, http2, quic+warp) can work, 1 when none can.
    Doctor(DoctorArgs),
    /// Start a podnet command at boot, with no root: a systemd user unit (it
    /// stops at logout unless linger is on), else an @reboot line in the
    /// crontab.
    Autostart(AutostartArgs),
    /// One command for a sandbox with basic networking: test
    /// what works, start WARP when it is needed, expose ports, and print
    /// what works now and the commands to use.
    #[command(subcommand_required = true, arg_required_else_help = false)]
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// List the instances that run in the background (--detach).
    Ps {
        /// Print one JSON document: {"instances": [...]}.
        #[arg(long)]
        json: bool,
    },
    /// Stop a detached instance: SIGTERM, then SIGKILL after --timeout.
    #[command(group = clap::ArgGroup::new("target").args(["name", "all"]).required(true))]
    Stop {
        /// The name of the instance (podnet ps).
        name: Option<String>,
        /// Stop each instance.
        #[arg(long, conflicts_with = "name")]
        all: bool,
        /// Seconds to wait before SIGKILL.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
    /// Print the log of a detached instance.
    Logs {
        /// The name of the instance (podnet ps).
        name: String,
        /// Print new lines as they come, until Ctrl-C.
        #[arg(short, long)]
        follow: bool,
        /// Print only the last lines.
        #[arg(short = 'n', long, value_name = "LINES")]
        lines: Option<usize>,
    },
    /// Wait until a detached instance is ready, and print its ready
    /// document.
    Wait {
        /// The name of the instance (podnet ps).
        name: String,
        /// Seconds to wait (else exit 69).
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
}

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
struct AutostartArgs {
    #[command(subcommand)]
    command: AutostartCommand,
}

#[derive(Subcommand, Debug)]
enum AutostartCommand {
    /// Add an entry that runs `podnet ARGS`. The token and a proxy password
    /// go to a private env file (mode 0600), not to the unit, the crontab
    /// or the command line. Exit 69 when this host has no systemd user
    /// manager and no crontab.
    Add {
        /// The name of the entry (letters, digits, - and _).
        name: String,
        /// The podnet command and its arguments, after `--`, with no leading
        /// `podnet` (one is dropped). The command must parse.
        #[arg(last = true, required_unless_present = "from")]
        args: Vec<String>,
        /// Take the command and its arguments from the detached instance
        /// INSTANCE (podnet ps), with no --detach options.
        #[arg(long, value_name = "INSTANCE", conflicts_with = "args")]
        from: Option<String>,
    },
    /// Remove an entry: its unit or its crontab line, and its files. Other
    /// units and crontab lines stay as they are.
    Remove {
        /// The name of the entry.
        name: String,
    },
    /// List the entries.
    List,
    /// Run an entry in the place of this process: the unit and the crontab
    /// line call this. It reads NAME.args and NAME.env in DIR.
    Run {
        /// The name of the entry.
        name: String,
        /// The directory of the entries (`<state>/autostart`).
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum AgentCommand {
    /// Test the host (podnet doctor --agent), start podnet warp up when direct
    /// networking does not do each task, start a detached quick tunnel for
    /// each --expose PORT, and print one JSON document.
    Up {
        /// Also add the block of podnet warp up --persist to the shell files.
        #[arg(long)]
        persist: bool,
        /// A local port to expose with a quick tunnel (repeatable).
        #[arg(long = "expose", value_name = "PORT")]
        expose: Vec<u16>,
        /// The TCP port of the WARP proxy on 127.0.0.1.
        #[arg(long, default_value_t = 40000)]
        port: u16,
        /// Start WARP also when direct networking works.
        #[arg(long)]
        warp: bool,
    },
    /// Stop what podnet agent up started and put back each change.
    Down,
    /// Print the state: the instances, podnet warp up, and the doctor.
    Status,
}

#[derive(Args, Debug)]
struct DoctorArgs {
    /// Print one JSON document.
    #[arg(long)]
    json: bool,
    /// Test what dev work can do here: git over HTTPS and SSH, the package
    /// registries, UDP DNS, IPv6 and localhost, directly, through the proxy
    /// and through a running podnet warp up; then print the commands to run.
    #[arg(long)]
    agent: bool,
    /// Samples of each TCP path (1-9). All samples end in 10 s.
    #[arg(long, default_value_t = 9, value_parser = clap::value_parser!(u8).range(1..=9))]
    samples: u8,
    /// The time limit of one connection and of one TLS handshake, in seconds.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=10))]
    timeout: u64,
}

#[derive(Args, Debug)]
struct ManArgs {
    /// Sections: commands (tunnel, warp run) and topics (environment, files,
    /// exit-status, examples, pod). `podnet man tunnel serve` gives both.
    #[arg(value_name = "SECTION", num_args = 0..)]
    section: Vec<String>,
    /// Write to stdout, also on a terminal.
    #[arg(long)]
    no_pager: bool,
    /// Write a man(7) page.
    #[arg(long, conflicts_with = "json")]
    roff: bool,
    /// Write the manual as one JSON object.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone, Debug)]
struct UpdateArgs {
    /// Only say which release is available; change nothing.
    #[arg(long)]
    check: bool,
    /// The tag to install, for example v0.3.0-beta.11. Default: the newest
    /// release (a prerelease only when this binary is a prerelease).
    #[arg(long, value_name = "TAG", value_parser = parse_release_tag)]
    version: Option<String>,
    /// Put the binary before the last update (podnet.prev) back, with no
    /// network. A second --rollback goes forward again.
    #[arg(long, conflicts_with_all = ["check", "version", "force"])]
    rollback: bool,
    /// Install the release also when it is the version of this binary.
    /// Without it, podnet says that the version is installed and exits 0.
    #[arg(long)]
    force: bool,
}

/// A `--version` of `podnet update`: a release tag (issue 227).
fn parse_release_tag(value: &str) -> Result<String, String> {
    if podnet::update::valid_tag(value) {
        Ok(value.to_string())
    } else {
        Err("not a release tag (for example v0.3.0-beta.9)".to_string())
    }
}

#[derive(Args, Clone, Debug)]
struct PortsArgs {
    /// Print one JSON object: {"ports": [PORT, ...]}.
    #[arg(long)]
    json: bool,
    /// Connect to each port, and list only the ports that accept a
    /// connection. With --json, the others are in "unreachable".
    #[arg(long)]
    probe: bool,
}

#[derive(Args, Clone, Debug)]
struct TunnelOpts {
    #[command(flatten)]
    detach: DetachArgs,
    /// Quick-tunnel provisioning endpoint.
    #[arg(long, default_value = "https://api.trycloudflare.com", global = true)]
    service_url: String,
    /// User-Agent sent when provisioning.
    #[arg(long, global = true)]
    user_agent: Option<String>,
    /// Edge connections (1-8), for redundancy: when one is lost, the others
    /// carry the visitors. The edge chooses the connection of each request,
    /// and one request uses one connection, so more connections do not make
    /// one transfer faster. Default: ha-connections of --config, else 2.
    #[arg(long, global = true, value_parser = clap::value_parser!(u8).range(1..=8))]
    ha_connections: Option<u8>,
    /// Edge protocol: quic (UDP 7844), http2 or h2 (TCP 7844), or auto
    /// (quic, then http2). Default: protocol of --config, else auto.
    #[arg(long, global = true, value_parser = ["auto", "quic", "http2", "h2"])]
    protocol: Option<String>,
    /// How to reach the edge: auto (try 7844, fall back to WARP on 443),
    /// direct (port 7844), warp (carried on TCP 443) or relay (HTTP/2 in a
    /// WebSocket to the relay of --relay, on TCP 443).
    #[arg(long, default_value = "auto", global = true, value_parser = ["auto", "direct", "warp", "relay"])]
    transport: String,
    /// The WebSocket-to-TCP relay of --transport relay: a URL, or a comma
    /// list of hosts of one deployment. The variable PODNET_RELAY_TOKEN (not
    /// PODNET_RELAY) gives a token; without it, podnet mints one.
    #[arg(long, value_name = "URL", global = true, env = "PODNET_RELAY", hide_env_values = true, default_value = podnet::ws_relay::DEFAULT_RELAY)]
    relay: String,
    /// Keep the WARP device and MASQUE key here and resume them next run.
    /// Without it, every run registers a new anonymous device.
    #[arg(long, value_name = "PATH", global = true)]
    warp_identity: Option<PathBuf>,
    /// How the next edge leg starts: staggered (when the leg before has not
    /// registered in 2 s, or at once when it fails) or serial (only after the
    /// leg before failed).
    #[arg(long, global = true, default_value = "staggered", env = "PODNET_LEG_FAILOVER", hide_env_values = true, value_parser = ["staggered", "serial"])]
    leg_failover: String,
    /// Do not fetch the public URL to prove reachability.
    #[arg(long, global = true)]
    no_verify: bool,
    /// Print a QR code for the public URL.
    #[arg(long, global = true)]
    qr: bool,
    /// Print the state of the tunnel as JSON lines on stdout, in place of
    /// the text lines. Each line is one object with the key "event":
    /// "ready" (url, tunnel_id, locations, and pin for share) or "verified"
    /// (url).
    #[arg(long, global = true)]
    json: bool,
    /// Stay up for this many seconds instead of until Ctrl-C (it also ends
    /// the verify of the public URL).
    #[arg(long, global = true)]
    run_for: Option<u64>,
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
    auth_user: Option<String>,
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
    auth_password_file: Option<PathBuf>,
    /// Check the plan and stop: the flags, the config file, each origin (a
    /// connection, and the TLS handshake for https, with no request), the
    /// files and the directories, and the edge legs. No Cloudflare API call,
    /// no edge connection, no file is written. Exit 0 when each check
    /// passes, 1 when a check fails. With --json, one JSON document.
    #[arg(long, global = true)]
    check: bool,
}

/// How a tunnel command prints its state.
#[derive(Clone, Copy, Debug, Default)]
struct Show {
    qr: bool,
    json: bool,
    /// The origin answers 404 for `/` as its normal answer: `serve` of a
    /// directory with no `index.html` (issue 119).
    root_404: bool,
    /// The tunnel has --auth-user: the verify gets 401 (issue 205).
    auth: bool,
}

impl TunnelOpts {
    fn show(&self) -> Show {
        Show {
            qr: self.qr,
            json: self.json,
            root_404: false,
            auth: self.auth_user.is_some(),
        }
    }

    fn apply(&self, mut config: Config) -> Result<Config> {
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
                podnet::proxy_auth::Credentials::load(user, file)
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
struct DetachArgs {
    /// Run in the background: podnet prints one JSON document when the
    /// command is ready (its URL or its listen address) and exits 0. The
    /// instance keeps running when the shell or the terminal closes. podnet
    /// ps, logs, wait and stop manage it.
    #[arg(long)]
    detach: bool,
    /// The name of the detached instance. Default: the command and a hash
    /// of its arguments. A second start with the same name and the same
    /// arguments gives the same instance. With no --detach: register this
    /// process under the name (it is not forked and not restarted); podnet
    /// ps, logs, wait and stop see it.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
    /// With --detach: seconds to wait for the instance to be ready (else
    /// exit 124).
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    ready_timeout: u64,
    /// Stop a running instance of the same name that has other arguments,
    /// and start this one (needs --detach). connect: also take a unix
    /// socket of -L that another process serves (by default, a socket that
    /// answers is refused, exit 69; a stale socket file is replaced).
    #[arg(long)]
    replace: bool,
    /// Do not start the instance again when it ends. Without it, a
    /// supervisor starts it again with a backoff (1 s to 30 s), but not
    /// after exit 64 or 78, and not after a planned end (--stop-after,
    /// --idle-secs, --run-for). A quick tunnel gets a new URL; podnet ps
    /// shows it. With --name and no --detach, there is no supervisor.
    #[arg(long)]
    no_restart: bool,
}

impl DetachArgs {
    fn options(&self) -> podnet::detach::Options {
        podnet::detach::Options {
            name: self.name.clone(),
            ready_timeout: std::time::Duration::from_secs(self.ready_timeout.max(1)),
            replace: self.replace,
            restart: !self.no_restart,
        }
    }
}

#[derive(Args, Debug)]
struct TunnelArgs {
    #[command(flatten)]
    common: TunnelOpts,
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

#[derive(Args, Debug)]
struct ServeArgs {
    #[command(flatten)]
    common: TunnelOpts,
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
enum ModeArg {
    Upload,
    Download,
    Proxy,
}

#[derive(Args, Debug)]
struct ShareArgs {
    #[command(flatten)]
    common: TunnelOpts,
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
#[command(subcommand_required = true, arg_required_else_help = false)]
struct RelayArgs {
    /// The relay for a new pair. A pair keeps the relay that made it.
    #[arg(long, value_name = "URL", global = true, env = "PODNET_RELAY", hide_env_values = true, default_value = podnet::ws_relay::DEFAULT_RELAY)]
    relay: String,
    #[command(subcommand)]
    command: RelayCommand,
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    /// Ask the relay for a pair: a name, a node token (kept in a file of
    /// mode 0600 in the state directory) and a connect token for the
    /// operator. A pair lasts at most 72 h.
    Pair {
        /// Print the pair as JSON (with the connect token, not the node
        /// token).
        #[arg(long)]
        json: bool,
    },
    /// Hold the node socket of a pair, and connect each session of an
    /// operator to a local service. A lost socket is opened again.
    Node {
        /// The pair name. Default: the pair with the most time left.
        pair: Option<String>,
        /// The local service: host:port or unix:/path.
        #[arg(long, value_name = "TARGET")]
        to: String,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Open a session to a node and copy stdin and stdout (an SSH
    /// ProxyCommand), or each connection of --listen.
    Connect {
        /// The pair name.
        name: String,
        /// The connect token. Prefer the variable or --token-file: other
        /// users of the host can read a command line. Default: the local
        /// pair file.
        #[arg(long, env = "PODNET_RELAY_CONNECT_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Read the connect token from this file.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
        /// Accept local connections here (tcp://[bind:]port or unix:/path),
        /// one session for each, in place of stdin and stdout.
        #[arg(long, value_name = "LISTEN")]
        listen: Option<String>,
    },
    /// Stop a node and its sessions at the relay (POST /v1/stop), and
    /// remove the local pair file.
    Stop {
        /// The pair name.
        name: String,
    },
}

#[derive(Args, Debug)]
struct ConnectArgs {
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
    detach: DetachArgs,
}

#[derive(Args, Debug)]
struct QrArgs {
    /// URL to encode (at most 2331 bytes). Another text gets a warning.
    url: String,
}

#[derive(Args, Debug)]
struct DemoArgs {
    #[command(flatten)]
    common: TunnelOpts,
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

fn main() {
    // podnet-netns forks and makes its own runtime. Start it before the async
    // runtime of podnet exists.
    // args() panics on an argument that is not UTF-8 (issue 57); clap then
    // reports the bad argument as a usage error.
    // A detached child (issue 70) closes the descriptors that it got and
    // drops its flag before anything else.
    let args = podnet::detach::prepare(std::env::args_os().collect());
    let args = cloudflared_compat(args);
    let argv: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if let Err(err) = apply_token_files(&argv) {
        eprintln!("podnet: {err:#}");
        std::process::exit(podnet::exit::USAGE);
    }
    if argv.get(1).map(String::as_str) == Some("pod") {
        podnet_netns::set_program_name("podnet pod");
        std::process::exit(podnet_netns::main_with_args(&argv[2..]));
    }
    let cli = match top_command()
        .try_get_matches_from(&args)
        .and_then(|matches| Cli::from_arg_matches(&matches))
    {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            // Help that the user asked for exits 0. Help that comes up
            // because a subcommand is missing (podnet net) is a usage error.
            let code = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => podnet::exit::SUCCESS,
                _ => podnet::exit::USAGE,
            };
            // Issue 181: with --log-format json, a usage error is one JSON
            // line too (found in argv: the parse failed).
            if code != podnet::exit::SUCCESS && json_wanted(&argv) {
                eprintln!("{}", error_json(&err.render().to_string(), code));
            } else {
                let _ = err.print();
                for line in usage_hints(&err) {
                    eprintln!("{line}");
                }
            }
            if code != podnet::exit::SUCCESS {
                podnet::report::send(command_name(&argv).as_deref(), code, None);
            }
            std::process::exit(code);
        }
    };
    let command = command_name(&argv);
    LOG_JSON.store(
        cli.log_format == "json",
        std::sync::atomic::Ordering::Relaxed,
    );
    // Issue 115: -q silences the warnings of the pod too. No thread runs
    // yet.
    if cli.quiet {
        // SAFETY: one thread: the runtime does not exist yet.
        unsafe { std::env::set_var(podnet_netns::QUIET_VARIABLE, "1") };
    }
    // Issue 189: `podnet -v pod -- PROG` (a global option before pod) runs the
    // pod too; before, it panicked. Still one thread: the pod forks.
    if let Command::Pod { args } = &cli.command {
        if let Some(option) = pod_network_option(&cli) {
            eprintln!("podnet: podnet pod does not use {option}; give the proxy to the pod with -x (podnet pod --help)");
            std::process::exit(podnet::exit::USAGE);
        }
        podnet_netns::set_program_name("podnet pod");
        std::process::exit(podnet_netns::main_with_args(&pod_args_of(&argv, args)));
    }
    // Issue 126: a server command holds one descriptor for each connection.
    // A command that runs a program of the user leaves its limit as it is.
    let runs_a_program = matches!(
        command.as_deref(),
        Some("warp exec" | "warp shell" | "warp run" | "autostart run")
    );
    if !runs_a_program {
        podnet::rlimit::raise();
    }
    if let Some(detach) = detach_of(&cli.command).filter(|d| d.detach) {
        let name = command.clone().unwrap_or_default();
        if !podnet::detach::is_child() {
            std::process::exit(podnet::detach::start(&name, &detach.options()));
        }
        if let Err(err) = podnet::detach::child_begin() {
            eprintln!("podnet: --detach: {err:#}");
            std::process::exit(podnet::detach::TEMPFAIL);
        }
    } else if podnet::detach::is_child() {
        eprintln!("podnet: --detach-child is for podnet itself");
        std::process::exit(podnet::exit::USAGE);
    } else if let Some(detach) = detach_of(&cli.command) {
        if detach.replace && !matches!(cli.command, Command::Connect(_)) {
            eprintln!("podnet: --replace needs --detach");
            std::process::exit(podnet::exit::USAGE);
        }
        // Issue 209: --name with no --detach registers this process.
        match &detach.name {
            Some(name) => {
                if let Err(err) = podnet::instances::check_name(name) {
                    eprintln!("podnet: --name: {err:#}");
                    std::process::exit(podnet::exit::USAGE);
                }
                if let Err(err) =
                    podnet::detach::register(name, command.as_deref().unwrap_or_default())
                {
                    eprintln!("podnet: --name: {err:#}");
                    std::process::exit(podnet::detach::TEMPFAIL);
                }
            }
            None if detach.no_restart => {
                eprintln!("podnet: --no-restart needs --detach or --name");
                std::process::exit(podnet::exit::USAGE);
            }
            None => {}
        }
    }
    if let Some(path) = &cli.ca_file {
        podnet::trust::set_ca_file(path.clone());
        // Issue 173: a roots file that cannot be used exits 78 for each
        // command (status and doctor too), before any work.
        if let Err(err) = podnet::trust::roots() {
            // Issue 253: trust::roots names the file already.
            let err = podnet::exit::fault(podnet::exit::Fault::Config, err);
            print_error(
                &podnet::report::error_line(&err),
                podnet::exit::code_of(&err),
            );
            let code = podnet::exit::code_of(&err);
            podnet::report::send(command.as_deref(), code, Some(&err));
            std::process::exit(code);
        }
    }
    if let Err(err) = network_options(&cli) {
        // A flag is a usage error; a variable (PODNET_RESOLVE) has its class.
        let err = if podnet::exit::code_of(&err) == podnet::exit::FAILURE {
            podnet::exit::fault(podnet::exit::Fault::Usage, err)
        } else {
            err
        };
        print_error(
            &podnet::report::error_line(&err),
            podnet::exit::code_of(&err),
        );
        let code = podnet::exit::code_of(&err);
        podnet::report::send(command.as_deref(), code, Some(&err));
        std::process::exit(code);
    }
    // A command that only prints ends at a closed stdout (podnet status |
    // head) with no panic: the default action of SIGPIPE. The server
    // commands keep SIGPIPE ignored.
    if matches!(
        command.as_deref(),
        Some(
            "status"
                | "ports"
                | "qr"
                | "man"
                | "completions"
                | "doctor"
                | "net doctor"
                | "net addresses"
                | "net demo"
        )
    ) {
        // SAFETY: signal() with SIG_DFL, before any thread starts.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    let level = if cli.quiet {
        "podnet=warn"
    } else {
        match cli.verbose {
            0 => "podnet=info",
            1 => "podnet=debug",
            _ => "podnet=trace",
        }
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.is_empty() => EnvFilter::try_new(&value).unwrap_or_else(|e| {
            // Before, a bad RUST_LOG gave the default level with no word.
            eprintln!("podnet: RUST_LOG={value:?} does not parse ({e}); the log level is {level}");
            EnvFilter::new(level)
        }),
        _ => EnvFilter::new(level),
    };
    // Colours only on a terminal: a log file or a pipe gets plain text.
    let ansi = match cli.color.as_str() {
        "always" => true,
        "never" => false,
        // A detached instance writes its log to a file (issue 103).
        _ => {
            std::io::IsTerminal::is_terminal(&std::io::stderr())
                && std::env::var_os("NO_COLOR").is_none()
                && !podnet::detach::is_child()
        }
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(podnet::report::TeeStderr);
    if cli.log_format == "json" {
        builder.json().with_ansi(false).init();
    } else {
        builder.with_ansi(ansi).init();
    }
    if let Some(line) = foreground_hint(
        command.as_deref(),
        &argv,
        podnet::detach::is_child(),
        no_terminal(),
    ) {
        tracing::info!("{line}");
    }
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
        .and_then(|runtime| {
            runtime.block_on(async {
                install_signals();
                async_main(cli).await
            })
        });
    podnet::detach::unregister();
    if let Err(err) = result {
        let code = podnet::exit::code_of(&err);
        let line = podnet::report::error_line(&err);
        // Issues 182 and 210: a supervised child tells its supervisor how
        // long the service asks to wait.
        if let Some(secs) = podnet::quicktunnel::retry_of(&err).and_then(|r| r.retry_after_s) {
            podnet::detach::retry_after(secs);
        }
        // The report has the error in "error"; "messages" holds the log
        // lines before it (issue 55: the line was in both).
        print_error(&line, code);
        podnet::report::send(command.as_deref(), code, Some(&err));
        std::process::exit(code);
    }
}

/// `--log-format json` (issue 181): the last error line is JSON too.
static LOG_JSON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Flags of cloudflared that podnet does not have, with the advice for each
/// (E9).
const CLOUDFLARED_FLAGS: &[(&str, &str)] = &[
    (
        "--logfile",
        "the log goes to stderr: redirect it (2>FILE), or use --detach and podnet logs",
    ),
    (
        "--log-directory",
        "the log goes to stderr: redirect it, or use --detach and podnet logs",
    ),
    (
        "--pidfile",
        "use --detach: podnet ps shows the pid, podnet stop stops it",
    ),
    ("--metrics", "podnet has no metrics listener flag"),
    (
        "--origincert",
        "a named tunnel needs --token, --token-file or --credentials-file",
    ),
    (
        "--autoupdate-freq",
        "podnet does not update itself: podnet update",
    ),
    (
        "--grace-period",
        "podnet drains the open streams for up to 90 s at a stop",
    ),
    (
        "--edge-ip-version",
        "podnet tries IPv4 and IPv6 edge addresses",
    ),
    ("--region", "podnet uses the global region"),
    (
        "--retries",
        "podnet connects again with a backoff and no limit",
    ),
    ("--tag", "podnet sends no tags"),
    ("--post-quantum", "podnet has no post-quantum option"),
];

/// cloudflared arguments for `tunnel` (E9): `tunnel run` is `tunnel`;
/// `--no-autoupdate` is ignored; `--loglevel LEVEL` becomes -v, -vv or -q
/// (info: nothing). Other arguments stay. Only before `--`, and only when
/// the command is `tunnel`.
fn cloudflared_compat(args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let Some(words) = args
        .iter()
        .map(|a| a.to_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()
    else {
        return args;
    };
    let end = words.iter().position(|w| w == "--").unwrap_or(words.len());
    let Some(at) = words[..end].iter().position(|w| w == "tunnel") else {
        return args;
    };
    // The command is tunnel (not a value "tunnel" of another command).
    let plain: Vec<String> = words
        .iter()
        .filter(|w| *w != "--no-autoupdate")
        .cloned()
        .collect();
    if command_name(&plain).as_deref() != Some("tunnel") {
        return args;
    }
    let mut out: Vec<String> = Vec::with_capacity(words.len());
    let mut i = 0;
    while i < words.len() {
        let word = &words[i];
        if i >= end {
            out.push(word.clone());
            i += 1;
            continue;
        }
        if i == at + 1 && word == "run" {
            i += 1;
            continue;
        }
        if word == "--no-autoupdate" {
            i += 1;
            continue;
        }
        let level = if let Some(level) = word.strip_prefix("--loglevel=") {
            i += 1;
            Some(level.to_string())
        } else if word == "--loglevel" {
            i += 2;
            words.get(i - 1).cloned()
        } else {
            None
        };
        if let Some(level) = level {
            match level.to_ascii_lowercase().as_str() {
                "debug" => out.push("-v".into()),
                "trace" => out.push("-vv".into()),
                "warn" | "error" | "fatal" | "panic" => out.push("-q".into()),
                _ => {}
            }
            continue;
        }
        out.push(word.clone());
        i += 1;
    }
    out.into_iter().map(Into::into).collect()
}

/// The token of a file (E4): the text with no white space at the ends; an
/// error for an empty or a large file.
fn read_token_file(path: &std::path::Path) -> Result<String> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if meta.len() > 64 * 1024 {
        bail!(
            "{} is not a token file: it has {} bytes",
            path.display(),
            meta.len()
        );
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let token = text.trim();
    if token.is_empty() {
        bail!("the token file {} is empty", path.display());
    }
    Ok(token.to_string())
}

/// Read the token of --token-file (or of TUNNEL_TOKEN_FILE) into the token
/// variable of the command, before the parse: the token is then not on a
/// command line, and each user of the token reads it as before. A token
/// flag together with a token file is an error.
fn apply_token_files(argv: &[String]) -> Result<()> {
    let relay_connect = command_name(argv).as_deref() == Some("relay connect");
    let variable = if relay_connect {
        podnet::relay_reverse::CONNECT_TOKEN_VARIABLE
    } else {
        "TUNNEL_TOKEN"
    };
    let mut path = None;
    let mut words = argv.iter().skip(1);
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if (word == "--token" || word.starts_with("--token="))
            && argv
                .iter()
                .any(|w| w == "--token-file" || w.starts_with("--token-file="))
        {
            bail!("--token and --token-file: give one of them");
        }
        if let Some(value) = word.strip_prefix("--token-file=") {
            path = Some(PathBuf::from(value));
        } else if word == "--token-file" {
            path = words.next().map(PathBuf::from);
        }
    }
    if path.is_none() && !relay_connect && std::env::var_os("TUNNEL_TOKEN").is_none() {
        path = std::env::var_os("TUNNEL_TOKEN_FILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
    }
    let Some(path) = path else {
        return Ok(());
    };
    let token = read_token_file(&path)?;
    podnet::report::hide(&token);
    // SAFETY: one thread: the runtime does not exist yet.
    unsafe { std::env::set_var(variable, token) };
    Ok(())
}

/// Whether stdin and stderr are both no terminal (an agent, a pipe, a
/// service).
fn no_terminal() -> bool {
    use std::io::IsTerminal as _;
    !std::io::stdin().is_terminal() && !std::io::stderr().is_terminal()
}

/// The commands that serve until a stop signal.
const SERVER_COMMANDS: &[&str] = &["tunnel", "serve", "share", "connect", "relay node"];

/// E12: one line for a server command in the foreground with no terminal
/// (a tool call of an agent waits for its end): --detach or --run-for.
fn foreground_hint(
    command: Option<&str>,
    argv: &[String],
    child: bool,
    no_terminal: bool,
) -> Option<String> {
    let command = command?;
    if child || !no_terminal || !SERVER_COMMANDS.contains(&command) {
        return None;
    }
    let given = |flag: &str| {
        argv.iter()
            .any(|a| a == flag || a.starts_with(&format!("{flag}=")))
    };
    if ["--detach", "--run-for", "--exit-on-verify", "--help", "-h"]
        .iter()
        .any(|f| given(f))
    {
        return None;
    }
    Some(format!(
        "podnet {command} runs in the foreground until a stop signal, and no terminal is attached: add --detach to run it in the background (podnet ps, podnet stop), or --run-for SECS"
    ))
}

/// The commands of the top help, by purpose (E1). Each subcommand is in
/// one group; a test checks it.
const HELP_GROUPS: &[(&str, &[&str])] = &[
    (
        "Publish a local service",
        &["tunnel", "serve", "share", "demo", "qr"],
    ),
    (
        "Reach the internet from a limited host",
        &["agent", "warp", "pod", "net", "connect", "relay"],
    ),
    (
        "Run in the background",
        &["ps", "logs", "wait", "stop", "autostart"],
    ),
    (
        "Check this host and podnet",
        &[
            "doctor",
            "status",
            "ports",
            "bug-report",
            "update",
            "man",
            "completions",
            "help",
        ],
    ),
];

/// The "Start here" block of the top help.
const START_HERE: &str = "\
Start here:
  podnet doctor                              test the path from this host to the edge
  podnet tunnel --url http://localhost:8080  a public URL for a local service
  podnet agent up                            a sandbox: test, start WARP if needed, expose ports
  podnet man                                 the full manual";

/// The first part of `text`: up to the end of the first sentence or the
/// first colon, with no issue reference.
fn first_sentence(text: &str) -> String {
    let end = [". ", ": "]
        .iter()
        .filter_map(|mark| text.find(mark))
        .min()
        .unwrap_or(text.len());
    let mut part = text[..end].to_string();
    while let Some(start) = part.find(" (issue ") {
        match part[start..].find(')') {
            Some(len) => part.replace_range(start..start + len + 1, ""),
            None => break,
        }
    }
    part
}

/// The commands of `cmd` by purpose, with the first sentence of each.
fn grouped_commands(cmd: &clap::Command) -> String {
    let width = cmd
        .get_subcommands()
        .map(|c| c.get_name().len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (title, names) in HELP_GROUPS {
        out.push_str(&format!("{title}:\n"));
        for name in *names {
            let about = cmd
                .find_subcommand(name)
                .and_then(|c| c.get_about())
                .map(|a| a.to_string())
                .unwrap_or_else(|| {
                    "Print this message or the help of the given subcommand(s)".into()
                });
            out.push_str(&format!("  {name:width$}  {}\n", first_sentence(&about)));
        }
        out.push('\n');
    }
    out
}

/// The top command, with the commands by purpose and a "Start here" block
/// in its help.
fn top_command() -> clap::Command {
    let cmd = Cli::command();
    let template = format!(
        "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{START_HERE}\n\n{}Options:\n{{options}}{{after-help}}",
        grouped_commands(&cmd)
    );
    let root = Cli::command();
    with_examples(cmd.help_template(template), "podnet", &root)
}

/// The command path of an example: `podnet`, then each word that names a
/// subcommand (`podnet warp proxy -r` is `podnet warp proxy`).
fn example_path(cmd: &clap::Command, line: &str) -> String {
    let mut path = String::from("podnet");
    let mut at = cmd;
    for word in line.split_whitespace().skip(1) {
        match at.find_subcommand(word) {
            Some(sub) => {
                path.push(' ');
                path.push_str(word);
                at = sub;
            }
            None => break,
        }
    }
    path
}

/// E7: the examples of `podnet man examples` in the help of their command
/// (`podnet tunnel --help`), from the one table of the manual.
fn with_examples(cmd: clap::Command, path: &str, root: &clap::Command) -> clap::Command {
    let examples: Vec<&podnet::manual::facts::Example> = podnet::manual::facts::EXAMPLES
        .iter()
        .filter(|e| path != "podnet" && example_path(root, e.command) == path)
        .collect();
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    let mut cmd = cmd;
    for name in names {
        let sub_path = format!("{path} {name}");
        cmd = cmd.mut_subcommand(&name, |sub| with_examples(sub, &sub_path, root));
    }
    if examples.is_empty() {
        return cmd;
    }
    let mut text = String::from("Examples:");
    for e in examples {
        text.push_str(&format!("\n  {}\n      {}", e.command, e.meaning));
    }
    cmd.after_help(text)
}

/// The lines after a usage error (E8, E10): a word that is no command but
/// looks like a port, a URL or a path names the command for it; an unknown
/// command or flag names the version and `podnet update --check`.
fn usage_hints(err: &clap::Error) -> Vec<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let invalid = || match err
        .get(ContextKind::InvalidSubcommand)
        .or(err.get(ContextKind::InvalidArg))
    {
        Some(ContextValue::String(word)) => Some(word.clone()),
        _ => None,
    };
    let mut lines = Vec::new();
    match err.kind() {
        ErrorKind::InvalidSubcommand => {
            if let Some(hint) = invalid().as_deref().and_then(word_hint) {
                lines.push(hint);
            }
        }
        ErrorKind::UnknownArgument => {
            let word = invalid().unwrap_or_default();
            let name = word.split('=').next().unwrap_or("");
            if let Some((flag, advice)) = CLOUDFLARED_FLAGS.iter().find(|(f, _)| *f == name) {
                lines.push(format!(
                    "hint: {flag} is a flag of cloudflared, not of podnet; {advice}"
                ));
                return lines;
            }
        }
        _ => return lines,
    }
    lines.push(format!(
        "podnet {} does not know {}; a newer release can: podnet update --check",
        env!("CARGO_PKG_VERSION"),
        invalid().map_or_else(|| "it".to_string(), |w| format!("'{w}'"))
    ));
    lines
}

/// The command for a word that is no command of podnet.
fn word_hint(word: &str) -> Option<String> {
    if !word.is_empty() && word.len() <= 5 && word.bytes().all(|b| b.is_ascii_digit()) {
        return Some(format!(
            "hint: for a public URL of the local port {word}: podnet tunnel --url http://localhost:{word}"
        ));
    }
    let lower = word.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(format!(
            "hint: for a public URL of the local service {word}: podnet tunnel --url {word}"
        ));
    }
    if lower.starts_with("wss://") || lower.starts_with("ws://") {
        return Some(format!(
            "hint: for a local socket to the WebSocket forward {word}: podnet connect --local 127.0.0.1:2222 {word}"
        ));
    }
    let path = std::path::Path::new(word);
    if word.starts_with('/') || word.starts_with("./") || word.starts_with("~/") || path.exists() {
        return Some(if path.is_file() {
            format!("hint: to send the file {word}: podnet share --mode download --file {word}")
        } else {
            format!("hint: to serve the directory {word}: podnet serve --dir {word}")
        });
    }
    None
}

/// Whether `argv` asks for `--log-format json` (before a parse).
fn json_wanted(argv: &[String]) -> bool {
    argv.windows(2)
        .any(|w| w[0] == "--log-format" && w[1] == "json")
        || argv.iter().any(|a| a == "--log-format=json")
}

/// The last error line as one JSON object, in the shape of a log line of
/// `--log-format json`.
fn error_json(text: &str, code: i32) -> String {
    let message = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.strip_prefix("podnet: ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("; ");
    serde_json::json!({
        "level": "ERROR",
        "fields": { "message": message.trim_end(), "exit_code": code },
        "target": "podnet",
    })
    .to_string()
}

/// Print the last error line: text, or JSON with --log-format json.
fn print_error(line: &str, code: i32) {
    if LOG_JSON.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("{}", error_json(line, code));
    } else {
        eprintln!("{line}");
    }
}

/// The stop request: false until SIGINT, SIGTERM or SIGHUP comes.
static STOP: std::sync::OnceLock<tokio::sync::watch::Receiver<bool>> = std::sync::OnceLock::new();

/// Whether the action of `signal` is SIG_IGN (`nohup` gives it for SIGHUP).
fn signal_ignored(signal: libc::c_int) -> bool {
    // SAFETY: sigaction() with no new action only reads the old action.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(signal, std::ptr::null(), &mut old) == 0
            && old.sa_sigaction == libc::SIG_IGN
    }
}

/// At the start of the runtime: take SIGINT, SIGTERM and SIGHUP (issue
/// 91). After the ready of a command (or its first wait), each is in the
/// stop request, also when it comes between two waits. Before, and in a
/// command that does not wait, each has the default action. A second
/// signal during the shutdown also has the default action. SIGHUP stays ignored in a detached instance
/// and when the parent ignored it (`nohup`).
fn install_signals() {
    use tokio::signal::unix::{signal, SignalKind};
    STOP.get_or_init(|| {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut kinds = vec![
            (SignalKind::interrupt(), libc::SIGINT, "SIGINT"),
            (SignalKind::terminate(), libc::SIGTERM, "SIGTERM"),
        ];
        if !podnet::detach::is_child() && !signal_ignored(libc::SIGHUP) {
            kinds.push((SignalKind::hangup(), libc::SIGHUP, "SIGHUP"));
        }
        let tx = std::sync::Arc::new(tx);
        for (kind, number, name) in kinds {
            match signal(kind) {
                Ok(mut stream) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        while stream.recv().await.is_some() {
                            // No command waits, or the second signal
                            // during the shutdown: the default action.
                            if !podnet::detach::stop_armed() || *tx.borrow() {
                                // SAFETY: signal() and raise() with a
                                // valid signal number.
                                unsafe {
                                    libc::signal(number, libc::SIG_DFL);
                                    libc::raise(number);
                                    // Issue 208: PID 1 of a namespace (a
                                    // container with no init) drops a
                                    // signal with the default action, and
                                    // raise returns. Exit as a shell does.
                                    libc::_exit(128 + number);
                                }
                            }
                            if number == libc::SIGINT {
                                tracing::info!("Ctrl-C: stopping");
                            } else {
                                tracing::info!("{name}: stopping");
                            }
                            let _ = tx.send(true);
                        }
                    });
                }
                Err(err) => tracing::warn!("{name}: cannot take the signal ({err})"),
            }
        }
        rx
    });
}

/// Ready on SIGINT (Ctrl-C), SIGTERM (systemd, Docker, Kubernetes, podnet
/// stop) or SIGHUP (the terminal closed): each starts the same clean
/// shutdown, and the exit code is 0. A detached instance ignores SIGHUP.
/// A signal that came before this call is not lost.
async fn shutdown_signal() -> std::io::Result<()> {
    install_signals();
    podnet::detach::arm_stop();
    let mut rx = STOP.get().expect("installed").clone();
    let _ = rx.wait_for(|stop| *stop).await;
    Ok(())
}

/// Ready after `run_for` seconds (when given), or on a stop signal. The end
/// of `run_for` is a planned end (issue 195).
async fn sleep_or_signal(run_for: Option<u64>) {
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => podnet::detach::planned_end(),
                _ = shutdown_signal() => {}
            }
        }
        None => {
            let _ = shutdown_signal().await;
        }
    }
}

/// The deadline of `--run-for` from now (issue 179).
fn deadline_of(run_for: Option<u64>) -> Option<tokio::time::Instant> {
    run_for.map(|s| tokio::time::Instant::now() + Duration::from_secs(s))
}

/// Ready at `deadline`, never with none.
async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// `Some(out)` when `work` ends; `None` when a stop signal comes first
/// (issue 101: the verify after the ready line can be stopped cleanly), or
/// at `deadline` (issue 179: `--run-for` during the verify; a planned end).
async fn until_stop_or<T>(
    deadline: Option<tokio::time::Instant>,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = shutdown_signal() => None,
        _ = sleep_until_opt(deadline) => {
            podnet::detach::planned_end();
            None
        }
        out = work => Some(out),
    }
}

/// Run `podnet ARGS` and give its last line as JSON (the ready document of
/// a detached start), with its stderr on this stderr.
fn run_self_json(args: &[String]) -> Result<serde_json::Value> {
    let exe = std::env::current_exe()?;
    let out = std::process::Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        bail!("podnet {} exited {}", args.join(" "), out.status);
    }
    let last = text.lines().last().unwrap_or("");
    serde_json::from_str(last).with_context(|| format!("the output of podnet {}", args.join(" ")))
}

/// `podnet agent up`, `down` and `status`.
async fn agent(command: AgentCommand) -> Result<()> {
    let timeout = Duration::from_secs(4);
    match command {
        AgentCommand::Up {
            persist,
            expose,
            port,
            warp,
        } => {
            podnet::warp::check_tcp_burst()?;
            podnet::warp::check_cc()?;
            let before = podnet::agent::run(timeout).await;
            let direct_enough = before
                .rows
                .iter()
                .all(|r| r.direct == podnet::agent::Outcome::Ok)
                && before.udp_dns.works();
            let mut doc = serde_json::json!({});
            let mut warp_doc = serde_json::Value::Null;
            let warp_wanted = warp || !direct_enough || before.warp_up;
            if warp_wanted {
                let mut args = vec![
                    "warp".to_string(),
                    "up".into(),
                    "--port".into(),
                    port.to_string(),
                ];
                if persist {
                    args.push("--persist".into());
                }
                match run_self_json(&args) {
                    Ok(d) => warp_doc = d,
                    Err(err) => {
                        eprintln!("podnet: agent up: podnet warp up failed: {err:#}");
                        doc["warp_error"] = format!("{err:#}").into();
                    }
                }
            }
            let mut exposed = Vec::new();
            for p in &expose {
                let name = format!("expose-{p}");
                // Issue 119: a port with no origin gets no tunnel (it gave
                // a URL that answered 502).
                if !podnet::ports::reachable(*p, Duration::from_secs(2)).await {
                    exposed.push(serde_json::json!({
                        "port": p,
                        "state": "origin-unreachable",
                        "error": format!("nothing accepts a connection on 127.0.0.1:{p}"),
                    }));
                    continue;
                }
                let base = vec![
                    "tunnel".to_string(),
                    "--port".into(),
                    p.to_string(),
                    "--detach".into(),
                    "--name".into(),
                    name.clone(),
                ];
                let result = run_self_json(&base).or_else(|first| {
                    eprintln!("podnet: agent up: the tunnel of port {p} failed ({first:#}); trying --transport relay");
                    let mut relay = base.clone();
                    relay.extend(["--transport".into(), "relay".into(), "--replace".into()]);
                    run_self_json(&relay)
                });
                match result {
                    Ok(d) => exposed.push(
                        serde_json::json!({"port": p, "state": "ready", "name": name, "url": d["url"]}),
                    ),
                    Err(err) => exposed.push(
                        serde_json::json!({"port": p, "state": "failed", "error": format!("{err:#}")}),
                    ),
                }
            }
            let after = podnet::agent::run(timeout).await;
            let mut works = serde_json::Map::new();
            for row in &after.rows {
                works.insert(
                    row.task.to_string(),
                    serde_json::to_value(row.working()).unwrap_or_default(),
                );
            }
            let mode = if !warp_doc.is_null() {
                "warp"
            } else {
                "direct"
            };
            let warp_tcp = warp_doc["tcp"].as_bool().unwrap_or(true);
            let commands = agent_commands(mode == "warp", warp_tcp);
            doc["event"] = "agent".into();
            doc["mode"] = mode.into();
            doc["warp"] = warp_doc;
            doc["exposed"] = exposed.into();
            doc["works"] = works.into();
            doc["udp_dns"] = after.udp_dns.works().into();
            doc["ipv6"] = after.ipv6.works().into();
            doc["commands"] = commands.into();
            let mut advice = after.advice.clone();
            if let Some(err) = doc["warp_error"].as_str().map(str::to_string) {
                // Issue 97: do not give the command that just failed as advice.
                advice.retain(|line| !line.contains("podnet warp up"));
                advice.push(format!(
                    "podnet warp up failed ({err}); see podnet net doctor, and use podnet warp run -- CMD for one program"
                ));
            }
            // Issue 117: say what --persist changed.
            let files: Vec<&str> = doc["warp"]["persist_files"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            if !files.is_empty() {
                advice.push(format!(
                    "--persist: new shells load WARP from {}; podnet warp down removes it",
                    files.join(", ")
                ));
            }
            doc["advice"] = advice.into();
            let doc = podnet::status::stamped(doc);
            println!("{doc}");
            // Issue 97: WARP was needed and did not start: not a success.
            if warp_wanted && !doc["warp_error"].is_null() {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("agent up: WARP was needed, and podnet warp up failed"),
                ));
            }
            // Issue 173: an expose that failed is not a success.
            let failed = exposes_failed(&doc["exposed"]);
            if failed > 0 {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!(
                        "agent up: {failed} of {} exposes failed (see \"exposed\")",
                        expose.len()
                    ),
                ));
            }
            Ok(())
        }
        AgentCommand::Down => {
            let dir = podnet::instances::lookup_dir();
            for entry in podnet::instances::list(&dir) {
                if entry.record.name.starts_with("expose-") {
                    podnet::detach::stop(&dir, &entry.record.name, Duration::from_secs(10))?;
                    println!("podnet: agent down: stopped {}", entry.record.name);
                }
            }
            podnet::warp::up::down()
        }
        AgentCommand::Status => {
            instances_ps(false)?;
            println!();
            let report = podnet::agent::run(timeout).await;
            print!("{}", podnet::agent::text(&report));
            Ok(())
        }
    }
}

/// The class of a failed `warp license` (issue 173): the API refused the
/// key (HTTP 4xx, other than 401, 403 and 429) is a usage error; else the
/// service is not available.
fn license_fault(err: &anyhow::Error) -> Fault {
    match podnet::warp::register::api_status(err) {
        Some(401 | 403 | 429) => Fault::Unavailable,
        Some(400..=499) => Fault::Usage,
        _ => Fault::Unavailable,
    }
}

/// The number of exposes of `agent up` that are not ready.
fn exposes_failed(exposed: &serde_json::Value) -> usize {
    exposed
        .as_array()
        .map(|a| a.iter().filter(|e| e["state"] != "ready").count())
        .unwrap_or(0)
}

/// `podnet ps`: the instances of the run directory.
fn instances_ps(json: bool) -> Result<()> {
    let dir = podnet::instances::lookup_dir();
    podnet::instances::prune(&dir);
    let list = podnet::instances::list(&dir);
    if json {
        let items: Vec<serde_json::Value> = list
            .iter()
            .map(|e| {
                let r = &e.record;
                serde_json::json!({
                    "name": r.name,
                    "state": r.state,
                    "pid": r.pid,
                    "supervisor": r.supervisor,
                    "command": r.command,
                    "args": r.args,
                    "cwd": r.cwd,
                    "started": r.started,
                    "restarts": r.restarts,
                    "log": r.log,
                    "ready": r.ready,
                })
            })
            .collect();
        println!(
            "{}",
            podnet::status::stamped(serde_json::json!({
                "instances": items,
                "dir": dir.display().to_string(),
            }))
        );
        return Ok(());
    }
    if list.is_empty() {
        println!("podnet: no detached instance");
        return Ok(());
    }
    println!("NAME                     STATE          PID RST     AGE  URL/LISTEN");
    let now = podnet::instances::now();
    for e in &list {
        let r = &e.record;
        let at = r
            .ready
            .as_ref()
            .and_then(|d| d.get("url").or_else(|| d.get("listen")))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let age = now.saturating_sub(r.started);
        let age = if age >= 3600 {
            format!("{}h{:02}m", age / 3600, age % 3600 / 60)
        } else {
            format!("{}m{:02}s", age / 60, age % 60)
        };
        println!(
            "{:<24} {:<9} {:>8} {:>3} {:>7}  {}",
            r.name, r.state, r.pid, r.restarts, age, at
        );
        // Issue 203: the endpoint for podnet connect, on its own line.
        if let Some(forward) = r
            .ready
            .as_ref()
            .and_then(|d| d.get("forward"))
            .and_then(|v| v.as_str())
        {
            println!("{:<24} forward {forward}", "");
        }
    }
    Ok(())
}

/// `podnet stop`.
fn instances_stop(name: Option<String>, all: bool, timeout: u64) -> Result<()> {
    let dir = podnet::instances::lookup_dir();
    let names: Vec<String> = if all {
        podnet::instances::list(&dir)
            .into_iter()
            .map(|e| e.record.name)
            .collect()
    } else {
        let name = name.unwrap_or_default();
        podnet::instances::check_name(&name).map_err(|e| podnet::exit::fault(Fault::Usage, e))?;
        let alive = podnet::instances::is_alive(&dir, &name);
        if alive && podnet::instances::read(&dir, &name).is_none() {
            // Issue 264: the locks of a live instance stay.
            return Err(podnet::detach::unreadable(&dir, &name));
        }
        if !alive {
            podnet::instances::remove(&dir, &name);
            return Err(podnet::exit::fault(
                Fault::Unavailable,
                anyhow::anyhow!("no instance {name} runs (podnet ps)"),
            ));
        }
        vec![name]
    };
    let mut failed = None;
    for name in names {
        match podnet::detach::stop(&dir, &name, std::time::Duration::from_secs(timeout)) {
            Ok(()) => println!("podnet: stopped  {name}"),
            // --all: one instance that cannot stop does not keep the
            // others running.
            Err(err) if all => {
                eprintln!("podnet: stop {name}: {err:#}");
                failed = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    match failed {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// `podnet logs`.
async fn instances_logs(name: &str, follow: bool, lines: Option<usize>) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let dir = podnet::instances::lookup_dir();
    let path = podnet::instances::paths(&dir, name)
        .map_err(|e| podnet::exit::fault(Fault::Usage, e))?
        .log;
    let text = std::fs::read(&path).map_err(|e| {
        podnet::exit::fault(
            Fault::Unavailable,
            anyhow::anyhow!("no log of {name} at {}: {e}", path.display()),
        )
    })?;
    let shown: Vec<u8> = match lines {
        Some(n) => {
            let all: Vec<&[u8]> = text.split_inclusive(|b| *b == b'\n').collect();
            all[all.len().saturating_sub(n)..].concat()
        }
        None => text.clone(),
    };
    {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let _ = out.write_all(&shown);
        let _ = out.flush();
    }
    if !follow {
        return Ok(());
    }
    // Follow: read what comes after the end; a log that became shorter was
    // rotated (cut to 0), so read it from its start.
    let mut offset = text.len() as u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            _ = shutdown_signal() => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
        }
        let Ok(mut file) = tokio::fs::File::open(&path).await else {
            continue;
        };
        let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
        }
        if len == offset {
            continue;
        }
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            offset += n as u64;
            use std::io::Write as _;
            let mut out = std::io::stdout();
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
        }
    }
}

/// The files of `podnet warp up` other than the env file.
struct UpFiles {
    /// The blocks of the shell files.
    persist: bool,
    /// The file of environment.d (issue 138).
    env_d: bool,
}

/// `podnet warp up`: start `warp proxy` detached (instance `warp`) with the
/// WARP options of this command line, then write the env file.
fn warp_up(
    args: &WarpArgs,
    port: u16,
    files: UpFiles,
    ready_timeout: u64,
    replace: bool,
    dns: Option<std::net::SocketAddr>,
    auth: Option<(&String, &PathBuf)>,
) -> Result<()> {
    let socket = podnet::warp::up::socket_path()?;
    if files.env_d {
        podnet::warp::up::check_env_d().fault(Fault::Config)?;
    }
    let mut argv = warp_up_args(args, port, &socket, ready_timeout);
    // Issue 146: the path of the password goes to the child, not the
    // password.
    if let Some((user, file)) = auth {
        let file = file.canonicalize().unwrap_or_else(|_| file.clone());
        argv.extend([
            "--proxy-user".into(),
            user.clone(),
            "--proxy-password-file".into(),
            file.display().to_string(),
        ]);
    }
    if let Some(dns) = dns {
        argv.push("--dns".into());
        argv.push(dns.to_string());
    }
    // Issue 115: the advice of a running instance with other arguments
    // names --replace; warp up has it now.
    if replace {
        argv.push("--replace".into());
    }
    let doc = podnet::warp::up::start("podnet warp proxy --detach", &argv)?;
    // Issue 97: the TCP listener or the socket can be refused by the host;
    // the env file and the advice follow what came up.
    let (tcp, socket_up) = podnet::warp::up::listeners_of(&doc);
    for line in up_summary(tcp.is_some(), port, socket_up, &socket) {
        eprintln!("{line}");
    }
    let env = podnet::warp::up::write_env(tcp, &socket)?;
    let persist = files.persist;
    let mut persist_files = Vec::new();
    // Issue 138: the variables for the programs of the next login.
    let mut env_d = serde_json::Value::Null;
    if files.env_d {
        match tcp {
            Some(port) => {
                let file = podnet::warp::up::write_env_d(port)?;
                eprintln!(
                    "podnet: warp up: wrote {} (for the next login; podnet warp down removes it)",
                    file.display()
                );
                env_d = file.display().to_string().into();
            }
            None => eprintln!(
                "podnet: warp up: --env-d needs the TCP listener; no environment.d file is written"
            ),
        }
    }
    if persist {
        for file in podnet::warp::up::persist(&env)? {
            eprintln!("podnet: warp up: a block in {}", file.display());
            persist_files.push(file.display().to_string());
        }
    }
    let mut doc = doc;
    // Issue 117: the document names the files of --persist.
    doc["persist_files"] = persist_files.into();
    doc["env"] = env.display().to_string().into();
    doc["socket"] = socket.display().to_string().into();
    doc["persist"] = persist.into();
    doc["env_d"] = env_d;
    doc["tcp"] = tcp.is_some().into();
    println!("{doc}");
    Ok(())
}

/// The lines of `warp up` on stderr when a listener did not start (issue
/// 115: the working listener comes first, then the one that failed).
fn up_summary(tcp: bool, port: u16, socket_up: bool, socket: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    if !tcp && socket_up {
        out.push(format!(
            "podnet: warp up: the WARP proxy runs on unix:{}; use: podnet warp exec -- CMD (or podnet warp shell). The host refused the TCP listener 127.0.0.1:{port}, so there are no proxy variables",
            socket.display()
        ));
    } else if !tcp {
        out.push(format!(
            "podnet: warp up: the TCP listener 127.0.0.1:{port} did not start; there are no proxy variables"
        ));
    }
    if !socket_up {
        out.push("podnet: warp up: the unix socket did not start; podnet warp exec and podnet warp shell do not work. Use the proxy variables: eval \"$(podnet warp env)\"".into());
    }
    out
}

/// The default `--idle` of `podnet warp nc -u`, in seconds.
const UDP_NC_IDLE: u64 = 3;

/// The end of the TCP pipe of `podnet warp nc` (issue 188).
fn nc_end(idle: Option<u64>, shutdown: bool) -> podnet::warp::nc::PipeEnd {
    podnet::warp::nc::PipeEnd {
        shutdown,
        idle: idle.map_or(podnet::warp::nc::TCP_IDLE, Duration::from_secs),
    }
}

/// `podnet warp nc -u` on stdin and stdout (issue 115). The process ends
/// here: a read of stdin blocks a thread.
async fn udp_nc(
    out: tokio::sync::mpsc::Sender<Vec<u8>>,
    back: tokio::sync::mpsc::Receiver<Vec<u8>>,
    idle: u64,
) -> Result<()> {
    podnet::warp::nc::udp_pipe_with(
        out,
        back,
        tokio::io::stdin(),
        tokio::io::stdout(),
        Duration::from_secs(idle),
    )
    .await?;
    std::process::exit(0);
}

/// `podnet warp ssh-config --write`, `--remove` and `--check` (issue 130).
fn ssh_config_file(
    exe: &std::path::Path,
    host: Option<&str>,
    write: bool,
    remove: bool,
    config: &str,
) -> Result<()> {
    use podnet::warp::ssh_config as sc;
    let path = sc::expand(config).fault(Fault::Config)?;
    if write || remove {
        podnet::state::check_own(&path)?;
    }
    let old = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(anyhow::anyhow!("reading {}: {err}", path.display())),
    };
    let text = old.as_deref().unwrap_or("");
    let shown = path.display();
    if remove {
        let new = sc::remove(text, host).with_context(|| shown.to_string())?;
        if old.is_some() && sc::save(&path, old.as_deref(), &new)? {
            println!("podnet: warp ssh-config: removed from {shown}");
        } else {
            println!("podnet: warp ssh-config: no block in {shown}");
        }
        return Ok(());
    }
    let host = host.ok_or_else(|| {
        podnet::exit::fault(
            Fault::Usage,
            anyhow::anyhow!("give --host PATTERN (for example --host github.com)"),
        )
    })?;
    let block = sc::block(exe, host);
    if write {
        let new = sc::write(text, host, &block).with_context(|| shown.to_string())?;
        if sc::save(&path, old.as_deref(), &new)? {
            println!("podnet: warp ssh-config: the block for {host} is in {shown}");
        } else {
            println!("podnet: warp ssh-config: the block for {host} in {shown} is current");
        }
        return Ok(());
    }
    match sc::state(text, host, &block).with_context(|| shown.to_string())? {
        sc::State::Current => {
            println!("podnet: warp ssh-config: the block for {host} in {shown} is current");
            Ok(())
        }
        sc::State::Stale => bail!("the block for {host} in {shown} names another binary; run podnet warp ssh-config --write --host {host}"),
        sc::State::Missing => bail!("no block for {host} in {shown}; run podnet warp ssh-config --write --host {host}"),
    }
}

/// The `commands` of the document of `agent up` (issues 110 and 116): the
/// eval line only when the TCP listener of warp up runs; `warp exec` and
/// `warp ssh-config` use the unix socket, so they are always there in the
/// WARP mode.
fn agent_commands(warp: bool, warp_tcp: bool) -> Vec<String> {
    let mut commands: Vec<String> = Vec::new();
    if warp && warp_tcp {
        commands.push("eval \"$(podnet warp env)\"   # proxy variables for this shell".into());
    }
    if warp {
        commands
            .push("podnet warp exec -- CMD   # any program, also static binaries and UDP".into());
        commands.push("podnet warp ssh-config --write --host github.com   # git over SSH".into());
    }
    commands.push("podnet agent status".into());
    commands.push("podnet agent down".into());
    commands
}

/// `warp` and the options of `podnet warp` that a child of `warp up` needs:
/// the identity, the relay, and the front door (the IPv6-only kit, 0002:
/// `warp up --tun` dropped `--masque-endpoint`).
fn warp_global_args(args: &WarpArgs) -> Vec<String> {
    let mut argv: Vec<String> = vec!["warp".into()];
    if let Some(path) = &args.identity {
        argv.push("--identity".into());
        argv.push(path.display().to_string());
    }
    if args.ephemeral {
        argv.push("--ephemeral".into());
    }
    if args.no_relay {
        argv.push("--no-relay".into());
    }
    if let Some(endpoint) = args.masque_endpoint {
        argv.push("--masque-endpoint".into());
        argv.push(endpoint.to_string());
    }
    if let Some(sni) = &args.masque_sni {
        argv.push("--masque-sni".into());
        argv.push(sni.clone());
    }
    if let Some(endpoint) = args.carry_endpoint {
        argv.push("--carry-endpoint".into());
        argv.push(endpoint.to_string());
    }
    if let Some(endpoint) = args.wireguard_endpoint {
        argv.push("--wireguard-endpoint".into());
        argv.push(endpoint.to_string());
    }
    for resolver in &args.resolver {
        argv.push("--resolver".into());
        argv.push(resolver.clone());
    }
    if let Some(secs) = args.session_max_age {
        argv.push("--session-max-age".into());
        argv.push(secs.to_string());
    }
    for (flag, value) in [
        ("--device-name", &args.device_name),
        ("--device-model", &args.device_model),
        ("--device-locale", &args.device_locale),
        ("--fragment-client-hello", &args.fragment_client_hello),
        ("--fragment-size", &args.fragment_size),
        ("--cc", &args.cc),
        ("--masque-transport", &args.masque_transport),
        ("--transport", &args.transport),
        ("--carry", &args.carry),
    ] {
        if let Some(value) = value {
            argv.push(flag.into());
            argv.push(value.clone());
        }
    }
    argv
}

/// The command line of the `warp tun --default-route --detach` of `podnet
/// warp up --tun`.
fn warp_up_tun_args(args: &WarpArgs, ready_timeout: u64) -> Vec<String> {
    let mut argv = warp_global_args(args);
    argv.extend([
        "tun".to_string(),
        "--default-route".into(),
        "--detach".into(),
        "--name".into(),
        podnet::warp::up::TUN_INSTANCE.into(),
        "--ready-timeout".into(),
        ready_timeout.to_string(),
    ]);
    argv
}

/// The command line of the `warp proxy --detach` of `podnet warp up`.
fn warp_up_args(
    args: &WarpArgs,
    port: u16,
    socket: &std::path::Path,
    ready_timeout: u64,
) -> Vec<String> {
    let mut argv = warp_global_args(args);
    argv.extend([
        "proxy".into(),
        "--listen".into(),
        format!("tcp://127.0.0.1:{port}"),
        "--listen".into(),
        format!("unix:{}", socket.display()),
        "--detach".into(),
        "--name".into(),
        podnet::warp::up::INSTANCE.into(),
        "--ready-timeout".into(),
        ready_timeout.to_string(),
    ]);
    argv
}

/// The options of --detach of a command that can run in the background.
fn detach_of(command: &Command) -> Option<&DetachArgs> {
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
fn network_options(cli: &Cli) -> Result<()> {
    use podnet::egress::{set_choice, Proxy, ProxyChoice};
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
        set_choice(ProxyChoice::Via(
            Proxy::parse_trusted(spec).context("--proxy")?,
        ));
    } else if cli.no_proxy {
        set_choice(ProxyChoice::Direct);
    }
    if let Some(list) = &cli.resolve {
        podnet::resolve::set_pins(list).context("--resolve")?;
    } else if let Ok(list) = std::env::var(podnet::resolve::PINS_VARIABLE) {
        // Issue 252: a bad PODNET_RESOLVE was a warning at the first dial
        // (and none for a command with no dial).
        podnet::resolve::parse_pins(&list)
            .context(podnet::resolve::PINS_VARIABLE)
            .fault(Fault::Config)?;
    }
    Ok(())
}

/// The command of `argv` for the report: `tunnel`, `warp run`, or `None`.
fn command_name(argv: &[String]) -> Option<String> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let mut words = Vec::new();
    let mut rest = argv.iter().skip(1);
    // Issue 181: an option before the subcommand (podnet -q tunnel, podnet
    // --proxy URL warp run) is skipped, with its value; before, the name
    // stopped at the first option.
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        if let Some(option) = arg.strip_prefix('-') {
            let (name, inline) = match option.split_once('=') {
                Some((n, _)) => (n, true),
                None => (option, false),
            };
            let found = match name.strip_prefix('-') {
                Some(long) => cmd.get_arguments().find(|a| a.get_long() == Some(long)),
                // -vv, -q: the first letter names the option.
                None => name
                    .chars()
                    .next()
                    .and_then(|c| cmd.get_arguments().find(|a| a.get_short() == Some(c))),
            };
            let Some(found) = found else { break };
            let takes_value = found.get_action().takes_values();
            let short_with_value = !name.starts_with('-') && name.chars().count() > 1;
            if takes_value && !inline && !short_with_value {
                rest.next();
            }
            continue;
        }
        match cmd.find_subcommand(arg) {
            Some(sub) => {
                words.push(arg.clone());
                cmd = sub.clone();
            }
            None => break,
        }
    }
    (!words.is_empty()).then(|| words.join(" "))
}

/// The global network option of `podnet OPTION pod`, which the pod does not
/// use (issue 189): its proxy is `-x`.
fn pod_network_option(cli: &Cli) -> Option<&'static str> {
    if cli.proxy.is_some() {
        Some("--proxy")
    } else if cli.no_proxy {
        Some("--no-proxy")
    } else if cli.resolve.is_some() {
        Some("--resolve")
    } else if cli.ca_file.is_some() {
        Some("--ca-file")
    } else {
        None
    }
}

/// The arguments of the pod: what follows the word `pod` in `argv` (clap
/// can drop the first `--` of the trailing arguments).
fn pod_args_of(argv: &[String], parsed: &[String]) -> Vec<String> {
    let tail = &argv[argv.len().saturating_sub(parsed.len() + 1)..];
    if tail.first().map(String::as_str) == Some("--") && tail[1..] == *parsed {
        return tail.to_vec();
    }
    parsed.to_vec()
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Tunnel(args) => tunnel(args).await,
        Command::Serve(args) => serve(args).await,
        Command::Share(args) => share(args).await,
        Command::Connect(args) => connect(args).await,
        Command::Update(args) if args.rollback => {
            let path = std::env::current_exe()
                .and_then(|p| p.canonicalize())
                .context("finding this binary")?;
            let now = podnet::update::rollback(&path).fault(Fault::Unavailable)?;
            println!(
                "{}: {now} (put back from {})",
                path.display(),
                podnet::update::previous_of(&path).display()
            );
            Ok(())
        }
        Command::Update(args) => {
            use podnet::update::Outcome;
            // Issue 249: an empty tag asked the network, then exit 69.
            if let Some(tag) = args.version.as_deref() {
                let good = !tag.is_empty()
                    && tag
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
                if !good {
                    return Err(podnet::exit::fault(
                        Fault::Usage,
                        anyhow::anyhow!("--version {tag:?}: give a tag like v0.3.0-beta.11"),
                    ));
                }
            }
            match podnet::update::run(args.version.as_deref(), args.check, args.force)
                .await
                .fault(Fault::Unavailable)?
            {
                Outcome::UpToDate(tag) => println!("podnet {tag} is the newest release"),
                Outcome::Same(tag) => {
                    println!("podnet {tag} is installed; nothing to do (--force installs it again)")
                }
                Outcome::Available { current, tag } => {
                    println!("podnet {current}; release {tag} is available (podnet update)")
                }
                Outcome::Updated { from, to, path } => {
                    println!(
                        "podnet {from} -> {to}: {} (signature and SHA-256 checked)",
                        path.display()
                    )
                }
            }
            Ok(())
        }
        Command::Agent { command } => agent(command).await,
        Command::Ps { json } => instances_ps(json),
        Command::Stop { name, all, timeout } => instances_stop(name, all, timeout),
        Command::Logs {
            name,
            follow,
            lines,
        } => instances_logs(&name, follow, lines).await,
        Command::Wait { name, timeout } => {
            podnet::instances::check_name(&name)
                .map_err(|e| podnet::exit::fault(Fault::Usage, e))?;
            let dir = podnet::instances::lookup_dir();
            let doc = podnet::detach::wait_ready_record(
                &dir,
                &name,
                std::time::Duration::from_secs(timeout),
            )?;
            println!("{doc}");
            Ok(())
        }
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut cmd, "podnet", &mut script);
            match std::io::Write::write_all(&mut std::io::stdout(), &script) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                other => other.context("writing the completion script"),
            }
        }
        Command::Ports(args) => {
            let mut ports = podnet::ports::listening_ports();
            if args.probe {
                // Issue 119: a port in the LISTEN table can refuse each
                // connection.
                let (open, unreachable) = podnet::ports::probe(&ports).await;
                ports = open;
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({ "ports": ports, "probed": true, "unreachable": unreachable })
                    );
                    return Ok(());
                }
                for port in &unreachable {
                    eprintln!("podnet: ports: {port} listens, and refuses a connection");
                }
            }
            if args.json {
                println!(
                    "{}",
                    podnet::status::stamped(serde_json::json!({ "ports": ports }))
                );
            } else {
                for port in ports {
                    println!("{port}");
                }
            }
            Ok(())
        }
        Command::Qr(args) => {
            // Issue 95: a text over the limit is a usage mistake; a text
            // that is not a URL gets a warning (a QR code of any text is
            // valid).
            if args.url.len() > podnet::qr::MAX_BYTES {
                return Err(podnet::exit::fault(
                    Fault::Usage,
                    anyhow::anyhow!(
                        "the text is {} bytes; a QR code holds at most {} bytes",
                        args.url.len(),
                        podnet::qr::MAX_BYTES
                    ),
                ));
            }
            if !podnet::qr::looks_like_url(&args.url) {
                eprintln!(
                    "podnet: warning: {:?} is not a URL (scheme://...); the QR code holds the text as it is",
                    args.url
                );
            }
            print!("{}", podnet::qr::render_terminal(&args.url)?);
            Ok(())
        }
        Command::Demo(args) => demo(args).await,
        Command::Net(args) => net(args).await,
        Command::Warp(args) => warp(*args).await,
        Command::Relay(args) => relay(args).await,
        Command::Pod { .. } => Err(podnet::exit::fault(
            Fault::Usage,
            anyhow::anyhow!("podnet pod runs before the runtime"),
        )),
        Command::Man(args) => {
            use clap::CommandFactory;
            let manual = podnet::manual::model::build(Cli::command());
            let request = podnet::manual::Request {
                section: (!args.section.is_empty()).then(|| args.section.join(" ")),
                no_pager: args.no_pager,
                roff: args.roff,
                json: args.json,
            };
            let text = podnet::manual::body(&manual, &request)
                .map_err(|e| podnet::exit::fault(podnet::exit::Fault::Usage, anyhow::anyhow!(e)))?;
            let paged = !request.roff && !request.json;
            podnet::manual::pager::show(&text, request.no_pager || !paged)?;
            Ok(())
        }
        Command::Doctor(args) if args.agent => {
            let report = podnet::agent::run(Duration::from_secs(args.timeout.max(3))).await;
            if args.json {
                println!(
                    "{}",
                    podnet::status::stamped(serde_json::to_value(&report)?)
                );
            } else {
                print!("{}", podnet::agent::text(&report));
            }
            Ok(())
        }
        Command::Doctor(args) => {
            podnet::udp::check_edge_env()?;
            podnet::udp::Choice::from_env()?;
            let report = podnet::doctor::run(podnet::doctor::Options {
                samples: args.samples as usize,
                timeout: Duration::from_secs(args.timeout),
                ..podnet::doctor::Options::default()
            })
            .await;
            if args.json {
                println!("{}", report.to_json());
            } else {
                print!("{}", report.text());
            }
            if !report.ok() {
                bail!("no leg can work on this host; the doctor gives the reason for each");
            }
            Ok(())
        }
        Command::Autostart(args) => autostart(args.command),
        Command::Status { .. } => {
            println!("{}", podnet::status::document());
            Ok(())
        }
        Command::BugReport { doctor } => {
            let report = if doctor {
                let options = podnet::doctor::Options {
                    samples: 3,
                    ..Default::default()
                };
                Some(podnet::doctor::run(options).await.to_json())
            } else {
                None
            };
            print!("{}", podnet::bug_report::text(report.as_ref()));
            Ok(())
        }
    }
}

async fn tunnel(args: TunnelArgs) -> Result<()> {
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
async fn preflight(config: &Config, show: Show) -> Result<()> {
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

/// The arguments of `autostart add` (issue 117): a first argument `podnet`
/// (or a path to it) is dropped, and the rest must parse as a podnet command.
/// Before, `-- podnet warp up` was kept as `podnet podnet warp up`, which failed
/// at each boot with no message.
fn autostart_args(mut args: Vec<String>) -> Result<Vec<String>> {
    let is_podnet = |arg: &str| std::path::Path::new(arg).file_name() == Some("podnet".as_ref());
    if args.first().is_some_and(|a| is_podnet(a)) {
        args.remove(0);
    }
    // Issue 265: an entry with --detach forked at each boot, and its
    // service manager saw the parent end.
    let kept = podnet::detach::without_start_options(&args);
    if kept != args {
        eprintln!("podnet: autostart add: --detach, --name, --ready-timeout and --no-restart are removed; the entry runs in the foreground");
        args = kept;
    }
    if let Err(err) = Cli::try_parse_from(std::iter::once("podnet".to_string()).chain(args.clone()))
    {
        let first = err.to_string();
        let first = first
            .lines()
            .next()
            .unwrap_or_default()
            .trim_start_matches("error: ");
        return Err(podnet::exit::fault(
            Fault::Usage,
            anyhow::anyhow!(
                "autostart add: `podnet {}` is not a podnet command: {first}",
                args.join(" ")
            ),
        ));
    }
    Ok(args)
}

fn autostart(command: AutostartCommand) -> Result<()> {
    use podnet::autostart;
    match command {
        AutostartCommand::Add { name, args, from } => {
            let (args, secrets) = match from {
                Some(instance) => {
                    let dir = podnet::instances::run_dir().fault(Fault::Config)?;
                    let record = podnet::instances::read(&dir, &instance).ok_or_else(|| {
                        podnet::exit::fault(
                            Fault::Usage,
                            anyhow::anyhow!("no detached instance {instance} (podnet ps)"),
                        )
                    })?;
                    // Issue 265: the record has no secret; NAME.secrets has them.
                    (
                        record.args,
                        podnet::instances::read_secrets(&dir, &instance),
                    )
                }
                None => (args, Vec::new()),
            };
            let args = autostart_args(args)?;
            let added = autostart::add(&name, &args, &secrets, autostart::PROGRAM_LIMIT)?;
            println!(
                "podnet: autostart {name} added ({}): {}",
                added.way.name(),
                added.detail
            );
            Ok(())
        }
        AutostartCommand::Remove { name } => {
            for line in autostart::remove(&name, autostart::PROGRAM_LIMIT)? {
                println!("podnet: {line}");
            }
            Ok(())
        }
        AutostartCommand::List => {
            for name in autostart::list()? {
                println!("{name}");
            }
            Ok(())
        }
        AutostartCommand::Run { name, dir } => {
            use std::os::unix::process::CommandExt;
            let (args, vars) = autostart::load(&name, &dir).fault(Fault::Config)?;
            let exe = std::env::current_exe().context("the path of this binary")?;
            let err = std::process::Command::new(exe)
                .args(&args)
                .envs(vars)
                .exec();
            Err(anyhow::anyhow!("starting podnet {}: {err}", args.join(" ")))
        }
    }
}

/// Split `host:port`, `[v6]:port` or `ip:port` into the host and the port.
/// A front door of `warp scan` (issue 139): IP or IP:PORT, port 443.
fn parse_door(spec: &str) -> Result<std::net::SocketAddr> {
    let spec = spec.trim();
    if let Ok(addr) = spec.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    let ip: std::net::IpAddr = spec
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .with_context(|| format!("{spec:?} is not IP or IP:PORT"))?;
    Ok(std::net::SocketAddr::new(ip, 443))
}

/// One line of an exit (issue 147): `AMS NL 104.28.1.2 warp=on 42 ms`.
fn exit_line(exit: &podnet::warp::exit::Exit) -> String {
    format!(
        "{} {} {} warp={} {} ms",
        exit.colo,
        exit.loc.as_deref().unwrap_or("-"),
        exit.ip.as_deref().unwrap_or("-"),
        exit.warp.as_deref().unwrap_or("-"),
        exit.rtt.as_millis()
    )
}

fn split_host_port(spec: &str) -> Result<(String, u16)> {
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

async fn connect(args: ConnectArgs) -> Result<()> {
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
            podnet::proxy_auth::Credentials::load(user, file)
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
struct SocketFile {
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
fn unix_listener(
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

async fn serve(args: ServeArgs) -> Result<()> {
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
fn share_mode(args: &ShareArgs) -> Result<ModeArg> {
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

async fn share(args: ShareArgs) -> Result<()> {
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

async fn demo(args: DemoArgs) -> Result<()> {
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

async fn run_tunnel(
    config: Config,
    show: Show,
    run_for: Option<u64>,
    controls: Vec<Arc<ShareControl>>,
) -> Result<()> {
    let verify = config.verify;
    let handle = Tunnel::builder().config(config).build()?.start().await?;
    announce(&handle, show)?;
    // Issue 179: --run-for also ends the verify.
    let deadline = deadline_of(run_for);
    if verify {
        if let Some(url) = handle.url() {
            // Issue 205: the 401 of --auth-user is the normal answer.
            let accepted: &[u16] = match (show.root_404, show.auth) {
                (true, true) => &[404, 401],
                (true, false) => &[404],
                (false, true) => &[401],
                (false, false) => &[],
            };
            let Some(checked) =
                until_stop_or(deadline, handle.verify_accepting(url, None, accepted)).await
            else {
                handle.shutdown().await;
                return Ok(());
            };
            let checked = match checked {
                Ok(c) => c,
                Err(err) => {
                    // The IPv6-only kit, 0005: the edge connections end
                    // cleanly, not at the exit of the process.
                    handle.shutdown().await;
                    return Err(err);
                }
            };
            verified(show, url, checked.dns);
        }
    }
    podnet::detach::ready(tunnel_doc(&handle, handle.url(), verify));
    serve_until(&handle, wait(deadline, controls)).await?;
    handle.shutdown().await;
    Ok(())
}

async fn run_share(
    config: Config,
    show: Show,
    run_for: Option<u64>,
    pin: Option<String>,
    path: String,
    idle_secs: u64,
) -> Result<()> {
    let verify = config.verify;
    let handle = Tunnel::builder().config(config).build()?.start().await?;
    let deadline = deadline_of(run_for);
    let base = handle
        .url()
        .unwrap_or("https://<your-named-tunnel-hostname>")
        .to_string();
    let public = format!("{}{}", base.trim_end_matches('/'), path);
    // Issue 101: from the ready line on, a stop signal is a clean stop.
    podnet::detach::arm_stop();
    if show.json {
        println!(
            "{}",
            serde_json::json!({
                "event": "ready",
                "url": public,
                "tunnel_id": handle.tunnel_id().to_string(),
                "locations": handle.locations(),
                "leg": handle.leg(),
                "pin": pin,
            })
        );
    } else {
        println!();
        println!("  podnet: session  {public}");
        if let Some(pin) = &pin {
            println!("  podnet: PIN      {pin}");
        }
        println!(
            "  podnet: edge     {} ({})",
            handle.locations().join(", "),
            handle.leg()
        );
        println!();
    }
    if show.qr {
        print!("{}", podnet::qr::render_terminal(&public)?);
    }
    if verify && handle.url().is_some() {
        let Some(check) = until_stop_or(deadline, handle.verify_url(&public, None)).await else {
            handle.shutdown().await;
            return Ok(());
        };
        let check = match check {
            Ok(c) => c,
            Err(err) => {
                handle.shutdown().await;
                return Err(err);
            }
        };
        verified(show, &public, check.dns);
    }
    let mut doc = tunnel_doc(&handle, Some(&public), verify);
    doc["pin"] = pin.clone().into();
    podnet::detach::ready(doc);
    let controls = handle.share_controls();
    serve_until(&handle, wait_with_idle(deadline, controls, idle_secs)).await?;
    handle.shutdown().await;
    Ok(())
}

async fn run_demo(
    config: Config,
    show: Show,
    run_for: Option<u64>,
    exit_on_verify: bool,
) -> Result<()> {
    let handle = Tunnel::builder().config(config).build()?.start().await?;
    announce(&handle, show)?;
    let deadline = deadline_of(run_for);
    if exit_on_verify {
        let Some(check) =
            until_stop_or(deadline, handle.verify(Some("Hello, world! (podnet)"))).await
        else {
            handle.shutdown().await;
            return Ok(());
        };
        let check = match check {
            Ok(c) => c,
            Err(err) => {
                handle.shutdown().await;
                return Err(err);
            }
        };
        if show.json {
            let dns = check.map(|c| c.dns).unwrap_or("none");
            verified(show, handle.url().unwrap_or(""), dns);
        } else {
            println!(
                "  podnet: PROOF   {} -> HTTP 200 (built-in hello world)",
                handle.url().unwrap_or("")
            );
        }
        handle.shutdown().await;
        return Ok(());
    }
    let Some(check) = until_stop_or(deadline, handle.verify(Some("Hello, world! (podnet)"))).await
    else {
        handle.shutdown().await;
        return Ok(());
    };
    if let Err(err) = check {
        handle.shutdown().await;
        return Err(err);
    }
    podnet::detach::ready(tunnel_doc(&handle, handle.url(), true));
    serve_until(&handle, wait(deadline, vec![])).await?;
    handle.shutdown().await;
    Ok(())
}

/// Serve until `done`, or until each edge leg has stopped for a cause: then
/// the command fails with the cause (exit 69).
async fn serve_until(
    handle: &podnet::TunnelHandle,
    done: impl std::future::Future<Output = ()>,
) -> Result<()> {
    tokio::select! {
        _ = done => Ok(()),
        reason = handle.stopped() => Err(podnet::exit::fault(
            Fault::Unavailable,
            anyhow::anyhow!("each edge connection stopped: {reason}"),
        )),
    }
}

/// The ready document of a tunnel for --detach.
fn tunnel_doc(
    handle: &podnet::TunnelHandle,
    url: Option<&str>,
    verified: bool,
) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "url": url,
        "verified": verified && url.is_some(),
        "tunnel_id": handle.tunnel_id().to_string(),
        "locations": handle.locations(),
        "leg": handle.leg(),
    });
    // Issue 203: the endpoint for podnet connect.
    if let Some(path) = handle.forward_path() {
        doc["forward"] = url.and_then(|u| podnet::ws::forward_url(u, path)).into();
        doc["forward_path"] = path.into();
    }
    doc
}

/// The ready document of a listener for --detach.
fn listen_doc(listen: &podnet::vnet::proxy::ProxyListen) -> serde_json::Value {
    serde_json::json!({ "listen": listen.to_string() })
}

/// `podnet relay` (issue 88).
async fn relay(args: RelayArgs) -> Result<()> {
    use podnet::relay_reverse as reverse;
    let relay = podnet::ws_relay::Relay::new(&args.relay, None).fault(Fault::Usage)?;
    let dir = reverse::pairs_dir()?;
    match args.command {
        RelayCommand::Pair { json } => {
            let pair = reverse::pair(&relay).await.fault(Fault::Unavailable)?;
            podnet::report::hide(&pair.node_token);
            podnet::report::hide(&pair.stop_token);
            let path = reverse::save(&pair, &dir)?;
            let left = pair.left().as_secs();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "name": pair.name,
                        "connect_token": pair.connect_token,
                        "expires": pair.expires,
                        "relay": pair.relay,
                        "file": path,
                    })
                );
            } else {
                println!("name        {}", pair.name);
                println!("expires     in {} h {} min", left / 3600, left % 3600 / 60);
                println!("file        {} (node token, mode 0600)", path.display());
                println!("connect     {}", pair.connect_token);
                println!();
                println!(
                    "On this host: podnet relay node {} --to 127.0.0.1:22 --detach",
                    pair.name
                );
                println!("Give the connect token to the operator over a channel that you trust. The operator:");
                println!(
                    "  {}=<connect token> ssh -o ProxyCommand='podnet relay connect {}' USER@{}",
                    podnet::relay_reverse::CONNECT_TOKEN_VARIABLE,
                    pair.name,
                    pair.name
                );
            }
            Ok(())
        }
        RelayCommand::Node { pair, to, .. } => {
            let target = reverse::Target::parse(&to).fault(Fault::Usage)?;
            // With no pair name, the node takes the next stored pair at
            // the expiry.
            let follow = pair.is_none().then_some(dir.as_path());
            let pair = reverse::load(&dir, pair.as_deref())?;
            podnet::report::hide(&pair.node_token);
            podnet::ws_relay::Relay::single(&pair.relay, None).fault(Fault::Config)?;
            tokio::select! {
                result = reverse::run_node(follow, pair, &target) => result,
                _ = shutdown_signal() => Ok(()),
            }
        }
        RelayCommand::Connect {
            name,
            token,
            listen,
            ..
        } => {
            let (token, relay) = match token {
                Some(token) => (token, relay),
                None => {
                    let pair = reverse::load(&dir, Some(&name))
                        .context("no --token and no local pair file")?;
                    let relay =
                        podnet::ws_relay::Relay::new(&pair.relay, None).fault(Fault::Config)?;
                    (pair.connect_token, relay)
                }
            };
            podnet::report::hide(&token);
            match listen {
                None => {
                    reverse::connect(
                        &relay,
                        &name,
                        &token,
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                    )
                    .await?;
                    // stdin of tokio blocks the shutdown of the runtime.
                    std::process::exit(0);
                }
                Some(listen) => {
                    let listen =
                        podnet::vnet::proxy::ProxyListen::parse(&listen).fault(Fault::Usage)?;
                    let relay = Arc::new(relay);
                    let (name, token) = (Arc::new(name), Arc::new(token));
                    let serve = |io: Box<dyn RelayIo>| {
                        let (relay, name, token) = (relay.clone(), name.clone(), token.clone());
                        tokio::spawn(async move {
                            let (read, write) = tokio::io::split(io);
                            if let Err(err) =
                                reverse::connect(&relay, &name, &token, read, write).await
                            {
                                tracing::warn!(error = %format!("{err:#}"), "a relay session failed");
                            }
                        });
                    };
                    match listen {
                        podnet::vnet::proxy::ProxyListen::Tcp(addr) => {
                            let listener = tokio::net::TcpListener::bind(addr).await?;
                            println!(
                                "podnet: relay    {} -> tcp://{}",
                                name,
                                listener.local_addr()?
                            );
                            podnet::detach::arm_stop();
                            loop {
                                tokio::select! {
                                    accepted = listener.accept() => serve(Box::new(accepted?.0)),
                                    _ = shutdown_signal() => return Ok(()),
                                }
                            }
                        }
                        podnet::vnet::proxy::ProxyListen::Unix(path) => {
                            podnet::net::claim_socket_path(&path, false)?;
                            let listener = podnet_netns::listen::bind_private(&path)?;
                            println!("podnet: relay    {} -> unix:{}", name, path.display());
                            podnet::detach::arm_stop();
                            loop {
                                tokio::select! {
                                    accepted = listener.accept() => serve(Box::new(accepted?.0)),
                                    _ = shutdown_signal() => return Ok(()),
                                }
                            }
                        }
                    }
                }
            }
        }
        RelayCommand::Stop { name } => {
            let pair = reverse::load(&dir, Some(&name))?;
            // Issue 119: the local node of the pair stops first, so that it
            // does not connect again.
            if let Ok(run) = podnet::instances::run_dir() {
                let records: Vec<_> = podnet::instances::list(&run)
                    .into_iter()
                    .filter(|e| e.alive)
                    .map(|e| e.record)
                    .collect();
                for instance in reverse::instances_of_pair(&records, &name) {
                    podnet::detach::stop(&run, &instance, Duration::from_secs(10))?;
                    println!("podnet: relay    stopped the node instance {instance}");
                }
            }
            let relay = podnet::ws_relay::Relay::new(&pair.relay, None).fault(Fault::Config)?;
            reverse::stop(&relay, &pair)
                .await
                .fault(Fault::Unavailable)?;
            let _ = std::fs::remove_file(dir.join(format!("{name}.json")));
            println!("podnet: relay    {name} stopped");
            Ok(())
        }
    }
}

trait RelayIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> RelayIo for T {}

/// The WARP+ line of `warp status` (issue 95). The field `warp_plus` of
/// the API is true also for a free account; WARP+ is an account type
/// other than free, or premium data.
/// A license key of the command line: one character or more (issue 178:
/// an empty key went to the API).
fn non_empty_key(value: &str) -> std::result::Result<String, String> {
    let key = value.trim();
    if key.is_empty() {
        return Err("give a license key".into());
    }
    Ok(key.to_string())
}

/// A JSON value for a text line: a string with no quotes (issue 178).
fn plain_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "-".into(),
        other => other.to_string(),
    }
}

fn warp_plus_label(account: &serde_json::Value) -> &'static str {
    let kind = account
        .get("account_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let premium = account
        .get("premium_data")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if premium > 0 || !(kind.is_empty() || kind == "free") {
        "yes"
    } else {
        "no"
    }
}

/// After a fetch of the public URL: one JSON line with --json. `dns` is
/// the step of the resolver chain that resolves the name (issue 94).
fn verified(show: Show, url: &str, dns: &str) {
    if show.json {
        println!(
            "{}",
            serde_json::json!({"event": "verified", "url": url, "dns": dns})
        );
    }
}

fn announce(handle: &podnet::TunnelHandle, show: Show) -> Result<()> {
    // Issue 101: from the ready line on, a stop signal is a clean stop
    // (before, only after the verify).
    podnet::detach::arm_stop();
    if show.json {
        let mut doc = serde_json::json!({
            "event": "ready",
            "url": handle.url(),
            "tunnel_id": handle.tunnel_id().to_string(),
            "locations": handle.locations(),
            "leg": handle.leg(),
        });
        if let Some(path) = handle.forward_path() {
            doc["forward"] = handle.forward().into();
            doc["forward_path"] = path.into();
        }
        let doc = podnet::status::stamped(doc);
        println!("{doc}");
    } else {
        announce_text(handle);
    }
    if show.qr {
        match handle.url() {
            Some(url) => print!("{}", podnet::qr::render_terminal(url)?),
            None => tracing::warn!(
                "--qr: a named tunnel has its hostname in Cloudflare, and podnet does not know it; no QR code"
            ),
        }
    }
    Ok(())
}

fn announce_text(handle: &podnet::TunnelHandle) {
    println!();
    match handle.url() {
        Some(url) => println!("  podnet: public   {url}"),
        None => println!(
            "  podnet: tunnel   {} (named; hostname configured in Cloudflare)",
            handle.tunnel_id()
        ),
    }
    println!(
        "  podnet: edge     {} ({})",
        handle.locations().join(", "),
        handle.leg()
    );
    match (handle.forward(), handle.forward_path()) {
        (Some(url), _) => println!("  podnet: forward  {url} (podnet connect {url} -L ...)"),
        (None, Some(path)) => println!("  podnet: forward  path {path} of the hostname"),
        _ => {}
    }
    println!();
}

/// Wait for a stop signal, the deadline of `--run-for`, or a stop of a
/// share (`--stop-after`). Each end but a signal is a planned end (issue
/// 195): a supervisor does not start the instance again.
async fn wait(deadline: Option<tokio::time::Instant>, controls: Vec<Arc<ShareControl>>) {
    tokio::select! {
        _ = shutdown_signal() => {}
        _ = sleep_until_opt(deadline) => podnet::detach::planned_end(),
        _ = wait_controls(controls) => podnet::detach::planned_end(),
    }
}

/// Ready when a control has no activity for `idle_secs` (never for 0).
///
/// Issue 271: the idle clock starts at the call, when the session serves,
/// not when the session was built (before the provisioning).
fn idle_watch(
    controls: Vec<Arc<ShareControl>>,
    idle_secs: u64,
) -> impl std::future::Future<Output = ()> {
    for control in &controls {
        control.touch();
    }
    let idle = (idle_secs > 0).then(|| Duration::from_secs(idle_secs));
    async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Some(idle) = idle {
                if controls.iter().any(|c| c.idle_for() >= idle) {
                    return;
                }
            }
        }
    }
}

/// [`wait`] that also ends after `idle_secs` with no request (a planned
/// end too).
async fn wait_with_idle(
    deadline: Option<tokio::time::Instant>,
    controls: Vec<Arc<ShareControl>>,
    idle_secs: u64,
) {
    let watch = idle_watch(controls.clone(), idle_secs);
    tokio::select! {
        _ = shutdown_signal() => {}
        _ = sleep_until_opt(deadline) => podnet::detach::planned_end(),
        _ = wait_controls(controls) => podnet::detach::planned_end(),
        _ = watch => podnet::detach::planned_end(),
    }
}

async fn wait_controls(controls: Vec<Arc<ShareControl>>) {
    if controls.is_empty() {
        std::future::pending::<()>().await;
    }
    let mut set = tokio::task::JoinSet::new();
    for control in controls {
        set.spawn(async move { control.wait_stop().await });
    }
    let _ = set.join_next().await;
}

// Keep ShareMode referenced for future CLI flags.
#[allow(dead_code)]
fn _mode(mode: ShareMode) -> ShareMode {
    mode
}

// ── userspace virtual networking ─────────────────────────────────────────────

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
struct NetArgs {
    #[command(subcommand)]
    command: NetCommand,
}

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
struct WarpArgs {
    /// The file that keeps the device and its MASQUE key, so that each run
    /// uses the same device. Default: warp.json in the state directory
    /// (see PODNET_STATE_DIR in podnet man environment).
    #[arg(long, value_name = "PATH", global = true)]
    identity: Option<PathBuf>,
    /// Register a new device for this run only, and do not save it.
    #[arg(long, global = true, conflicts_with = "identity")]
    ephemeral: bool,
    /// A resolver of the DNS inside the tunnel, in place of 1.1.1.1:53:
    /// IP[:PORT] (UDP), or tls://IP[:PORT][#NAME] (DNS over TLS, port 853;
    /// the certificate must have NAME, or the IP address). Repeatable; the
    /// first that answers wins.
    #[arg(
        long,
        value_name = "SPEC",
        global = true,
        env = "PODNET_WARP_RESOLVERS",
        hide_env_values = true,
        value_delimiter = ','
    )]
    resolver: Vec<String>,
    /// The name of a new device in the dashboard (1 to 64 characters).
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        env = "PODNET_WARP_DEVICE_NAME",
        hide_env_values = true
    )]
    device_name: Option<String>,
    /// The model that a new device declares (default PC).
    #[arg(
        long,
        value_name = "MODEL",
        global = true,
        env = "PODNET_WARP_DEVICE_MODEL",
        hide_env_values = true
    )]
    device_model: Option<String>,
    /// The locale that a new device declares, as en_US (default en_US).
    #[arg(
        long,
        value_name = "LOCALE",
        global = true,
        env = "PODNET_WARP_DEVICE_LOCALE",
        hide_env_values = true
    )]
    device_locale: Option<String>,
    /// Split the TLS ClientHello of the MASQUE connection into records:
    /// record (records of --fragment-size bytes) or sni (the first record
    /// ends in the server name). off: one record (the default).
    #[arg(
        long,
        value_name = "MODE",
        global = true,
        env = "PODNET_WARP_FRAGMENT", hide_env_values = true,
        num_args = 0..=1,
        default_missing_value = "record"
    )]
    fragment_client_hello: Option<String>,
    /// The bytes of handshake data in each record of
    /// --fragment-client-hello: N or MIN-MAX, 16 to 4096 (default 64-160).
    #[arg(
        long,
        value_name = "MIN[-MAX]",
        global = true,
        env = "PODNET_WARP_FRAGMENT_SIZE",
        hide_env_values = true
    )]
    fragment_size: Option<String>,
    /// The congestion controller of the TCP connections of the userspace
    /// stack (what the stack sends): none (the default), reno or cubic.
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        env = "PODNET_WARP_CC",
        hide_env_values = true
    )]
    cc: Option<String>,
    /// Close each MASQUE session on purpose at this age, and open a new one
    /// (a new egress address). The TCP flows of the old session end.
    /// Default: off. Not for warp tun.
    #[arg(
        long,
        value_name = "SECS",
        global = true,
        env = "PODNET_WARP_SESSION_MAX_AGE", hide_env_values = true,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    session_max_age: Option<u64>,
    /// Do not try the WebSocket relay (--relay, PODNET_RELAY) when the direct
    /// MASQUE path fails. Without it, podnet tries the relay: the TLS to the
    /// front door stays end to end in the WebSocket.
    #[arg(long, global = true)]
    no_relay: bool,
    /// The MASQUE front door (IP:PORT) in place of the one of the device.
    #[arg(long, value_name = "IP:PORT", global = true)]
    masque_endpoint: Option<std::net::SocketAddr>,
    /// The TLS name of the MASQUE front door in place of
    /// consumer-masque.cloudflareclient.com.
    #[arg(long, value_name = "NAME", global = true)]
    masque_sni: Option<String>,
    /// The transport of the MASQUE session: h2 (HTTP/2 on TCP 443, the
    /// default) or h3 (HTTP/3 on UDP 443: each packet is a QUIC datagram;
    /// no proxy and no relay).
    #[arg(
        long,
        value_name = "PROTOCOL",
        global = true,
        env = "PODNET_WARP_MASQUE_TRANSPORT", hide_env_values = true,
        value_parser = ["h2", "h3"]
    )]
    masque_transport: Option<String>,
    /// The leg of the tunnel: masque (the default) or wireguard (UDP to the
    /// WireGuard front door, with the device of `podnet warp export`, which
    /// podnet registers when the file has none).
    #[arg(
        long,
        value_name = "TRANSPORT",
        global = true,
        env = "PODNET_WARP_TRANSPORT", hide_env_values = true,
        value_parser = ["masque", "wireguard"]
    )]
    transport: Option<String>,
    /// The WireGuard front door (IP:PORT) in place of the one of the
    /// device record (port 2408).
    #[arg(
        long,
        value_name = "IP:PORT",
        global = true,
        env = "PODNET_WARP_WG_ENDPOINT",
        hide_env_values = true
    )]
    wireguard_endpoint: Option<std::net::SocketAddr>,
    /// wg: a second WireGuard device inside the tunnel (its own device in
    /// warp-carry.json of the state directory); the tools use its stack.
    /// With --transport wireguard, both hops are WireGuard.
    #[arg(
        long,
        value_name = "CARRY",
        global = true,
        env = "PODNET_WARP_CARRY", hide_env_values = true,
        value_parser = ["none", "wg"]
    )]
    carry: Option<String>,
    /// The front door (IP:PORT) of the carried device in place of the one
    /// of its record.
    #[arg(
        long,
        value_name = "IP:PORT",
        global = true,
        env = "PODNET_WARP_CARRY_ENDPOINT",
        hide_env_values = true
    )]
    carry_endpoint: Option<std::net::SocketAddr>,

    #[command(subcommand)]
    command: WarpCommand,
}

#[derive(Subcommand, Debug)]
enum WarpCommand {
    /// Register a device (or load the saved one) and print it.
    Register,
    /// Print the device and the account (type, WARP+ state, quota).
    Status {
        /// Print the account record as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Attach a WARP+ license key to the device.
    License {
        /// The license key, or - to read it from stdin (it is then not on
        /// the command line).
        #[arg(value_parser = non_empty_key)]
        key: String,
    },
    /// Make a new MASQUE key and enrol it. The old key stops working.
    Rotate,
    /// Remove the device from the WARP service and delete the saved file.
    Delete,
    /// Open the tunnel and test TCP connects through it. Exit 69 when a
    /// target fails.
    Probe {
        /// A TCP destination to reach through the tunnel, host:port.
        #[arg(long, value_delimiter = ',')]
        target: Vec<String>,
    },
    /// Open the tunnel and print its exit: the data center (colo), the
    /// country and the address that a destination sees (from
    /// http://1.1.1.1/cdn-cgi/trace), and the IPv6 egress address (the
    /// trace at 2606:4700:4700::1111, else the TXT of whoami.cloudflare).
    /// Exit 69 when there is no answer.
    Exit {
        /// Print one JSON object.
        #[arg(long)]
        json: bool,
        /// Do not ask for the IPv6 egress address.
        #[arg(long)]
        no_ipv6: bool,
    },
    /// Print a WireGuard config of a new WARP device (wg-quick or JSON),
    /// for other clients. The device and its private key are in
    /// warp-wg.json of the state directory, not in warp.json. Its data
    /// path is WireGuard on UDP (port 2408), not MASQUE on TCP 443. The
    /// output holds the private key: a terminal is refused with no --out
    /// (--out - prints it), and a redirected file becomes mode 0600.
    Export {
        /// wg-quick or json.
        #[arg(long, default_value = "wg-quick", value_parser = ["wg-quick", "json"])]
        format: String,
        /// Write the config to this file (mode 0600) in place of stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// The file of the exported device (default: warp-wg.json in the
        /// state directory).
        #[arg(long, value_name = "FILE")]
        export_identity: Option<PathBuf>,
        /// The Endpoint of the config, HOST:PORT (default: the endpoint of
        /// the device record, port 2408).
        #[arg(long, value_name = "HOST:PORT")]
        endpoint: Option<String>,
        /// PersistentKeepalive in seconds; 0 writes no line.
        #[arg(long, value_name = "SECS", default_value_t = 25)]
        keepalive: u16,
        /// Register a new device even when the file has one.
        #[arg(long, conflicts_with = "delete")]
        new: bool,
        /// Remove the exported device from the service and delete its file.
        #[arg(long)]
        delete: bool,
    },
    /// Measure front doors of WARP: the TCP connect and the TLS handshake
    /// with the pinned key, for each --candidate and the front doors of the
    /// device record. The fastest goes first. Exit 69 when none answers.
    Scan {
        /// A front door to measure: IP or IP:PORT (port 443); an IPv6
        /// address with a port is in brackets. Repeatable.
        #[arg(long, value_name = "IP[:PORT]", value_delimiter = ',')]
        candidate: Vec<String>,
        /// The time limit of each front door, in milliseconds (100 to
        /// 60000).
        #[arg(long, value_name = "MS", default_value_t = 3000,
              value_parser = clap::value_parser!(u64).range(100..=60_000))]
        timeout_ms: u64,
        /// Print one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Forward local listeners through WARP (as ssh -L): each connection to
    /// LISTEN goes through the tunnel to HOST:PORT.
    Forward {
        /// LISTEN=HOST:PORT. LISTEN is PORT (on 127.0.0.1), ADDR:PORT,
        /// tcp://ADDR:PORT or unix:/PATH. HOST is resolved inside the
        /// tunnel; a tunnel: prefix is accepted. Repeatable.
        #[arg(
            short = 'L',
            long = "local",
            value_name = "LISTEN=HOST:PORT",
            required = true,
            env = "PODNET_WARP_FORWARD",
            hide_env_values = true,
            value_delimiter = ','
        )]
        local: Vec<String>,
        /// Exit 69 when any listener does not start.
        #[arg(long)]
        strict: bool,
        /// The most connections of each listener at the same time. 0: no
        /// limit.
        #[arg(long, value_name = "N", default_value_t = 32)]
        max_connections: usize,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a local SOCKS5 and HTTP CONNECT proxy whose traffic goes through
    /// WARP (the proxy mode of the WARP client).
    Proxy {
        /// Where to accept clients: tcp://host:port or unix:/path.
        /// Repeatable: each listener serves the same WARP session.
        /// A listener that the host refuses is reported, and the proxy
        /// starts with the others; with none, the exit code is 69.
        #[arg(long, default_value = "tcp://127.0.0.1:40000")]
        listen: Vec<String>,
        /// Exit 69 when any listener does not start.
        #[arg(long)]
        strict: bool,
        /// The most clients at the same time; a client over it is closed
        /// at once, with a warning in the log. 0: no limit.
        #[arg(long, value_name = "N", default_value_t = 0)]
        max_connections: u64,
        /// Also answer DNS on this UDP address (for example
        /// 127.0.0.1:5353): each query goes through WARP to 1.1.1.1.
        #[arg(long, value_name = "ADDR")]
        dns: Option<std::net::SocketAddr>,
        /// Clients must give this user (SOCKS5 user and password, or HTTP
        /// Basic), with the password of --proxy-password-file.
        #[arg(
            long,
            value_name = "USER",
            env = "PODNET_PROXY_USER",
            hide_env_values = true,
            requires = "proxy_password_file"
        )]
        proxy_user: Option<String>,
        /// The file with the password of --proxy-user on its first line
        /// (mode 0600).
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_PROXY_PASSWORD_FILE",
            hide_env_values = true,
            requires = "proxy_user"
        )]
        proxy_password_file: Option<PathBuf>,
        /// A rule for the destinations: KIND:VALUE=ACTION. KIND is domain
        /// (NAME, or .NAME for the name and the names under it) or cidr
        /// (ADDR/PREFIX, IPv4 or IPv6, or @FILE with one prefix on each
        /// line). ACTION is tunnel, direct (from the host, with no proxy)
        /// or reject. The first rule that matches wins. Repeatable.
        #[arg(
            short = 'r',
            long = "rule",
            value_name = "KIND:VALUE=ACTION",
            env = "PODNET_WARP_RULES",
            hide_env_values = true,
            value_delimiter = ','
        )]
        rules: Vec<String>,
        /// Serve each TCP client on its own HTTP/3 CONNECT stream to the L4
        /// door of WARP (UDP 443), with no IP stack. UDP is not served. The
        /// rules (-r, --rules-file, --rule-default) apply; an address rule
        /// (cidr:) decides an address, not a name, as no name is resolved.
        #[arg(long, env = "PODNET_WARP_L4", hide_env_values = true, conflicts_with_all = ["dns", "listen_identity"])]
        l4: bool,
        /// The TLS name of the L4 door.
        #[arg(long, value_name = "NAME", default_value = podnet::warp::l4::L4_SNI, requires = "l4")]
        l4_sni: String,
        /// LISTEN=PATH: a listener whose clients use the WARP device of the
        /// identity file PATH (made when it does not exist: that registers
        /// a new device), with a session of its own. The --listen listeners
        /// use --identity. Repeatable; each PATH once.
        #[arg(long, value_name = "LISTEN=PATH")]
        listen_identity: Vec<String>,
        /// A file with one rule on each line (# starts a comment), after
        /// the --rule rules. podnet reads it again when it changes.
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_WARP_RULES_FILE",
            hide_env_values = true
        )]
        rules_file: Option<PathBuf>,
        /// The action when no rule matches.
        #[arg(long, value_name = "ACTION", default_value = "tunnel")]
        rule_default: String,
        /// Check the rules, print them, and exit (0, or 64 for a bad rule).
        #[arg(long)]
        check: bool,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Start WARP for this sandbox, in the background: a
    /// detached warp proxy on 127.0.0.1:PORT and on a unix socket, and an
    /// env file with the proxy variables. Later shells join it with
    /// `eval "$(podnet warp env)"`, `podnet warp exec -- CMD`, `podnet warp
    /// shell`, or --persist.
    Up {
        /// The TCP port of the proxy on 127.0.0.1.
        #[arg(long, default_value_t = 40000)]
        port: u16,
        /// Add a marked block to ~/.bashrc and ~/.profile: each new shell
        /// loads the env file, and an interactive shell runs under the pod
        /// (static binaries and UDP go through WARP too). podnet warp down
        /// removes it.
        #[arg(long)]
        persist: bool,
        /// Also write the proxy variables to
        /// $XDG_CONFIG_HOME/environment.d/90-podnet-warp.conf (else
        /// ~/.config/environment.d/90-podnet-warp.conf): the systemd user
        /// manager gives them to the programs of the next login (a
        /// desktop, a user unit). podnet warp down removes the file. A file
        /// of that name that podnet did not write is not changed.
        #[arg(long)]
        env_d: bool,
        /// Seconds to wait for WARP to be ready.
        #[arg(long, default_value_t = 90)]
        ready_timeout: u64,
        /// With CAP_NET_ADMIN: send the whole host through WARP with warp
        /// tun --default-route (instance warp-tun), in place of the proxy.
        #[arg(long, conflicts_with = "persist")]
        tun: bool,
        /// Stop a running warp up with other arguments (another --port),
        /// and start this one.
        #[arg(long)]
        replace: bool,
        /// Also answer DNS on this UDP address (for example
        /// 127.0.0.1:5353): each query goes through WARP to 1.1.1.1.
        #[arg(long, value_name = "ADDR")]
        dns: Option<std::net::SocketAddr>,
        /// Clients must give this user (SOCKS5 user and password, or HTTP
        /// Basic), with the password of --proxy-password-file.
        #[arg(
            long,
            value_name = "USER",
            env = "PODNET_PROXY_USER",
            hide_env_values = true,
            requires = "proxy_password_file"
        )]
        proxy_user: Option<String>,
        /// The file with the password of --proxy-user on its first line
        /// (mode 0600).
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_PROXY_PASSWORD_FILE",
            hide_env_values = true,
            requires = "proxy_user"
        )]
        proxy_password_file: Option<PathBuf>,
    },
    /// Stop what podnet warp up started, and remove its env file and its
    /// block in ~/.bashrc and ~/.profile.
    Down,
    /// Print the proxy variables of the running podnet warp up, for
    /// `eval "$(podnet warp env)"`. Exit 69 with no output when warp up has no
    /// TCP listener (no proxy variables).
    Env,
    /// Run a program under the pod of the running podnet warp up: TCP, DNS
    /// and UDP go through WARP, also for static binaries.
    Exec {
        /// A podnet-netns rule, repeatable (see podnet pod --help).
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
    /// Run $SHELL under the pod of the running podnet warp up. When it does
    /// not run, the shell starts as it is (with the proxy variables when
    /// the env file is there).
    Shell,
    /// A byte pipe from stdin and stdout to HOST:PORT through WARP, for
    /// `ssh -o ProxyCommand='podnet warp nc %h %p'` and git over SSH.
    /// It uses the running podnet warp up, else a WARP session of its
    /// own.
    Nc {
        host: String,
        port: u16,
        /// Go through the WebSocket relay (--relay) to HOST:PORT, with no
        /// WARP (TCP, IPv4).
        #[arg(long, conflicts_with = "udp")]
        via_relay: bool,
        /// UDP: each read of stdin is one datagram to HOST:PORT; each
        /// datagram that comes back goes to stdout.
        #[arg(short = 'u', long)]
        udp: bool,
        /// After the end of stdin, end when no data came for this many
        /// seconds (default 3 with -u, else 5). TCP: podnet then sends the FIN.
        #[arg(long, value_name = "SECS")]
        idle: Option<u64>,
        /// TCP: send the FIN at the end of stdin, then wait for the far end
        /// to close (as nc -N). Without it, podnet sends no FIN until the end:
        /// some servers drop a half-closed connection before they answer.
        #[arg(short = 'N', long, conflicts_with = "udp")]
        shutdown: bool,
    },
    /// Print an SSH config block and GIT_SSH_COMMAND that use podnet warp nc.
    /// With --write, --remove or --check: own the block in the SSH config
    /// file, between two marker lines.
    SshConfig {
        /// The Host pattern of the block (default * for the printed block;
        /// --write and --check need one).
        #[arg(long)]
        host: Option<String>,
        /// Add the block for --host to the SSH config file, or replace it.
        /// The block goes before the first Host or Match line. A Host line
        /// of the file that names the same pattern is an error (exit 1).
        #[arg(long, conflicts_with_all = ["remove", "check"])]
        write: bool,
        /// Remove the block for --host (with no --host: each block of podnet).
        #[arg(long, conflicts_with = "check")]
        remove: bool,
        /// Exit 1 when the block for --host is missing or names another
        /// binary. Writes nothing.
        #[arg(long)]
        check: bool,
        /// The SSH config file.
        #[arg(long, value_name = "FILE", default_value = "~/.ssh/config")]
        config: String,
    },
    /// Make a TUN interface whose packets go through WARP. Needs
    /// CAP_NET_ADMIN and /dev/net/tun. Routes are not changed.
    Tun {
        /// The interface name.
        #[arg(long, default_value = "podnet0")]
        interface: String,
        /// Send the whole host through WARP: host routes keep the
        /// MASQUE connection outside, default routes go to the TUN (IPv4 and
        /// IPv6), DNS goes to 1.1.1.1. The default routes go away while the
        /// session is down; each change is put back at the end.
        #[arg(long)]
        default_route: bool,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a program with all its traffic sent through WARP. No root and no
    /// TUN device are necessary (podnet-netns).
    Run {
        /// The backend: auto, netns-raw, netns or seccomp. netns-raw moves the
        /// raw packets of a namespace through WARP (TCP, UDP, ICMP, IPv6; no
        /// root). auto takes netns-raw when it works, else seccomp, so that
        /// UDP goes through WARP too.
        #[arg(long, default_value = "auto")]
        backend: String,
        /// A podnet-netns rule, repeatable: domain:NAME=PROXY,
        /// domain:.SUFFIX=PROXY, cidr:NET/LEN=PROXY; PROXY may be direct.
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        /// The program keeps the proxy variables of this shell.
        #[arg(long)]
        keep_proxy_env: bool,
        /// Where a port that the program listens on is a unix socket
        /// (seccomp backend). The directory must be of this user and not
        /// writable by the group or others [default:
        /// $XDG_RUNTIME_DIR/podnet-netns-inbound, else
        /// $TMPDIR/podnet-netns-inbound-UID].
        #[arg(long, value_name = "DIR")]
        inbound_dir: Option<PathBuf>,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
}

async fn warp_client(args: &WarpArgs) -> Result<(podnet::warp::WarpClient, Option<PathBuf>)> {
    let (client, path) = warp_client_inner(args).await?;
    let peer = wireguard_peer(args).await?;
    let carry = carry_peer(args).await?;
    Ok((
        client
            .with_masque(masque_options(args))
            .with_wireguard(peer)
            .with_carry(carry),
        path,
    ))
}

/// The carried device of `--carry wg` (issues 154 and 155): warp-carry.json
/// of the state directory, registered when the file has none.
async fn carry_peer(args: &WarpArgs) -> Result<Option<podnet::warp::wg::Peer>> {
    if args.carry.as_deref() != Some("wg") {
        return Ok(None);
    }
    let path = podnet::state::state_dir()
        .fault(Fault::Config)?
        .map(|dir| dir.join("warp-carry.json"))
        .context("PODNET_STATE_DIR=none keeps no carried device; --carry wg needs one")
        .fault(Fault::Config)?;
    let exported = podnet::warp::export::load_or_register(&path, false, None)
        .await
        .fault(Fault::Unavailable)?;
    let peer = podnet::warp::wg::Peer::from_exported(&exported, args.carry_endpoint)
        .fault(Fault::Config)?;
    tracing::info!(endpoint = %peer.endpoint, "a second WireGuard device goes inside the tunnel");
    Ok(Some(peer))
}

/// The WireGuard peer of `--transport wireguard` (issue 152): the device of
/// `warp export` (warp-wg.json of the state directory).
async fn wireguard_peer(args: &WarpArgs) -> Result<Option<podnet::warp::wg::Peer>> {
    if args.transport.as_deref() != Some("wireguard") {
        return Ok(None);
    }
    let path = podnet::warp::export::default_path()
        .fault(Fault::Config)?
        .context("PODNET_STATE_DIR=none keeps no WireGuard device; --transport wireguard needs one")
        .fault(Fault::Config)?;
    let exported = podnet::warp::export::load_or_register(&path, false, None)
        .await
        .fault(Fault::Unavailable)?;
    let peer = podnet::warp::wg::Peer::from_exported(&exported, args.wireguard_endpoint)
        .fault(Fault::Config)?;
    tracing::info!(endpoint = %peer.endpoint, "the tunnel goes on WireGuard (UDP)");
    Ok(Some(peer))
}

/// The MASQUE options of the command line.
fn masque_options(args: &WarpArgs) -> podnet::warp::MasqueOptions {
    podnet::warp::MasqueOptions {
        no_relay: args.no_relay,
        endpoint: args.masque_endpoint,
        sni: args.masque_sni.clone(),
        h3: args.masque_transport.as_deref() == Some("h3"),
    }
}

/// The pairs of --listen-identity LISTEN=PATH (issue 150). Each PATH once,
/// and not the identity of --identity (`main`): one device has one
/// session in a process.
fn identity_pairs(
    specs: &[String],
    main: Option<&std::path::Path>,
    listens: &[String],
) -> Result<Vec<(podnet::vnet::proxy::ProxyListen, PathBuf)>> {
    // Issue 178: a listener of --listen is not a listener of an identity.
    let mains: Vec<podnet::vnet::proxy::ProxyListen> = listens
        .iter()
        .flat_map(|l| l.split(','))
        .filter_map(|l| podnet::vnet::proxy::ProxyListen::parse(l.trim()).ok())
        .collect();
    let mut out: Vec<(podnet::vnet::proxy::ProxyListen, PathBuf)> = Vec::new();
    for spec in specs {
        let (listen, path) = spec
            .split_once('=')
            .filter(|(l, p)| !l.is_empty() && !p.is_empty())
            .with_context(|| format!("{spec:?}: give LISTEN=PATH"))?;
        let listen = podnet::vnet::proxy::ProxyListen::parse(listen)?;
        let path = PathBuf::from(path);
        let same = |a: &std::path::Path, b: &std::path::Path| {
            a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
        };
        if main.is_some_and(|m| same(m, &path)) {
            bail!("{spec:?}: {} is the identity of --identity", path.display());
        }
        if out.iter().any(|(_, p)| same(p, &path)) {
            bail!("{spec:?}: {} is given twice", path.display());
        }
        if out.iter().any(|(l, _)| *l == listen) {
            bail!("{spec:?}: the listener is given twice");
        }
        if mains.contains(&listen) {
            bail!("{spec:?}: the listener is in --listen and in --listen-identity");
        }
        out.push((listen, path));
    }
    Ok(out)
}

async fn warp_client_inner(args: &WarpArgs) -> Result<(podnet::warp::WarpClient, Option<PathBuf>)> {
    use podnet::warp::WarpClient;
    if args.ephemeral {
        return Ok((
            WarpClient::register().await.fault(Fault::Unavailable)?,
            None,
        ));
    }
    let path = match args.identity.clone() {
        Some(path) => path,
        None => match WarpClient::default_identity_path().fault(Fault::Config)? {
            Some(path) => path,
            None => {
                eprintln!("podnet: PODNET_STATE_DIR=none: the WARP device is not saved");
                return Ok((
                    WarpClient::register().await.fault(Fault::Unavailable)?,
                    None,
                ));
            }
        },
    };
    Ok((
        WarpClient::register_or_load(&path)
            .await
            .fault(Fault::Unavailable)?,
        Some(path),
    ))
}

async fn warp(mut args: WarpArgs) -> Result<()> {
    // Issue 111: a bad PODNET_WARP_TCP_BURST fails before any network wait.
    podnet::warp::check_tcp_burst()?;
    // Issue 134: the congestion controller of the stack.
    if let Some(cc) = &args.cc {
        podnet::warp::ip::set_cc(podnet::warp::ip::parse_cc(cc)?);
    }
    // Issue 185: the renewal of the session.
    if let Some(secs) = args.session_max_age {
        if matches!(args.command, WarpCommand::Tun { .. }) {
            return Err(podnet::exit::fault(
                Fault::Usage,
                anyhow::anyhow!("--session-max-age works with warp proxy, forward, run and up, not with warp tun"),
            ));
        }
        podnet::warp::live::set_max_age(Some(Duration::from_secs(secs)));
    }
    // Issue 145: the resolvers of the tunnel.
    let resolvers = podnet::warp::proxy::parse_resolvers(&args.resolver).fault(Fault::Usage)?;
    podnet::warp::proxy::set_resolvers(resolvers);
    // Issue 135: the split of the ClientHello of the MASQUE connection.
    if let Some(split) = podnet::tls_fragment::Split::parse(
        args.fragment_client_hello.as_deref().unwrap_or("off"),
        args.fragment_size.as_deref(),
    )
    .fault(Fault::Config)?
    {
        podnet::tls_fragment::set(split);
    }
    // Issue 141: the name, the model and the locale of a new device.
    podnet::warp::register::DeviceHints {
        name: args.device_name.clone(),
        model: args.device_model.clone(),
        locale: args.device_locale.clone(),
    }
    .set()
    .fault(Fault::Usage)?;
    // These commands use the running instance of podnet warp up.
    match &args.command {
        WarpCommand::Up {
            tun: true,
            ready_timeout,
            ..
        } => {
            let argv = warp_up_tun_args(&args, *ready_timeout);
            let doc = podnet::warp::up::start("podnet warp tun --default-route --detach", &argv)?;
            println!("{doc}");
            return Ok(());
        }
        WarpCommand::Up {
            port,
            persist,
            env_d,
            ready_timeout,
            replace,
            dns,
            proxy_user,
            proxy_password_file,
            ..
        } => {
            let auth = proxy_user.as_ref().zip(proxy_password_file.as_ref());
            let files = UpFiles {
                persist: *persist,
                env_d: *env_d,
            };
            return warp_up(&args, *port, files, *ready_timeout, *replace, *dns, auth);
        }
        WarpCommand::Down => return podnet::warp::up::down(),
        WarpCommand::Env => {
            let text = podnet::warp::up::env_text()?;
            // Issue 255: no proxy variables is not a success: a script
            // that runs `eval "$(podnet warp env)" && CMD` must not run CMD
            // with no proxy.
            if !text.contains("ALL_PROXY") {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!(
                        "warp env: the TCP listener of podnet warp up did not start, so there are no proxy variables; use: podnet warp exec -- CMD"
                    ),
                ));
            }
            print!("{text}");
            return Ok(());
        }
        WarpCommand::Exec { rules, program } => {
            return Err(podnet::warp::up::exec_in_pod(rules, program));
        }
        WarpCommand::Shell => return Err(podnet::warp::up::shell()),
        WarpCommand::SshConfig {
            host,
            write,
            remove,
            check,
            config,
        } => {
            // Issue 252: a pattern with a newline wrote an own ProxyCommand.
            if let Some(host) = host {
                podnet::warp::ssh_config::check_host(host).fault(Fault::Usage)?;
            }
            let exe = std::env::current_exe()?.canonicalize()?;
            if !(*write || *remove || *check) {
                print!(
                    "{}",
                    podnet::warp::nc::ssh_config(&exe, host.as_deref().unwrap_or("*"))
                );
                return Ok(());
            }
            return ssh_config_file(&exe, host.as_deref(), *write, *remove, config);
        }
        WarpCommand::Nc {
            host,
            port,
            via_relay: true,
            idle,
            shutdown,
            ..
        } => {
            let relay = podnet::ws_relay::Relay::from_env(None).fault(Fault::Config)?;
            let io = podnet::warp::nc::via_relay(&relay, host, *port)
                .await
                .fault(Fault::Unavailable)?;
            return podnet::warp::nc::pipe(io, nc_end(*idle, *shutdown))
                .await
                .fault(Fault::Unavailable);
        }
        WarpCommand::Nc {
            host,
            port,
            udp: true,
            idle,
            ..
        } => {
            if let Some((out, back)) = podnet::warp::nc::udp_via_running(host, *port).await? {
                return udp_nc(out, back, idle.unwrap_or(UDP_NC_IDLE)).await;
            }
        }
        WarpCommand::Nc {
            host,
            port,
            idle,
            shutdown,
            ..
        } => {
            if let Some(io) = podnet::warp::nc::via_running(host, *port).await? {
                return podnet::warp::nc::pipe(io, nc_end(*idle, *shutdown))
                    .await
                    .fault(Fault::Unavailable);
            }
        }
        // Issue 148: a WireGuard device of its own; warp.json is not used.
        WarpCommand::Export {
            format,
            out,
            export_identity,
            endpoint,
            keepalive,
            new,
            delete,
        } => {
            let path = match export_identity.clone() {
                Some(path) => path,
                None => podnet::warp::export::default_path()
                    .fault(Fault::Config)?
                    .context("PODNET_STATE_DIR=none keeps no file; give --export-identity PATH")
                    .fault(Fault::Config)?,
            };
            if *delete {
                // Issue 178: a second --delete names the missing file.
                if !podnet::state::exists(&path).fault(Fault::Config)? {
                    return Err(podnet::exit::fault(
                        Fault::Config,
                        anyhow::anyhow!("no exported device at {}", path.display()),
                    ));
                }
                let id = podnet::warp::export::delete(&path, None)
                    .await
                    .fault(Fault::Unavailable)?;
                eprintln!(
                    "podnet: warp export: the device {id} is deleted, and {}",
                    path.display()
                );
                return Ok(());
            }
            // Issue 177: no private key on a terminal, before a device is
            // registered.
            let to_stdout = out
                .as_deref()
                .is_none_or(|p| p == std::path::Path::new("-"));
            {
                use std::io::IsTerminal as _;
                podnet::warp::export::check_sink(out.as_deref(), std::io::stdout().is_terminal())
                    .fault(Fault::Usage)?;
            }
            let exported = podnet::warp::export::load_or_register(&path, *new, None)
                .await
                .fault(Fault::Unavailable)?;
            let config =
                podnet::warp::export::Config::of(&exported, endpoint.as_deref(), *keepalive)
                    .fault(Fault::Unavailable)?;
            let text = match format.as_str() {
                "json" => format!("{:#}\n", config.json(&exported.device.id)),
                _ => config.wg_quick(),
            };
            match out {
                Some(file) if !to_stdout => {
                    podnet::warp::write_private_file(file, text.as_bytes())
                        .with_context(|| format!("writing {}", file.display()))?;
                    eprintln!("podnet: warp export: wrote {}", file.display());
                }
                _ => {
                    if podnet::warp::export::tighten_stdout() {
                        eprintln!("podnet: warp export: the file of stdout is mode 0600 now (it holds the private key)");
                    }
                    print!("{text}");
                }
            }
            eprintln!(
                "podnet: warp export: the device {} is in {} (podnet warp export --delete removes it)",
                exported.device.id,
                path.display()
            );
            return Ok(());
        }
        // Issues 132 and 136: check the rules with no device and no session.
        WarpCommand::Proxy {
            rules,
            rules_file,
            rule_default,
            check: true,
            ..
        } => {
            let default = podnet::warp::rules::Action::parse(rule_default).fault(Fault::Usage)?;
            let table = podnet::warp::rules::Table::build(rules, rules_file.as_deref(), default)
                .fault(Fault::Usage)?;
            for rule in &table.rules {
                println!("rule        {}", rule.spec);
            }
            println!("default     {}", table.default.name());
            return Ok(());
        }
        // Issue 150: a bad --listen-identity is a usage error before any
        // registration.
        WarpCommand::Proxy {
            listen_identity,
            listen,
            ..
        } if !listen_identity.is_empty() => {
            let main = match &args.identity {
                Some(path) => Some(path.clone()),
                None if args.ephemeral => None,
                None => podnet::warp::WarpClient::default_identity_path().fault(Fault::Config)?,
            };
            identity_pairs(listen_identity, main.as_deref(), listen).fault(Fault::Usage)?;
        }
        _ => {}
    }
    // These commands use a saved device and register none.
    if matches!(
        args.command,
        WarpCommand::Status { .. }
            | WarpCommand::License { .. }
            | WarpCommand::Rotate
            | WarpCommand::Delete
    ) && !args.ephemeral
    {
        // Issue 178: find the saved identity with no directory made, in each
        // candidate directory; a stat error is a configuration error.
        let path = match args.identity.clone() {
            Some(path) => Some(path),
            None => match podnet::state::find_existing("warp.json").fault(Fault::Config)? {
                Some(found) => {
                    args.identity = Some(found.clone());
                    Some(found)
                }
                None => podnet::state::candidates(&|k| std::env::var_os(k))
                    .and_then(|c| c.into_iter().next())
                    .map(|(_, dir)| dir.join("warp.json")),
            },
        };
        match path {
            Some(path) if podnet::state::exists(&path).fault(Fault::Config)? => {}
            Some(path) => {
                return Err(podnet::exit::fault(
                    Fault::Config,
                    anyhow::anyhow!(
                        "no WARP identity at {}; run podnet warp register first",
                        path.display()
                    ),
                ))
            }
            None => {
                return Err(podnet::exit::fault(
                    Fault::Config,
                    anyhow::anyhow!(
                        "PODNET_STATE_DIR=none keeps no WARP identity; give --identity PATH"
                    ),
                ))
            }
        }
    }
    let (mut client, path) = warp_client(&args).await?;
    let masque = masque_options(&args);
    let save = |client: &podnet::warp::WarpClient| -> Result<()> {
        if let Some(path) = &path {
            client.save(path)?;
        }
        Ok(())
    };

    match args.command {
        WarpCommand::Register => print_device(&client, path.as_deref()),
        WarpCommand::Status { json } => {
            client.refresh().await?;
            save(&client)?;
            let mut account = client.account().await?;
            // Issue 116: the instance of warp up, with the account.
            let instance = podnet::warp::up::instance_state();
            if json {
                let active = warp_plus_label(&account) == "yes";
                if let Some(doc) = account.as_object_mut() {
                    doc.insert("instance".into(), instance);
                    // Issue 178: warp_plus of the API is not the state of
                    // the account; warp_plus_active is.
                    doc.insert("warp_plus_active".into(), active.into());
                }
                println!("{}", serde_json::to_string_pretty(&account)?);
                return Ok(());
            }
            print_device(&client, path.as_deref());
            println!("warp up     {}", podnet::warp::up::instance_line(&instance));
            let field = |name: &str| account.get(name).map(plain_value).unwrap_or_default();
            println!("type        {}", field("account_type"));
            println!("warp+       {}", warp_plus_label(&account));
            println!("premium     {}", field("premium_data"));
            println!("quota       {}", field("quota"));
        }
        WarpCommand::License { key } => {
            let key = if key == "-" {
                let mut text = String::new();
                std::io::Read::read_to_string(
                    &mut std::io::Read::take(std::io::stdin(), 4096),
                    &mut text,
                )
                .context("reading the license key from stdin")
                .fault(Fault::Usage)?;
                let text = text.trim().to_string();
                if text.is_empty() {
                    return Err(podnet::exit::fault(
                        Fault::Usage,
                        anyhow::anyhow!("no license key on stdin"),
                    ));
                }
                text
            } else {
                key
            };
            podnet::report::hide(&key);
            let account = client
                .set_license(&key)
                .await
                .map_err(|err| podnet::exit::fault(license_fault(&err), err))?;
            save(&client)?;
            let field = |name: &str| account.get(name).map(plain_value).unwrap_or_default();
            println!("license     set");
            println!("type        {}", field("account_type"));
            println!("warp+       {}", warp_plus_label(&account));
        }
        WarpCommand::Rotate => {
            client.rotate_key().await?;
            save(&client)?;
            println!("key         rotated");
            print_device(&client, path.as_deref());
        }
        WarpCommand::Delete => {
            client.delete().await?;
            if let Some(path) = &path {
                let _ = std::fs::remove_file(path);
            }
            println!("device      {} deleted", client.device().id);
        }
        WarpCommand::Scan {
            candidate,
            timeout_ms,
            json,
        } => {
            let candidates = candidate
                .iter()
                .map(|c| parse_door(c))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            let timeout = std::time::Duration::from_millis(timeout_ms);
            let results = client
                .scan(&candidates, timeout)
                .await
                .fault(Fault::Config)?;
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            if json {
                let doors: Vec<_> = results
                    .iter()
                    .map(|(a, r)| match r {
                        Ok(t) => serde_json::json!({
                            "endpoint": a.to_string(),
                            "ok": true,
                            "tcp_ms": t.tcp.as_millis() as u64,
                            "tls_ms": t.tls.as_millis() as u64,
                        }),
                        Err(err) => serde_json::json!({
                            "endpoint": a.to_string(),
                            "ok": false,
                            "error": format!("{err:#}"),
                        }),
                    })
                    .collect();
                println!("{}", serde_json::json!({ "doors": doors }));
            } else {
                for (a, r) in &results {
                    match r {
                        Ok(t) => println!(
                            "OK          {a:<28} tcp {:>5} ms  tls {:>5} ms",
                            t.tcp.as_millis(),
                            t.tls.as_millis()
                        ),
                        Err(err) => println!("FAIL        {a:<28} {err:#}"),
                    }
                }
                if let Some((best, _)) = results.iter().find(|(_, r)| r.is_ok()) {
                    println!("use         podnet warp --masque-endpoint {best} ...");
                }
            }
            if ok == 0 {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("no front door answered"),
                ));
            }
        }
        WarpCommand::Exit { json, no_ipv6 } => {
            let stack = client.connect().await.fault(Fault::Unavailable)?;
            let mut exit = podnet::warp::exit::trace(&stack)
                .await
                .fault(Fault::Unavailable)?;
            // Issue 184: the IPv6 egress address changes with each session.
            if !no_ipv6 {
                if client.device().ipv6().is_none() {
                    exit.ipv6_error = Some("the device has no IPv6 address".into());
                } else {
                    match podnet::warp::exit::egress_v6(&stack).await {
                        Ok(ip) => exit.ipv6 = Some(ip),
                        Err(err) => exit.ipv6_error = Some(format!("{err:#}")),
                    }
                }
            }
            if json {
                println!("{}", exit.to_json());
            } else {
                println!("colo        {}", exit.colo);
                println!("country     {}", exit.loc.as_deref().unwrap_or("-"));
                println!("ip          {}", exit.ip.as_deref().unwrap_or("-"));
                if !no_ipv6 {
                    match (&exit.ipv6, &exit.ipv6_error) {
                        (Some(ip), _) => println!("ipv6        {ip}"),
                        (None, Some(why)) => println!("ipv6        - ({why})"),
                        _ => println!("ipv6        -"),
                    }
                }
                println!("warp        {}", exit.warp.as_deref().unwrap_or("-"));
                println!("rtt         {} ms", exit.rtt.as_millis());
            }
        }
        WarpCommand::Probe { target } => {
            let targets = if target.is_empty() {
                vec!["1.1.1.1:443".to_string(), "198.41.192.27:7844".to_string()]
            } else {
                target
            };
            // Check each target before any output or connection: a bad
            // value is a usage error (exit 64).
            let targets = targets
                .iter()
                .map(|spec| split_host_port(spec).map(|(h, p)| (spec.clone(), h, p)))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            println!("device      {}", client.device().id);
            println!(
                "masque      {}",
                client
                    .device()
                    .masque_endpoint()
                    .map_or_else(|| "-".to_string(), |a| a.to_string())
            );
            let stack = client.connect().await.fault(Fault::Unavailable)?;
            println!(
                "tunnel      up ({})",
                if client.is_wireguard() {
                    "WireGuard over UDP"
                } else if args.masque_transport.as_deref() == Some("h3") {
                    "MASQUE over HTTP/3, UDP 443"
                } else {
                    "MASQUE over TCP 443"
                }
            );
            // Issue 147: the exit of the session. It does not change the
            // exit code.
            match podnet::warp::exit::trace(&stack).await {
                Ok(exit) => println!("exit        {}", exit_line(&exit)),
                Err(err) => println!("exit        - ({err:#})"),
            }
            let total = targets.len() + 1;
            let mut failed = 0;
            // Issue 178: the summary names the failed checks.
            let mut names: Vec<String> = Vec::new();
            // Issue 115: the UDP data path: a DNS query through the tunnel.
            match podnet::warp::proxy::check_data_path(&stack, true).await {
                Ok(took) => println!("OK          udp 1.1.1.1:53 (DNS) in {took:?}"),
                Err(err) => {
                    failed += 1;
                    names.push("udp 1.1.1.1:53".into());
                    println!("FAIL        udp 1.1.1.1:53 (DNS): {err:#}");
                }
            }
            for (spec, host, port) in targets {
                let started = std::time::Instant::now();
                let attempt = async {
                    // A name is resolved by DNS through the tunnel.
                    let ip = podnet::warp::proxy::resolve(&stack, &host).await?;
                    let addr = std::net::SocketAddr::new(ip, port);
                    let conn = stack.tcp_connect(addr).await?;
                    Ok::<_, anyhow::Error>((addr, conn))
                };
                match tokio::time::timeout(std::time::Duration::from_secs(12), attempt).await {
                    Ok(Ok((addr, conn))) => {
                        println!("OK          {spec} ({addr}) in {:?}", started.elapsed());
                        conn.close().await;
                    }
                    Ok(Err(err)) => {
                        failed += 1;
                        names.push(spec.clone());
                        println!("FAIL        {spec}: {err:#}");
                    }
                    Err(_) => {
                        failed += 1;
                        names.push(spec.clone());
                        println!("TIMEOUT     {spec}");
                    }
                }
            }
            // Issue 95: a target that fails is a failure of the probe.
            if failed > 0 {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!(
                        "{failed} of {total} targets failed through WARP: {}",
                        names.join(", ")
                    ),
                ));
            }
        }
        WarpCommand::Proxy {
            listen,
            run_for,
            strict,
            max_connections,
            dns,
            proxy_user,
            proxy_password_file,
            rules,
            rules_file,
            rule_default,
            listen_identity,
            l4,
            l4_sni,
            ..
        } => {
            // Issue 150: the listeners of the other identities.
            let pairs =
                identity_pairs(&listen_identity, path.as_deref(), &listen).fault(Fault::Usage)?;
            podnet::warp::proxy::set_max_connections(max_connections);
            // Issues 132 and 136: the rules of the destinations.
            let default = podnet::warp::rules::Action::parse(&rule_default).fault(Fault::Usage)?;
            let table = podnet::warp::rules::Table::build(&rules, rules_file.as_deref(), default)
                .fault(Fault::Usage)?;
            podnet::warp::rules::set(table);
            if let Some(file) = rules_file {
                podnet::warp::rules::watch(rules, file, default);
            }
            // Issue 146: the credentials of the clients.
            if let (Some(user), Some(file)) = (&proxy_user, &proxy_password_file) {
                let credentials =
                    podnet::proxy_auth::Credentials::load(user, file).fault(Fault::Config)?;
                podnet::warp::proxy::set_credentials(credentials);
            }
            // Issue 117: the DNS listener is bound before the session, as
            // the proxy listeners.
            let dns_socket = match dns {
                Some(addr) => Some(
                    tokio::net::UdpSocket::bind(addr)
                        .await
                        .with_context(|| format!("binding the DNS address {addr}"))
                        .fault(Fault::Unavailable)?,
                ),
                None => None,
            };
            let listens = listen
                .iter()
                .map(|l| podnet::vnet::proxy::ProxyListen::parse(l))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            // Issue 97: each listener is bound on its own, before the WARP
            // session. A listener that the host refuses (EACCES on a TCP
            // bind) is reported; the proxy starts with the others.
            let (bound, mut failed) = podnet::warp::proxy::bind_all(&listens).await;
            let mut extra = Vec::new();
            for (listen, identity) in pairs {
                match podnet::warp::proxy::bind(&listen).await {
                    Ok(b) => extra.push((b, identity)),
                    Err(err) => failed.push((listen, err)),
                }
            }
            for (listen, err) in &failed {
                eprintln!(
                    "podnet: warp proxy: {} is not available: {err:#}",
                    listen_doc(listen)["listen"].as_str().unwrap_or("?")
                );
            }
            if bound.is_empty() || (strict && !failed.is_empty()) {
                let list = failed
                    .iter()
                    .map(|(_, err)| format!("{err:#}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("warp proxy: a listener did not start: {list}"),
                ));
            }
            // Issue 140: one HTTP/3 CONNECT for each client, no stack.
            if l4 {
                let door = Arc::new(client.l4(&l4_sni).fault(Fault::Config)?);
                door.connection().await.fault(Fault::Unavailable)?;
                let proxies: Vec<_> = bound
                    .into_iter()
                    .map(|b| podnet::warp::proxy::run_l4(door.clone(), b))
                    .collect();
                for proxy in &proxies {
                    println!(
                        "podnet: warp proxy  {}  (L4: {l4_sni}, HTTP/3 on UDP; TCP only)",
                        listen_doc(&proxy.listen)["listen"].as_str().unwrap_or("?")
                    );
                }
                let mut doc = listen_doc(&proxies[0].listen);
                doc["listens"] = proxies
                    .iter()
                    .map(|p| listen_doc(&p.listen)["listen"].clone())
                    .collect::<Vec<_>>()
                    .into();
                doc["l4"] = true.into();
                podnet::detach::ready(doc);
                sleep_or_signal(run_for).await;
                for proxy in &proxies {
                    proxy.abort();
                }
                return Ok(());
            }
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            podnet::warp::proxy::health_log(live.clone());
            if let Some(socket) = dns_socket {
                podnet::warp::proxy::serve_dns(live.clone(), socket);
            }
            let mut proxies: Vec<_> = bound
                .into_iter()
                .map(|b| podnet::warp::proxy::run(live.clone(), b))
                .collect();
            let mut identities = Vec::new();
            for (b, identity) in extra {
                let other = podnet::warp::WarpClient::register_or_load(&identity)
                    .await
                    .fault(Fault::Unavailable)?
                    .with_masque(masque.clone());
                let device = other.device().id.clone();
                let other = Arc::new(other)
                    .connect_live()
                    .await
                    .fault(Fault::Unavailable)?;
                let proxy = podnet::warp::proxy::run(other, b);
                identities.push(serde_json::json!({
                    "listen": listen_doc(&proxy.listen)["listen"],
                    "identity": identity.display().to_string(),
                    "device": device,
                }));
                proxies.push(proxy);
            }
            for proxy in &proxies {
                match &proxy.listen {
                    podnet::vnet::proxy::ProxyListen::Tcp(addr) => {
                        println!("podnet: warp proxy  socks5h://{addr}  (and HTTP CONNECT)");
                        println!("  export ALL_PROXY=socks5h://{addr} HTTPS_PROXY=http://{addr}");
                    }
                    podnet::vnet::proxy::ProxyListen::Unix(path) => {
                        println!("podnet: warp proxy  unix:{}", path.display());
                        println!(
                            "  podnet pod -x socks5://unix:{} -- PROGRAM",
                            path.display()
                        );
                    }
                }
            }
            let mut doc = listen_doc(&proxies[0].listen);
            doc["listens"] = proxies
                .iter()
                .map(|p| listen_doc(&p.listen)["listen"].clone())
                .collect::<Vec<_>>()
                .into();
            doc["failed"] = failed
                .iter()
                .map(|(listen, err)| {
                    serde_json::json!({
                        "listen": listen_doc(listen)["listen"],
                        "error": format!("{err:#}"),
                    })
                })
                .collect::<Vec<_>>()
                .into();
            doc["identities"] = identities.into();
            podnet::detach::ready(doc);
            sleep_or_signal(run_for).await;
            for proxy in &proxies {
                proxy.abort();
            }
        }
        WarpCommand::Forward {
            local,
            strict,
            max_connections,
            run_for,
            ..
        } => {
            // Issue 143: check each rule before any bind or session (exit 64).
            let rules = local
                .iter()
                .map(|spec| podnet::warp::forward::Rule::parse(spec))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            let mut bound = Vec::new();
            let mut failed = Vec::new();
            for rule in rules {
                match podnet::warp::proxy::bind(&rule.listen).await {
                    Ok(b) => bound.push((b, rule)),
                    Err(err) => {
                        eprintln!(
                            "podnet: warp forward: {} is not available: {err:#}",
                            rule.target()
                        );
                        failed.push((rule, err));
                    }
                }
            }
            if bound.is_empty() || (strict && !failed.is_empty()) {
                let list = failed
                    .iter()
                    .map(|(_, err)| format!("{err:#}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("warp forward: a listener did not start: {list}"),
                ));
            }
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            podnet::warp::proxy::health_log(live.clone());
            let forwards: Vec<_> = bound
                .into_iter()
                .map(|(b, rule)| podnet::warp::forward::run(live.clone(), b, rule, max_connections))
                .collect();
            let mut docs = Vec::new();
            for forward in &forwards {
                let listen = listen_doc(&forward.listen)["listen"].clone();
                println!(
                    "podnet: warp forward  {}  ->  {} (through WARP)",
                    listen.as_str().unwrap_or("?"),
                    forward.rule.target()
                );
                docs.push(serde_json::json!({ "listen": listen, "to": forward.rule.target() }));
            }
            let mut doc = listen_doc(&forwards[0].listen);
            doc["forward"] = docs.into();
            doc["failed"] = failed
                .iter()
                .map(|(rule, err)| {
                    serde_json::json!({
                        "listen": listen_doc(&rule.listen)["listen"],
                        "to": rule.target(),
                        "error": format!("{err:#}"),
                    })
                })
                .collect::<Vec<_>>()
                .into();
            podnet::detach::ready(doc);
            sleep_or_signal(run_for).await;
            for forward in &forwards {
                forward.abort();
            }
        }
        #[cfg(target_os = "linux")]
        WarpCommand::Tun {
            interface: name,
            default_route,
            ..
        } => {
            let address = client
                .device()
                .ipv4()
                .context("the device has no IPv4 address")
                .fault(Fault::Unavailable)?;
            // Issue 102: a TUN that cannot be made, or a session that
            // cannot open, is an unavailable path (69), as for warp up --tun.
            let tun =
                podnet::warp::tun::Tun::create(&name, address, 1280).fault(Fault::Unavailable)?;
            let session = client.connect_raw().await.fault(Fault::Unavailable)?;
            // The IPv6-only kit, 0001: the front door of the session, not
            // the first address of the device record.
            let endpoint = client
                .endpoint_in_use()
                .map(|e| e.ip().to_string())
                .unwrap_or_default();
            println!("podnet: tun      {} {address}/32 mtu 1280", tun.name);
            if let Some(v6) = client.device().ipv6() {
                match tun.add_ipv6(v6) {
                    Ok(()) => println!("podnet: tun      {} {v6}/128", tun.name),
                    Err(err) => {
                        tracing::warn!(error = %format!("{err:#}"), "the TUN has no IPv6 address")
                    }
                }
            }
            println!(
                "podnet: masque   {endpoint} (do not route this address into {})",
                tun.name
            );
            println!(
                "  ip route add 1.1.1.1/32 dev {}        # one destination",
                tun.name
            );
            println!(
                "  ip route add 0.0.0.0/1 dev {0}; ip route add 128.0.0.0/1 dev {0}",
                tun.name
            );
            let host_prefix = if endpoint.contains(':') {
                "-6 route add {}/128"
            } else {
                "route add {}/32"
            };
            println!(
                "  ip {} via <your gateway>   # keep the session outside",
                host_prefix.replace("{}", &endpoint)
            );
            // --default-route (issue 77): the addresses of the MASQUE
            // connection stay outside the tunnel.
            let routes = if default_route {
                // The front door of the session (or its proxy) must stay
                // outside the TUN; the relay of a later session should,
                // where a route to it exists.
                let session_host = match podnet::egress::proxy_for(&endpoint, 443) {
                    Some(proxy) => proxy.host().to_string(),
                    None => endpoint.clone(),
                };
                let mut relay_host = String::new();
                if !args.no_relay {
                    if let Ok(relay) = podnet::ws_relay::Relay::from_env(None) {
                        // Issue 105: a relay that is reached through the
                        // proxy needs no route of its own.
                        relay_host = match podnet::egress::proxy_for(relay.host(), relay.port()) {
                            Some(proxy) => proxy.host().to_string(),
                            None => relay.host().to_string(),
                        };
                    }
                }
                let addresses = |host: String| async move {
                    if host.is_empty() {
                        return Vec::new();
                    }
                    podnet::resolve::resolve(&host).await.unwrap_or_default()
                };
                let required = addresses(session_host).await;
                let mut optional = addresses(relay_host).await;
                optional.retain(|ip| !required.contains(ip));
                let routes = podnet::warp::route::Routes::setup(
                    &tun.name,
                    required,
                    optional,
                    client.device().ipv6().is_some(),
                )
                .fault(Fault::Unavailable)?;
                let outside = routes
                    .exempted()
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "podnet: routes   the default routes go to {}; outside: {}",
                    tun.name,
                    if outside.is_empty() {
                        "none needed (the MASQUE connection goes through loopback or a connected subnet)".to_string()
                    } else {
                        outside
                    }
                );
                Some(std::sync::Mutex::new(routes))
            } else {
                None
            };
            podnet::detach::ready(serde_json::json!({
                "tun": tun.name,
                "address": address.to_string(),
                "default_route": default_route,
            }));
            // The TUN stays; a session that ends is opened again (issue 75).
            let tun_ref = &tun;
            let client_ref = &client;
            let routes_ref = &routes;
            let keep = async move {
                let mut session = Some(session);
                let mut delay = std::time::Duration::from_secs(1);
                loop {
                    let current = match session.take() {
                        Some(s) => s,
                        None => match client_ref.connect_raw().await {
                            Ok(s) => {
                                tracing::info!("a new WARP session is open");
                                delay = std::time::Duration::from_secs(1);
                                s
                            }
                            Err(err) => {
                                tracing::warn!(error = %format!("{err:#}"), next_try_s = delay.as_secs(), "a new WARP session failed");
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(std::time::Duration::from_secs(30));
                                continue;
                            }
                        },
                    };
                    // The default routes only while a session is up.
                    if let Some(routes) = routes_ref {
                        let up = routes.lock().unwrap_or_else(|e| e.into_inner()).up();
                        if let Err(err) = up {
                            // #278: no session with half of the default
                            // routes; up() removed the half that was in.
                            tracing::error!(error = %format!("{err:#}"), next_try_s = delay.as_secs(), "no default routes on the TUN; podnet tries again");
                            drop(current);
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(std::time::Duration::from_secs(30));
                            continue;
                        }
                    }
                    if let Err(err) = podnet::warp::tun::run(tun_ref, current).await {
                        tracing::warn!(error = %format!("{err:#}"), "the WARP session ended; opening a new one");
                    }
                    if let Some(routes) = routes_ref {
                        routes.lock().unwrap_or_else(|e| e.into_inner()).down();
                    }
                }
            };
            tokio::select! {
                _ = keep => {}
                _ = shutdown_signal() => {}
            }
            // Dropped: the routes and the resolver are put back.
            drop(routes);
        }
        #[cfg(not(target_os = "linux"))]
        WarpCommand::Tun { .. } => bail!("podnet warp tun is available on Linux only"),
        WarpCommand::Up { .. }
        | WarpCommand::Down
        | WarpCommand::Export { .. }
        | WarpCommand::Env
        | WarpCommand::Exec { .. }
        | WarpCommand::Shell
        | WarpCommand::SshConfig { .. } => unreachable!("handled before the client is made"),
        WarpCommand::Nc {
            host,
            port,
            udp,
            idle,
            shutdown,
            ..
        } => {
            // No podnet warp up runs: a session of this process. Issue 115:
            // say so, because the two ways fail in other ways.
            tracing::info!(
                "podnet warp up is not running; warp nc opens a WARP session of its own"
            );
            let stack = Arc::new(client.connect().await.fault(Fault::Unavailable)?);
            if udp {
                let (out, back) = podnet::warp::nc::udp_via_stack(stack, &host, port)
                    .await
                    .fault(Fault::Unavailable)?;
                return udp_nc(out, back, idle.unwrap_or(UDP_NC_IDLE)).await;
            }
            let target = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => podnet_netns::socks::ProxyHost::Ip(ip),
                Err(_) => podnet_netns::socks::ProxyHost::Domain(host.clone()),
            };
            let io = podnet::warp::proxy::dial(stack, target, port)
                .await
                .fault(Fault::Unavailable)?;
            podnet::warp::nc::pipe(Box::new(io), nc_end(idle, shutdown))
                .await
                .fault(Fault::Unavailable)?;
        }
        WarpCommand::Run {
            backend,
            rules,
            keep_proxy_env,
            inbound_dir,
            program,
        } => {
            // netns-raw (issue 79): the TUN of a namespace goes to WARP as
            // raw packets: TCP, UDP, ICMP and IPv6 with no root. auto takes
            // it when this host can make the namespace.
            let raw = backend == "netns-raw"
                || (backend == "auto" && rules.is_empty() && podnet_netns::raw::available());
            if raw {
                match warp_run_raw(&client, &program, keep_proxy_env).await {
                    Ok(code) => std::process::exit(code),
                    // Issue 251: the program cannot run. The proxy pod
                    // cannot run it either: exit 3, as the netns backend.
                    Err(err) if err.downcast_ref::<podnet_netns::raw::ExecError>().is_some() => {
                        eprintln!("podnet: warp run: {err:#}");
                        std::process::exit(podnet::exit::NO_BACKEND);
                    }
                    Err(err) if backend == "auto" => {
                        tracing::info!(error = %format!("{err:#}"), "the netns-raw backend cannot run here; the pod with a proxy runs");
                    }
                    Err(err) => return Err(podnet::exit::fault(Fault::Unavailable, err)),
                }
            }
            let backend = if backend == "netns-raw" {
                "auto".to_string()
            } else {
                backend
            };
            let socket =
                std::env::temp_dir().join(format!("podnet-warp-{}.sock", std::process::id()));
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            let proxy = podnet::warp::proxy::serve(
                live,
                podnet::vnet::proxy::ProxyListen::Unix(socket.clone()),
            )
            .await?;
            let mut argv = vec![
                "--backend".to_string(),
                backend.clone(),
                "-x".to_string(),
                format!("socks5://unix:{}", socket.display()),
            ];
            if backend == "auto" {
                argv.push("--prefer-udp".to_string());
            }
            for rule in rules {
                argv.push("-r".to_string());
                argv.push(rule);
            }
            if keep_proxy_env {
                argv.push("--keep-proxy-env".to_string());
            }
            if let Some(dir) = inbound_dir {
                argv.push("--inbound-dir".to_string());
                argv.push(dir.display().to_string());
            }
            argv.push("--".to_string());
            argv.extend(program);
            // podnet-netns makes its own runtime, so run it on a plain thread.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(podnet_netns::main_with_args(&argv));
            });
            let code = done_rx.await.unwrap_or(1);
            proxy.abort();
            let _ = std::fs::remove_file(&socket);
            std::process::exit(code);
        }
    }
    Ok(())
}

/// `podnet warp run --backend netns-raw`: the program in a raw pod whose TUN
/// packets go through WARP; a session that ends is opened again. Gives the
/// exit code of the program.
async fn warp_run_raw(
    client: &podnet::warp::WarpClient,
    program: &[String],
    keep_proxy_env: bool,
) -> Result<i32> {
    let v4 = client
        .device()
        .ipv4()
        .context("the device has no IPv4 address")?;
    let mut session = Some(client.connect_raw().await?);
    let pod = podnet_netns::raw::spawn(&podnet_netns::raw::RawOptions {
        program: program.to_vec(),
        keep_proxy_env,
        v4,
        v6: client.device().ipv6(),
        mtu: podnet::warp::ip::TUNNEL_MTU,
        nameserver: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    })?;
    let pid = pod.pid;
    let tun = podnet::warp::tun::Tun::from_fd(pod.tun, "eth0")?;
    tracing::info!(pid, "the program runs in a raw pod (netns-raw)");
    let carry = async {
        let mut delay = std::time::Duration::from_secs(1);
        loop {
            let current = match session.take() {
                Some(s) => s,
                None => match client.connect_raw().await {
                    Ok(s) => {
                        tracing::info!("a new WARP session is open");
                        delay = std::time::Duration::from_secs(1);
                        s
                    }
                    Err(err) => {
                        tracing::warn!(error = %format!("{err:#}"), "a new WARP session failed");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(30));
                        continue;
                    }
                },
            };
            if let Err(err) = podnet::warp::tun::run(&tun, current).await {
                tracing::warn!(error = %format!("{err:#}"), "the WARP session ended; opening a new one");
            }
        }
    };
    let exited = async {
        loop {
            if let Some(code) = podnet_netns::raw::try_wait(pid) {
                return code;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    tokio::select! {
        code = exited => Ok(code),
        _ = carry => unreachable!("the loop does not end"),
    }
}

fn print_device(client: &podnet::warp::WarpClient, path: Option<&std::path::Path>) {
    let device = client.device();
    println!("device      {}", device.id);
    println!("account     {}", device.account.id);
    println!("tunnel      {}", device.tunnel_type);
    println!("key type    {}", device.key_type);
    let or_dash = |v: Option<String>| v.unwrap_or_else(|| "-".into());
    println!(
        "ipv4        {}",
        or_dash(device.ipv4().map(|a| a.to_string()))
    );
    println!(
        "ipv6        {}",
        or_dash(device.ipv6().map(|a| a.to_string()))
    );
    println!(
        "masque      {}",
        or_dash(device.masque_endpoint().map(|a| a.to_string()))
    );
    println!("protocol    {}", device.policy.tunnel_protocol);
    match path {
        Some(path) => println!("saved       {}", path.display()),
        None => println!("saved       no (--ephemeral or PODNET_STATE_DIR=none)"),
    }
}

#[derive(Subcommand, Debug)]
enum NetCommand {
    /// Prove the userspace TCP handshake + transfer in-process.
    Demo,
    /// Probe what this host permits.
    Doctor {
        /// Print one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Build (or locate) the LD_PRELOAD shim and print how to use it.
    Shim(ShimArgs),
    /// Print the default virtual address plan.
    Addresses {
        /// Print one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Run a SOCKS5 / HTTP CONNECT proxy into the virtual network.
    Proxy(ProxyArgs),
    /// Run a switch that connects stacks on this host and on other hosts.
    Switch(SwitchArgs),
    /// Run a SOCKS5 / HTTP CONNECT front door to a tailnet through tailscaled.
    Tailscale(TailscaleArgs),
    /// Build the LD_PRELOAD shim that sends tailnet connects to a front door.
    Socksify(SocksifyArgs),
    /// Write the user-table shims that Tailscale SSH needs on a host with no
    /// /etc/passwd.
    TsShims(TsShimsArgs),
}

#[derive(Args, Debug)]
struct TailscaleArgs {
    /// The LocalAPI socket of tailscaled.
    #[arg(long, default_value = podnet_netns::tailscale::DEFAULT_SOCKET)]
    socket: String,
    /// Where to accept proxy clients: unix:/path or tcp://[bind:]port.
    #[arg(long, default_value = "unix:/tmp/podnet-socks.sock")]
    listen: String,
    /// Port to use when a client omits one.
    #[arg(long, default_value_t = 80)]
    port: u16,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
}

#[derive(Args, Debug)]
struct SocksifyArgs {
    /// Directory to write and compile the shim into.
    #[arg(long)]
    out: Option<PathBuf>,
    /// The unix socket of the front door (exported as PODNET_SOCKS_PROXY). It
    /// is not --proxy: that is the global proxy URL of podnet.
    #[arg(long, value_name = "PATH", default_value = "/tmp/podnet-socks.sock")]
    socket: String,
    /// Log each redirect to stderr.
    #[arg(long)]
    log: bool,
    /// Print the environment as JSON instead of shell assignments.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct TsShimsArgs {
    /// Directory for passwd, group, getent, id and fakepwd.so. It must
    /// belong to this user, and other users must not write it. Default:
    /// `podnet-ts-shims` in the first private directory that is not noexec
    /// (as for `net shim`).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Local login name. Default: the current user.
    #[arg(long)]
    user: Option<String>,
    /// Local uid. Default: the current uid.
    #[arg(long)]
    uid: Option<u32>,
    /// Local gid. Default: the current gid.
    #[arg(long)]
    gid: Option<u32>,
    /// Login shell of the synthetic user.
    #[arg(long)]
    shell: Option<String>,
    /// Print the client environment as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ShimArgs {
    /// Directory to write and compile the shim into when none is found.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Log every translation the shim performs.
    #[arg(long)]
    log: bool,
    /// Rewrite 127.0.0.1 connections to the stack's local address.
    #[arg(long)]
    map_loopback: bool,
    /// Print the environment as JSON instead of shell assignments.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ProxyArgs {
    #[command(flatten)]
    detach: DetachArgs,
    /// Where to accept proxy clients: unix:/path or tcp://[bind:]port.
    #[arg(long, default_value = "unix:/tmp/podnet-vnet.socks")]
    listen: String,
    /// Name-to-address entries, repeatable: --map web=10.66.0.2
    #[arg(long = "map", value_name = "NAME=ADDR")]
    maps: Vec<String>,
    /// Forward a virtual endpoint to a real one, repeatable. REAL is
    /// host:port for TCP, or unix:/path for a unix service:
    /// --forward 10.66.0.2:8080=127.0.0.1:3000
    #[arg(long = "forward", value_name = "VIRT=REAL")]
    forwards: Vec<String>,
    /// Port to use when a client omits one.
    #[arg(long, default_value_t = 80)]
    port: u16,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
    /// Connect the stack to a switch (unix:/path or tcp://host:port) instead
    /// of a loopback link, so it reaches stacks on other hosts.
    #[arg(long)]
    switch: Option<String>,
    /// With a TCP --switch: read the shared token of the switch from this
    /// file. Without it, the token is the variable PODNET_SWITCH_TOKEN.
    #[arg(long, value_name = "PATH", requires = "switch")]
    switch_token_file: Option<PathBuf>,
    /// The IPv4 address of this stack on the switch, for example 10.66.0.3.
    #[arg(long)]
    address: Option<std::net::Ipv4Addr>,
    /// With --switch: drop this part of the packets that this stack sends
    /// to the switch (0.0 to 1.0), for tests.
    #[arg(long, default_value_t = 0.0, value_parser = probability, requires = "switch")]
    drop: f64,
    /// With --switch: send this part of the packets two times (0.0 to
    /// 1.0), for tests.
    #[arg(long, default_value_t = 0.0, value_parser = probability, requires = "switch")]
    duplicate: f64,
    /// With --switch: send this part of the packets out of order (0.0 to
    /// 1.0), for tests.
    #[arg(long, default_value_t = 0.0, value_parser = probability, requires = "switch")]
    reorder: f64,
    /// With --switch: the seed of the fault sequence.
    #[arg(long, default_value_t = 1, requires = "switch")]
    seed: u64,
    /// With --switch: serve the shim control socket with this abstract name.
    /// A shim program with PODNET_VNET_CONTROL=NAME that binds a virtual address
    /// can then accept connections from other hosts.
    #[arg(long)]
    control: Option<String>,
    /// With --switch: make a remote virtual address reachable for shim
    /// programs on this host, repeatable: --import 10.66.0.3:8080
    #[arg(long = "import", value_name = "VIRT")]
    imports: Vec<String>,
}

#[derive(Args, Debug)]
struct SwitchArgs {
    /// Where to accept stacks: unix:/path or tcp://host:port. A TCP
    /// listener needs a shared token (PODNET_SWITCH_TOKEN or
    /// --switch-token-file); a unix listener takes the same user only.
    #[arg(long, default_value = "unix:/tmp/podnet-vnet.switch")]
    listen: String,
    /// With a TCP --listen: read the shared token from this file. Without
    /// it, the token is the variable PODNET_SWITCH_TOKEN. Each TCP peer must
    /// send it.
    #[arg(long, value_name = "PATH")]
    switch_token_file: Option<PathBuf>,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
    #[command(flatten)]
    detach: DetachArgs,
}

async fn net(args: NetArgs) -> Result<()> {
    match args.command {
        NetCommand::Demo => {
            let report = podnet::vnet::stack::loopback_proof();
            print!("{}", report.render());
            if !report.passed() {
                bail!("userspace TCP proof did not complete");
            }
            Ok(())
        }
        NetCommand::Doctor { json } => {
            podnet::udp::check_edge_env()?;
            let mut probes = podnet::vnet::doctor::run();
            let target = podnet::udp::probe_target();
            probes.push(
                tokio::task::spawn_blocking(move || podnet::vnet::doctor::udp_probe(target))
                    .await
                    .context("the UDP probe")?,
            );
            let verdict = podnet::vnet::doctor::verdict(&probes);
            if json {
                use podnet::vnet::doctor::ProbeResult;
                let rows: Vec<_> = probes
                    .iter()
                    .map(|p| {
                        let (status, detail) = match &p.result {
                            ProbeResult::Ok(d) => ("ok", d.as_str()),
                            ProbeResult::Fail(d) => ("fail", d.as_str()),
                            ProbeResult::Unknown(d) => ("unknown", d.as_str()),
                            ProbeResult::Unsupported => ("unsupported", ""),
                        };
                        serde_json::json!({"probe": p.name, "status": status, "detail": detail})
                    })
                    .collect();
                println!(
                    "{}",
                    podnet::status::stamped(
                        serde_json::json!({"probes": rows, "verdict": verdict})
                    )
                );
                return Ok(());
            }
            print!("{}", podnet::vnet::doctor::render(&probes));
            print!("\n{}", podnet::vnet::doctor::NEEDS);
            println!("\n{verdict}");
            if verdict.starts_with("podnet-vnet: not ready") {
                println!("podnet-vnet: the host conditions that podnet handles: https://github.com/Azathothas/podnet/blob/main/docs/target-environment.md");
            }
            Ok(())
        }
        NetCommand::Shim(args) => net_shim(args),
        NetCommand::Addresses { json } => {
            let subnet = VirtualSubnet::default();
            if json {
                let examples: Vec<_> = [53u16, 80, 443, 8080]
                    .iter()
                    .map(|port| {
                        let addr =
                            VirtAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 66, 0, 2)), *port);
                        Ok(serde_json::json!({
                            "address": addr.to_string(),
                            "abstract_name": addr.abstract_name()?,
                        }))
                    })
                    .collect::<Result<_>>()?;
                println!(
                    "{}",
                    serde_json::json!({
                        "v4_subnet": subnet.v4.to_string(),
                        "v6_subnet": subnet.v6.to_string(),
                        "gateway_v4": subnet.gateway(podnet::vnet::Family::V4).to_string(),
                        "gateway_v6": subnet.gateway(podnet::vnet::Family::V6).to_string(),
                        "examples": examples,
                    })
                );
                return Ok(());
            }
            println!("podnet-vnet: v4 subnet {}", subnet.v4);
            println!("podnet-vnet: v6 subnet {}", subnet.v6);
            println!(
                "podnet-vnet: gateway  {} / {}",
                subnet.gateway(podnet::vnet::Family::V4),
                subnet.gateway(podnet::vnet::Family::V6)
            );
            // Issue 254: the columns have names.
            println!("podnet-vnet: {:<20} ABSTRACT SOCKET", "ADDRESS");
            for port in [53u16, 80, 443, 8080] {
                let addr = VirtAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 66, 0, 2)), port);
                println!("podnet-vnet: {addr:<20} \\0{}", addr.abstract_name()?);
            }
            Ok(())
        }
        NetCommand::Proxy(args) => net_proxy(args).await,
        NetCommand::Switch(args) => {
            let listen = podnet::vnet::proxy::ProxyListen::parse(&args.listen)?;
            // Issue 309: a TCP switch needs a shared token.
            let token = podnet::vnet::switch::token(args.switch_token_file.as_deref())
                .fault(Fault::Usage)?;
            if let Some(token) = &token {
                podnet::report::hide(token);
            }
            if matches!(listen, podnet::vnet::proxy::ProxyListen::Tcp(_)) && token.is_none() {
                return Err(anyhow::anyhow!(
                    "a TCP switch needs a shared token: set {}, or give --switch-token-file",
                    podnet::vnet::switch::TOKEN_VARIABLE
                ))
                .fault(Fault::Usage);
            }
            let switch = podnet::vnet::switch::serve(listen, token).await?;
            // Issue 300: the bound address (a TCP port 0 gives the port).
            println!("podnet: switch   {}", switch.listen);
            podnet::detach::ready(listen_doc(&switch.listen));
            sleep_or_signal(args.run_for).await;
            switch.abort();
            Ok(())
        }
        NetCommand::Tailscale(args) => net_tailscale(args).await,
        NetCommand::Socksify(args) => net_socksify(args),
        NetCommand::TsShims(args) => net_ts_shims(args),
    }
}

fn net_shim(args: ShimArgs) -> Result<()> {
    let directory = args
        .out
        .clone()
        .map(Ok)
        .unwrap_or_else(|| podnet::state::exec_dir("podnet-vnet"))?;
    let shim = match podnet::vnet::shim::locate() {
        Some(shim) if args.out.is_none() => shim,
        _ => podnet::vnet::shim::build(&directory)?,
    };
    let options = podnet::vnet::shim::ShimOptions {
        log: args.log,
        map_loopback: args.map_loopback,
        ..podnet::vnet::shim::ShimOptions::default()
    };
    let env = options.environment(&shim.path);
    if args.json {
        let object: serde_json::Map<String, serde_json::Value> = env
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        println!("{}", serde_json::to_string_pretty(&object)?);
    } else {
        println!("podnet: shim     {}", shim.path.display());
        println!("podnet: origin   {:?}", shim.origin);
        for (key, value) in &env {
            println!("  export {key}={value}");
        }
    }
    Ok(())
}

/// A probability from 0.0 to 1.0 (issue 196).
fn probability(value: &str) -> std::result::Result<f64, String> {
    let p: f64 = value
        .parse()
        .map_err(|_| format!("{value} is not a number"))?;
    if !(0.0..=1.0).contains(&p) {
        return Err(format!("{value} is not from 0.0 to 1.0"));
    }
    Ok(p)
}

async fn net_proxy(args: ProxyArgs) -> Result<()> {
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
enum RealTarget {
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
trait DialStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> DialStream for T {}

async fn net_tailscale(args: TailscaleArgs) -> Result<()> {
    use podnet::vnet::proxy::ProxyListen;
    use podnet::vnet::tailscale::{self, Dialer};

    let listen = ProxyListen::parse(&args.listen)?;
    // The LocalAPI socket of tailscaled must answer before the front door
    // starts: before, a missing tailscaled was found only at the first
    // SOCKS request, and the command exited 0.
    tokio::net::UnixStream::connect(&args.socket)
        .await
        .with_context(|| {
            format!(
                "the LocalAPI socket {} of tailscaled does not answer: start tailscaled, or give --socket",
                args.socket
            )
        })
        .fault(Fault::Unavailable)?;
    let proxy = tailscale::serve(Dialer::new(&args.socket), listen, args.port).await?;
    // Issue 300: the bound address (a TCP port 0 gives the port).
    println!("podnet: proxy    {}", proxy.listen);
    println!("podnet: localapi {}", args.socket);
    println!("podnet: note     run tailscaled with --tun=userspace-networking");
    println!("podnet: shim     eval \"$(podnet net socksify --socket <listen-path>)\"");
    sleep_or_signal(args.run_for).await;
    proxy.abort();
    Ok(())
}

fn print_environment(environment: Vec<(String, String)>, json: bool, export: &str) -> Result<()> {
    if json {
        let object: serde_json::Map<String, serde_json::Value> = environment
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        println!("{}", serde_json::to_string_pretty(&object)?);
    } else {
        for (key, value) in &environment {
            println!("{export}{key}={value}");
        }
    }
    Ok(())
}

fn net_socksify(args: SocksifyArgs) -> Result<()> {
    let directory = args
        .out
        .clone()
        .map(Ok)
        .unwrap_or_else(|| podnet::state::exec_dir("podnet-socks"))?;
    let shim = match podnet::vnet::shim::locate_socks() {
        Some(shim) if args.out.is_none() => shim,
        _ => podnet::vnet::shim::build_socks(&directory)?,
    };
    let preload = match std::env::var("LD_PRELOAD") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", shim.path.display()),
        _ => shim.path.display().to_string(),
    };
    let mut environment = vec![
        ("LD_PRELOAD".to_string(), preload),
        ("PODNET_SOCKS_PROXY".to_string(), args.socket.clone()),
    ];
    if args.log {
        environment.push(("PODNET_SOCKS_LOG".to_string(), "1".to_string()));
    }
    if !args.json {
        eprintln!("podnet: shim     {}", shim.path.display());
        eprintln!("podnet: origin   {:?}", shim.origin);
    }
    print_environment(environment, args.json, "export ")
}

fn net_ts_shims(args: TsShimsArgs) -> Result<()> {
    use podnet::vnet::tailscale_ssh;

    let directory = args
        .out
        .clone()
        .map(Ok)
        .unwrap_or_else(|| podnet::state::exec_dir("podnet-ts-shims"))?;
    let mut user = tailscale_ssh::current_user();
    if let Some(name) = args.user {
        user.name = name;
    }
    if let Some(uid) = args.uid {
        user.uid = uid;
    }
    if let Some(gid) = args.gid {
        user.gid = gid;
    }
    if let Some(shell) = args.shell {
        user.shell = shell;
    }
    let shims = tailscale_ssh::install(&directory, std::slice::from_ref(&user))?;
    let environment = tailscale_ssh::client_environment(&shims);
    if !args.json {
        println!("podnet: shims    {}", shims.dir.display());
        println!(
            "podnet: user     {} uid={} gid={}",
            user.name, user.uid, user.gid
        );
        println!("podnet: passwd   {}", shims.passwd.display());
        println!("podnet: fakepwd  {}", shims.fakepwd.display());
        println!(
            "podnet: daemon   PATH={}:$PATH tailscaled ... --statedir {}",
            shims.dir.display(),
            shims.dir.display()
        );
        println!("podnet: note     --statedir lets the daemon keep its SSH host keys");
    }
    print_environment(environment, args.json, "  export ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issues 253 and 254: a lint of each help screen. No issue numbers of
    /// this project, no `[env: X=]`, no `<a|b>` value name next to a list
    /// of possible values, and each shell of completions.
    #[test]
    fn each_help_screen_passes_the_lint() {
        fn walk(cmd: &clap::Command, path: String, out: &mut Vec<(String, String)>) {
            let mut cmd = cmd.clone();
            out.push((path.clone(), cmd.render_long_help().to_string()));
            for sub in cmd.get_subcommands() {
                if sub.get_name() != "help" {
                    walk(sub, format!("{path} {}", sub.get_name()), out);
                }
            }
        }
        let mut screens = Vec::new();
        let mut root = Cli::command();
        root.build();
        walk(&root, "podnet".into(), &mut screens);
        let mut faults = Vec::new();
        for (path, help) in &screens {
            for line in help.lines() {
                let lower = line.to_ascii_lowercase();
                if let Some(at) = lower.find("issue ") {
                    if lower[at + 6..].starts_with(|c: char| c.is_ascii_digit()) {
                        faults.push(format!("{path}: an issue number: {line}"));
                    }
                }
                if line.contains("=]") && line.contains("[env: ") {
                    faults.push(format!("{path}: an env value bracket: {line}"));
                }
                if let Some(at) = line.find(" <") {
                    let name = &line[at + 2..];
                    if let Some(end) = name.find('>') {
                        let value = &name[..end];
                        if value.contains('|')
                            && !value.contains("--")
                            && !line.trim_start().starts_with("Usage:")
                        {
                            faults.push(format!("{path}: a value name with |: {line}"));
                        }
                    }
                }
            }
        }
        assert!(faults.is_empty(), "{}", faults.join("\n"));
        let completions = &screens
            .iter()
            .find(|(p, _)| p == "podnet completions")
            .unwrap()
            .1;
        assert!(completions.contains("PowerShell"), "{completions}");
        assert!(completions.contains("Elvish"), "{completions}");
    }

    // Issue 271: the idle clock of a share starts when the session serves.
    // A control that was built 1.1 s before does not end a session with
    // --idle-secs 1 at the first check (5 s); in 60 s of the paused clock
    // the watch does not end.
    #[tokio::test(start_paused = true)]
    async fn the_idle_clock_starts_when_the_session_serves() {
        let control = Arc::new(ShareControl::default());
        std::thread::sleep(Duration::from_millis(1100));
        let watch = idle_watch(vec![control], 1);
        let ended = tokio::time::timeout(Duration::from_secs(60), watch).await;
        assert!(ended.is_err(), "the watch ended at the first check");
    }

    /// E1: each command of podnet is in one group of the top help.
    #[test]
    fn each_command_is_in_one_help_group() {
        let cmd = Cli::command();
        let mut names: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        names.push("help".into());
        let listed: Vec<&str> = HELP_GROUPS
            .iter()
            .flat_map(|(_, n)| n.iter().copied())
            .collect();
        for name in &names {
            let count = listed.iter().filter(|l| **l == name.as_str()).count();
            assert_eq!(count, 1, "{name} is in {count} groups");
        }
        for name in &listed {
            assert!(names.iter().any(|n| n == name), "{name} is no command");
        }
        let help = top_command().render_help().to_string();
        assert!(help.contains("Start here:"), "{help}");
        assert!(!help.contains("(issue "), "{help}");
        assert_eq!(first_sentence("Test it: the proxy. More"), "Test it");
        assert_eq!(first_sentence("One command (issue 87): x"), "One command");
    }

    /// E12: a server command with no terminal names --detach.
    #[test]
    fn a_foreground_server_with_no_terminal_gets_one_line() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let tunnel = argv(&["podnet", "tunnel", "--url", "http://localhost:1"]);
        let line = foreground_hint(Some("tunnel"), &tunnel, false, true).unwrap();
        assert!(
            line.contains("--detach") && line.contains("--run-for"),
            "{line}"
        );
        assert!(
            foreground_hint(Some("tunnel"), &tunnel, false, false).is_none(),
            "a terminal"
        );
        assert!(
            foreground_hint(Some("tunnel"), &tunnel, true, true).is_none(),
            "a detached child"
        );
        assert!(foreground_hint(Some("status"), &tunnel, false, true).is_none());
        for flag in ["--detach", "--run-for=5", "--exit-on-verify"] {
            let mut with = tunnel.clone();
            with.push(flag.into());
            assert!(
                foreground_hint(Some("tunnel"), &with, false, true).is_none(),
                "{flag}"
            );
        }
        assert!(foreground_hint(Some("relay node"), &tunnel, false, true).is_some());
    }

    /// E9: the arguments of cloudflared for a tunnel.
    #[test]
    fn cloudflared_arguments_work() {
        let run = |a: &[&str]| -> Vec<String> {
            cloudflared_compat(a.iter().map(Into::into).collect())
                .into_iter()
                .map(|o| o.into_string().unwrap())
                .collect()
        };
        assert_eq!(
            run(&["podnet", "--no-autoupdate", "tunnel", "run", "--token", "T"]),
            ["podnet", "tunnel", "--token", "T"]
        );
        assert_eq!(
            run(&["podnet", "tunnel", "--loglevel", "debug", "--url", "u"]),
            ["podnet", "tunnel", "-v", "--url", "u"]
        );
        assert_eq!(
            run(&["podnet", "tunnel", "--loglevel=warn"]),
            ["podnet", "tunnel", "-q"]
        );
        assert_eq!(
            run(&["podnet", "tunnel", "--loglevel", "info"]),
            ["podnet", "tunnel"]
        );
        // Not for another command, and not after --.
        let other = [
            "podnet",
            "warp",
            "run",
            "--",
            "tunnel",
            "run",
            "--no-autoupdate",
        ];
        assert_eq!(run(&other), other);
        let other = ["podnet", "serve", "--name", "tunnel", "--dir", "run"];
        assert_eq!(run(&other), other);
        // A parse of the result works.
        let parsed = top_command().try_get_matches_from(run(&[
            "podnet",
            "tunnel",
            "run",
            "--no-autoupdate",
            "--loglevel",
            "error",
            "--url",
            "http://127.0.0.1:1",
        ]));
        assert!(parsed.is_ok(), "{parsed:?}");
        let err = top_command()
            .try_get_matches_from(["podnet", "tunnel", "--logfile", "x"])
            .unwrap_err();
        let hints = usage_hints(&err);
        assert!(
            hints[0].contains("--logfile is a flag of cloudflared"),
            "{hints:?}"
        );
        assert_eq!(hints.len(), 1, "{hints:?}");
    }

    /// E7: an example is in the help of its command.
    #[test]
    fn the_help_of_a_command_has_its_examples() {
        let help = |path: &[&str]| -> String {
            let mut cmd = top_command();
            for name in path {
                cmd = cmd.find_subcommand(name).unwrap().clone();
            }
            cmd.render_long_help().to_string()
        };
        let tunnel = help(&["tunnel"]);
        assert!(tunnel.contains("Examples:"), "{tunnel}");
        assert!(
            tunnel.contains("podnet tunnel --url http://127.0.0.1:8080"),
            "{tunnel}"
        );
        assert!(!tunnel.contains("podnet warp"), "{tunnel}");
        let node = help(&["relay", "node"]);
        assert!(
            node.contains("podnet relay node --to 127.0.0.1:22"),
            "{node}"
        );
        assert_eq!(
            example_path(&Cli::command(), "podnet warp proxy -r 1080"),
            "podnet warp proxy"
        );
        // Each example belongs to a command (not to podnet alone).
        for e in podnet::manual::facts::EXAMPLES
            .iter()
            .filter(|e| e.command.starts_with("podnet "))
        {
            assert_ne!(
                example_path(&Cli::command(), e.command),
                "podnet",
                "{}",
                e.command
            );
        }
    }

    /// E8: a word that is no command names the command for it.
    #[test]
    fn a_word_that_is_no_command_gets_a_hint() {
        let hint = |w: &str| word_hint(w).unwrap_or_default();
        assert!(hint("8080").contains("podnet tunnel --url http://localhost:8080"));
        assert!(hint("https://example.org").contains("podnet tunnel --url https://example.org"));
        assert!(hint("wss://x.example").contains("podnet connect --local"));
        assert!(hint("/").contains("podnet serve --dir /"));
        assert!(hint("Cargo.toml").contains("podnet share --mode download --file Cargo.toml"));
        assert_eq!(word_hint("tunel"), None);
        assert_eq!(word_hint("123456"), None, "not a port");
    }

    /// E10: an unknown command or flag names the version and the update.
    #[test]
    fn an_unknown_command_names_the_version() {
        let err = top_command()
            .try_get_matches_from(["podnet", "8080"])
            .unwrap_err();
        let lines = usage_hints(&err);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains(env!("CARGO_PKG_VERSION")), "{lines:?}");
        assert!(lines[1].contains("podnet update --check"), "{lines:?}");
        let err = top_command()
            .try_get_matches_from(["podnet", "tunnel", "--bogus"])
            .unwrap_err();
        assert!(usage_hints(&err)[0].contains("'--bogus'"));
        let err = top_command()
            .try_get_matches_from(["podnet", "tunnel", "--port", "x"])
            .unwrap_err();
        assert!(
            usage_hints(&err).is_empty(),
            "a bad value is no unknown flag"
        );
    }

    fn share_args(argv: &[&str]) -> ShareArgs {
        let cli = Cli::try_parse_from(["podnet", "share"].iter().chain(argv)).unwrap();
        match cli.command {
            Command::Share(args) => args,
            other => panic!("{other:?}"),
        }
    }

    // Issue 118: the mode follows the flags; flags of two modes are an
    // error. Before, --file with no --mode gave an upload session.
    #[test]
    fn the_share_mode_follows_the_flags() {
        let mode = |argv: &[&str]| share_mode(&share_args(argv));
        assert_eq!(mode(&["--file", "f"]).unwrap(), ModeArg::Download);
        assert_eq!(mode(&["--port", "3000"]).unwrap(), ModeArg::Proxy);
        assert_eq!(mode(&["--mode", "upload"]).unwrap(), ModeArg::Upload);
        assert_eq!(mode(&["--dir", "d"]).unwrap(), ModeArg::Upload);
        assert_eq!(
            mode(&["--mode", "download", "--file", "f"]).unwrap(),
            ModeArg::Download
        );
        for bad in [
            // Issue 250: no mode flag is an error.
            &[][..],
            &["--file", "f", "--port", "1"][..],
            &["--mode", "upload", "--file", "f"][..],
            &["--mode", "proxy", "--dir", "d"][..],
        ] {
            let err = mode(bad).unwrap_err();
            assert_eq!(podnet::exit::code_of(&err), 64, "{bad:?}: {err}");
        }
    }

    // The IPv6-only kit, 0002: warp up --tun gives its child the front door
    // and the TLS name.
    #[test]
    fn the_pairs_of_listen_identity() {
        let main = std::path::Path::new("/s/warp.json");
        let pairs = identity_pairs(
            &[
                "tcp://127.0.0.1:40001=/s/b.json".into(),
                "unix:/run/c.sock=/s/c.json".into(),
            ],
            Some(main),
            &["tcp://127.0.0.1:40000".into()],
        )
        .unwrap();
        assert_eq!(pairs.len(), 2);
        // Issue 178: the listener of --listen.
        assert!(identity_pairs(
            &["tcp://127.0.0.1:40000=/s/b.json".into()],
            Some(main),
            &["tcp://127.0.0.1:40000".into()],
        )
        .is_err());
        assert_eq!(pairs[1].1, PathBuf::from("/s/c.json"));
        for bad in [
            vec!["127.0.0.1:40001=/s/warp.json"],
            vec!["127.0.0.1:40001=/s/b.json", "127.0.0.1:40002=/s/b.json"],
            vec!["127.0.0.1:40001=/s/b.json", "127.0.0.1:40001=/s/c.json"],
            vec!["127.0.0.1:40001"],
            vec!["=/s/b.json"],
            vec!["nothing=/s/b.json"],
        ] {
            let specs: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert!(identity_pairs(&specs, Some(main), &[]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_front_doors_of_a_scan() {
        assert_eq!(
            parse_door("162.159.198.1").unwrap().to_string(),
            "162.159.198.1:443"
        );
        assert_eq!(parse_door("162.159.198.1:8443").unwrap().port(), 8443);
        assert_eq!(
            parse_door("2606:4700:103::1").unwrap().to_string(),
            "[2606:4700:103::1]:443"
        );
        assert_eq!(parse_door("[2606:4700:103::1]:443").unwrap().port(), 443);
        assert!(parse_door("engage.cloudflareclient.com").is_err());
        assert!(parse_door("162.159.198.0/24").is_err());
    }

    #[test]
    fn warp_up_tun_keeps_the_front_door() {
        let cli = Cli::try_parse_from([
            "podnet",
            "warp",
            "--masque-endpoint",
            "[2606:4700:103::2]:443",
            "--masque-sni",
            "example.test",
            "--ephemeral",
            "up",
            "--tun",
        ])
        .unwrap();
        let Command::Warp(args) = cli.command else {
            panic!("not warp")
        };
        let argv = warp_up_tun_args(&args, 30);
        let has = |a: &str, b: &str| argv.windows(2).any(|w| w[0] == a && w[1] == b);
        assert!(
            has("--masque-endpoint", "[2606:4700:103::2]:443"),
            "{argv:?}"
        );
        assert!(has("--masque-sni", "example.test"), "{argv:?}");
        assert!(argv.contains(&"--ephemeral".to_string()));
        let tun = argv.iter().position(|a| a == "tun").unwrap();
        assert!(argv.iter().position(|a| a == "--masque-endpoint").unwrap() < tun);
        let parsed = Cli::try_parse_from(std::iter::once("podnet".to_string()).chain(argv));
        assert!(parsed.is_ok(), "the argv parses");
    }

    // Issues 110 and 116: a unix-only warp up gets warp exec and
    // ssh-config, and no eval line.
    #[test]
    fn the_agent_commands_follow_the_listeners() {
        let unix_only = agent_commands(true, false);
        assert!(
            !unix_only.iter().any(|c| c.contains("eval")),
            "{unix_only:?}"
        );
        assert!(unix_only.iter().any(|c| c.contains("podnet warp exec")));
        assert!(unix_only.iter().any(|c| c.contains("ssh-config")));
        let tcp = agent_commands(true, true);
        assert!(tcp[0].starts_with("eval"), "{tcp:?}");
        let direct = agent_commands(false, true);
        assert_eq!(direct, ["podnet agent status", "podnet agent down"]);
    }

    // Issue 115: with the TCP listener refused, the first line names the
    // unix socket that works.
    #[test]
    fn the_warp_up_summary_starts_with_what_works() {
        let socket = std::path::Path::new("/run/podnet/warp.sock");
        let lines = up_summary(false, 40000, true, socket);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("runs on unix:/run/podnet/warp.sock"),
            "{lines:?}"
        );
        assert!(lines[0].contains("podnet warp exec"), "{lines:?}");
        assert!(up_summary(true, 40000, true, socket).is_empty());
        assert_eq!(up_summary(true, 40000, false, socket).len(), 1);
    }

    /// Issue 101: once the stop is armed (at the ready line), a SIGTERM
    /// ends the work of `until_stop_or` (the verify) with `None`: a clean
    /// stop, not the default action. The only test here that takes
    /// signals: the stop request is global to the process.
    #[test]
    fn a_sigterm_after_the_ready_line_stops_the_verify_cleanly() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            install_signals();
            podnet::detach::arm_stop();
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                // SAFETY: kill() to this process.
                unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
            });
            let out = tokio::time::timeout(
                Duration::from_secs(10),
                until_stop_or(None, std::future::pending::<()>()),
            )
            .await
            .expect("the signal ends the wait");
            assert!(out.is_none());
            // The stop request stays: a later wait ends at once.
            assert!(until_stop_or(None, async { 1 }).await.is_none());
        });
    }

    /// Issue 179: --run-for ends the verify.
    #[tokio::test]
    async fn until_stop_or_ends_at_the_deadline() {
        let deadline = deadline_of(Some(0));
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            until_stop_or(deadline, std::future::pending::<()>()),
        )
        .await
        .expect("the deadline ends the wait");
        assert!(out.is_none());
    }

    /// warp probe targets (issue 67): a name, an IPv4 and an IPv6 address
    /// with a port; no port, port 0 or an empty host is refused.
    #[test]
    fn probe_targets_take_a_name_or_an_address() {
        assert_eq!(
            split_host_port("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_host_port("1.1.1.1:443").unwrap(),
            ("1.1.1.1".into(), 443)
        );
        assert_eq!(
            split_host_port("[2606:4700::1]:80").unwrap(),
            ("2606:4700::1".into(), 80)
        );
        for bad in ["example.com", "example.com:0", ":443", "a b:1", "host:http"] {
            assert!(split_host_port(bad).is_err(), "{bad}");
        }
    }

    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    /// Each example of the manual is a command line that the parser accepts.
    #[test]
    fn each_example_of_the_manual_parses() {
        for example in podnet::manual::facts::EXAMPLES {
            let words: Vec<&str> = example.command.split_whitespace().collect();
            assert_eq!(words[0], "podnet", "{}", example.command);
            if words.get(1) == Some(&"pod") {
                // pod has its own parser, in podnet-netns.
                continue;
            }
            if let Err(err) = Cli::try_parse_from(&words) {
                panic!("the example {:?} does not parse: {err}", example.command);
            }
        }
    }

    /// The manual names each command and each flag of the command tree.
    #[test]
    fn the_manual_names_each_command_and_flag() {
        let manual = podnet::manual::model::build(Cli::command());
        let text = podnet::manual::text::render(&manual);
        fn walk(cmd: &clap::Command, path: &mut Vec<String>, text: &str) {
            for sub in cmd.get_subcommands().filter(|c| c.get_name() != "help") {
                path.push(sub.get_name().to_string());
                assert!(
                    text.contains(&format!("podnet {}", path.join(" "))),
                    "the manual has no section for podnet {}",
                    path.join(" ")
                );
                for arg in sub.get_arguments().filter(|a| !a.is_hide_set()) {
                    if let Some(long) = arg.get_long() {
                        if long != "help" && long != "version" {
                            assert!(
                                text.contains(&format!("--{long}")),
                                "the manual has no --{long} (podnet {})",
                                path.join(" ")
                            );
                        }
                    }
                }
                walk(sub, path, text);
                path.pop();
            }
        }
        walk(&Cli::command(), &mut Vec::new(), &text);
        assert!(
            text.contains("podnet-netns"),
            "the pod section has the podnet-netns usage"
        );
    }

    #[test]
    fn the_warp_proxy_of_warp_up_parses() {
        let cli =
            Cli::try_parse_from(["podnet", "warp", "--no-relay", "up", "--port", "40100"]).unwrap();
        let Command::Warp(args) = cli.command else {
            panic!("not warp")
        };
        let argv = warp_up_args(&args, 40100, std::path::Path::new("/r/warp.sock"), 30);
        let parsed =
            Cli::try_parse_from(std::iter::once("podnet".to_string()).chain(argv)).unwrap();
        let Command::Warp(inner) = parsed.command else {
            panic!("not warp: the child command line")
        };
        assert!(inner.no_relay);
        match inner.command {
            WarpCommand::Proxy { listen, detach, .. } => {
                assert_eq!(listen, ["tcp://127.0.0.1:40100", "unix:/r/warp.sock"]);
                assert!(detach.detach);
                assert_eq!(detach.name.as_deref(), Some("warp"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_bad_command_line_is_a_usage_error() {
        let err = Cli::try_parse_from(["podnet", "tunel"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
        assert!(
            err.to_string().contains("tunnel"),
            "clap suggests the nearest command"
        );
    }

    #[test]
    fn the_command_name_of_the_report() {
        let argv = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(
            command_name(&argv("podnet warp run -- curl")).as_deref(),
            Some("warp run")
        );
        assert_eq!(
            command_name(&argv("podnet tunnel --url x")).as_deref(),
            Some("tunnel")
        );
        assert_eq!(command_name(&argv("podnet nothing")), None);
        // Issue 181: options before the command are skipped.
        for (line, want) in [
            ("podnet -q tunnel", "tunnel"),
            ("podnet -vv doctor", "doctor"),
            ("podnet --proxy http://x:1 warp run -- curl", "warp run"),
            (
                "podnet --color never --log-format json net doctor",
                "net doctor",
            ),
            ("podnet --ca-file=a.pem status", "status"),
        ] {
            assert_eq!(command_name(&argv(line)).as_deref(), Some(want), "{line}");
        }
    }

    // Issue 173: the classes of warp license and agent up.
    #[test]
    fn license_and_expose_classes() {
        let api = |status| {
            anyhow::Error::new(podnet::warp::register::ApiError {
                status,
                body: String::new(),
            })
            .context("PUT /reg/{id}/account")
        };
        assert!(matches!(license_fault(&api(400)), Fault::Usage));
        assert!(matches!(license_fault(&api(403)), Fault::Unavailable));
        assert!(matches!(license_fault(&api(500)), Fault::Unavailable));
        assert!(matches!(
            license_fault(&anyhow::anyhow!("no route")),
            Fault::Unavailable
        ));
        let exposed = serde_json::json!([
            {"state": "ready"},
            {"state": "failed"},
            {"state": "origin-unreachable"}
        ]);
        assert_eq!(exposes_failed(&exposed), 2);
        assert_eq!(exposes_failed(&serde_json::json!([])), 0);
    }

    // Issue 178: an empty license key is a usage error; a text field has no
    // quotes; warp_plus_active follows the account.
    #[test]
    fn warp_license_and_status_fields() {
        let err = Cli::try_parse_from(["podnet", "warp", "license", ""]).unwrap_err();
        assert_eq!(err.exit_code(), 2, "clap error");
        assert!(non_empty_key("  ").is_err());
        assert_eq!(non_empty_key(" k ").unwrap(), "k");
        assert_eq!(plain_value(&serde_json::json!("free")), "free");
        assert_eq!(plain_value(&serde_json::json!(5)), "5");
        assert_eq!(plain_value(&serde_json::Value::Null), "-");
        let free = serde_json::json!({"account_type": "free", "warp_plus": true});
        assert_eq!(warp_plus_label(&free), "no");
        let plus = serde_json::json!({"account_type": "limited", "premium_data": 10});
        assert_eq!(warp_plus_label(&plus), "yes");
    }

    #[test]
    fn the_pod_keeps_its_double_dash() {
        let v = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(
            pod_args_of(&v("podnet -v pod -- true"), &v("true")),
            v("-- true")
        );
        assert_eq!(
            pod_args_of(&v("podnet pod -x u -- a"), &v("-x u -- a")),
            v("-x u -- a")
        );
    }
}
