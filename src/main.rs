//! cfrs command line.

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
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use cfrs::config::{load_file, Config};
use cfrs::exit::{Fault, ResultExt};
use cfrs::gate::Gate;
use cfrs::ingress::{ForwardTarget, Ingress, IngressRule, OriginOptions, Service};
use cfrs::net::BoxedIo;
use cfrs::share::{ShareConfig, ShareControl, ShareMode};
use cfrs::vnet::{VirtAddr, VirtualSubnet};
use cfrs::ws::{self, LocalSpec};
use cfrs::{Protocol, Transport, Tunnel};

#[derive(Parser, Debug)]
#[command(
    name = "cfrs",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CFRS_BUILD_COMMIT"), ")"),
    about = "Cloudflare tunnels and the WARP client for hosts with strong network limits"
)]
struct Cli {
    /// The only file of TLS roots (PEM) for each connection that cfrs opens
    /// as a client. Without it, cfrs reads SSL_CERT_FILE, else cfrs-ca.pem
    /// beside the binary, the system bundle and the compiled-in roots.
    #[arg(long, global = true, value_name = "PATH")]
    ca_file: Option<PathBuf>,
    /// The proxy for each connection: http://, socks5:// or socks5h://
    /// [user:password@]host[:port]. Without it, cfrs reads HTTPS_PROXY and
    /// ALL_PROXY. NO_PROXY names the targets that do not use a proxy.
    /// CFRS_PROXY gives the same value, and keeps a password out of the
    /// command line.
    #[arg(
        long,
        global = true,
        value_name = "URL",
        conflicts_with = "no_proxy",
        env = "CFRS_PROXY",
        hide_env_values = true
    )]
    proxy: Option<String>,
    /// Use no proxy, also when HTTPS_PROXY or ALL_PROXY is set.
    #[arg(long, global = true)]
    no_proxy: bool,
    /// Addresses for names, in place of DNS: HOST=IP[,HOST=IP]. CFRS_RESOLVE
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
    /// Print a completion script for a shell: bash, zsh, fish or elvish.
    ///
    /// Bash: cfrs completions bash > ~/.local/share/bash-completion/completions/cfrs.
    /// Zsh: cfrs completions zsh > ~/.zfunc/_cfrs (with ~/.zfunc in fpath).
    /// Fish: cfrs completions fish > ~/.config/fish/completions/cfrs.fish.
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
    Warp(WarpArgs),
    /// Run a program with all its traffic sent through a proxy (pod-netns).
    ///
    /// Give the pod-netns arguments after `pod`. See `cfrs pod --help`.
    #[command(disable_help_flag = true)]
    Pod {
        /// The pod-netns arguments.
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
    /// Start a cfrs command at boot and after a logout, with no root: a
    /// systemd user unit, else an @reboot line in the crontab.
    Autostart(AutostartArgs),
    /// One command for a sandbox with basic networking (issue 87): test
    /// what works, start WARP when it is needed, expose ports, and print
    /// what works now and the commands to use.
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
    Stop {
        /// The name of the instance (cfrs ps).
        #[arg(required_unless_present = "all")]
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
        /// The name of the instance (cfrs ps).
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
        /// The name of the instance (cfrs ps).
        name: String,
        /// Seconds to wait (else exit 69).
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
}

#[derive(Args, Debug)]
struct AutostartArgs {
    #[command(subcommand)]
    command: AutostartCommand,
}

#[derive(Subcommand, Debug)]
enum AutostartCommand {
    /// Add an entry that runs `cfrs ARGS`. The token and a proxy password
    /// go to a private env file (mode 0600), not to the unit, the crontab
    /// or the command line. Exit 69 when this host has no systemd user
    /// manager and no crontab.
    Add {
        /// The name of the entry (letters, digits, - and _).
        name: String,
        /// The cfrs command and its arguments, after `--`.
        #[arg(last = true, required_unless_present = "from")]
        args: Vec<String>,
        /// Take the command and its arguments from the detached instance
        /// INSTANCE (cfrs ps), with no --detach options.
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
    /// Test the host (cfrs doctor --agent), start cfrs warp up when direct
    /// networking does not do each task, start a detached quick tunnel for
    /// each --expose PORT, and print one JSON document.
    Up {
        /// Also add the block of cfrs warp up --persist to the shell files.
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
    /// Stop what cfrs agent up started and put back each change.
    Down,
    /// Print the state: the instances, cfrs warp up, and the doctor.
    Status,
}

#[derive(Args, Debug)]
struct DoctorArgs {
    /// Print one JSON document.
    #[arg(long)]
    json: bool,
    /// Test what dev work can do here: git over HTTPS and SSH, the package
    /// registries, UDP DNS, IPv6 and localhost, directly, through the proxy
    /// and through a running cfrs warp up; then print the commands to run.
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
    /// One section: a command (tunnel, "warp run") or a topic (environment,
    /// files, exit-status, examples, pod).
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
    /// The tag to install, for example v0.3.0-beta.2. Default: the newest
    /// release (a prerelease only when this binary is a prerelease).
    #[arg(long, value_name = "TAG")]
    version: Option<String>,
    /// Put the binary before the last update (cfrs.prev) back, with no
    /// network. A second --rollback goes forward again.
    #[arg(long, conflicts_with_all = ["check", "version"])]
    rollback: bool,
}

#[derive(Args, Clone, Debug)]
struct PortsArgs {
    /// Print one JSON object: {"ports": [PORT, ...]}.
    #[arg(long)]
    json: bool,
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
    /// one transfer faster.
    #[arg(long, default_value_t = 2, global = true, value_parser = clap::value_parser!(u8).range(1..=8))]
    ha_connections: u8,
    /// Edge protocol: quic (UDP 7844), http2 (TCP 7844), or auto (quic, then http2).
    #[arg(long, default_value = "auto", global = true, value_parser = ["auto", "quic", "http2", "h2"])]
    protocol: String,
    /// How to reach the edge: auto (try 7844, fall back to WARP on 443),
    /// direct (port 7844), warp (carried on TCP 443) or relay (HTTP/2 in a
    /// WebSocket to the relay of --relay, on TCP 443).
    #[arg(long, default_value = "auto", global = true, value_parser = ["auto", "direct", "warp", "relay"])]
    transport: String,
    /// The WebSocket-to-TCP relay of --transport relay. CFRS_RELAY_TOKEN
    /// gives a token; without it, cfrs mints one.
    #[arg(long, value_name = "URL", global = true, env = "CFRS_RELAY", default_value = cfrs::ws_relay::DEFAULT_RELAY)]
    relay: String,
    /// Keep the WARP device and MASQUE key here and resume them next run.
    /// Without it, every run registers a new anonymous device.
    #[arg(long, value_name = "PATH", global = true)]
    warp_identity: Option<PathBuf>,
    /// How the next edge leg starts: staggered (when the leg before has not
    /// registered in 2 s, or at once when it fails) or serial (only after the
    /// leg before failed).
    #[arg(long, global = true, default_value = "staggered", env = "CFRS_LEG_FAILOVER", value_parser = ["staggered", "serial"])]
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
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long, global = true)]
    run_for: Option<u64>,
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
}

impl TunnelOpts {
    fn show(&self) -> Show {
        Show {
            qr: self.qr,
            json: self.json,
        }
    }

    fn apply(&self, mut config: Config) -> Result<Config> {
        config.service_url = self.service_url.clone();
        if let Some(user_agent) = &self.user_agent {
            config.user_agent = user_agent.clone();
        }
        config.ha_connections = self.ha_connections.clamp(1, 8);
        config.protocol = Protocol::parse(&self.protocol)?;
        config.transport = Transport::parse(&self.transport)?;
        if config.transport == Transport::Relay {
            cfrs::ws_relay::set(
                cfrs::ws_relay::Relay::from_env(Some(&self.relay)).fault(Fault::Usage)?,
            );
        }
        config.warp_identity = self.warp_identity.clone();
        config.verify = !self.no_verify;
        config.failover = cfrs::race::Failover::parse(&self.leg_failover)?;
        Ok(config)
    }
}

/// The options of a command that can run in the background (issue 70).
#[derive(Args, Clone, Debug, Default)]
struct DetachArgs {
    /// Run in the background: cfrs prints one JSON document when the
    /// command is ready (its URL or its listen address) and exits 0. The
    /// instance keeps running when the shell or the terminal closes. cfrs
    /// ps, logs, wait and stop manage it.
    #[arg(long)]
    detach: bool,
    /// The name of the detached instance. Default: the command and a hash
    /// of its arguments. A second start with the same name and the same
    /// arguments gives the same instance.
    #[arg(long, value_name = "NAME", requires = "detach")]
    name: Option<String>,
    /// Seconds to wait for the instance to be ready (else exit 75).
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    ready_timeout: u64,
    /// Stop a running instance of the same name that has other arguments,
    /// and start this one.
    #[arg(long, requires = "detach")]
    replace: bool,
    /// Do not start the instance again when it ends. Without it, a
    /// supervisor starts it again with a backoff (1 s to 30 s), but not
    /// after exit 64 or 78. A quick tunnel gets a new URL; cfrs ps shows it.
    #[arg(long, requires = "detach")]
    no_restart: bool,
}

impl DetachArgs {
    fn options(&self) -> cfrs::detach::Options {
        cfrs::detach::Options {
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
    #[arg(long)]
    url: Option<String>,
    /// HTTP origin on a unix socket.
    #[arg(long)]
    unix: Option<PathBuf>,
    /// HTTP origin on 127.0.0.1:<PORT>.
    #[arg(long)]
    port: Option<u16>,
    /// Raw TCP origin.
    #[arg(long)]
    tcp: Option<String>,
    /// Expose a raw stream over a WebSocket endpoint (tcp://host:port or unix:/path).
    #[arg(long)]
    forward: Option<String>,
    /// cloudflared's built-in hello world.
    #[arg(long)]
    hello_world: bool,
    /// cloudflared-style YAML config with ingress rules.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN: other users of
    /// the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
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
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN: other users of
    /// the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    Upload,
    Download,
    Proxy,
}

#[derive(Args, Debug)]
struct ShareArgs {
    #[command(flatten)]
    common: TunnelOpts,
    /// Session mode.
    #[arg(long, value_enum, default_value_t = ModeArg::Upload)]
    mode: ModeArg,
    /// Directory that receives uploads.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// File to share (download mode).
    #[arg(long)]
    file: Option<PathBuf>,
    /// Local HTTP port to share (proxy mode).
    #[arg(long)]
    port: Option<u16>,
    /// Require a 6-digit PIN (always on for proxy mode).
    #[arg(long)]
    password: bool,
    /// Stop the tunnel after the first successful transfer.
    #[arg(long)]
    stop_after: bool,
    /// Stop after this many idle seconds (0 disables).
    #[arg(long, default_value_t = 900)]
    idle_secs: u64,
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN: other users of
    /// the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
}

#[derive(Args, Debug)]
struct ConnectArgs {
    /// Public WebSocket URL, e.g. wss://<host>/__cfrs/ws.
    remote: String,
    /// Local listeners, repeatable: tcp://[bind:]port or unix:///path.
    #[arg(short = 'L', long = "local", required = true)]
    locals: Vec<String>,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
}

#[derive(Args, Debug)]
struct QrArgs {
    /// URL to encode.
    url: String,
}

#[derive(Args, Debug)]
struct DemoArgs {
    #[command(flatten)]
    common: TunnelOpts,
    /// Exit as soon as the public URL has been fetched.
    #[arg(long)]
    exit_on_verify: bool,
    /// Named-tunnel token. Prefer the variable TUNNEL_TOKEN: other users of
    /// the host can read a command line.
    #[arg(long, env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: Option<String>,
}

fn main() {
    // pod-netns forks and makes its own runtime. Start it before the async
    // runtime of cfrs exists.
    // args() panics on an argument that is not UTF-8 (issue 57); clap then
    // reports the bad argument as a usage error.
    // A detached child (issue 70) closes the descriptors that it got and
    // drops its flag before anything else.
    let args = cfrs::detach::prepare(std::env::args_os().collect());
    let argv: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if argv.get(1).map(String::as_str) == Some("pod") {
        std::process::exit(pod_netns::main_with_args(&argv[2..]));
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            // Help that the user asked for exits 0. Help that comes up
            // because a subcommand is missing (cfrs net) is a usage error.
            let code = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => cfrs::exit::SUCCESS,
                _ => cfrs::exit::USAGE,
            };
            let _ = err.print();
            if code != cfrs::exit::SUCCESS {
                cfrs::report::send(command_name(&argv).as_deref(), code, None);
            }
            std::process::exit(code);
        }
    };
    let command = command_name(&argv);
    if let Some(detach) = detach_of(&cli.command).filter(|d| d.detach) {
        let name = command.clone().unwrap_or_default();
        if !cfrs::detach::is_child() {
            std::process::exit(cfrs::detach::start(&name, &detach.options()));
        }
        if let Err(err) = cfrs::detach::child_begin() {
            eprintln!("cfrs: --detach: {err:#}");
            std::process::exit(cfrs::detach::TEMPFAIL);
        }
    } else if cfrs::detach::is_child() {
        eprintln!("cfrs: --detach-child is for cfrs itself");
        std::process::exit(cfrs::exit::USAGE);
    }
    if let Some(path) = &cli.ca_file {
        cfrs::trust::set_ca_file(path.clone());
    }
    if let Err(err) = network_options(&cli) {
        let err = cfrs::exit::fault(cfrs::exit::Fault::Usage, err);
        eprintln!("{}", cfrs::report::error_line(&err));
        let code = cfrs::exit::code_of(&err);
        cfrs::report::send(command.as_deref(), code, Some(&err));
        std::process::exit(code);
    }
    // A command that only prints ends at a closed stdout (cfrs status |
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
        "cfrs=warn"
    } else {
        match cli.verbose {
            0 => "cfrs=info",
            1 => "cfrs=debug",
            _ => "cfrs=trace",
        }
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.is_empty() => EnvFilter::try_new(&value).unwrap_or_else(|e| {
            // Before, a bad RUST_LOG gave the default level with no word.
            eprintln!("cfrs: RUST_LOG={value:?} does not parse ({e}); the log level is {level}");
            EnvFilter::new(level)
        }),
        _ => EnvFilter::new(level),
    };
    // Colours only on a terminal: a log file or a pipe gets plain text.
    let ansi = match cli.color.as_str() {
        "always" => true,
        "never" => false,
        _ => {
            std::io::IsTerminal::is_terminal(&std::io::stderr())
                && std::env::var_os("NO_COLOR").is_none()
        }
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(cfrs::report::TeeStderr);
    if cli.log_format == "json" {
        builder.json().with_ansi(false).init();
    } else {
        builder.with_ansi(ansi).init();
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
    if let Err(err) = result {
        let code = cfrs::exit::code_of(&err);
        let line = cfrs::report::error_line(&err);
        // The report has the error in "error"; "messages" holds the log
        // lines before it (issue 55: the line was in both).
        eprintln!("{line}");
        cfrs::report::send(command.as_deref(), code, Some(&err));
        std::process::exit(code);
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
        if !cfrs::detach::is_child() && !signal_ignored(libc::SIGHUP) {
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
                            if !cfrs::detach::stop_armed() || *tx.borrow() {
                                // SAFETY: signal() and raise() with a
                                // valid signal number.
                                unsafe {
                                    libc::signal(number, libc::SIG_DFL);
                                    libc::raise(number);
                                }
                                continue;
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

/// Ready on SIGINT (Ctrl-C), SIGTERM (systemd, Docker, Kubernetes, cfrs
/// stop) or SIGHUP (the terminal closed): each starts the same clean
/// shutdown, and the exit code is 0. A detached instance ignores SIGHUP.
/// A signal that came before this call is not lost.
async fn shutdown_signal() -> std::io::Result<()> {
    install_signals();
    cfrs::detach::arm_stop();
    let mut rx = STOP.get().expect("installed").clone();
    let _ = rx.wait_for(|stop| *stop).await;
    Ok(())
}

/// Ready after `run_for` seconds (when given), or on a stop signal.
async fn sleep_or_signal(run_for: Option<u64>) {
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                _ = shutdown_signal() => {}
            }
        }
        None => {
            let _ = shutdown_signal().await;
        }
    }
}

/// Run `cfrs ARGS` and give its last line as JSON (the ready document of
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
        bail!("cfrs {} exited {}", args.join(" "), out.status);
    }
    let last = text.lines().last().unwrap_or("");
    serde_json::from_str(last).with_context(|| format!("the output of cfrs {}", args.join(" ")))
}

/// `cfrs agent up`, `down` and `status`.
async fn agent(command: AgentCommand) -> Result<()> {
    let timeout = Duration::from_secs(4);
    match command {
        AgentCommand::Up {
            persist,
            expose,
            port,
            warp,
        } => {
            let before = cfrs::agent::run(timeout).await;
            let direct_enough = before
                .rows
                .iter()
                .all(|r| r.direct == cfrs::agent::Outcome::Ok)
                && before.udp_dns.works();
            let mut doc = serde_json::json!({});
            let mut warp_doc = serde_json::Value::Null;
            if warp || !direct_enough || before.warp_up {
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
                        eprintln!("cfrs: agent up: cfrs warp up failed: {err:#}");
                        doc["warp_error"] = format!("{err:#}").into();
                    }
                }
            }
            let mut exposed = Vec::new();
            for p in &expose {
                let name = format!("expose-{p}");
                let base = vec![
                    "tunnel".to_string(),
                    "--port".into(),
                    p.to_string(),
                    "--detach".into(),
                    "--name".into(),
                    name.clone(),
                ];
                let result = run_self_json(&base).or_else(|first| {
                    eprintln!("cfrs: agent up: the tunnel of port {p} failed ({first:#}); trying --transport relay");
                    let mut relay = base.clone();
                    relay.extend(["--transport".into(), "relay".into(), "--replace".into()]);
                    run_self_json(&relay)
                });
                match result {
                    Ok(d) => {
                        exposed.push(serde_json::json!({"port": p, "name": name, "url": d["url"]}))
                    }
                    Err(err) => {
                        exposed.push(serde_json::json!({"port": p, "error": format!("{err:#}")}))
                    }
                }
            }
            let after = cfrs::agent::run(timeout).await;
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
            let mut commands: Vec<String> = Vec::new();
            if mode == "warp" {
                commands
                    .push("eval \"$(cfrs warp env)\"   # proxy variables for this shell".into());
                commands.push(
                    "cfrs warp exec -- CMD   # any program, also static binaries and UDP".into(),
                );
                commands.push(
                    "cfrs warp ssh-config --host github.com >> ~/.ssh/config   # git over SSH"
                        .into(),
                );
            }
            commands.push("cfrs agent status".into());
            commands.push("cfrs agent down".into());
            doc["event"] = "agent".into();
            doc["mode"] = mode.into();
            doc["warp"] = warp_doc;
            doc["exposed"] = exposed.into();
            doc["works"] = works.into();
            doc["udp_dns"] = after.udp_dns.works().into();
            doc["ipv6"] = after.ipv6.works().into();
            doc["commands"] = commands.into();
            doc["advice"] = after.advice.clone().into();
            println!("{doc}");
            Ok(())
        }
        AgentCommand::Down => {
            let dir = cfrs::instances::run_dir().fault(Fault::Config)?;
            for entry in cfrs::instances::list(&dir) {
                if entry.record.name.starts_with("expose-") {
                    cfrs::detach::stop(&dir, &entry.record.name, Duration::from_secs(10))?;
                    println!("cfrs: agent down: stopped {}", entry.record.name);
                }
            }
            cfrs::warp::up::down()
        }
        AgentCommand::Status => {
            instances_ps(false)?;
            println!();
            let report = cfrs::agent::run(timeout).await;
            print!("{}", cfrs::agent::text(&report));
            Ok(())
        }
    }
}

/// `cfrs ps`: the instances of the run directory.
fn instances_ps(json: bool) -> Result<()> {
    let dir = cfrs::instances::run_dir().fault(Fault::Config)?;
    let list = cfrs::instances::list(&dir);
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
        println!("{}", serde_json::json!({ "instances": items }));
        return Ok(());
    }
    if list.is_empty() {
        println!("cfrs: no detached instance");
        return Ok(());
    }
    println!("NAME                     STATE          PID RST     AGE  URL/LISTEN");
    let now = cfrs::instances::now();
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
    }
    Ok(())
}

/// `cfrs stop`.
fn instances_stop(name: Option<String>, all: bool, timeout: u64) -> Result<()> {
    let dir = cfrs::instances::run_dir().fault(Fault::Config)?;
    let names: Vec<String> = if all {
        cfrs::instances::list(&dir)
            .into_iter()
            .map(|e| e.record.name)
            .collect()
    } else {
        let name = name.unwrap_or_default();
        if cfrs::instances::read(&dir, &name).is_none() || !cfrs::instances::is_alive(&dir, &name) {
            cfrs::instances::remove(&dir, &name);
            return Err(cfrs::exit::fault(
                Fault::Unavailable,
                anyhow::anyhow!("no instance {name} runs (cfrs ps)"),
            ));
        }
        vec![name]
    };
    for name in names {
        cfrs::detach::stop(&dir, &name, std::time::Duration::from_secs(timeout))?;
        println!("cfrs: stopped  {name}");
    }
    Ok(())
}

/// `cfrs logs`.
async fn instances_logs(name: &str, follow: bool, lines: Option<usize>) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let dir = cfrs::instances::run_dir().fault(Fault::Config)?;
    let path = cfrs::instances::paths(&dir, name).log;
    let text = std::fs::read(&path).map_err(|e| {
        cfrs::exit::fault(
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

/// `cfrs warp up`: start `warp proxy` detached (instance `warp`) with the
/// WARP options of this command line, then write the env file.
fn warp_up(args: &WarpArgs, port: u16, persist: bool, ready_timeout: u64) -> Result<()> {
    let socket = cfrs::warp::up::socket_path()?;
    let argv = warp_up_args(args, port, &socket, ready_timeout);
    let doc = cfrs::warp::up::start(&argv)?;
    let env = cfrs::warp::up::write_env(port, &socket)?;
    if persist {
        for file in cfrs::warp::up::persist(&env)? {
            eprintln!("cfrs: warp up: a block in {}", file.display());
        }
    }
    let mut doc = doc;
    doc["env"] = env.display().to_string().into();
    doc["socket"] = socket.display().to_string().into();
    doc["persist"] = persist.into();
    println!("{doc}");
    Ok(())
}

/// The command line of the `warp proxy --detach` of `cfrs warp up`.
fn warp_up_args(
    args: &WarpArgs,
    port: u16,
    socket: &std::path::Path,
    ready_timeout: u64,
) -> Vec<String> {
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
    argv.extend([
        "proxy".into(),
        "--listen".into(),
        format!("tcp://127.0.0.1:{port}"),
        "--listen".into(),
        format!("unix:{}", socket.display()),
        "--detach".into(),
        "--name".into(),
        cfrs::warp::up::INSTANCE.into(),
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
        Command::Warp(args) => match &args.command {
            WarpCommand::Proxy { detach, .. } => Some(detach),
            WarpCommand::Tun { detach, .. } => Some(detach),
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
    use cfrs::egress::{set_choice, Proxy, ProxyChoice};
    if let Some(spec) = &cli.proxy {
        cfrs::report::hide(spec);
        set_choice(ProxyChoice::Via(Proxy::parse(spec).context("--proxy")?));
    } else if cli.no_proxy {
        set_choice(ProxyChoice::Direct);
    }
    if let Some(list) = &cli.resolve {
        cfrs::resolve::set_pins(list).context("--resolve")?;
    }
    Ok(())
}

/// The command of `argv` for the report: `tunnel`, `warp run`, or `None`.
fn command_name(argv: &[String]) -> Option<String> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let mut words = Vec::new();
    for arg in argv.iter().skip(1) {
        if arg.starts_with('-') {
            break;
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
            let now = cfrs::update::rollback(&path).fault(Fault::Unavailable)?;
            println!(
                "{}: {now} (put back from {})",
                path.display(),
                cfrs::update::previous_of(&path).display()
            );
            Ok(())
        }
        Command::Update(args) => {
            use cfrs::update::Outcome;
            match cfrs::update::run(args.version.as_deref(), args.check)
                .await
                .fault(Fault::Unavailable)?
            {
                Outcome::UpToDate(tag) => println!("cfrs {tag} is the newest release"),
                Outcome::Available { current, tag } => {
                    println!("cfrs {current}; release {tag} is available (cfrs update)")
                }
                Outcome::Updated { from, to, path } => {
                    println!(
                        "cfrs {from} -> {to}: {} (signature and SHA-256 checked)",
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
            let dir = cfrs::instances::run_dir().fault(Fault::Config)?;
            let doc = cfrs::detach::wait_ready_record(
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
            clap_complete::generate(shell, &mut cmd, "cfrs", &mut script);
            match std::io::Write::write_all(&mut std::io::stdout(), &script) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                other => other.context("writing the completion script"),
            }
        }
        Command::Ports(args) => {
            let ports = cfrs::ports::listening_ports();
            if args.json {
                println!("{}", serde_json::json!({ "ports": ports }));
            } else {
                for port in ports {
                    println!("{port}");
                }
            }
            Ok(())
        }
        Command::Qr(args) => {
            print!("{}", cfrs::qr::render_terminal(&args.url)?);
            Ok(())
        }
        Command::Demo(args) => demo(args).await,
        Command::Net(args) => net(args).await,
        Command::Warp(args) => warp(args).await,
        Command::Pod { .. } => unreachable!("main runs pod before the runtime"),
        Command::Man(args) => {
            use clap::CommandFactory;
            let manual = cfrs::manual::model::build(Cli::command());
            let request = cfrs::manual::Request {
                section: (!args.section.is_empty()).then(|| args.section.join(" ")),
                no_pager: args.no_pager,
                roff: args.roff,
                json: args.json,
            };
            let text = cfrs::manual::body(&manual, &request)
                .map_err(|e| cfrs::exit::fault(cfrs::exit::Fault::Usage, anyhow::anyhow!(e)))?;
            let paged = !request.roff && !request.json;
            cfrs::manual::pager::show(&text, request.no_pager || !paged)?;
            Ok(())
        }
        Command::Doctor(args) if args.agent => {
            let report = cfrs::agent::run(Duration::from_secs(args.timeout.max(3))).await;
            if args.json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print!("{}", cfrs::agent::text(&report));
            }
            Ok(())
        }
        Command::Doctor(args) => {
            cfrs::udp::check_edge_env()?;
            cfrs::udp::Choice::from_env()?;
            let report = cfrs::doctor::run(cfrs::doctor::Options {
                samples: args.samples as usize,
                timeout: Duration::from_secs(args.timeout),
                ..cfrs::doctor::Options::default()
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
            println!("{}", cfrs::status::document());
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
    if let Some(token) = &args.token {
        cfrs::report::hide(token);
        config.credentials = cfrs::config::parse_token(token)?;
    } else if let Some(path) = &args.credentials_file {
        config.credentials = cfrs::config::parse_credentials_file(path)?;
    }

    if args.config.is_none() {
        let mut ingress = Ingress::new();
        if let Some(forward) = &args.forward {
            let target = ForwardTarget::parse(forward).fault(Fault::Usage)?;
            ingress = ingress.rule_with(IngressRule {
                hostname: None,
                path: Some(cfrs::ws::DEFAULT_PATH.to_string()),
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
            return Err(cfrs::exit::fault(
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
    // to answer 503.
    if !config
        .ingress
        .rules
        .iter()
        .any(|rule| !matches!(rule.service, Service::Forward(_)))
    {
        config.verify = false;
    }

    if args.common.check {
        return preflight(&config, args.common.show()).await;
    }
    run_tunnel(config, args.common.show(), args.common.run_for, vec![]).await
}

/// `--check`: print the report of the check, and fail when a check failed.
async fn preflight(config: &Config, show: Show) -> Result<()> {
    let report = cfrs::preflight::check(config).await;
    if show.json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.text());
    }
    let failed = report
        .checks
        .iter()
        .filter(|c| c.status == cfrs::preflight::Status::Fail)
        .count();
    if failed > 0 {
        bail!(
            "the check failed ({failed} of {}); nothing was started",
            report.checks.len()
        );
    }
    Ok(())
}

fn autostart(command: AutostartCommand) -> Result<()> {
    use cfrs::autostart;
    match command {
        AutostartCommand::Add { name, args, from } => {
            let args = match from {
                Some(instance) => {
                    let dir = cfrs::instances::run_dir().fault(Fault::Config)?;
                    let record = cfrs::instances::read(&dir, &instance).ok_or_else(|| {
                        cfrs::exit::fault(
                            Fault::Usage,
                            anyhow::anyhow!("no detached instance {instance} (cfrs ps)"),
                        )
                    })?;
                    cfrs::detach::without_detach_options(&record.args)
                }
                None => args,
            };
            let added = autostart::add(&name, &args, autostart::PROGRAM_LIMIT)?;
            println!(
                "cfrs: autostart {name} added ({}): {}",
                added.way.name(),
                added.detail
            );
            Ok(())
        }
        AutostartCommand::Remove { name } => {
            for line in autostart::remove(&name, autostart::PROGRAM_LIMIT)? {
                println!("cfrs: {line}");
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
            Err(anyhow::anyhow!("starting cfrs {}: {err}", args.join(" ")))
        }
    }
}

/// Split `host:port`, `[v6]:port` or `ip:port` into the host and the port.
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
        service = Some(Service::parse(url)?);
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
        if port == 0 {
            bail!("--port 0: give a port from 1 to 65535");
        }
        service = Some(Service::Http(format!("http://127.0.0.1:{port}")));
    }
    if let Some(addr) = &args.tcp {
        choices += 1;
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
    cfrs::init_crypto();
    if !(args.remote.starts_with("wss://") || args.remote.starts_with("ws://")) {
        return Err(cfrs::exit::fault(
            Fault::Usage,
            anyhow::anyhow!(
                "the remote {} is not a WebSocket URL: give wss://<host>/__cfrs/ws",
                args.remote
            ),
        ));
    }
    let mut tasks = Vec::new();
    for raw in &args.locals {
        let local = LocalSpec::parse(raw)?;
        let remote = args.remote.clone();
        match local {
            LocalSpec::Tcp { bind, port } => {
                let listener = tokio::net::TcpListener::bind((bind.as_str(), port))
                    .await
                    .with_context(|| format!("binding {bind}:{port}"))?;
                println!(
                    "cfrs: {} -> {remote}",
                    LocalSpec::Tcp {
                        bind: bind.clone(),
                        port
                    }
                    .describe()
                );
                tasks.push(tokio::spawn(accept_loop(listener, remote)));
            }
            LocalSpec::Unix(path) => {
                #[cfg(unix)]
                {
                    let listener = unix_listener(&path)?;
                    println!(
                        "cfrs: {} -> {remote}",
                        LocalSpec::Unix(path.clone()).describe()
                    );
                    tasks.push(tokio::spawn(accept_unix(listener, remote)));
                }
                #[cfg(not(unix))]
                {
                    let _ = remote;
                    bail!(
                        "unix sockets are not supported on this platform: {}",
                        path.display()
                    );
                }
            }
        }
    }
    sleep_or_signal(args.run_for).await;
    for task in tasks {
        task.abort();
    }
    Ok(())
}

async fn accept_loop(listener: tokio::net::TcpListener, remote: String) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let remote = remote.clone();
                tokio::spawn(async move {
                    let io: BoxedIo = Box::new(stream);
                    if let Err(err) = ws::connect_bridge(&remote, io).await {
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

#[cfg(unix)]
fn unix_listener(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    pod_netns::listen::bind_private(path)
        .with_context(|| format!("binding unix:{}", path.display()))
}

#[cfg(unix)]
async fn accept_unix(listener: tokio::net::UnixListener, remote: String) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let remote = remote.clone();
                tokio::spawn(async move {
                    let io: BoxedIo = Box::new(stream);
                    if let Err(err) = ws::connect_bridge(&remote, io).await {
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
    let mut config = Config::default();
    if let Some(token) = &args.token {
        cfrs::report::hide(token);
        config.credentials = cfrs::config::parse_token(token)?;
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

async fn share(args: ShareArgs) -> Result<()> {
    let mut share_config = match args.mode {
        ModeArg::Upload => {
            let dir = args.dir.clone().unwrap_or_else(default_upload_dir);
            ShareConfig::upload(dir)
        }
        ModeArg::Download => {
            let file = args.file.clone().context("download mode needs --file")?;
            ShareConfig::download(file)
        }
        ModeArg::Proxy => {
            let port = args.port.context("proxy mode needs --port")?;
            // A check sends no request to the origin: it only connects.
            if !args.common.check {
                cfrs::ports::confirm_local_http(port).await?;
            }
            ShareConfig::proxy(format!("127.0.0.1:{port}"))
        }
    };
    if args.password || matches!(args.mode, ModeArg::Proxy) {
        share_config.gate = Gate::pin();
    }
    share_config.stop_after = args.stop_after;

    let mut config = Config::default();
    if let Some(token) = &args.token {
        cfrs::report::hide(token);
        config.credentials = cfrs::config::parse_token(token)?;
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
        cfrs::report::hide(token);
        config.credentials = cfrs::config::parse_token(token)?;
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
        downloads.join("cfrs")
    } else {
        home.join("cfrs-uploads")
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
    if verify {
        handle.verify(None).await?;
        if let Some(url) = handle.url() {
            verified(show, url);
        }
    }
    cfrs::detach::ready(tunnel_doc(&handle, handle.url(), verify));
    serve_until(&handle, wait(run_for, controls)).await?;
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
    let base = handle
        .url()
        .unwrap_or("https://<your-named-tunnel-hostname>")
        .to_string();
    let public = format!("{}{}", base.trim_end_matches('/'), path);
    if show.json {
        println!(
            "{}",
            serde_json::json!({
                "event": "ready",
                "url": public,
                "tunnel_id": handle.tunnel_id().to_string(),
                "locations": handle.locations(),
                "pin": pin,
            })
        );
    } else {
        println!();
        println!("  cfrs: session  {public}");
        if let Some(pin) = &pin {
            println!("  cfrs: PIN      {pin}");
        }
        println!("  cfrs: edge     {}", handle.locations().join(", "));
        println!();
    }
    if show.qr {
        print!("{}", cfrs::qr::render_terminal(&public)?);
    }
    if verify && handle.url().is_some() {
        handle.verify_url(&public, None).await?;
        verified(show, &public);
    }
    let mut doc = tunnel_doc(&handle, Some(&public), verify);
    doc["pin"] = pin.clone().into();
    cfrs::detach::ready(doc);
    let controls = handle.share_controls();
    serve_until(&handle, wait_with_idle(run_for, controls, idle_secs)).await?;
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
    if exit_on_verify {
        handle.verify(Some("Hello, world! (cfrs)")).await?;
        if show.json {
            verified(show, handle.url().unwrap_or(""));
        } else {
            println!(
                "  cfrs: PROOF   {} -> HTTP 200 (built-in hello world)",
                handle.url().unwrap_or("")
            );
        }
        handle.shutdown().await;
        return Ok(());
    }
    handle.verify(Some("Hello, world! (cfrs)")).await?;
    cfrs::detach::ready(tunnel_doc(&handle, handle.url(), true));
    serve_until(&handle, wait(run_for, vec![])).await?;
    handle.shutdown().await;
    Ok(())
}

/// Serve until `done`, or until each edge leg has stopped for a cause: then
/// the command fails with the cause (exit 69).
async fn serve_until(
    handle: &cfrs::TunnelHandle,
    done: impl std::future::Future<Output = ()>,
) -> Result<()> {
    tokio::select! {
        _ = done => Ok(()),
        reason = handle.stopped() => Err(cfrs::exit::fault(
            Fault::Unavailable,
            anyhow::anyhow!("each edge connection stopped: {reason}"),
        )),
    }
}

/// The ready document of a tunnel for --detach.
fn tunnel_doc(handle: &cfrs::TunnelHandle, url: Option<&str>, verified: bool) -> serde_json::Value {
    serde_json::json!({
        "url": url,
        "verified": verified && url.is_some(),
        "tunnel_id": handle.tunnel_id().to_string(),
        "locations": handle.locations(),
    })
}

/// The ready document of a listener for --detach.
fn listen_doc(listen: &cfrs::vnet::proxy::ProxyListen) -> serde_json::Value {
    match listen {
        cfrs::vnet::proxy::ProxyListen::Unix(path) => {
            serde_json::json!({ "listen": format!("unix:{}", path.display()) })
        }
        cfrs::vnet::proxy::ProxyListen::Tcp(addr) => {
            serde_json::json!({ "listen": format!("tcp://{addr}") })
        }
    }
}

/// After a fetch of the public URL: one JSON line with --json.
fn verified(show: Show, url: &str) {
    if show.json {
        println!("{}", serde_json::json!({"event": "verified", "url": url}));
    }
}

fn announce(handle: &cfrs::TunnelHandle, show: Show) -> Result<()> {
    if show.json {
        println!(
            "{}",
            serde_json::json!({
                "event": "ready",
                "url": handle.url(),
                "tunnel_id": handle.tunnel_id().to_string(),
                "locations": handle.locations(),
            })
        );
    } else {
        announce_text(handle);
    }
    if show.qr {
        match handle.url() {
            Some(url) => print!("{}", cfrs::qr::render_terminal(url)?),
            None => tracing::warn!(
                "--qr: a named tunnel has its hostname in Cloudflare, and cfrs does not know it; no QR code"
            ),
        }
    }
    Ok(())
}

fn announce_text(handle: &cfrs::TunnelHandle) {
    println!();
    match handle.url() {
        Some(url) => println!("  cfrs: public   {url}"),
        None => println!(
            "  cfrs: tunnel   {} (named; hostname configured in Cloudflare)",
            handle.tunnel_id()
        ),
    }
    println!("  cfrs: edge     {}", handle.locations().join(", "));
    println!();
}

async fn wait(run_for: Option<u64>, controls: Vec<Arc<ShareControl>>) -> () {
    let stop_controls = async move {
        if controls.is_empty() {
            std::future::pending::<()>().await;
        }
        let mut set = tokio::task::JoinSet::new();
        for control in controls {
            set.spawn(async move { control.wait_stop().await });
        }
        let _ = set.join_next().await;
    };
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                _ = shutdown_signal() => {}
                _ = stop_controls => {}
            }
        }
        None => {
            tokio::select! {
                _ = shutdown_signal() => {}
                _ = stop_controls => {}
            }
        }
    }
}

async fn wait_with_idle(run_for: Option<u64>, controls: Vec<Arc<ShareControl>>, idle_secs: u64) {
    let idle = (idle_secs > 0).then(|| Duration::from_secs(idle_secs));
    let watch = {
        let controls = controls.clone();
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
    };
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                _ = shutdown_signal() => {}
                _ = wait_controls(controls) => {}
                _ = watch => {}
            }
        }
        None => {
            tokio::select! {
                _ = shutdown_signal() => {}
                _ = wait_controls(controls) => {}
                _ = watch => {}
            }
        }
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
struct NetArgs {
    #[command(subcommand)]
    command: NetCommand,
}

#[derive(Args, Debug)]
struct WarpArgs {
    /// The file that keeps the device and its MASQUE key, so that each run
    /// uses the same device. Default: warp.json in the state directory
    /// (see CFRS_STATE_DIR in cfrs man environment).
    #[arg(long, value_name = "PATH", global = true)]
    identity: Option<PathBuf>,
    /// Register a new device for this run only, and do not save it.
    #[arg(long, global = true, conflicts_with = "identity")]
    ephemeral: bool,
    /// Do not try the WebSocket relay (--relay, CFRS_RELAY) when the direct
    /// MASQUE path fails. Without it, cfrs tries the relay: the TLS to the
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
        /// The license key.
        key: String,
    },
    /// Make a new MASQUE key and enrol it. The old key stops working.
    Rotate,
    /// Remove the device from the WARP service and delete the saved file.
    Delete,
    /// Open the tunnel and test TCP connects through it.
    Probe {
        /// A TCP destination to reach through the tunnel, host:port.
        #[arg(long, value_delimiter = ',')]
        target: Vec<String>,
    },
    /// Run a local SOCKS5 and HTTP CONNECT proxy whose traffic goes through
    /// WARP (the proxy mode of the WARP client).
    Proxy {
        /// Where to accept clients: tcp://host:port or unix:/path.
        /// Repeatable: each listener serves the same WARP session.
        #[arg(long, default_value = "tcp://127.0.0.1:40000")]
        listen: Vec<String>,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Start WARP for this sandbox, in the background (issue 78): a
    /// detached warp proxy on 127.0.0.1:PORT and on a unix socket, and an
    /// env file with the proxy variables. Later shells join it with
    /// `eval "$(cfrs warp env)"`, `cfrs warp exec -- CMD`, `cfrs warp
    /// shell`, or --persist.
    Up {
        /// The TCP port of the proxy on 127.0.0.1.
        #[arg(long, default_value_t = 40000)]
        port: u16,
        /// Add a marked block to ~/.bashrc and ~/.profile: each new shell
        /// loads the env file, and an interactive shell runs under the pod
        /// (static binaries and UDP go through WARP too). cfrs warp down
        /// removes it.
        #[arg(long)]
        persist: bool,
        /// Seconds to wait for WARP to be ready.
        #[arg(long, default_value_t = 90)]
        ready_timeout: u64,
        /// With CAP_NET_ADMIN: send the whole host through WARP with warp
        /// tun --default-route (instance warp-tun), in place of the proxy.
        #[arg(long, conflicts_with = "persist")]
        tun: bool,
    },
    /// Stop what cfrs warp up started, and remove its env file and its
    /// block in ~/.bashrc and ~/.profile.
    Down,
    /// Print the proxy variables of the running cfrs warp up, for
    /// `eval "$(cfrs warp env)"`.
    Env,
    /// Run a program under the pod of the running cfrs warp up: TCP, DNS
    /// and UDP go through WARP, also for static binaries.
    Exec {
        /// A pod-netns rule, repeatable (see cfrs pod --help).
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
    /// Run $SHELL under the pod of the running cfrs warp up. When it does
    /// not run, the shell starts as it is (with the proxy variables when
    /// the env file is there).
    Shell,
    /// A byte pipe from stdin and stdout to HOST:PORT through WARP, for
    /// `ssh -o ProxyCommand='cfrs warp nc %h %p'` and git over SSH (issue
    /// 85). It uses the running cfrs warp up, else a WARP session of its
    /// own.
    Nc {
        host: String,
        port: u16,
        /// Go through the WebSocket relay (--relay) to HOST:PORT, with no
        /// WARP (TCP, IPv4).
        #[arg(long)]
        via_relay: bool,
    },
    /// Print an SSH config block and GIT_SSH_COMMAND that use cfrs warp nc.
    SshConfig {
        /// The Host pattern of the block.
        #[arg(long, default_value = "*")]
        host: String,
    },
    /// Make a TUN interface whose packets go through WARP. Needs
    /// CAP_NET_ADMIN and /dev/net/tun. Routes are not changed.
    Tun {
        /// The interface name.
        #[arg(long, default_value = "cfrs0")]
        interface: String,
        /// Send the whole host through WARP (issue 77): host routes keep the
        /// MASQUE connection outside, default routes go to the TUN (IPv4 and
        /// IPv6), DNS goes to 1.1.1.1. The default routes go away while the
        /// session is down; each change is put back at the end.
        #[arg(long)]
        default_route: bool,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a program with all its traffic sent through WARP. No root and no
    /// TUN device are necessary (pod-netns).
    Run {
        /// The backend: auto, netns-raw, netns or seccomp. netns-raw moves the
        /// raw packets of a namespace through WARP (TCP, UDP, ICMP, IPv6; no
        /// root). auto takes netns-raw when it works, else seccomp, so that
        /// UDP goes through WARP too.
        #[arg(long, default_value = "auto")]
        backend: String,
        /// A pod-netns rule, repeatable: domain:NAME=PROXY,
        /// domain:.SUFFIX=PROXY, cidr:NET/LEN=PROXY; PROXY may be direct.
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        /// The program keeps the proxy variables of this shell.
        #[arg(long)]
        keep_proxy_env: bool,
        /// Where a port that the program listens on is a unix socket
        /// (seccomp backend).
        #[arg(long, value_name = "DIR")]
        inbound_dir: Option<PathBuf>,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
}

async fn warp_client(args: &WarpArgs) -> Result<(cfrs::warp::WarpClient, Option<PathBuf>)> {
    let masque = cfrs::warp::MasqueOptions {
        no_relay: args.no_relay,
        endpoint: args.masque_endpoint,
        sni: args.masque_sni.clone(),
    };
    let (client, path) = warp_client_inner(args).await?;
    Ok((client.with_masque(masque), path))
}

async fn warp_client_inner(args: &WarpArgs) -> Result<(cfrs::warp::WarpClient, Option<PathBuf>)> {
    use cfrs::warp::WarpClient;
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
                eprintln!("cfrs: CFRS_STATE_DIR=none: the WARP device is not saved");
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

async fn warp(args: WarpArgs) -> Result<()> {
    // These commands use the running instance of cfrs warp up.
    match &args.command {
        WarpCommand::Up {
            tun: true,
            ready_timeout,
            ..
        } => {
            let mut argv = vec!["warp".to_string()];
            if args.no_relay {
                argv.push("--no-relay".into());
            }
            if let Some(path) = &args.identity {
                argv.push("--identity".into());
                argv.push(path.display().to_string());
            }
            argv.extend([
                "tun".to_string(),
                "--default-route".into(),
                "--detach".into(),
                "--name".into(),
                cfrs::warp::up::TUN_INSTANCE.into(),
                "--ready-timeout".into(),
                ready_timeout.to_string(),
            ]);
            let doc = cfrs::warp::up::start(&argv)?;
            println!("{doc}");
            return Ok(());
        }
        WarpCommand::Up {
            port,
            persist,
            ready_timeout,
            ..
        } => return warp_up(&args, *port, *persist, *ready_timeout),
        WarpCommand::Down => return cfrs::warp::up::down(),
        WarpCommand::Env => {
            print!("{}", cfrs::warp::up::env_text()?);
            return Ok(());
        }
        WarpCommand::Exec { rules, program } => {
            return Err(cfrs::warp::up::exec_in_pod(rules, program));
        }
        WarpCommand::Shell => return Err(cfrs::warp::up::shell()),
        WarpCommand::SshConfig { host } => {
            let exe = std::env::current_exe()?.canonicalize()?;
            print!("{}", cfrs::warp::nc::ssh_config(&exe, host));
            return Ok(());
        }
        WarpCommand::Nc {
            host,
            port,
            via_relay: true,
        } => {
            let relay = cfrs::ws_relay::Relay::from_env(None).fault(Fault::Config)?;
            let io = cfrs::warp::nc::via_relay(&relay, host, *port)
                .await
                .fault(Fault::Unavailable)?;
            return cfrs::warp::nc::pipe(io).await;
        }
        WarpCommand::Nc { host, port, .. } => {
            if let Some(io) = cfrs::warp::nc::via_running(host, *port).await? {
                return cfrs::warp::nc::pipe(io).await;
            }
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
        let path = match args.identity.clone() {
            Some(path) => Some(path),
            None => cfrs::warp::WarpClient::default_identity_path().fault(Fault::Config)?,
        };
        match path {
            Some(path) if path.exists() => {}
            Some(path) => {
                return Err(cfrs::exit::fault(
                    Fault::Config,
                    anyhow::anyhow!(
                        "no WARP identity at {}; run cfrs warp register first",
                        path.display()
                    ),
                ))
            }
            None => {
                return Err(cfrs::exit::fault(
                    Fault::Config,
                    anyhow::anyhow!(
                        "CFRS_STATE_DIR=none keeps no WARP identity; give --identity PATH"
                    ),
                ))
            }
        }
    }
    let (mut client, path) = warp_client(&args).await?;
    let save = |client: &cfrs::warp::WarpClient| -> Result<()> {
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
            let account = client.account().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&account)?);
                return Ok(());
            }
            print_device(&client, path.as_deref());
            let field = |name: &str| account.get(name).map(|v| v.to_string()).unwrap_or_default();
            println!("type        {}", field("account_type"));
            println!("warp+       {}", field("warp_plus"));
            println!("premium     {}", field("premium_data"));
            println!("quota       {}", field("quota"));
        }
        WarpCommand::License { key } => {
            cfrs::report::hide(&key);
            let account = client.set_license(&key).await?;
            save(&client)?;
            let field = |name: &str| account.get(name).map(|v| v.to_string()).unwrap_or_default();
            println!("license     set");
            println!("type        {}", field("account_type"));
            println!("warp+       {}", field("warp_plus"));
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
            println!("tunnel      up (TCP 443 only)");
            for (spec, host, port) in targets {
                let started = std::time::Instant::now();
                let attempt = async {
                    // A name is resolved by DNS through the tunnel.
                    let ip = cfrs::warp::proxy::resolve(&stack, &host).await?;
                    let addr = std::net::SocketAddr::new(ip, port);
                    let conn = stack.tcp_connect(addr).await?;
                    Ok::<_, anyhow::Error>((addr, conn))
                };
                match tokio::time::timeout(std::time::Duration::from_secs(12), attempt).await {
                    Ok(Ok((addr, conn))) => {
                        println!("OK          {spec} ({addr}) in {:?}", started.elapsed());
                        conn.close().await;
                    }
                    Ok(Err(err)) => println!("FAIL        {spec}: {err:#}"),
                    Err(_) => println!("TIMEOUT     {spec}"),
                }
            }
        }
        WarpCommand::Proxy {
            listen, run_for, ..
        } => {
            let listens = listen
                .iter()
                .map(|l| cfrs::vnet::proxy::ProxyListen::parse(l))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            let mut proxies = Vec::new();
            for listen in listens {
                proxies.push(cfrs::warp::proxy::serve(live.clone(), listen).await?);
            }
            for proxy in &proxies {
                match &proxy.listen {
                    cfrs::vnet::proxy::ProxyListen::Tcp(addr) => {
                        println!("cfrs: warp proxy  socks5h://{addr}  (and HTTP CONNECT)");
                        println!("  export ALL_PROXY=socks5h://{addr} HTTPS_PROXY=http://{addr}");
                    }
                    cfrs::vnet::proxy::ProxyListen::Unix(path) => {
                        println!("cfrs: warp proxy  unix:{}", path.display());
                        println!("  cfrs pod -x socks5://unix:{} -- PROGRAM", path.display());
                    }
                }
            }
            let mut doc = listen_doc(&proxies[0].listen);
            doc["listens"] = proxies
                .iter()
                .map(|p| listen_doc(&p.listen)["listen"].clone())
                .collect::<Vec<_>>()
                .into();
            cfrs::detach::ready(doc);
            sleep_or_signal(run_for).await;
            for proxy in &proxies {
                proxy.abort();
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
                .context("the device has no IPv4 address")?;
            let tun = cfrs::warp::tun::Tun::create(&name, address, 1280)?;
            let session = client.connect_raw().await?;
            let endpoint = client
                .device()
                .masque_endpoint()
                .map(|e| e.ip().to_string())
                .unwrap_or_default();
            println!("cfrs: tun      {} {address}/32 mtu 1280", tun.name);
            if let Some(v6) = client.device().ipv6() {
                match tun.add_ipv6(v6) {
                    Ok(()) => println!("cfrs: tun      {} {v6}/128", tun.name),
                    Err(err) => {
                        tracing::warn!(error = %format!("{err:#}"), "the TUN has no IPv6 address")
                    }
                }
            }
            println!(
                "cfrs: masque   {endpoint} (do not route this address into {})",
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
            println!(
                "  ip route add {endpoint}/32 via <your gateway>   # keep the session outside"
            );
            // --default-route (issue 77): the addresses of the MASQUE
            // connection stay outside the tunnel.
            let routes = if default_route {
                let mut hosts: Vec<String> = Vec::new();
                match cfrs::egress::proxy_for(&endpoint, 443) {
                    Some(proxy) => hosts.push(proxy.host().to_string()),
                    None => hosts.push(endpoint.clone()),
                }
                if !args.no_relay {
                    if let Ok(relay) = cfrs::ws_relay::Relay::from_env(None) {
                        hosts.push(relay.host().to_string());
                    }
                }
                let mut exempt: Vec<std::net::Ipv4Addr> = Vec::new();
                for host in hosts.iter().filter(|h| !h.is_empty()) {
                    for ip in cfrs::resolve::resolve(host).await.unwrap_or_default() {
                        if let std::net::IpAddr::V4(v4) = ip {
                            if !exempt.contains(&v4) {
                                exempt.push(v4);
                            }
                        }
                    }
                }
                let routes = cfrs::warp::route::Routes::setup(
                    &tun.name,
                    exempt.clone(),
                    client.device().ipv6().is_some(),
                )
                .fault(Fault::Unavailable)?;
                println!(
                    "cfrs: routes   the default routes go to {}; outside: {}",
                    tun.name,
                    exempt
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                Some(std::sync::Mutex::new(routes))
            } else {
                None
            };
            cfrs::detach::ready(serde_json::json!({
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
                            tracing::warn!(error = %format!("{err:#}"), "the default routes on the TUN");
                        }
                    }
                    if let Err(err) = cfrs::warp::tun::run(tun_ref, current).await {
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
        WarpCommand::Tun { .. } => bail!("cfrs warp tun is available on Linux only"),
        WarpCommand::Up { .. }
        | WarpCommand::Down
        | WarpCommand::Env
        | WarpCommand::Exec { .. }
        | WarpCommand::Shell
        | WarpCommand::SshConfig { .. } => unreachable!("handled before the client is made"),
        WarpCommand::Nc { host, port, .. } => {
            // No cfrs warp up runs: a session of this process.
            let stack = Arc::new(client.connect().await.fault(Fault::Unavailable)?);
            let target = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => pod_netns::socks::ProxyHost::Ip(ip),
                Err(_) => pod_netns::socks::ProxyHost::Domain(host.clone()),
            };
            let io = cfrs::warp::proxy::dial(stack, target, port)
                .await
                .fault(Fault::Unavailable)?;
            cfrs::warp::nc::pipe(Box::new(io)).await?;
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
                || (backend == "auto" && rules.is_empty() && pod_netns::raw::available());
            if raw {
                match warp_run_raw(&client, &program, keep_proxy_env).await {
                    Ok(code) => std::process::exit(code),
                    Err(err) if backend == "auto" => {
                        tracing::info!(error = %format!("{err:#}"), "the netns-raw backend cannot run here; the pod with a proxy runs");
                    }
                    Err(err) => return Err(cfrs::exit::fault(Fault::Unavailable, err)),
                }
            }
            let backend = if backend == "netns-raw" {
                "auto".to_string()
            } else {
                backend
            };
            let socket =
                std::env::temp_dir().join(format!("cfrs-warp-{}.sock", std::process::id()));
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            let proxy = cfrs::warp::proxy::serve(
                live,
                cfrs::vnet::proxy::ProxyListen::Unix(socket.clone()),
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
            // pod-netns makes its own runtime, so run it on a plain thread.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(pod_netns::main_with_args(&argv));
            });
            let code = done_rx.await.unwrap_or(1);
            proxy.abort();
            let _ = std::fs::remove_file(&socket);
            std::process::exit(code);
        }
    }
    Ok(())
}

/// `cfrs warp run --backend netns-raw`: the program in a raw pod whose TUN
/// packets go through WARP; a session that ends is opened again. Gives the
/// exit code of the program.
async fn warp_run_raw(
    client: &cfrs::warp::WarpClient,
    program: &[String],
    keep_proxy_env: bool,
) -> Result<i32> {
    let v4 = client
        .device()
        .ipv4()
        .context("the device has no IPv4 address")?;
    let mut session = Some(client.connect_raw().await?);
    let pod = pod_netns::raw::spawn(&pod_netns::raw::RawOptions {
        program: program.to_vec(),
        keep_proxy_env,
        v4,
        v6: client.device().ipv6(),
        mtu: cfrs::warp::ip::TUNNEL_MTU,
        nameserver: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    })?;
    let pid = pod.pid;
    let tun = cfrs::warp::tun::Tun::from_fd(pod.tun, "eth0")?;
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
            if let Err(err) = cfrs::warp::tun::run(&tun, current).await {
                tracing::warn!(error = %format!("{err:#}"), "the WARP session ended; opening a new one");
            }
        }
    };
    let exited = async {
        loop {
            if let Some(code) = pod_netns::raw::try_wait(pid) {
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

fn print_device(client: &cfrs::warp::WarpClient, path: Option<&std::path::Path>) {
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
        None => println!("saved       no (--ephemeral or CFRS_STATE_DIR=none)"),
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
    #[arg(long, default_value = pod_netns::tailscale::DEFAULT_SOCKET)]
    socket: String,
    /// Where to accept proxy clients: unix:/path or tcp://[bind:]port.
    #[arg(long, default_value = "unix:/tmp/cfrssocks.sock")]
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
    /// The unix socket of the front door (exported as CFRSSOCKS_PROXY). It
    /// is not --proxy: that is the global proxy URL of cfrs.
    #[arg(long, value_name = "PATH", default_value = "/tmp/cfrssocks.sock")]
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
    /// Directory for passwd, group, getent, id and fakepwd.so.
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
    #[arg(long, default_value = "unix:/tmp/cfrsnet.socks")]
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
    /// The IPv4 address of this stack on the switch, for example 10.66.0.3.
    #[arg(long)]
    address: Option<std::net::Ipv4Addr>,
    /// Drop this part of the sent packets (0.0 to 1.0), for tests.
    #[arg(long, default_value_t = 0.0)]
    drop: f64,
    /// Send this part of the packets two times (0.0 to 1.0), for tests.
    #[arg(long, default_value_t = 0.0)]
    duplicate: f64,
    /// Send this part of the packets out of order (0.0 to 1.0), for tests.
    #[arg(long, default_value_t = 0.0)]
    reorder: f64,
    /// The seed of the fault sequence.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// With --switch: serve the shim control socket with this abstract name.
    /// A shim program with CFRSNET_CONTROL=NAME that binds a virtual address
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
    /// Where to accept stacks: unix:/path or tcp://host:port.
    #[arg(long, default_value = "unix:/tmp/cfrsnet.switch")]
    listen: String,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
    #[command(flatten)]
    detach: DetachArgs,
}

async fn net(args: NetArgs) -> Result<()> {
    match args.command {
        NetCommand::Demo => {
            let report = cfrs::vnet::stack::loopback_proof();
            print!("{}", report.render());
            if !report.passed() {
                bail!("userspace TCP proof did not complete");
            }
            Ok(())
        }
        NetCommand::Doctor { json } => {
            cfrs::udp::check_edge_env()?;
            let mut probes = cfrs::vnet::doctor::run();
            let target = cfrs::udp::probe_target();
            probes.push(
                tokio::task::spawn_blocking(move || cfrs::vnet::doctor::udp_probe(target))
                    .await
                    .context("the UDP probe")?,
            );
            let verdict = cfrs::vnet::doctor::verdict(&probes);
            if json {
                use cfrs::vnet::doctor::ProbeResult;
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
                    serde_json::json!({"probes": rows, "verdict": verdict})
                );
                return Ok(());
            }
            print!("{}", cfrs::vnet::doctor::render(&probes));
            print!("\n{}", cfrs::vnet::doctor::NEEDS);
            println!("\n{verdict}");
            if verdict.starts_with("cfrsnet: not ready") {
                println!("cfrsnet: the host conditions that cfrs handles: https://github.com/Azathothas/cfrs/blob/main/docs/target-environment.md");
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
                        "gateway_v4": subnet.gateway(cfrs::vnet::Family::V4).to_string(),
                        "gateway_v6": subnet.gateway(cfrs::vnet::Family::V6).to_string(),
                        "examples": examples,
                    })
                );
                return Ok(());
            }
            println!("cfrsnet: v4 subnet {}", subnet.v4);
            println!("cfrsnet: v6 subnet {}", subnet.v6);
            println!(
                "cfrsnet: gateway  {} / {}",
                subnet.gateway(cfrs::vnet::Family::V4),
                subnet.gateway(cfrs::vnet::Family::V6)
            );
            for port in [53u16, 80, 443, 8080] {
                let addr = VirtAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 66, 0, 2)), port);
                println!("cfrsnet: {addr:<20} \\0{}", addr.abstract_name()?);
            }
            Ok(())
        }
        NetCommand::Proxy(args) => net_proxy(args).await,
        NetCommand::Switch(args) => {
            let listen = cfrs::vnet::proxy::ProxyListen::parse(&args.listen)?;
            let switch = cfrs::vnet::switch::serve(listen).await?;
            match &switch.listen {
                cfrs::vnet::proxy::ProxyListen::Unix(path) => {
                    println!("cfrs: switch   unix:{}", path.display())
                }
                cfrs::vnet::proxy::ProxyListen::Tcp(addr) => {
                    println!("cfrs: switch   tcp://{addr}")
                }
            }
            cfrs::detach::ready(listen_doc(&switch.listen));
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
        .unwrap_or_else(|| cfrs::state::exec_dir("cfrsnet"))?;
    let shim = match cfrs::vnet::shim::locate() {
        Some(shim) if args.out.is_none() => shim,
        _ => cfrs::vnet::shim::build(&directory)?,
    };
    let options = cfrs::vnet::shim::ShimOptions {
        log: args.log,
        map_loopback: args.map_loopback,
        ..cfrs::vnet::shim::ShimOptions::default()
    };
    let env = options.environment(&shim.path);
    if args.json {
        let object: serde_json::Map<String, serde_json::Value> = env
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect();
        println!("{}", serde_json::to_string_pretty(&object)?);
    } else {
        println!("cfrs: shim     {}", shim.path.display());
        println!("cfrs: origin   {:?}", shim.origin);
        for (key, value) in &env {
            println!("  export {key}={value}");
        }
    }
    Ok(())
}

async fn net_proxy(args: ProxyArgs) -> Result<()> {
    use cfrs::vnet::proxy::{ProxyListen, Resolver};

    let mut _link = None;
    let net = match &args.switch {
        None => Arc::new(cfrs::vnet::NetStack::loopback()),
        Some(switch) => {
            let address = args
                .address
                .context("--switch needs --address, the address of this stack")?;
            let config = cfrs::vnet::StackConfig {
                local_v4: address,
                ..cfrs::vnet::StackConfig::default()
            };
            let net = Arc::new(cfrs::vnet::NetStack::over_link(config));
            let faults = cfrs::vnet::switch::Faults {
                drop: args.drop,
                duplicate: args.duplicate,
                reorder: args.reorder,
                seed: args.seed,
            };
            let switch = ProxyListen::parse(switch)?;
            _link = Some(cfrs::vnet::switch::attach(&net, &switch, faults).await?);
            #[cfg(target_os = "linux")]
            {
                if let Some(name) = &args.control {
                    cfrs::vnet::switch::serve_control(net.clone(), name)?;
                    println!("cfrs: control  \\0{name}  (CFRSNET_CONTROL={name})");
                }
                for spec in &args.imports {
                    let virt: VirtAddr = spec.trim().parse()?;
                    cfrs::vnet::switch::import(net.clone(), virt)?;
                    println!("cfrs: import   {virt}");
                }
            }
            match &switch {
                ProxyListen::Unix(path) => {
                    println!("cfrs: switch   unix:{} as {address}", path.display())
                }
                ProxyListen::Tcp(addr) => println!("cfrs: switch   tcp://{addr} as {address}"),
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
    let mut proxy = cfrs::vnet::proxy::serve(net.clone(), listen, resolver, args.port).await?;
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
        println!("cfrs: forward  {virt} -> {}", real.describe());
    }
    match &proxy.listen {
        ProxyListen::Unix(path) => println!("cfrs: proxy    unix:{}", path.display()),
        ProxyListen::Tcp(addr) => println!("cfrs: proxy    tcp://{addr}"),
    }
    cfrs::detach::ready(listen_doc(&proxy.listen));
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
    use cfrs::vnet::proxy::ProxyListen;
    use cfrs::vnet::tailscale::{self, Dialer};

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
    match &proxy.listen {
        ProxyListen::Unix(path) => println!("cfrs: proxy    unix:{}", path.display()),
        ProxyListen::Tcp(addr) => println!("cfrs: proxy    tcp://{addr}"),
    }
    println!("cfrs: localapi {}", args.socket);
    println!("cfrs: note     run tailscaled with --tun=userspace-networking");
    println!("cfrs: shim     eval \"$(cfrs net socksify --socket <listen-path>)\"");
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
        .unwrap_or_else(|| cfrs::state::exec_dir("cfrssocks"))?;
    let shim = match cfrs::vnet::shim::locate_socks() {
        Some(shim) if args.out.is_none() => shim,
        _ => cfrs::vnet::shim::build_socks(&directory)?,
    };
    let preload = match std::env::var("LD_PRELOAD") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", shim.path.display()),
        _ => shim.path.display().to_string(),
    };
    let mut environment = vec![
        ("LD_PRELOAD".to_string(), preload),
        ("CFRSSOCKS_PROXY".to_string(), args.socket.clone()),
    ];
    if args.log {
        environment.push(("CFRSSOCKS_LOG".to_string(), "1".to_string()));
    }
    if !args.json {
        eprintln!("cfrs: shim     {}", shim.path.display());
        eprintln!("cfrs: origin   {:?}", shim.origin);
    }
    print_environment(environment, args.json, "export ")
}

fn net_ts_shims(args: TsShimsArgs) -> Result<()> {
    use cfrs::vnet::tailscale_ssh;

    let directory = args
        .out
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("cfrs-ts-shims"));
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
        println!("cfrs: shims    {}", shims.dir.display());
        println!(
            "cfrs: user     {} uid={} gid={}",
            user.name, user.uid, user.gid
        );
        println!("cfrs: passwd   {}", shims.passwd.display());
        println!("cfrs: fakepwd  {}", shims.fakepwd.display());
        println!(
            "cfrs: daemon   PATH={}:$PATH tailscaled ... --statedir {}",
            shims.dir.display(),
            shims.dir.display()
        );
        println!("cfrs: note     --statedir lets the daemon keep its SSH host keys");
    }
    print_environment(environment, args.json, "  export ")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for example in cfrs::manual::facts::EXAMPLES {
            let words: Vec<&str> = example.command.split_whitespace().collect();
            assert_eq!(words[0], "cfrs", "{}", example.command);
            if words.get(1) == Some(&"pod") {
                // pod has its own parser, in pod-netns.
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
        let manual = cfrs::manual::model::build(Cli::command());
        let text = cfrs::manual::text::render(&manual);
        fn walk(cmd: &clap::Command, path: &mut Vec<String>, text: &str) {
            for sub in cmd.get_subcommands().filter(|c| c.get_name() != "help") {
                path.push(sub.get_name().to_string());
                assert!(
                    text.contains(&format!("cfrs {}", path.join(" "))),
                    "the manual has no section for cfrs {}",
                    path.join(" ")
                );
                for arg in sub.get_arguments().filter(|a| !a.is_hide_set()) {
                    if let Some(long) = arg.get_long() {
                        if long != "help" && long != "version" {
                            assert!(
                                text.contains(&format!("--{long}")),
                                "the manual has no --{long} (cfrs {})",
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
            text.contains("pod-netns"),
            "the pod section has the pod-netns usage"
        );
    }

    #[test]
    fn the_warp_proxy_of_warp_up_parses() {
        let cli =
            Cli::try_parse_from(["cfrs", "warp", "--no-relay", "up", "--port", "40100"]).unwrap();
        let Command::Warp(args) = cli.command else {
            panic!("not warp")
        };
        let argv = warp_up_args(&args, 40100, std::path::Path::new("/r/warp.sock"), 30);
        let parsed = Cli::try_parse_from(std::iter::once("cfrs".to_string()).chain(argv)).unwrap();
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
        let err = Cli::try_parse_from(["cfrs", "tunel"]).unwrap_err();
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
            command_name(&argv("cfrs warp run -- curl")).as_deref(),
            Some("warp run")
        );
        assert_eq!(
            command_name(&argv("cfrs tunnel --url x")).as_deref(),
            Some("tunnel")
        );
        assert_eq!(command_name(&argv("cfrs nothing")), None);
    }
}
