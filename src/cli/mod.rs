//! The command line of the binary: the parse, the dispatch and the parts
//! that more than one command uses. Only the binary declares this module:
//! it has no public path.

pub(crate) mod argv;
pub(crate) mod help;
pub(crate) mod opts;
pub(crate) mod signals;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use podnet::exit::{Fault, ResultExt};

use crate::{
    agent, autostart, connect, demo, instances_logs, instances_ps, instances_stop, net, relay,
    serve, share, tunnel, warp, AgentCommand, AutostartArgs, ConnectArgs, DemoArgs, DoctorArgs,
    ManArgs, NetArgs, PortsArgs, QrArgs, RelayArgs, ServeArgs, ShareArgs, TunnelArgs, UpdateArgs,
    WarpArgs,
};

#[derive(Parser, Debug)]
#[command(
    name = "podnet",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("PODNET_BUILD_COMMIT"), ")"),
    about = "Cloudflare tunnels and the WARP client for hosts with strong network limits"
)]
pub(crate) struct Cli {
    /// A file of TLS roots (PEM). podnet uses only these roots for each
    /// connection that it opens as a client. Without it, podnet reads SSL_CERT_FILE, else podnet-ca.pem
    /// beside the binary, the system bundle and the compiled-in roots.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) ca_file: Option<PathBuf>,
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
    pub(crate) proxy: Option<String>,
    /// Use no proxy, also when HTTPS_PROXY or ALL_PROXY is set.
    #[arg(long, global = true)]
    pub(crate) no_proxy: bool,
    /// Addresses for names, in place of DNS: HOST=IP[,HOST=IP]. PODNET_RESOLVE
    /// adds to it. TLS still checks the name of the certificate.
    #[arg(long, global = true, value_name = "HOST=IP")]
    pub(crate) resolve: Option<String>,
    /// Log warnings and errors only.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub(crate) quiet: bool,
    /// Log more: -v for debug, -vv for trace. RUST_LOG takes priority.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,
    /// Colours in the log: auto (only on a terminal, and not with NO_COLOR),
    /// always or never.
    #[arg(long, global = true, default_value = "auto", value_parser = ["auto", "always", "never"])]
    pub(crate) color: String,
    /// The form of the log on stderr: text, or json (one object for each
    /// line).
    #[arg(long, global = true, default_value = "text", value_parser = ["text", "json"])]
    pub(crate) log_format: String,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
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

pub(crate) async fn async_main(cli: Cli) -> Result<()> {
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
