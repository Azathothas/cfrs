//! `podnet relay`: the reverse relay.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use podnet::exit::{Fault, ResultExt};

use crate::cli::opts::DetachArgs;
use crate::cli::signals::shutdown_signal;

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
pub(crate) struct RelayArgs {
    /// The relay for a new pair. A pair keeps the relay that made it.
    #[arg(long, value_name = "URL", global = true, env = "PODNET_RELAY", hide_env_values = true, default_value = podnet::ws_relay::default_relay())]
    relay: String,
    #[command(subcommand)]
    pub(crate) command: RelayCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RelayCommand {
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

/// `podnet relay` (issue 88).
pub(crate) async fn relay(args: RelayArgs) -> Result<()> {
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
