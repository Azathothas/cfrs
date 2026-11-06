//! `podnet net`: userspace virtual networking.

pub(crate) mod proxy;
pub(crate) mod shim;

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};

use podnet::exit::{Fault, ResultExt};
use podnet::vnet::{VirtAddr, VirtualSubnet};

use crate::cli::cmd::run::listen_doc;
use crate::cli::opts::DetachArgs;
use crate::cli::signals::sleep_or_signal;
use proxy::{net_proxy, probability};
use shim::{net_shim, net_socksify, net_tailscale, net_ts_shims};

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
pub(crate) struct NetArgs {
    #[command(subcommand)]
    pub(crate) command: NetCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum NetCommand {
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
pub(crate) struct TailscaleArgs {
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
pub(crate) struct SocksifyArgs {
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
pub(crate) struct TsShimsArgs {
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
pub(crate) struct ShimArgs {
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
pub(crate) struct ProxyArgs {
    #[command(flatten)]
    pub(crate) detach: DetachArgs,
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
pub(crate) struct SwitchArgs {
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
    pub(crate) detach: DetachArgs,
}

pub(crate) async fn net(args: NetArgs) -> Result<()> {
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
                println!("podnet-vnet: the host conditions that podnet handles: https://github.com/PodUtils/podnet/blob/main/docs/target-environment.md");
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
