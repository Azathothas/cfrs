//! The shim commands of `podnet net`: `shim`, `tailscale`, `socksify` and
//! `ts-shims`.

use anyhow::{Context, Result};

use podnet::exit::{Fault, ResultExt};

use super::{ShimArgs, SocksifyArgs, TailscaleArgs, TsShimsArgs};
use crate::cli::signals::sleep_or_signal;

pub(crate) fn net_shim(args: ShimArgs) -> Result<()> {
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

pub(crate) async fn net_tailscale(args: TailscaleArgs) -> Result<()> {
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

pub(crate) fn print_environment(
    environment: Vec<(String, String)>,
    json: bool,
    export: &str,
) -> Result<()> {
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

pub(crate) fn net_socksify(args: SocksifyArgs) -> Result<()> {
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

pub(crate) fn net_ts_shims(args: TsShimsArgs) -> Result<()> {
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
