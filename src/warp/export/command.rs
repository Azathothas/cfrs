//! The command `podnet warp export` (issue 148): its flags and its run.

use std::path::PathBuf;

use anyhow::{Context as _, Result};

use crate::exit::{Fault, ResultExt as _};

/// The flags of `podnet warp export`.
#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// wg-quick or json.
    #[arg(long, default_value = "wg-quick", value_parser = ["wg-quick", "json"])]
    pub format: String,
    /// Write the config to this file (mode 0600) in place of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// The file of the exported device (default: warp-wg.json in the
    /// state directory).
    #[arg(long, value_name = "FILE")]
    pub export_identity: Option<PathBuf>,
    /// The Endpoint of the config, HOST:PORT (default: the endpoint of
    /// the device record, port 2408).
    #[arg(long, value_name = "HOST:PORT")]
    pub endpoint: Option<String>,
    /// PersistentKeepalive in seconds; 0 writes no line.
    #[arg(long, value_name = "SECS", default_value_t = 25)]
    pub keepalive: u16,
    /// Register a new device even when the file has one.
    #[arg(long, conflicts_with = "delete")]
    pub new: bool,
    /// Remove the exported device from the service and delete its file.
    #[arg(long)]
    pub delete: bool,
    /// Test the data path of the device and write no config: the WireGuard
    /// leg of podnet with the reserved bytes, then with zeros (as kernel
    /// WireGuard and wg-quick send), each with a TCP connect to the target
    /// of --probe (default 1.1.1.1:443). Prints "device ok" (exit 0),
    /// "needs reserved bytes" (exit 1) or "device data path dead, use
    /// --new" (exit 69).
    #[arg(long, conflicts_with_all = ["delete", "out"])]
    pub check: bool,
}

/// Run `podnet warp export`.
pub async fn run(args: &Args) -> Result<()> {
    let path = match args.export_identity.clone() {
        Some(path) => path,
        None => super::default_path()
            .fault(Fault::Config)?
            .context("PODNET_STATE_DIR=none keeps no file; give --export-identity PATH")
            .fault(Fault::Config)?,
    };
    if args.delete {
        // Issue 178: a second --delete names the missing file.
        let id = super::delete(&path, None).await.fault(Fault::Unavailable)?;
        eprintln!(
            "podnet: warp export: the device {id} is deleted, and {}",
            path.display()
        );
        return Ok(());
    }
    if args.check {
        return check(args, &path).await;
    }
    // Issue 177: no private key on a terminal, before a device is
    // registered.
    let to_stdout = args
        .out
        .as_deref()
        .is_none_or(|p| p == std::path::Path::new("-"));
    {
        use std::io::IsTerminal as _;
        super::check_sink(args.out.as_deref(), std::io::stdout().is_terminal())
            .fault(Fault::Usage)?;
    }
    let exported = super::load_or_register(&path, args.new, None)
        .await
        .fault(Fault::Unavailable)?;
    let config = super::Config::of(&exported, args.endpoint.as_deref(), args.keepalive)
        .fault(Fault::Unavailable)?;
    let text = match args.format.as_str() {
        "json" => format!("{:#}\n", config.json(&exported.device.id)),
        _ => config.wg_quick(),
    };
    match &args.out {
        Some(file) if !to_stdout => {
            crate::warp::write_private_file(file, text.as_bytes())
                .with_context(|| format!("writing {}", file.display()))?;
            eprintln!("podnet: warp export: wrote {}", file.display());
        }
        _ => {
            if super::tighten_stdout() {
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
    Ok(())
}

/// `--check` (T-074).
async fn check(args: &Args, path: &std::path::Path) -> Result<()> {
    let exported = super::load_or_register(path, args.new, None)
        .await
        .fault(Fault::Unavailable)?;
    let endpoint = match &args.endpoint {
        None => None,
        Some(spec) => Some(
            tokio::net::lookup_host(spec.as_str())
                .await
                .ok()
                .and_then(|mut a| a.next())
                .with_context(|| format!("--endpoint {spec}: give HOST:PORT"))
                .fault(Fault::Usage)?,
        ),
    };
    let peer = crate::warp::wg::Peer::from_exported(&exported, endpoint).fault(Fault::Config)?;
    let probe = crate::warp::live::DEFAULT_PROBE;
    let target = crate::warp::live::probe().map_or(probe.target, |p| p.target);
    let report = super::check::run(&peer, target, probe.limit).await;
    for line in report.lines(target) {
        println!("{line}");
    }
    use super::check::Verdict;
    match report.verdict {
        Verdict::Ok => Ok(()),
        Verdict::NeedsReserved => anyhow::bail!(
            "the device needs the reserved bytes: kernel WireGuard and wg-quick send zeros; use a client that sends them (podnet warp --transport wireguard does)"
        ),
        Verdict::Dead => Err(crate::exit::fault(
            Fault::Unavailable,
            anyhow::anyhow!("the device carries no TCP; podnet warp export --new registers a new one"),
        )),
    }
}
