//! The WARP client of `podnet warp`: the device, the MASQUE options and the
//! WireGuard peers of the command line.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use podnet::exit::{Fault, ResultExt};

use super::args::WarpArgs;

pub(crate) async fn warp_client(
    args: &WarpArgs,
) -> Result<(podnet::warp::WarpClient, Option<PathBuf>)> {
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
pub(crate) async fn carry_peer(args: &WarpArgs) -> Result<Option<podnet::warp::wg::Peer>> {
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
pub(crate) async fn wireguard_peer(args: &WarpArgs) -> Result<Option<podnet::warp::wg::Peer>> {
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
pub(crate) fn masque_options(args: &WarpArgs) -> podnet::warp::MasqueOptions {
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
pub(crate) fn identity_pairs(
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

pub(crate) async fn warp_client_inner(
    args: &WarpArgs,
) -> Result<(podnet::warp::WarpClient, Option<PathBuf>)> {
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
