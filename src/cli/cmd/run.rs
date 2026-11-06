//! The run loop of the tunnel commands: start, announce, verify, wait
//! and stop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use podnet::config::Config;
use podnet::exit::Fault;
use podnet::share::{ShareControl, ShareMode};
use podnet::Tunnel;

use crate::cli::opts::Show;
use crate::cli::signals::{deadline_of, shutdown_signal, sleep_until_opt, until_stop_or};

pub(crate) async fn run_tunnel(
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

pub(crate) async fn run_share(
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

pub(crate) async fn run_demo(
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
pub(crate) fn listen_doc(listen: &podnet::vnet::proxy::ProxyListen) -> serde_json::Value {
    serde_json::json!({ "listen": listen.to_string() })
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
pub(crate) fn idle_watch(
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
