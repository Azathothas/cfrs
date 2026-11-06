//! `podnet agent`: test the host, start WARP when it is needed, expose
//! ports, and print one JSON document.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Subcommand;

use podnet::exit::Fault;

use crate::cli::cmd::instances::instances_ps;

#[derive(Subcommand, Debug)]
pub(crate) enum AgentCommand {
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

/// Run `podnet ARGS` and give its last line as JSON (the ready document of
/// a detached start), with its stderr on this stderr.
pub(crate) fn run_self_json(args: &[String]) -> Result<serde_json::Value> {
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
pub(crate) async fn agent(command: AgentCommand) -> Result<()> {
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
            let failed = podnet::agent::exposes_failed(&doc["exposed"]);
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

/// The `commands` of the document of `agent up` (issues 110 and 116): the
/// eval line only when the TCP listener of warp up runs; `warp exec` and
/// `warp ssh-config` use the unix socket, so they are always there in the
/// WARP mode.
pub(crate) fn agent_commands(warp: bool, warp_tcp: bool) -> Vec<String> {
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
