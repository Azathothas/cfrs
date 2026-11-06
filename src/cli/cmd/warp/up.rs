//! `podnet warp up`, `down`, `env`, `exec`, `shell`, `ssh-config` and `nc`:
//! the commands of the running instance of `podnet warp up`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use podnet::exit::{Fault, ResultExt};

use super::args::{WarpArgs, WarpCommand};

/// The commands that use the running instance of podnet warp up. Gives true
/// when the command is done, and false when it needs a WARP client (`warp
/// nc` with no running warp up) or is not one of these commands.
pub(crate) async fn before_client(args: &WarpArgs) -> Result<bool> {
    let done = match &args.command {
        WarpCommand::Up {
            tun: true,
            ready_timeout,
            ..
        } => {
            let argv = warp_up_tun_args(args, *ready_timeout);
            let doc = podnet::warp::up::start("podnet warp tun --default-route --detach", &argv)?;
            println!("{doc}");
            Ok(())
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
            warp_up(args, *port, files, *ready_timeout, *replace, *dns, auth)
        }
        WarpCommand::Down => podnet::warp::up::down(),
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
            Ok(())
        }
        WarpCommand::Exec { rules, program, at } => {
            Err(podnet::warp::pod::exec_in_pod(at, rules, program))
        }
        WarpCommand::Shell(at) => Err(podnet::warp::pod::shell(at)),
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
                return Ok(true);
            }
            ssh_config_file(&exe, host.as_deref(), *write, *remove, config)
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
            podnet::warp::nc::pipe(io, nc_end(*idle, *shutdown))
                .await
                .fault(Fault::Unavailable)
        }
        WarpCommand::Nc {
            host,
            port,
            udp: true,
            idle,
            at,
            ..
        } => match podnet::warp::nc::udp_via_running(at, host, *port).await? {
            Some((out, back)) => udp_nc(out, back, idle.unwrap_or(UDP_NC_IDLE)).await,
            None => return Ok(false),
        },
        WarpCommand::Nc {
            host,
            port,
            idle,
            shutdown,
            at,
            ..
        } => match podnet::warp::nc::via_running(at, host, *port).await? {
            Some(io) => podnet::warp::nc::pipe(io, nc_end(*idle, *shutdown))
                .await
                .fault(Fault::Unavailable),
            None => return Ok(false),
        },
        _ => return Ok(false),
    };
    done.map(|()| true)
}

/// `podnet warp nc` with no running podnet warp up: a WARP session of this
/// process.
pub(crate) async fn nc_session(
    client: podnet::warp::WarpClient,
    host: &str,
    port: u16,
    udp: bool,
    idle: Option<u64>,
    shutdown: bool,
) -> Result<()> {
    // No podnet warp up runs: a session of this process. Issue 115:
    // say so, because the two ways fail in other ways.
    tracing::info!("podnet warp up is not running; warp nc opens a WARP session of its own");
    let stack = Arc::new(client.connect().await.fault(Fault::Unavailable)?);
    if udp {
        let (out, back) = podnet::warp::nc::udp_via_stack(stack, host, port)
            .await
            .fault(Fault::Unavailable)?;
        return udp_nc(out, back, idle.unwrap_or(UDP_NC_IDLE)).await;
    }
    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => podnet_netns::socks::ProxyHost::Ip(ip),
        Err(_) => podnet_netns::socks::ProxyHost::Domain(host.to_string()),
    };
    let io = podnet::warp::proxy::dial(stack, target, port)
        .await
        .fault(Fault::Unavailable)?;
    podnet::warp::nc::pipe(Box::new(io), nc_end(idle, shutdown))
        .await
        .fault(Fault::Unavailable)?;
    Ok(())
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
    for line in podnet::warp::find::up_summary(tcp.is_some(), port, socket_up, &socket) {
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
    if let Some(probe) = args.probe {
        argv.push(podnet::warp::live::probe_arg(probe));
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
pub(crate) fn warp_up_tun_args(args: &WarpArgs, ready_timeout: u64) -> Vec<String> {
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
pub(crate) fn warp_up_args(
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
