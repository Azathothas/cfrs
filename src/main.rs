//! podnet command line.

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

mod cli;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, FromArgMatches as _, Subcommand};
use tracing_subscriber::EnvFilter;

use podnet::exit::{Fault, ResultExt};

use cli::argv::{
    apply_token_files, cloudflared_compat, command_name, foreground_hint, no_terminal, pod_args_of,
    pod_network_option, LOG_JSON,
};
use cli::cmd::run::listen_doc;
use cli::cmd::tunnel::split_host_port;
use cli::help::{error_json, json_wanted, print_error, top_command, usage_hints};
use cli::opts::{detach_of, network_options, DetachArgs};
use cli::signals::{install_signals, shutdown_signal, sleep_or_signal};
use cli::{async_main, Cli, Command};

fn main() {
    // podnet-netns forks and makes its own runtime. Start it before the async
    // runtime of podnet exists.
    // args() panics on an argument that is not UTF-8 (issue 57); clap then
    // reports the bad argument as a usage error.
    // A detached child (issue 70) closes the descriptors that it got and
    // drops its flag before anything else.
    let args = podnet::detach::prepare(std::env::args_os().collect());
    let args = cloudflared_compat(args);
    let argv: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if let Err(err) = apply_token_files(&argv) {
        eprintln!("podnet: {err:#}");
        std::process::exit(podnet::exit::USAGE);
    }
    if argv.get(1).map(String::as_str) == Some("pod") {
        podnet_netns::set_program_name("podnet pod");
        std::process::exit(podnet_netns::main_with_args(&argv[2..]));
    }
    let cli = match top_command()
        .try_get_matches_from(&args)
        .and_then(|matches| Cli::from_arg_matches(&matches))
    {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            // Help that the user asked for exits 0. Help that comes up
            // because a subcommand is missing (podnet net) is a usage error.
            let code = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => podnet::exit::SUCCESS,
                _ => podnet::exit::USAGE,
            };
            // Issue 181: with --log-format json, a usage error is one JSON
            // line too (found in argv: the parse failed).
            if code != podnet::exit::SUCCESS && json_wanted(&argv) {
                eprintln!("{}", error_json(&err.render().to_string(), code));
            } else {
                let _ = err.print();
                for line in usage_hints(&err) {
                    eprintln!("{line}");
                }
            }
            if code != podnet::exit::SUCCESS {
                podnet::report::send(command_name(&argv).as_deref(), code, None);
            }
            std::process::exit(code);
        }
    };
    let command = command_name(&argv);
    LOG_JSON.store(
        cli.log_format == "json",
        std::sync::atomic::Ordering::Relaxed,
    );
    // Issue 115: -q silences the warnings of the pod too. No thread runs
    // yet.
    if cli.quiet {
        // SAFETY: one thread: the runtime does not exist yet.
        unsafe { std::env::set_var(podnet_netns::QUIET_VARIABLE, "1") };
    }
    // Issue 189: `podnet -v pod -- PROG` (a global option before pod) runs the
    // pod too; before, it panicked. Still one thread: the pod forks.
    if let Command::Pod { args } = &cli.command {
        if let Some(option) = pod_network_option(&cli) {
            eprintln!("podnet: podnet pod does not use {option}; give the proxy to the pod with -x (podnet pod --help)");
            std::process::exit(podnet::exit::USAGE);
        }
        podnet_netns::set_program_name("podnet pod");
        std::process::exit(podnet_netns::main_with_args(&pod_args_of(&argv, args)));
    }
    // Issue 126: a server command holds one descriptor for each connection.
    // A command that runs a program of the user leaves its limit as it is.
    let runs_a_program = matches!(
        command.as_deref(),
        Some("warp exec" | "warp shell" | "warp run" | "autostart run")
    );
    if !runs_a_program {
        podnet::rlimit::raise();
    }
    if let Some(detach) = detach_of(&cli.command).filter(|d| d.detach) {
        let name = command.clone().unwrap_or_default();
        if !podnet::detach::is_child() {
            std::process::exit(podnet::detach::start(&name, &detach.options()));
        }
        if let Err(err) = podnet::detach::child_begin() {
            eprintln!("podnet: --detach: {err:#}");
            std::process::exit(podnet::detach::TEMPFAIL);
        }
    } else if podnet::detach::is_child() {
        eprintln!("podnet: --detach-child is for podnet itself");
        std::process::exit(podnet::exit::USAGE);
    } else if let Some(detach) = detach_of(&cli.command) {
        if detach.replace && !matches!(cli.command, Command::Connect(_)) {
            eprintln!("podnet: --replace needs --detach");
            std::process::exit(podnet::exit::USAGE);
        }
        // Issue 209: --name with no --detach registers this process.
        match &detach.name {
            Some(name) => {
                if let Err(err) = podnet::instances::check_name(name) {
                    eprintln!("podnet: --name: {err:#}");
                    std::process::exit(podnet::exit::USAGE);
                }
                if let Err(err) =
                    podnet::detach::register(name, command.as_deref().unwrap_or_default())
                {
                    eprintln!("podnet: --name: {err:#}");
                    std::process::exit(podnet::detach::TEMPFAIL);
                }
            }
            None if detach.no_restart => {
                eprintln!("podnet: --no-restart needs --detach or --name");
                std::process::exit(podnet::exit::USAGE);
            }
            None => {}
        }
    }
    if let Some(path) = &cli.ca_file {
        podnet::trust::set_ca_file(path.clone());
        // Issue 173: a roots file that cannot be used exits 78 for each
        // command (status and doctor too), before any work.
        if let Err(err) = podnet::trust::context().roots() {
            // Issue 253: trust::roots names the file already.
            let err = podnet::exit::fault(podnet::exit::Fault::Config, err.into());
            print_error(
                &podnet::report::error_line(&err),
                podnet::exit::code_of(&err),
            );
            let code = podnet::exit::code_of(&err);
            podnet::report::send(command.as_deref(), code, Some(&err));
            std::process::exit(code);
        }
    }
    if let Err(err) = network_options(&cli) {
        // A flag is a usage error; a variable (PODNET_RESOLVE) has its class.
        let err = if podnet::exit::code_of(&err) == podnet::exit::FAILURE {
            podnet::exit::fault(podnet::exit::Fault::Usage, err)
        } else {
            err
        };
        print_error(
            &podnet::report::error_line(&err),
            podnet::exit::code_of(&err),
        );
        let code = podnet::exit::code_of(&err);
        podnet::report::send(command.as_deref(), code, Some(&err));
        std::process::exit(code);
    }
    // A command that only prints ends at a closed stdout (podnet status |
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
        podnet::report::log_filter("warn")
    } else {
        match cli.verbose {
            0 => podnet::report::log_filter("info"),
            1 => podnet::report::log_filter("debug"),
            _ => podnet::report::log_filter("trace"),
        }
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.is_empty() => EnvFilter::try_new(&value).unwrap_or_else(|e| {
            // Before, a bad RUST_LOG gave the default level with no word.
            eprintln!("podnet: RUST_LOG={value:?} does not parse ({e}); the log level is {level}");
            EnvFilter::new(&level)
        }),
        _ => EnvFilter::new(&level),
    };
    // Colours only on a terminal: a log file or a pipe gets plain text.
    let ansi = match cli.color.as_str() {
        "always" => true,
        "never" => false,
        // A detached instance writes its log to a file (issue 103).
        _ => {
            std::io::IsTerminal::is_terminal(&std::io::stderr())
                && std::env::var_os("NO_COLOR").is_none()
                && !podnet::detach::is_child()
        }
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(podnet::report::TeeStderr);
    if cli.log_format == "json" {
        builder.json().with_ansi(false).init();
    } else {
        builder.with_ansi(ansi).init();
    }
    if let Some(line) = foreground_hint(
        command.as_deref(),
        &argv,
        podnet::detach::is_child(),
        no_terminal(),
    ) {
        tracing::info!("{line}");
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
    podnet::detach::unregister();
    if let Err(err) = result {
        let code = podnet::exit::code_of(&err);
        let line = podnet::report::error_line(&err);
        // Issues 182 and 210: a supervised child tells its supervisor how
        // long the service asks to wait.
        if let Some(secs) = podnet::quicktunnel::retry_of(&err).and_then(|r| r.retry_after_s) {
            podnet::detach::retry_after(secs);
        }
        // The report has the error in "error"; "messages" holds the log
        // lines before it (issue 55: the line was in both).
        print_error(&line, code);
        podnet::report::send(command.as_deref(), code, Some(&err));
        std::process::exit(code);
    }
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
fn warp_up_tun_args(args: &WarpArgs, ready_timeout: u64) -> Vec<String> {
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
fn warp_up_args(
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

/// A front door of `warp scan` (issue 139): IP or IP:PORT, port 443.
fn parse_door(spec: &str) -> Result<std::net::SocketAddr> {
    let spec = spec.trim();
    if let Ok(addr) = spec.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    let ip: std::net::IpAddr = spec
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .with_context(|| format!("{spec:?} is not IP or IP:PORT"))?;
    Ok(std::net::SocketAddr::new(ip, 443))
}

/// One line of an exit (issue 147): `AMS NL 104.28.1.2 warp=on 42 ms`.
fn exit_line(exit: &podnet::warp::exit::Exit) -> String {
    format!(
        "{} {} {} warp={} {} ms",
        exit.colo,
        exit.loc.as_deref().unwrap_or("-"),
        exit.ip.as_deref().unwrap_or("-"),
        exit.warp.as_deref().unwrap_or("-"),
        exit.rtt.as_millis()
    )
}

/// The WARP+ line of `warp status` (issue 95). The field `warp_plus` of
/// the API is true also for a free account; WARP+ is an account type
/// other than free, or premium data.
/// A license key of the command line: one character or more (issue 178:
/// an empty key went to the API).
fn non_empty_key(value: &str) -> std::result::Result<String, String> {
    let key = value.trim();
    if key.is_empty() {
        return Err("give a license key".into());
    }
    Ok(key.to_string())
}

/// A JSON value for a text line: a string with no quotes (issue 178).
fn plain_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "-".into(),
        other => other.to_string(),
    }
}

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
struct WarpArgs {
    /// The file that keeps the device and its MASQUE key, so that each run
    /// uses the same device. Default: warp.json in the state directory
    /// (see PODNET_STATE_DIR in podnet man environment).
    #[arg(long, value_name = "PATH", global = true)]
    identity: Option<PathBuf>,
    /// Register a new device for this run only, and do not save it.
    #[arg(long, global = true, conflicts_with = "identity")]
    ephemeral: bool,
    /// A resolver of the DNS inside the tunnel, in place of 1.1.1.1:53:
    /// IP[:PORT] (UDP), or tls://IP[:PORT][#NAME] (DNS over TLS, port 853;
    /// the certificate must have NAME, or the IP address). Repeatable; the
    /// first that answers wins.
    #[arg(
        long,
        value_name = "SPEC",
        global = true,
        env = "PODNET_WARP_RESOLVERS",
        hide_env_values = true,
        value_delimiter = ','
    )]
    resolver: Vec<String>,
    /// The name of a new device in the dashboard (1 to 64 characters).
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        env = "PODNET_WARP_DEVICE_NAME",
        hide_env_values = true
    )]
    device_name: Option<String>,
    /// The model that a new device declares (default PC).
    #[arg(
        long,
        value_name = "MODEL",
        global = true,
        env = "PODNET_WARP_DEVICE_MODEL",
        hide_env_values = true
    )]
    device_model: Option<String>,
    /// The locale that a new device declares, as en_US (default en_US).
    #[arg(
        long,
        value_name = "LOCALE",
        global = true,
        env = "PODNET_WARP_DEVICE_LOCALE",
        hide_env_values = true
    )]
    device_locale: Option<String>,
    /// Split the TLS ClientHello of the MASQUE connection into records:
    /// record (records of --fragment-size bytes) or sni (the first record
    /// ends in the server name). off: one record (the default).
    #[arg(
        long,
        value_name = "MODE",
        global = true,
        env = "PODNET_WARP_FRAGMENT", hide_env_values = true,
        num_args = 0..=1,
        default_missing_value = "record"
    )]
    fragment_client_hello: Option<String>,
    /// The bytes of handshake data in each record of
    /// --fragment-client-hello: N or MIN-MAX, 16 to 4096 (default 64-160).
    #[arg(
        long,
        value_name = "MIN[-MAX]",
        global = true,
        env = "PODNET_WARP_FRAGMENT_SIZE",
        hide_env_values = true
    )]
    fragment_size: Option<String>,
    /// The congestion controller of the TCP connections of the userspace
    /// stack (what the stack sends): none (the default), reno or cubic.
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        env = "PODNET_WARP_CC",
        hide_env_values = true
    )]
    cc: Option<String>,
    /// Close each MASQUE session on purpose at this age, and open a new one
    /// (a new egress address). The TCP flows of the old session end.
    /// Default: off.
    #[arg(
        long,
        value_name = "SECS",
        global = true,
        env = "PODNET_WARP_SESSION_MAX_AGE", hide_env_values = true,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    session_max_age: Option<u64>,
    /// The TCP probe of the data path: IP:PORT or off (default 1.1.1.1:443). After 3
    /// failed connects (one each 30 s), a new session takes the new flows (warp tun: a SYN).
    #[arg(long, value_name = "IP:PORT|off", global = true, value_parser = podnet::warp::live::parse_probe)]
    probe: Option<Option<podnet::warp::live::Probe>>,
    /// Do not try the WebSocket relay (--relay, PODNET_RELAY) when the direct
    /// MASQUE path fails. Without it, podnet tries the relay: the TLS to the
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
    /// The transport of the MASQUE session: h2 (HTTP/2 on TCP 443, the
    /// default) or h3 (HTTP/3 on UDP 443: each packet is a QUIC datagram;
    /// no proxy and no relay).
    #[arg(
        long,
        value_name = "PROTOCOL",
        global = true,
        env = "PODNET_WARP_MASQUE_TRANSPORT", hide_env_values = true,
        value_parser = ["h2", "h3"]
    )]
    masque_transport: Option<String>,
    /// The leg of the tunnel: masque (the default) or wireguard (UDP to the
    /// WireGuard front door, with the device of `podnet warp export`, which
    /// podnet registers when the file has none).
    #[arg(
        long,
        value_name = "TRANSPORT",
        global = true,
        env = "PODNET_WARP_TRANSPORT", hide_env_values = true,
        value_parser = ["masque", "wireguard"]
    )]
    transport: Option<String>,
    /// The WireGuard front door (IP:PORT) in place of the one of the
    /// device record (port 2408).
    #[arg(
        long,
        value_name = "IP:PORT",
        global = true,
        env = "PODNET_WARP_WG_ENDPOINT",
        hide_env_values = true
    )]
    wireguard_endpoint: Option<std::net::SocketAddr>,
    /// wg: a second WireGuard device inside the tunnel (its own device in
    /// warp-carry.json of the state directory); the tools use its stack.
    /// With --transport wireguard, both hops are WireGuard.
    #[arg(
        long,
        value_name = "CARRY",
        global = true,
        env = "PODNET_WARP_CARRY", hide_env_values = true,
        value_parser = ["none", "wg"]
    )]
    carry: Option<String>,
    /// The front door (IP:PORT) of the carried device in place of the one
    /// of its record.
    #[arg(
        long,
        value_name = "IP:PORT",
        global = true,
        env = "PODNET_WARP_CARRY_ENDPOINT",
        hide_env_values = true
    )]
    carry_endpoint: Option<std::net::SocketAddr>,

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
        /// The license key, or - to read it from stdin (it is then not on
        /// the command line).
        #[arg(value_parser = non_empty_key)]
        key: String,
    },
    /// Make a new MASQUE key and enrol it. The old key stops working.
    Rotate,
    /// Remove the device from the WARP service and delete the saved file.
    Delete,
    /// Open the tunnel and test TCP connects through it. Exit 69 when a
    /// target fails.
    Probe {
        /// A TCP destination to reach through the tunnel, host:port.
        #[arg(long, value_delimiter = ',')]
        target: Vec<String>,
    },
    /// Open the tunnel and print its exit: the data center (colo), the
    /// country and the address that a destination sees (from
    /// http://1.1.1.1/cdn-cgi/trace), and the IPv6 egress address (the
    /// trace at 2606:4700:4700::1111, else the TXT of whoami.cloudflare).
    /// Exit 69 when there is no answer.
    Exit {
        /// Print one JSON object.
        #[arg(long)]
        json: bool,
        /// Do not ask for the IPv6 egress address.
        #[arg(long)]
        no_ipv6: bool,
    },
    /// Print a WireGuard config of a new WARP device (wg-quick or JSON),
    /// for other clients. The device and its private key are in
    /// warp-wg.json of the state directory, not in warp.json. Its data
    /// path is WireGuard on UDP (port 2408), not MASQUE on TCP 443. The
    /// output holds the private key: a terminal is refused with no --out
    /// (--out - prints it), and a redirected file becomes mode 0600. WARP
    /// reads 3 reserved bytes in each message; kernel WireGuard and
    /// wg-quick send zeros. --check tells if the device needs the bytes.
    Export(podnet::warp::export::command::Args),
    /// Measure front doors of WARP: the TCP connect and the TLS handshake
    /// with the pinned key, for each --candidate and the front doors of the
    /// device record. The fastest goes first. Exit 69 when none answers.
    Scan {
        /// A front door to measure: IP or IP:PORT (port 443); an IPv6
        /// address with a port is in brackets. Repeatable.
        #[arg(long, value_name = "IP[:PORT]", value_delimiter = ',')]
        candidate: Vec<String>,
        /// The time limit of each front door, in milliseconds (100 to
        /// 60000).
        #[arg(long, value_name = "MS", default_value_t = 3000,
              value_parser = clap::value_parser!(u64).range(100..=60_000))]
        timeout_ms: u64,
        /// Print one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Forward local listeners through WARP (as ssh -L): each connection to
    /// LISTEN goes through the tunnel to HOST:PORT.
    Forward {
        /// LISTEN=HOST:PORT. LISTEN is PORT (on 127.0.0.1), ADDR:PORT,
        /// tcp://ADDR:PORT or unix:/PATH. HOST is resolved inside the
        /// tunnel; a tunnel: prefix is accepted. Repeatable.
        #[arg(
            short = 'L',
            long = "local",
            value_name = "LISTEN=HOST:PORT",
            required_unless_present = "list",
            env = "PODNET_WARP_FORWARD",
            hide_env_values = true,
            value_delimiter = ','
        )]
        local: Vec<String>,
        /// Print the forwards of the detached instances (podnet ps) and exit.
        #[arg(long)]
        list: bool,
        /// Exit 69 when any listener does not start.
        #[arg(long)]
        strict: bool,
        /// The most connections of each listener at the same time. 0: no
        /// limit.
        #[arg(long, value_name = "N", default_value_t = 32)]
        max_connections: usize,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a local SOCKS5 and HTTP CONNECT proxy whose traffic goes through
    /// WARP (the proxy mode of the WARP client).
    Proxy {
        /// Where to accept clients: tcp://host:port or unix:/path.
        /// Repeatable: each listener serves the same WARP session.
        /// A listener that the host refuses is reported, and the proxy
        /// starts with the others; with none, the exit code is 69.
        #[arg(long, default_value = "tcp://127.0.0.1:40000")]
        listen: Vec<String>,
        /// Exit 69 when any listener does not start.
        #[arg(long)]
        strict: bool,
        /// The most clients at the same time; a client over it is closed
        /// at once, with a warning in the log. 0: no limit.
        #[arg(long, value_name = "N", default_value_t = 0)]
        max_connections: u64,
        /// Also answer DNS on this UDP address (for example
        /// 127.0.0.1:5353): each query goes through WARP to 1.1.1.1.
        #[arg(long, value_name = "ADDR")]
        dns: Option<std::net::SocketAddr>,
        /// Clients must give this user (SOCKS5 user and password, or HTTP
        /// Basic), with the password of --proxy-password-file.
        #[arg(
            long,
            value_name = "USER",
            env = "PODNET_PROXY_USER",
            hide_env_values = true,
            requires = "proxy_password_file"
        )]
        proxy_user: Option<String>,
        /// The file with the password of --proxy-user on its first line
        /// (mode 0600).
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_PROXY_PASSWORD_FILE",
            hide_env_values = true,
            requires = "proxy_user"
        )]
        proxy_password_file: Option<PathBuf>,
        /// A rule for the destinations: KIND:VALUE=ACTION. KIND is domain
        /// (NAME, or .NAME for the name and the names under it) or cidr
        /// (ADDR/PREFIX, IPv4 or IPv6, or @FILE with one prefix on each
        /// line). ACTION is tunnel, direct (from the host, with no proxy)
        /// or reject. The first rule that matches wins. Repeatable.
        #[arg(
            short = 'r',
            long = "rule",
            value_name = "KIND:VALUE=ACTION",
            env = "PODNET_WARP_RULES",
            hide_env_values = true,
            value_delimiter = ','
        )]
        rules: Vec<String>,
        /// Serve each TCP client on its own HTTP/3 CONNECT stream to the L4
        /// door of WARP (UDP 443), with no IP stack. UDP is not served. The
        /// rules (-r, --rules-file, --rule-default) apply; an address rule
        /// (cidr:) decides an address, not a name, as no name is resolved.
        #[arg(long, env = "PODNET_WARP_L4", hide_env_values = true, conflicts_with_all = ["dns", "listen_identity"])]
        l4: bool,
        /// The TLS name of the L4 door.
        #[arg(long, value_name = "NAME", default_value = podnet::warp::l4::l4_sni(), requires = "l4")]
        l4_sni: String,
        /// LISTEN=PATH: a listener whose clients use the WARP device of the
        /// identity file PATH (made when it does not exist: that registers
        /// a new device), with a session of its own. The --listen listeners
        /// use --identity. Repeatable; each PATH once.
        #[arg(long, value_name = "LISTEN=PATH")]
        listen_identity: Vec<String>,
        /// A file with one rule on each line (# starts a comment), after
        /// the --rule rules. podnet reads it again when it changes.
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_WARP_RULES_FILE",
            hide_env_values = true
        )]
        rules_file: Option<PathBuf>,
        /// The action when no rule matches.
        #[arg(long, value_name = "ACTION", default_value = "tunnel")]
        rule_default: String,
        /// Check the rules, print them, and exit (0, or 64 for a bad rule).
        #[arg(long)]
        check: bool,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Start WARP for this sandbox, in the background: a
    /// detached warp proxy on 127.0.0.1:PORT and on a unix socket, and an
    /// env file with the proxy variables. Later shells join it with
    /// `eval "$(podnet warp env)"`, `podnet warp exec -- CMD`, `podnet warp
    /// shell`, or --persist.
    Up {
        /// The TCP port of the proxy on 127.0.0.1.
        #[arg(long, default_value_t = 40000)]
        port: u16,
        /// Add a marked block to ~/.bashrc and ~/.profile: each new shell
        /// loads the env file, and an interactive shell runs under the pod
        /// (static binaries and UDP go through WARP too). podnet warp down
        /// removes it.
        #[arg(long)]
        persist: bool,
        /// Also write the proxy variables to
        /// $XDG_CONFIG_HOME/environment.d/90-podnet-warp.conf (else
        /// ~/.config/environment.d/90-podnet-warp.conf): the systemd user
        /// manager gives them to the programs of the next login (a
        /// desktop, a user unit). podnet warp down removes the file. A file
        /// of that name that podnet did not write is not changed.
        #[arg(long)]
        env_d: bool,
        /// Seconds to wait for WARP to be ready.
        #[arg(long, default_value_t = 90)]
        ready_timeout: u64,
        /// With CAP_NET_ADMIN: send the whole host through WARP with warp
        /// tun --default-route (instance warp-tun), in place of the proxy.
        #[arg(long, conflicts_with = "persist")]
        tun: bool,
        /// Stop a running warp up with other arguments (another --port),
        /// and start this one.
        #[arg(long)]
        replace: bool,
        /// Also answer DNS on this UDP address (for example
        /// 127.0.0.1:5353): each query goes through WARP to 1.1.1.1.
        #[arg(long, value_name = "ADDR")]
        dns: Option<std::net::SocketAddr>,
        /// Clients must give this user (SOCKS5 user and password, or HTTP
        /// Basic), with the password of --proxy-password-file.
        #[arg(
            long,
            value_name = "USER",
            env = "PODNET_PROXY_USER",
            hide_env_values = true,
            requires = "proxy_password_file"
        )]
        proxy_user: Option<String>,
        /// The file with the password of --proxy-user on its first line
        /// (mode 0600).
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_PROXY_PASSWORD_FILE",
            hide_env_values = true,
            requires = "proxy_user"
        )]
        proxy_password_file: Option<PathBuf>,
    },
    /// Stop what podnet warp up started, and remove its env file and its
    /// block in ~/.bashrc and ~/.profile.
    Down,
    /// Print the proxy variables of the running podnet warp up, for
    /// `eval "$(podnet warp env)"`. Exit 69 with no output when warp up has no
    /// TCP listener (no proxy variables).
    Env,
    /// Run a program under the pod of the running podnet warp up: TCP, DNS
    /// and UDP go through WARP, also for static binaries.
    Exec {
        /// A podnet-netns rule, repeatable (see podnet pod --help).
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        #[command(flatten)]
        at: podnet::warp::pod::PodOptions,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
    /// Run $SHELL under the pod of the running podnet warp up. When it does
    /// not run, the shell starts as it is (with the proxy variables when
    /// the env file is there).
    Shell(podnet::warp::pod::PodOptions),
    /// A byte pipe from stdin and stdout to HOST:PORT through WARP, for
    /// `ssh -o ProxyCommand='podnet warp nc %h %p'` and git over SSH.
    /// It uses the running podnet warp up, else a WARP session of its
    /// own.
    Nc {
        host: String,
        port: u16,
        #[command(flatten)]
        at: podnet::warp::find::At,
        /// Go through the WebSocket relay (--relay) to HOST:PORT, with no
        /// WARP (TCP, IPv4).
        #[arg(long, conflicts_with = "udp")]
        via_relay: bool,
        /// UDP: each read of stdin is one datagram to HOST:PORT; each
        /// datagram that comes back goes to stdout.
        #[arg(short = 'u', long)]
        udp: bool,
        /// After the end of stdin, end when no data came for this many
        /// seconds (default 3 with -u, else 5). TCP: podnet then sends the FIN.
        #[arg(long, value_name = "SECS")]
        idle: Option<u64>,
        /// TCP: send the FIN at the end of stdin, then wait for the far end
        /// to close (as nc -N). Without it, podnet sends no FIN until the end:
        /// some servers drop a half-closed connection before they answer.
        #[arg(short = 'N', long, conflicts_with = "udp")]
        shutdown: bool,
    },
    /// Print an SSH config block and GIT_SSH_COMMAND that use podnet warp nc.
    /// With --write, --remove or --check: own the block in the SSH config
    /// file, between two marker lines.
    SshConfig {
        /// The Host pattern of the block (default * for the printed block;
        /// --write and --check need one).
        #[arg(long)]
        host: Option<String>,
        /// Add the block for --host to the SSH config file, or replace it.
        /// The block goes before the first Host or Match line. A Host line
        /// of the file that names the same pattern is an error (exit 1).
        #[arg(long, conflicts_with_all = ["remove", "check"])]
        write: bool,
        /// Remove the block for --host (with no --host: each block of podnet).
        #[arg(long, conflicts_with = "check")]
        remove: bool,
        /// Exit 1 when the block for --host is missing or names another
        /// binary. Writes nothing.
        #[arg(long)]
        check: bool,
        /// The SSH config file.
        #[arg(long, value_name = "FILE", default_value = "~/.ssh/config")]
        config: String,
    },
    /// Make a TUN interface whose packets go through WARP. Needs
    /// CAP_NET_ADMIN and /dev/net/tun. Routes are not changed.
    Tun {
        /// The interface name.
        #[arg(long, default_value = "podnet0")]
        interface: String,
        /// Send the whole host through WARP: host routes keep the
        /// MASQUE connection outside, default routes go to the TUN (IPv4 and
        /// IPv6), DNS goes to 1.1.1.1. The default routes go away while the
        /// session is down; each change is put back at the end.
        #[arg(long)]
        default_route: bool,
        /// Keep the rp_filter of the interface. Without it, podnet writes 0.
        #[arg(long)]
        keep_rp_filter: bool,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a program with all its traffic sent through WARP. No root and no
    /// TUN device are necessary (podnet-netns).
    Run {
        /// The backend: auto, netns-raw, netns or seccomp. netns-raw moves the
        /// raw packets of a namespace through WARP (TCP, UDP, ICMP, IPv6; no
        /// root). auto takes netns-raw when it works, else seccomp, so that
        /// UDP goes through WARP too.
        #[arg(long, default_value = "auto")]
        backend: String,
        /// A podnet-netns rule, repeatable: domain:NAME=PROXY,
        /// domain:.SUFFIX=PROXY, cidr:NET/LEN=PROXY; PROXY may be direct.
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        /// The program keeps the proxy variables of this shell.
        #[arg(long)]
        keep_proxy_env: bool,
        /// Where a port that the program listens on is a unix socket
        /// (seccomp backend). The directory must be of this user and not
        /// writable by the group or others [default:
        /// $XDG_RUNTIME_DIR/podnet-netns-inbound, else
        /// $TMPDIR/podnet-netns-inbound-UID].
        #[arg(long, value_name = "DIR")]
        inbound_dir: Option<PathBuf>,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
}

async fn warp_client(args: &WarpArgs) -> Result<(podnet::warp::WarpClient, Option<PathBuf>)> {
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
async fn carry_peer(args: &WarpArgs) -> Result<Option<podnet::warp::wg::Peer>> {
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
async fn wireguard_peer(args: &WarpArgs) -> Result<Option<podnet::warp::wg::Peer>> {
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
fn masque_options(args: &WarpArgs) -> podnet::warp::MasqueOptions {
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
fn identity_pairs(
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

async fn warp_client_inner(args: &WarpArgs) -> Result<(podnet::warp::WarpClient, Option<PathBuf>)> {
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

async fn warp(mut args: WarpArgs) -> Result<()> {
    // Issue 111: a bad PODNET_WARP_TCP_BURST fails before any network wait.
    podnet::warp::check_tcp_burst()?;
    // Issue 134: the congestion controller of the stack.
    if let Some(cc) = &args.cc {
        podnet::warp::ip::set_cc(podnet::warp::ip::parse_cc(cc)?);
    }
    // Issue 185: the renewal of the session.
    if let Some(secs) = args.session_max_age {
        podnet::warp::live::set_max_age(Some(Duration::from_secs(secs)));
    }
    if let Some(probe) = args.probe {
        podnet::warp::live::set_probe(probe);
    }
    // Issue 145: the resolvers of the tunnel.
    let resolvers = podnet::warp::proxy::parse_resolvers(&args.resolver).fault(Fault::Usage)?;
    podnet::warp::proxy::set_resolvers(resolvers);
    // Issue 135: the split of the ClientHello of the MASQUE connection.
    if let Some(split) = podnet::warp::live::parse_split(
        args.fragment_client_hello.as_deref().unwrap_or("off"),
        args.fragment_size.as_deref(),
    )
    .fault(Fault::Config)?
    {
        podnet::warp::live::set_split(split);
    }
    // Issue 141: the name, the model and the locale of a new device.
    podnet::warp::register::DeviceHints {
        name: args.device_name.clone(),
        model: args.device_model.clone(),
        locale: args.device_locale.clone(),
    }
    .set()
    .fault(Fault::Usage)?;
    // These commands use the running instance of podnet warp up.
    match &args.command {
        WarpCommand::Up {
            tun: true,
            ready_timeout,
            ..
        } => {
            let argv = warp_up_tun_args(&args, *ready_timeout);
            let doc = podnet::warp::up::start("podnet warp tun --default-route --detach", &argv)?;
            println!("{doc}");
            return Ok(());
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
            return warp_up(&args, *port, files, *ready_timeout, *replace, *dns, auth);
        }
        WarpCommand::Down => return podnet::warp::up::down(),
        WarpCommand::Forward { list: true, .. } => {
            let list = podnet::instances::list(&podnet::instances::lookup_dir());
            print!("{}", podnet::instances::text::forward_list(&list));
            return Ok(());
        }
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
            return Ok(());
        }
        WarpCommand::Exec { rules, program, at } => {
            return Err(podnet::warp::pod::exec_in_pod(at, rules, program));
        }
        WarpCommand::Shell(at) => return Err(podnet::warp::pod::shell(at)),
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
                return Ok(());
            }
            return ssh_config_file(&exe, host.as_deref(), *write, *remove, config);
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
            return podnet::warp::nc::pipe(io, nc_end(*idle, *shutdown))
                .await
                .fault(Fault::Unavailable);
        }
        WarpCommand::Nc {
            host,
            port,
            udp: true,
            idle,
            at,
            ..
        } => {
            if let Some((out, back)) = podnet::warp::nc::udp_via_running(at, host, *port).await? {
                return udp_nc(out, back, idle.unwrap_or(UDP_NC_IDLE)).await;
            }
        }
        WarpCommand::Nc {
            host,
            port,
            idle,
            shutdown,
            at,
            ..
        } => {
            if let Some(io) = podnet::warp::nc::via_running(at, host, *port).await? {
                return podnet::warp::nc::pipe(io, nc_end(*idle, *shutdown))
                    .await
                    .fault(Fault::Unavailable);
            }
        }
        // Issue 148: a WireGuard device of its own; warp.json is not used.
        WarpCommand::Export(args) => return podnet::warp::export::command::run(args).await,
        // Issues 132 and 136: check the rules with no device and no session.
        WarpCommand::Proxy {
            rules,
            rules_file,
            rule_default,
            check: true,
            ..
        } => {
            let default = podnet::warp::rules::Action::parse(rule_default).fault(Fault::Usage)?;
            let table = podnet::warp::rules::Table::build(rules, rules_file.as_deref(), default)
                .fault(Fault::Usage)?;
            for rule in &table.rules {
                println!("rule        {}", rule.spec);
            }
            println!("default     {}", table.default.name());
            return Ok(());
        }
        // Issue 150: a bad --listen-identity is a usage error before any
        // registration.
        WarpCommand::Proxy {
            listen_identity,
            listen,
            ..
        } if !listen_identity.is_empty() => {
            let main = match &args.identity {
                Some(path) => Some(path.clone()),
                None if args.ephemeral => None,
                None => podnet::warp::WarpClient::default_identity_path().fault(Fault::Config)?,
            };
            identity_pairs(listen_identity, main.as_deref(), listen).fault(Fault::Usage)?;
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
        // Issue 178: find the saved identity with no directory made, in each
        // candidate directory; a stat error is a configuration error.
        let path = match args.identity.clone() {
            Some(path) => Some(path),
            None => match podnet::state::find_existing("warp.json").fault(Fault::Config)? {
                Some(found) => {
                    args.identity = Some(found.clone());
                    Some(found)
                }
                None => podnet::state::candidates(&|k| std::env::var_os(k))
                    .and_then(|c| c.into_iter().next())
                    .map(|(_, dir)| dir.join("warp.json")),
            },
        };
        match path {
            Some(path) if podnet::state::exists(&path).fault(Fault::Config)? => {}
            Some(path) => {
                return Err(podnet::exit::fault(
                    Fault::Config,
                    anyhow::anyhow!(
                        "no WARP identity at {}; run podnet warp register first",
                        path.display()
                    ),
                ))
            }
            None => {
                return Err(podnet::exit::fault(
                    Fault::Config,
                    anyhow::anyhow!(
                        "PODNET_STATE_DIR=none keeps no WARP identity; give --identity PATH"
                    ),
                ))
            }
        }
    }
    let (mut client, path) = warp_client(&args).await?;
    let masque = masque_options(&args);
    let save = |client: &podnet::warp::WarpClient| -> Result<()> {
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
            let mut account = client.account().await?;
            // Issue 116: the instance of warp up, with the account.
            let instance = podnet::warp::up::instance_state();
            if json {
                let active = podnet::warp::identity::warp_plus_label(&account) == "yes";
                if let Some(doc) = account.as_object_mut() {
                    doc.insert("instance".into(), instance);
                    // Issue 178: warp_plus of the API is not the state of
                    // the account; warp_plus_active is.
                    doc.insert("warp_plus_active".into(), active.into());
                }
                println!("{}", serde_json::to_string_pretty(&account)?);
                return Ok(());
            }
            print_device(&client, path.as_deref());
            println!("warp up     {}", podnet::warp::up::instance_line(&instance));
            let field = |name: &str| account.get(name).map(plain_value).unwrap_or_default();
            println!("type        {}", field("account_type"));
            println!(
                "warp+       {}",
                podnet::warp::identity::warp_plus_label(&account)
            );
            println!("premium     {}", field("premium_data"));
            println!("quota       {}", field("quota"));
        }
        WarpCommand::License { key } => {
            let key = if key == "-" {
                let mut text = String::new();
                std::io::Read::read_to_string(
                    &mut std::io::Read::take(std::io::stdin(), 4096),
                    &mut text,
                )
                .context("reading the license key from stdin")
                .fault(Fault::Usage)?;
                let text = text.trim().to_string();
                if text.is_empty() {
                    return Err(podnet::exit::fault(
                        Fault::Usage,
                        anyhow::anyhow!("no license key on stdin"),
                    ));
                }
                text
            } else {
                key
            };
            podnet::report::hide(&key);
            let account = client.set_license(&key).await.map_err(|err| {
                podnet::exit::fault(podnet::warp::identity::license_fault(&err), err)
            })?;
            save(&client)?;
            let field = |name: &str| account.get(name).map(plain_value).unwrap_or_default();
            println!("license     set");
            println!("type        {}", field("account_type"));
            println!(
                "warp+       {}",
                podnet::warp::identity::warp_plus_label(&account)
            );
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
        WarpCommand::Scan {
            candidate,
            timeout_ms,
            json,
        } => {
            let candidates = candidate
                .iter()
                .map(|c| parse_door(c))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            let timeout = std::time::Duration::from_millis(timeout_ms);
            let results = client
                .scan(&candidates, timeout)
                .await
                .fault(Fault::Config)?;
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            if json {
                let doors: Vec<_> = results
                    .iter()
                    .map(|(a, r)| match r {
                        Ok(t) => serde_json::json!({
                            "endpoint": a.to_string(),
                            "ok": true,
                            "tcp_ms": t.tcp.as_millis() as u64,
                            "tls_ms": t.tls.as_millis() as u64,
                        }),
                        Err(err) => serde_json::json!({
                            "endpoint": a.to_string(),
                            "ok": false,
                            "error": format!("{err:#}"),
                        }),
                    })
                    .collect();
                println!("{}", serde_json::json!({ "doors": doors }));
            } else {
                for (a, r) in &results {
                    match r {
                        Ok(t) => println!(
                            "OK          {a:<28} tcp {:>5} ms  tls {:>5} ms",
                            t.tcp.as_millis(),
                            t.tls.as_millis()
                        ),
                        Err(err) => println!("FAIL        {a:<28} {err:#}"),
                    }
                }
                if let Some((best, _)) = results.iter().find(|(_, r)| r.is_ok()) {
                    println!("use         podnet warp --masque-endpoint {best} ...");
                }
            }
            if ok == 0 {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("no front door answered"),
                ));
            }
        }
        WarpCommand::Exit { json, no_ipv6 } => {
            let stack = client.connect().await.fault(Fault::Unavailable)?;
            let mut exit = podnet::warp::exit::trace(&stack)
                .await
                .fault(Fault::Unavailable)?;
            // Issue 184: the IPv6 egress address changes with each session.
            if !no_ipv6 {
                if client.device().ipv6().is_none() {
                    exit.ipv6_error = Some("the device has no IPv6 address".into());
                } else {
                    match podnet::warp::exit::egress_v6(&stack).await {
                        Ok(ip) => exit.ipv6 = Some(ip),
                        Err(err) => exit.ipv6_error = Some(format!("{err:#}")),
                    }
                }
            }
            if json {
                println!("{}", exit.to_json());
            } else {
                println!("colo        {}", exit.colo);
                println!("country     {}", exit.loc.as_deref().unwrap_or("-"));
                println!("ip          {}", exit.ip.as_deref().unwrap_or("-"));
                if !no_ipv6 {
                    match (&exit.ipv6, &exit.ipv6_error) {
                        (Some(ip), _) => println!("ipv6        {ip}"),
                        (None, Some(why)) => println!("ipv6        - ({why})"),
                        _ => println!("ipv6        -"),
                    }
                }
                println!("warp        {}", exit.warp.as_deref().unwrap_or("-"));
                println!("rtt         {} ms", exit.rtt.as_millis());
            }
        }
        WarpCommand::Probe { target } => {
            let targets = if target.is_empty() {
                podnet::services::probe_targets()
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
            println!(
                "tunnel      up ({})",
                if client.is_wireguard() {
                    "WireGuard over UDP"
                } else if args.masque_transport.as_deref() == Some("h3") {
                    "MASQUE over HTTP/3, UDP 443"
                } else {
                    "MASQUE over TCP 443"
                }
            );
            // Issue 147: the exit of the session. It does not change the
            // exit code.
            match podnet::warp::exit::trace(&stack).await {
                Ok(exit) => println!("exit        {}", exit_line(&exit)),
                Err(err) => println!("exit        - ({err:#})"),
            }
            let total = targets.len() + 1;
            let mut failed = 0;
            // Issue 178: the summary names the failed checks.
            let mut names: Vec<String> = Vec::new();
            // Issue 115: the UDP data path: a DNS query through the tunnel.
            match podnet::warp::proxy::check_data_path(&stack, true).await {
                Ok(took) => println!("OK          udp 1.1.1.1:53 (DNS) in {took:?}"),
                Err(err) => {
                    failed += 1;
                    names.push("udp 1.1.1.1:53".into());
                    println!("FAIL        udp 1.1.1.1:53 (DNS): {err:#}");
                }
            }
            for (spec, host, port) in targets {
                let started = std::time::Instant::now();
                let attempt = async {
                    // A name is resolved by DNS through the tunnel.
                    let ip = podnet::warp::proxy::resolve(&stack, &host).await?;
                    let addr = std::net::SocketAddr::new(ip, port);
                    let conn = stack.tcp_connect(addr).await?;
                    Ok::<_, anyhow::Error>((addr, conn))
                };
                match tokio::time::timeout(std::time::Duration::from_secs(12), attempt).await {
                    Ok(Ok((addr, conn))) => {
                        println!("OK          {spec} ({addr}) in {:?}", started.elapsed());
                        conn.close().await;
                    }
                    Ok(Err(err)) => {
                        failed += 1;
                        names.push(spec.clone());
                        println!("FAIL        {spec}: {err:#}");
                    }
                    Err(_) => {
                        failed += 1;
                        names.push(spec.clone());
                        println!("TIMEOUT     {spec}");
                    }
                }
            }
            // Issue 95: a target that fails is a failure of the probe.
            if failed > 0 {
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!(
                        "{failed} of {total} targets failed through WARP: {}",
                        names.join(", ")
                    ),
                ));
            }
        }
        WarpCommand::Proxy {
            listen,
            run_for,
            strict,
            max_connections,
            dns,
            proxy_user,
            proxy_password_file,
            rules,
            rules_file,
            rule_default,
            listen_identity,
            l4,
            l4_sni,
            ..
        } => {
            // Issue 150: the listeners of the other identities.
            let pairs =
                identity_pairs(&listen_identity, path.as_deref(), &listen).fault(Fault::Usage)?;
            podnet::warp::proxy::set_max_connections(max_connections);
            // Issues 132 and 136: the rules of the destinations.
            let default = podnet::warp::rules::Action::parse(&rule_default).fault(Fault::Usage)?;
            let table = podnet::warp::rules::Table::build(&rules, rules_file.as_deref(), default)
                .fault(Fault::Usage)?;
            podnet::warp::rules::set(table);
            if let Some(file) = rules_file {
                podnet::warp::rules::watch(rules, file, default);
            }
            // Issue 146: the credentials of the clients.
            if let (Some(user), Some(file)) = (&proxy_user, &proxy_password_file) {
                let credentials = podnet::ingress::credentials(user, file).fault(Fault::Config)?;
                podnet::warp::proxy::set_credentials(credentials);
            }
            // Issue 117: the DNS listener is bound before the session, as
            // the proxy listeners.
            let dns_socket = match dns {
                Some(addr) => Some(
                    tokio::net::UdpSocket::bind(addr)
                        .await
                        .with_context(|| format!("binding the DNS address {addr}"))
                        .fault(Fault::Unavailable)?,
                ),
                None => None,
            };
            let listens = listen
                .iter()
                .map(|l| podnet::vnet::proxy::ProxyListen::parse(l))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            // Issue 97: each listener is bound on its own, before the WARP
            // session. A listener that the host refuses (EACCES on a TCP
            // bind) is reported; the proxy starts with the others.
            let (bound, mut failed) = podnet::warp::proxy::bind_all(&listens).await;
            let mut extra = Vec::new();
            for (listen, identity) in pairs {
                match podnet::warp::proxy::bind(&listen).await {
                    Ok(b) => extra.push((b, identity)),
                    Err(err) => failed.push((listen, err)),
                }
            }
            for (listen, err) in &failed {
                eprintln!(
                    "podnet: warp proxy: {} is not available: {err:#}",
                    listen_doc(listen)["listen"].as_str().unwrap_or("?")
                );
            }
            if bound.is_empty() || (strict && !failed.is_empty()) {
                let list = failed
                    .iter()
                    .map(|(_, err)| format!("{err:#}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("warp proxy: a listener did not start: {list}"),
                ));
            }
            // Issue 140: one HTTP/3 CONNECT for each client, no stack.
            if l4 {
                let door = Arc::new(client.l4(&l4_sni).fault(Fault::Config)?);
                door.connection().await.fault(Fault::Unavailable)?;
                let proxies: Vec<_> = bound
                    .into_iter()
                    .map(|b| podnet::warp::proxy::run_l4(door.clone(), b))
                    .collect();
                for proxy in &proxies {
                    println!(
                        "podnet: warp proxy  {}  (L4: {l4_sni}, HTTP/3 on UDP; TCP only)",
                        listen_doc(&proxy.listen)["listen"].as_str().unwrap_or("?")
                    );
                }
                let mut doc = listen_doc(&proxies[0].listen);
                doc["listens"] = proxies
                    .iter()
                    .map(|p| listen_doc(&p.listen)["listen"].clone())
                    .collect::<Vec<_>>()
                    .into();
                doc["l4"] = true.into();
                podnet::detach::ready(doc);
                sleep_or_signal(run_for).await;
                for proxy in &proxies {
                    proxy.abort();
                }
                return Ok(());
            }
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            podnet::warp::proxy::health_log(live.clone());
            if let Some(socket) = dns_socket {
                podnet::warp::proxy::serve_dns(live.clone(), socket);
            }
            let mut proxies: Vec<_> = bound
                .into_iter()
                .map(|b| podnet::warp::proxy::run(live.clone(), b))
                .collect();
            let mut identities = Vec::new();
            for (b, identity) in extra {
                let other = podnet::warp::WarpClient::register_or_load(&identity)
                    .await
                    .fault(Fault::Unavailable)?
                    .with_masque(masque.clone());
                let device = other.device().id.clone();
                let other = Arc::new(other)
                    .connect_live()
                    .await
                    .fault(Fault::Unavailable)?;
                let proxy = podnet::warp::proxy::run(other, b);
                identities.push(serde_json::json!({
                    "listen": listen_doc(&proxy.listen)["listen"],
                    "identity": identity.display().to_string(),
                    "device": device,
                }));
                proxies.push(proxy);
            }
            for proxy in &proxies {
                match &proxy.listen {
                    podnet::vnet::proxy::ProxyListen::Tcp(addr) => {
                        println!("podnet: warp proxy  socks5h://{addr}  (and HTTP CONNECT)");
                        println!("  export ALL_PROXY=socks5h://{addr} HTTPS_PROXY=http://{addr}");
                    }
                    podnet::vnet::proxy::ProxyListen::Unix(path) => {
                        println!("podnet: warp proxy  unix:{}", path.display());
                        println!(
                            "  podnet pod -x socks5://unix:{} -- PROGRAM",
                            path.display()
                        );
                    }
                }
            }
            let mut doc = listen_doc(&proxies[0].listen);
            doc["listens"] = proxies
                .iter()
                .map(|p| listen_doc(&p.listen)["listen"].clone())
                .collect::<Vec<_>>()
                .into();
            doc["failed"] = failed
                .iter()
                .map(|(listen, err)| {
                    serde_json::json!({
                        "listen": listen_doc(listen)["listen"],
                        "error": format!("{err:#}"),
                    })
                })
                .collect::<Vec<_>>()
                .into();
            doc["identities"] = identities.into();
            podnet::detach::ready(podnet::warp::live::instance::with_data_path(doc));
            sleep_or_signal(run_for).await;
            for proxy in &proxies {
                proxy.abort();
            }
        }
        WarpCommand::Forward {
            local,
            strict,
            max_connections,
            run_for,
            ..
        } => {
            // Issue 143: check each rule before any bind or session (exit 64).
            let rules = local
                .iter()
                .map(|spec| podnet::warp::forward::Rule::parse(spec))
                .collect::<Result<Vec<_>>>()
                .fault(Fault::Usage)?;
            let mut bound = Vec::new();
            let mut failed = Vec::new();
            for rule in rules {
                match podnet::warp::proxy::bind(&rule.listen).await {
                    Ok(b) => bound.push((b, rule)),
                    Err(err) => {
                        eprintln!(
                            "podnet: warp forward: {} is not available: {err:#}",
                            rule.target()
                        );
                        failed.push((rule, err));
                    }
                }
            }
            if bound.is_empty() || (strict && !failed.is_empty()) {
                let list = failed
                    .iter()
                    .map(|(_, err)| format!("{err:#}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(podnet::exit::fault(
                    Fault::Unavailable,
                    anyhow::anyhow!("warp forward: a listener did not start: {list}"),
                ));
            }
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            podnet::warp::proxy::health_log(live.clone());
            let forwards: Vec<_> = bound
                .into_iter()
                .map(|(b, rule)| podnet::warp::forward::run(live.clone(), b, rule, max_connections))
                .collect();
            let mut docs = Vec::new();
            for forward in &forwards {
                let listen = listen_doc(&forward.listen)["listen"].clone();
                println!(
                    "podnet: warp forward  {}  ->  {} (through WARP)",
                    listen.as_str().unwrap_or("?"),
                    forward.rule.target()
                );
                docs.push(serde_json::json!({ "listen": listen, "to": forward.rule.target() }));
            }
            let mut doc = listen_doc(&forwards[0].listen);
            doc["forward"] = docs.into();
            doc["failed"] = failed
                .iter()
                .map(|(rule, err)| {
                    serde_json::json!({
                        "listen": listen_doc(&rule.listen)["listen"],
                        "to": rule.target(),
                        "error": format!("{err:#}"),
                    })
                })
                .collect::<Vec<_>>()
                .into();
            podnet::detach::ready(doc);
            sleep_or_signal(run_for).await;
            for forward in &forwards {
                forward.abort();
            }
        }
        #[cfg(target_os = "linux")]
        WarpCommand::Tun {
            interface: name,
            default_route,
            keep_rp_filter,
            ..
        } => {
            podnet::warp::tun::rp_filter::set_keep(keep_rp_filter);
            let address = client
                .device()
                .ipv4()
                .context("the device has no IPv4 address")
                .fault(Fault::Unavailable)?;
            // Issue 102: a TUN that cannot be made, or a session that
            // cannot open, is an unavailable path (69), as for warp up --tun.
            let tun =
                podnet::warp::tun::Tun::create(&name, address, 1280).fault(Fault::Unavailable)?;
            let session = client.connect_raw().await.fault(Fault::Unavailable)?;
            // The IPv6-only kit, 0001: the front door of the session, not
            // the first address of the device record.
            let endpoint = client
                .endpoint_in_use()
                .map(|e| e.ip().to_string())
                .unwrap_or_default();
            println!("podnet: tun      {} {address}/32 mtu 1280", tun.name);
            if let Some(v6) = client.device().ipv6() {
                match tun.add_ipv6(v6) {
                    Ok(()) => println!("podnet: tun      {} {v6}/128", tun.name),
                    Err(err) => {
                        tracing::warn!(error = %format!("{err:#}"), "the TUN has no IPv6 address")
                    }
                }
            }
            println!(
                "podnet: masque   {endpoint} (do not route this address into {})",
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
            let host_prefix = if endpoint.contains(':') {
                "-6 route add {}/128"
            } else {
                "route add {}/32"
            };
            println!(
                "  ip {} via <your gateway>   # keep the session outside",
                host_prefix.replace("{}", &endpoint)
            );
            // --default-route (issue 77): the addresses of the MASQUE
            // connection stay outside the tunnel.
            let routes = if default_route {
                // The front door of the session (or its proxy) must stay
                // outside the TUN; the relay of a later session should,
                // where a route to it exists.
                let session_host = match podnet::egress::proxy_for(&endpoint, 443) {
                    Some(proxy) => proxy.host,
                    None => endpoint.clone(),
                };
                let mut relay_host = String::new();
                if !args.no_relay {
                    if let Ok(relay) = podnet::ws_relay::Relay::from_env(None) {
                        // Issue 105: a relay that is reached through the
                        // proxy needs no route of its own.
                        relay_host = match podnet::egress::proxy_for(relay.host(), relay.port()) {
                            Some(proxy) => proxy.host,
                            None => relay.host().to_string(),
                        };
                    }
                }
                let addresses = |host: String| async move {
                    if host.is_empty() {
                        return Vec::new();
                    }
                    podnet::resolve::resolve(&host).await.unwrap_or_default()
                };
                let required = addresses(session_host).await;
                let mut optional = addresses(relay_host).await;
                optional.retain(|ip| !required.contains(ip));
                let routes = podnet::warp::route::Routes::setup(
                    &tun.name,
                    required,
                    optional,
                    client.device().ipv6().is_some(),
                )
                .fault(Fault::Unavailable)?;
                let outside = routes
                    .exempted()
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "podnet: routes   the default routes go to {}; outside: {}",
                    tun.name,
                    if outside.is_empty() {
                        "none needed (the MASQUE connection goes through loopback or a connected subnet)".to_string()
                    } else {
                        outside
                    }
                );
                Some(std::sync::Mutex::new(routes))
            } else {
                None
            };
            podnet::detach::ready(serde_json::json!({
                "tun": tun.name,
                "address": address.to_string(),
                "default_route": default_route,
                "rp_filter": podnet::warp::tun::rp_filter::apply(&tun.name),
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
                            // #278: no session with half of the default
                            // routes; up() removed the half that was in.
                            tracing::error!(error = %format!("{err:#}"), next_try_s = delay.as_secs(), "no default routes on the TUN; podnet tries again");
                            drop(current);
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(std::time::Duration::from_secs(30));
                            continue;
                        }
                    }
                    if let Err(err) = podnet::warp::tun::run(tun_ref, current).await {
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
        WarpCommand::Tun { .. } => bail!("podnet warp tun is available on Linux only"),
        WarpCommand::Up { .. }
        | WarpCommand::Down
        | WarpCommand::Export(_)
        | WarpCommand::Env
        | WarpCommand::Exec { .. }
        | WarpCommand::Shell(_)
        | WarpCommand::SshConfig { .. } => unreachable!("handled before the client is made"),
        WarpCommand::Nc {
            host,
            port,
            udp,
            idle,
            shutdown,
            ..
        } => {
            // No podnet warp up runs: a session of this process. Issue 115:
            // say so, because the two ways fail in other ways.
            tracing::info!(
                "podnet warp up is not running; warp nc opens a WARP session of its own"
            );
            let stack = Arc::new(client.connect().await.fault(Fault::Unavailable)?);
            if udp {
                let (out, back) = podnet::warp::nc::udp_via_stack(stack, &host, port)
                    .await
                    .fault(Fault::Unavailable)?;
                return udp_nc(out, back, idle.unwrap_or(UDP_NC_IDLE)).await;
            }
            let target = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => podnet_netns::socks::ProxyHost::Ip(ip),
                Err(_) => podnet_netns::socks::ProxyHost::Domain(host.clone()),
            };
            let io = podnet::warp::proxy::dial(stack, target, port)
                .await
                .fault(Fault::Unavailable)?;
            podnet::warp::nc::pipe(Box::new(io), nc_end(idle, shutdown))
                .await
                .fault(Fault::Unavailable)?;
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
                || (backend == "auto" && rules.is_empty() && podnet_netns::raw::available());
            if raw {
                match warp_run_raw(&client, &program, keep_proxy_env).await {
                    Ok(code) => std::process::exit(code),
                    // Issue 251: the program cannot run. The proxy pod
                    // cannot run it either: exit 3, as the netns backend.
                    Err(err) if err.downcast_ref::<podnet_netns::raw::ExecError>().is_some() => {
                        eprintln!("podnet: warp run: {err:#}");
                        std::process::exit(podnet::exit::NO_BACKEND);
                    }
                    Err(err) if backend == "auto" => {
                        tracing::info!(error = %format!("{err:#}"), "the netns-raw backend cannot run here; the pod with a proxy runs");
                    }
                    Err(err) => return Err(podnet::exit::fault(Fault::Unavailable, err)),
                }
            }
            let backend = if backend == "netns-raw" {
                "auto".to_string()
            } else {
                backend
            };
            let socket =
                std::env::temp_dir().join(format!("podnet-warp-{}.sock", std::process::id()));
            let live = Arc::new(client)
                .connect_live()
                .await
                .fault(Fault::Unavailable)?;
            let proxy = podnet::warp::proxy::serve(
                live,
                podnet::vnet::proxy::ProxyListen::Unix(socket.clone()),
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
            // podnet-netns makes its own runtime, so run it on a plain thread.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(podnet_netns::main_with_args(&argv));
            });
            let code = done_rx.await.unwrap_or(1);
            proxy.abort();
            let _ = std::fs::remove_file(&socket);
            std::process::exit(code);
        }
    }
    Ok(())
}

/// `podnet warp run --backend netns-raw`: the program in a raw pod whose TUN
/// packets go through WARP; a session that ends is opened again. Gives the
/// exit code of the program.
async fn warp_run_raw(
    client: &podnet::warp::WarpClient,
    program: &[String],
    keep_proxy_env: bool,
) -> Result<i32> {
    let v4 = client
        .device()
        .ipv4()
        .context("the device has no IPv4 address")?;
    let mut session = Some(client.connect_raw().await?);
    let pod = podnet_netns::raw::spawn(&podnet_netns::raw::RawOptions {
        program: program.to_vec(),
        keep_proxy_env,
        v4,
        v6: client.device().ipv6(),
        mtu: podnet::warp::ip::TUNNEL_MTU,
        nameserver: podnet::warp::route::nameservers_of_service()[0],
    })?;
    let pid = pod.pid;
    let tun = podnet::warp::tun::Tun::from_fd(pod.tun, "eth0")?;
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
            if let Err(err) = podnet::warp::tun::run(&tun, current).await {
                tracing::warn!(error = %format!("{err:#}"), "the WARP session ended; opening a new one");
            }
        }
    };
    let exited = async {
        loop {
            if let Some(code) = podnet_netns::raw::try_wait(pid) {
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

fn print_device(client: &podnet::warp::WarpClient, path: Option<&std::path::Path>) {
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
        None => println!("saved       no (--ephemeral or PODNET_STATE_DIR=none)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::cmd::agent::agent_commands;
    use crate::cli::cmd::run::idle_watch;
    use crate::cli::cmd::share::{share_mode, ModeArg, ShareArgs};
    use crate::cli::help::{example_path, first_sentence, word_hint, HELP_GROUPS};
    use crate::cli::signals::{deadline_of, until_stop_or};
    use clap::Parser as _;
    use podnet::share::ShareControl;

    /// Issues 253 and 254: a lint of each help screen. No issue numbers of
    /// this project, no `[env: X=]`, no `<a|b>` value name next to a list
    /// of possible values, and each shell of completions.
    #[test]
    fn each_help_screen_passes_the_lint() {
        fn walk(cmd: &clap::Command, path: String, out: &mut Vec<(String, String)>) {
            let mut cmd = cmd.clone();
            out.push((path.clone(), cmd.render_long_help().to_string()));
            for sub in cmd.get_subcommands() {
                if sub.get_name() != "help" {
                    walk(sub, format!("{path} {}", sub.get_name()), out);
                }
            }
        }
        let mut screens = Vec::new();
        let mut root = Cli::command();
        root.build();
        walk(&root, "podnet".into(), &mut screens);
        let mut faults = Vec::new();
        for (path, help) in &screens {
            for line in help.lines() {
                let lower = line.to_ascii_lowercase();
                if let Some(at) = lower.find("issue ") {
                    if lower[at + 6..].starts_with(|c: char| c.is_ascii_digit()) {
                        faults.push(format!("{path}: an issue number: {line}"));
                    }
                }
                if line.contains("=]") && line.contains("[env: ") {
                    faults.push(format!("{path}: an env value bracket: {line}"));
                }
                if let Some(at) = line.find(" <") {
                    let name = &line[at + 2..];
                    if let Some(end) = name.find('>') {
                        let value = &name[..end];
                        if value.contains('|')
                            && !value.contains("--")
                            && !line.trim_start().starts_with("Usage:")
                        {
                            faults.push(format!("{path}: a value name with |: {line}"));
                        }
                    }
                }
            }
        }
        assert!(faults.is_empty(), "{}", faults.join("\n"));
        let completions = &screens
            .iter()
            .find(|(p, _)| p == "podnet completions")
            .unwrap()
            .1;
        assert!(completions.contains("PowerShell"), "{completions}");
        assert!(completions.contains("Elvish"), "{completions}");
    }

    // Issue 271: the idle clock of a share starts when the session serves.
    // A control that was built 1.1 s before does not end a session with
    // --idle-secs 1 at the first check (5 s); in 60 s of the paused clock
    // the watch does not end.
    #[tokio::test(start_paused = true)]
    async fn the_idle_clock_starts_when_the_session_serves() {
        let control = Arc::new(ShareControl::default());
        std::thread::sleep(Duration::from_millis(1100));
        let watch = idle_watch(vec![control], 1);
        let ended = tokio::time::timeout(Duration::from_secs(60), watch).await;
        assert!(ended.is_err(), "the watch ended at the first check");
    }

    /// E1: each command of podnet is in one group of the top help.
    #[test]
    fn each_command_is_in_one_help_group() {
        let cmd = Cli::command();
        let mut names: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        names.push("help".into());
        let listed: Vec<&str> = HELP_GROUPS
            .iter()
            .flat_map(|(_, n)| n.iter().copied())
            .collect();
        for name in &names {
            let count = listed.iter().filter(|l| **l == name.as_str()).count();
            assert_eq!(count, 1, "{name} is in {count} groups");
        }
        for name in &listed {
            assert!(names.iter().any(|n| n == name), "{name} is no command");
        }
        let help = top_command().render_help().to_string();
        assert!(help.contains("Start here:"), "{help}");
        assert!(!help.contains("(issue "), "{help}");
        assert_eq!(first_sentence("Test it: the proxy. More"), "Test it");
        assert_eq!(first_sentence("One command (issue 87): x"), "One command");
    }

    /// E12: a server command with no terminal names --detach.
    #[test]
    fn a_foreground_server_with_no_terminal_gets_one_line() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let tunnel = argv(&["podnet", "tunnel", "--url", "http://localhost:1"]);
        let line = foreground_hint(Some("tunnel"), &tunnel, false, true).unwrap();
        assert!(
            line.contains("--detach") && line.contains("--run-for"),
            "{line}"
        );
        assert!(
            foreground_hint(Some("tunnel"), &tunnel, false, false).is_none(),
            "a terminal"
        );
        assert!(
            foreground_hint(Some("tunnel"), &tunnel, true, true).is_none(),
            "a detached child"
        );
        assert!(foreground_hint(Some("status"), &tunnel, false, true).is_none());
        for flag in ["--detach", "--run-for=5", "--exit-on-verify"] {
            let mut with = tunnel.clone();
            with.push(flag.into());
            assert!(
                foreground_hint(Some("tunnel"), &with, false, true).is_none(),
                "{flag}"
            );
        }
        assert!(foreground_hint(Some("relay node"), &tunnel, false, true).is_some());
    }

    /// E9: the arguments of cloudflared for a tunnel.
    #[test]
    fn cloudflared_arguments_work() {
        let run = |a: &[&str]| -> Vec<String> {
            cloudflared_compat(a.iter().map(Into::into).collect())
                .into_iter()
                .map(|o| o.into_string().unwrap())
                .collect()
        };
        assert_eq!(
            run(&["podnet", "--no-autoupdate", "tunnel", "run", "--token", "T"]),
            ["podnet", "tunnel", "--token", "T"]
        );
        assert_eq!(
            run(&["podnet", "tunnel", "--loglevel", "debug", "--url", "u"]),
            ["podnet", "tunnel", "-v", "--url", "u"]
        );
        assert_eq!(
            run(&["podnet", "tunnel", "--loglevel=warn"]),
            ["podnet", "tunnel", "-q"]
        );
        assert_eq!(
            run(&["podnet", "tunnel", "--loglevel", "info"]),
            ["podnet", "tunnel"]
        );
        // Not for another command, and not after --.
        let other = [
            "podnet",
            "warp",
            "run",
            "--",
            "tunnel",
            "run",
            "--no-autoupdate",
        ];
        assert_eq!(run(&other), other);
        let other = ["podnet", "serve", "--name", "tunnel", "--dir", "run"];
        assert_eq!(run(&other), other);
        // A parse of the result works.
        let parsed = top_command().try_get_matches_from(run(&[
            "podnet",
            "tunnel",
            "run",
            "--no-autoupdate",
            "--loglevel",
            "error",
            "--url",
            "http://127.0.0.1:1",
        ]));
        assert!(parsed.is_ok(), "{parsed:?}");
        let err = top_command()
            .try_get_matches_from(["podnet", "tunnel", "--logfile", "x"])
            .unwrap_err();
        let hints = usage_hints(&err);
        assert!(
            hints[0].contains("--logfile is a flag of cloudflared"),
            "{hints:?}"
        );
        assert_eq!(hints.len(), 1, "{hints:?}");
    }

    /// E7: an example is in the help of its command.
    #[test]
    fn the_help_of_a_command_has_its_examples() {
        let help = |path: &[&str]| -> String {
            let mut cmd = top_command();
            for name in path {
                cmd = cmd.find_subcommand(name).unwrap().clone();
            }
            cmd.render_long_help().to_string()
        };
        let tunnel = help(&["tunnel"]);
        assert!(tunnel.contains("Examples:"), "{tunnel}");
        assert!(
            tunnel.contains("podnet tunnel --url http://127.0.0.1:8080"),
            "{tunnel}"
        );
        assert!(!tunnel.contains("podnet warp"), "{tunnel}");
        let node = help(&["relay", "node"]);
        assert!(
            node.contains("podnet relay node --to 127.0.0.1:22"),
            "{node}"
        );
        assert_eq!(
            example_path(&Cli::command(), "podnet warp proxy -r 1080"),
            "podnet warp proxy"
        );
        // Each example belongs to a command (not to podnet alone).
        for e in podnet::manual::facts::EXAMPLES
            .iter()
            .filter(|e| e.command.starts_with("podnet "))
        {
            assert_ne!(
                example_path(&Cli::command(), e.command),
                "podnet",
                "{}",
                e.command
            );
        }
    }

    /// E8: a word that is no command names the command for it.
    #[test]
    fn a_word_that_is_no_command_gets_a_hint() {
        let hint = |w: &str| word_hint(w).unwrap_or_default();
        assert!(hint("8080").contains("podnet tunnel --url http://localhost:8080"));
        assert!(hint("https://example.org").contains("podnet tunnel --url https://example.org"));
        assert!(hint("wss://x.example").contains("podnet connect --local"));
        assert!(hint("/").contains("podnet serve --dir /"));
        assert!(hint("Cargo.toml").contains("podnet share --mode download --file Cargo.toml"));
        assert_eq!(word_hint("tunel"), None);
        assert_eq!(word_hint("123456"), None, "not a port");
    }

    /// E10: an unknown command or flag names the version and the update.
    #[test]
    fn an_unknown_command_names_the_version() {
        let err = top_command()
            .try_get_matches_from(["podnet", "8080"])
            .unwrap_err();
        let lines = usage_hints(&err);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains(env!("CARGO_PKG_VERSION")), "{lines:?}");
        assert!(lines[1].contains("podnet update --check"), "{lines:?}");
        let err = top_command()
            .try_get_matches_from(["podnet", "tunnel", "--bogus"])
            .unwrap_err();
        assert!(usage_hints(&err)[0].contains("'--bogus'"));
        let err = top_command()
            .try_get_matches_from(["podnet", "tunnel", "--port", "x"])
            .unwrap_err();
        assert!(
            usage_hints(&err).is_empty(),
            "a bad value is no unknown flag"
        );
    }

    fn share_args(argv: &[&str]) -> ShareArgs {
        let cli = Cli::try_parse_from(["podnet", "share"].iter().chain(argv)).unwrap();
        match cli.command {
            Command::Share(args) => args,
            other => panic!("{other:?}"),
        }
    }

    // Issue 118: the mode follows the flags; flags of two modes are an
    // error. Before, --file with no --mode gave an upload session.
    #[test]
    fn the_share_mode_follows_the_flags() {
        let mode = |argv: &[&str]| share_mode(&share_args(argv));
        assert_eq!(mode(&["--file", "f"]).unwrap(), ModeArg::Download);
        assert_eq!(mode(&["--port", "3000"]).unwrap(), ModeArg::Proxy);
        assert_eq!(mode(&["--mode", "upload"]).unwrap(), ModeArg::Upload);
        assert_eq!(mode(&["--dir", "d"]).unwrap(), ModeArg::Upload);
        assert_eq!(
            mode(&["--mode", "download", "--file", "f"]).unwrap(),
            ModeArg::Download
        );
        for bad in [
            // Issue 250: no mode flag is an error.
            &[][..],
            &["--file", "f", "--port", "1"][..],
            &["--mode", "upload", "--file", "f"][..],
            &["--mode", "proxy", "--dir", "d"][..],
        ] {
            let err = mode(bad).unwrap_err();
            assert_eq!(podnet::exit::code_of(&err), 64, "{bad:?}: {err}");
        }
    }

    // The IPv6-only kit, 0002: warp up --tun gives its child the front door
    // and the TLS name.
    #[test]
    fn the_pairs_of_listen_identity() {
        let main = std::path::Path::new("/s/warp.json");
        let pairs = identity_pairs(
            &[
                "tcp://127.0.0.1:40001=/s/b.json".into(),
                "unix:/run/c.sock=/s/c.json".into(),
            ],
            Some(main),
            &["tcp://127.0.0.1:40000".into()],
        )
        .unwrap();
        assert_eq!(pairs.len(), 2);
        // Issue 178: the listener of --listen.
        assert!(identity_pairs(
            &["tcp://127.0.0.1:40000=/s/b.json".into()],
            Some(main),
            &["tcp://127.0.0.1:40000".into()],
        )
        .is_err());
        assert_eq!(pairs[1].1, PathBuf::from("/s/c.json"));
        for bad in [
            vec!["127.0.0.1:40001=/s/warp.json"],
            vec!["127.0.0.1:40001=/s/b.json", "127.0.0.1:40002=/s/b.json"],
            vec!["127.0.0.1:40001=/s/b.json", "127.0.0.1:40001=/s/c.json"],
            vec!["127.0.0.1:40001"],
            vec!["=/s/b.json"],
            vec!["nothing=/s/b.json"],
        ] {
            let specs: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert!(identity_pairs(&specs, Some(main), &[]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_front_doors_of_a_scan() {
        assert_eq!(
            parse_door("162.159.198.1").unwrap().to_string(),
            "162.159.198.1:443"
        );
        assert_eq!(parse_door("162.159.198.1:8443").unwrap().port(), 8443);
        assert_eq!(
            parse_door("2606:4700:103::1").unwrap().to_string(),
            "[2606:4700:103::1]:443"
        );
        assert_eq!(parse_door("[2606:4700:103::1]:443").unwrap().port(), 443);
        assert!(parse_door("engage.cloudflareclient.com").is_err());
        assert!(parse_door("162.159.198.0/24").is_err());
    }

    #[test]
    fn warp_up_tun_keeps_the_front_door() {
        let cli = Cli::try_parse_from([
            "podnet",
            "warp",
            "--masque-endpoint",
            "[2606:4700:103::2]:443",
            "--masque-sni",
            "example.test",
            "--ephemeral",
            "up",
            "--tun",
        ])
        .unwrap();
        let Command::Warp(args) = cli.command else {
            panic!("not warp")
        };
        let argv = warp_up_tun_args(&args, 30);
        let has = |a: &str, b: &str| argv.windows(2).any(|w| w[0] == a && w[1] == b);
        assert!(
            has("--masque-endpoint", "[2606:4700:103::2]:443"),
            "{argv:?}"
        );
        assert!(has("--masque-sni", "example.test"), "{argv:?}");
        assert!(argv.contains(&"--ephemeral".to_string()));
        let tun = argv.iter().position(|a| a == "tun").unwrap();
        assert!(argv.iter().position(|a| a == "--masque-endpoint").unwrap() < tun);
        let parsed = Cli::try_parse_from(std::iter::once("podnet".to_string()).chain(argv));
        assert!(parsed.is_ok(), "the argv parses");
    }

    // Issues 110 and 116: a unix-only warp up gets warp exec and
    // ssh-config, and no eval line.
    #[test]
    fn the_agent_commands_follow_the_listeners() {
        let unix_only = agent_commands(true, false);
        assert!(
            !unix_only.iter().any(|c| c.contains("eval")),
            "{unix_only:?}"
        );
        assert!(unix_only.iter().any(|c| c.contains("podnet warp exec")));
        assert!(unix_only.iter().any(|c| c.contains("ssh-config")));
        let tcp = agent_commands(true, true);
        assert!(tcp[0].starts_with("eval"), "{tcp:?}");
        let direct = agent_commands(false, true);
        assert_eq!(direct, ["podnet agent status", "podnet agent down"]);
    }

    /// Issue 101: once the stop is armed (at the ready line), a SIGTERM
    /// ends the work of `until_stop_or` (the verify) with `None`: a clean
    /// stop, not the default action. The only test here that takes
    /// signals: the stop request is global to the process.
    #[test]
    fn a_sigterm_after_the_ready_line_stops_the_verify_cleanly() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            install_signals();
            podnet::detach::arm_stop();
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                // SAFETY: kill() to this process.
                unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
            });
            let out = tokio::time::timeout(
                Duration::from_secs(10),
                until_stop_or(None, std::future::pending::<()>()),
            )
            .await
            .expect("the signal ends the wait");
            assert!(out.is_none());
            // The stop request stays: a later wait ends at once.
            assert!(until_stop_or(None, async { 1 }).await.is_none());
        });
    }

    /// Issue 179: --run-for ends the verify.
    #[tokio::test]
    async fn until_stop_or_ends_at_the_deadline() {
        let deadline = deadline_of(Some(0));
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            until_stop_or(deadline, std::future::pending::<()>()),
        )
        .await
        .expect("the deadline ends the wait");
        assert!(out.is_none());
    }

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
        for example in podnet::manual::facts::EXAMPLES {
            let words: Vec<&str> = example.command.split_whitespace().collect();
            assert_eq!(words[0], "podnet", "{}", example.command);
            if words.get(1) == Some(&"pod") {
                // pod has its own parser, in podnet-netns.
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
        let manual = podnet::manual::model::build(Cli::command());
        let text = podnet::manual::text::render(&manual);
        fn walk(cmd: &clap::Command, path: &mut Vec<String>, text: &str) {
            for sub in cmd.get_subcommands().filter(|c| c.get_name() != "help") {
                path.push(sub.get_name().to_string());
                assert!(
                    text.contains(&format!("podnet {}", path.join(" "))),
                    "the manual has no section for podnet {}",
                    path.join(" ")
                );
                for arg in sub.get_arguments().filter(|a| !a.is_hide_set()) {
                    if let Some(long) = arg.get_long() {
                        if long != "help" && long != "version" {
                            assert!(
                                text.contains(&format!("--{long}")),
                                "the manual has no --{long} (podnet {})",
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
            text.contains("podnet-netns"),
            "the pod section has the podnet-netns usage"
        );
    }

    #[test]
    fn the_warp_proxy_of_warp_up_parses() {
        let cli =
            Cli::try_parse_from(["podnet", "warp", "--no-relay", "up", "--port", "40100"]).unwrap();
        let Command::Warp(args) = cli.command else {
            panic!("not warp")
        };
        let argv = warp_up_args(&args, 40100, std::path::Path::new("/r/warp.sock"), 30);
        let parsed =
            Cli::try_parse_from(std::iter::once("podnet".to_string()).chain(argv)).unwrap();
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
        let err = Cli::try_parse_from(["podnet", "tunel"]).unwrap_err();
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
            command_name(&argv("podnet warp run -- curl")).as_deref(),
            Some("warp run")
        );
        assert_eq!(
            command_name(&argv("podnet tunnel --url x")).as_deref(),
            Some("tunnel")
        );
        assert_eq!(command_name(&argv("podnet nothing")), None);
        // Issue 181: options before the command are skipped.
        for (line, want) in [
            ("podnet -q tunnel", "tunnel"),
            ("podnet -vv doctor", "doctor"),
            ("podnet --proxy http://x:1 warp run -- curl", "warp run"),
            (
                "podnet --color never --log-format json net doctor",
                "net doctor",
            ),
            ("podnet --ca-file=a.pem status", "status"),
        ] {
            assert_eq!(command_name(&argv(line)).as_deref(), Some(want), "{line}");
        }
    }

    // Issue 178: an empty license key is a usage error; a text field has no
    // quotes; warp_plus_active follows the account.
    #[test]
    fn warp_license_and_status_fields() {
        let err = Cli::try_parse_from(["podnet", "warp", "license", ""]).unwrap_err();
        assert_eq!(err.exit_code(), 2, "clap error");
        assert!(non_empty_key("  ").is_err());
        assert_eq!(non_empty_key(" k ").unwrap(), "k");
        assert_eq!(plain_value(&serde_json::json!("free")), "free");
        assert_eq!(plain_value(&serde_json::json!(5)), "5");
        assert_eq!(plain_value(&serde_json::Value::Null), "-");
        let free = serde_json::json!({"account_type": "free", "warp_plus": true});
        assert_eq!(podnet::warp::identity::warp_plus_label(&free), "no");
        let plus = serde_json::json!({"account_type": "limited", "premium_data": 10});
        assert_eq!(podnet::warp::identity::warp_plus_label(&plus), "yes");
    }

    #[test]
    fn the_pod_keeps_its_double_dash() {
        let v = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(
            pod_args_of(&v("podnet -v pod -- true"), &v("true")),
            v("-- true")
        );
        assert_eq!(
            pod_args_of(&v("podnet pod -x u -- a"), &v("-x u -- a")),
            v("-x u -- a")
        );
    }
}
