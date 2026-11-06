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

use anyhow::{Context, Result};
use clap::FromArgMatches as _;
use tracing_subscriber::EnvFilter;

use podnet::exit::{Fault, ResultExt};

use cli::argv::{
    apply_token_files, cloudflared_compat, command_name, foreground_hint, no_terminal, pod_args_of,
    pod_network_option, LOG_JSON,
};
use cli::cmd::run::listen_doc;
use cli::cmd::tunnel::split_host_port;
use cli::cmd::warp::client::{identity_pairs, masque_options};
use cli::cmd::warp::{WarpArgs, WarpCommand};
use cli::help::{error_json, json_wanted, print_error, top_command, usage_hints};
use cli::opts::{detach_of, network_options};
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

/// A JSON value for a text line: a string with no quotes (issue 178).
fn plain_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "-".into(),
        other => other.to_string(),
    }
}

/// The subcommands of `podnet warp` that need a WARP client: the account,
/// the probes, the proxy, the forwards, the TUN and `warp run`.
pub(crate) async fn warp_other(
    args: WarpArgs,
    mut client: podnet::warp::WarpClient,
    path: Option<PathBuf>,
) -> Result<()> {
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
        WarpCommand::Tun { .. } => anyhow::bail!("podnet warp tun is available on Linux only"),
        WarpCommand::Up { .. }
        | WarpCommand::Down
        | WarpCommand::Export(_)
        | WarpCommand::Env
        | WarpCommand::Exec { .. }
        | WarpCommand::Shell(_)
        | WarpCommand::SshConfig { .. }
        | WarpCommand::Nc { .. } => unreachable!("handled before this function"),
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
    use crate::cli::cmd::warp::args::non_empty_key;
    use crate::cli::cmd::warp::up::{warp_up_args, warp_up_tun_args};
    use crate::cli::help::{example_path, first_sentence, word_hint, HELP_GROUPS};
    use crate::cli::signals::{deadline_of, until_stop_or};
    use clap::Parser as _;
    use podnet::share::ShareControl;
    use std::time::Duration;

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
