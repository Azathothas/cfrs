//! The host commands: `status`, `doctor`, `man`, `update`, `ports`, `qr`,
//! `bug-report` and `completions`.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;

use podnet::exit::{Fault, ResultExt};

use crate::cli::Cli;

#[derive(Args, Debug)]
pub(crate) struct DoctorArgs {
    /// Print one JSON document.
    #[arg(long)]
    json: bool,
    /// Test what dev work can do here: git over HTTPS and SSH, the package
    /// registries, UDP DNS, IPv6 and localhost, directly, through the proxy
    /// and through a running podnet warp up; then print the commands to run.
    #[arg(long)]
    agent: bool,
    /// Samples of each TCP path (1-9). All samples end in 10 s.
    #[arg(long, default_value_t = 9, value_parser = clap::value_parser!(u8).range(1..=9))]
    samples: u8,
    /// The time limit of one connection and of one TLS handshake, in seconds.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=10))]
    timeout: u64,
}

#[derive(Args, Debug)]
pub(crate) struct ManArgs {
    /// Sections: commands (tunnel, warp run) and topics (environment, files,
    /// exit-status, examples, pod). `podnet man tunnel serve` gives both.
    #[arg(value_name = "SECTION", num_args = 0..)]
    section: Vec<String>,
    /// Write to stdout, also on a terminal.
    #[arg(long)]
    no_pager: bool,
    /// Write a man(7) page.
    #[arg(long, conflicts_with = "json")]
    roff: bool,
    /// Write the manual as one JSON object.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct UpdateArgs {
    /// Only say which release is available; change nothing.
    #[arg(long)]
    check: bool,
    /// The tag to install, for example v0.3.0-beta.11. Default: the newest
    /// release (a prerelease only when this binary is a prerelease).
    #[arg(long, value_name = "TAG", value_parser = parse_release_tag)]
    version: Option<String>,
    /// Put the binary before the last update (podnet.prev) back, with no
    /// network. A second --rollback goes forward again.
    #[arg(long, conflicts_with_all = ["check", "version", "force"])]
    rollback: bool,
    /// Install the release also when it is the version of this binary.
    /// Without it, podnet says that the version is installed and exits 0.
    #[arg(long)]
    force: bool,
}

/// A `--version` of `podnet update`: a release tag (issue 227).
pub(crate) fn parse_release_tag(value: &str) -> Result<String, String> {
    if podnet::update::valid_tag(value) {
        Ok(value.to_string())
    } else {
        Err("not a release tag (for example v0.3.0-beta.9)".to_string())
    }
}

#[derive(Args, Clone, Debug)]
pub(crate) struct PortsArgs {
    /// Print one JSON object: {"ports": [PORT, ...]}.
    #[arg(long)]
    json: bool,
    /// Connect to each port, and list only the ports that accept a
    /// connection. With --json, the others are in "unreachable".
    #[arg(long)]
    probe: bool,
}

#[derive(Args, Debug)]
pub(crate) struct QrArgs {
    /// URL to encode (at most 2331 bytes). Another text gets a warning.
    url: String,
}

/// `podnet update`, and `podnet update --rollback`.
pub(crate) async fn update(args: UpdateArgs) -> Result<()> {
    if args.rollback {
        let path = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .context("finding this binary")?;
        let now = podnet::update::rollback(&path).fault(Fault::Unavailable)?;
        println!(
            "{}: {now} (put back from {})",
            path.display(),
            podnet::update::previous_of(&path).display()
        );
        return Ok(());
    }
    use podnet::update::Outcome;
    // Issue 249: an empty tag asked the network, then exit 69.
    if let Some(tag) = args.version.as_deref() {
        let good = !tag.is_empty()
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
        if !good {
            return Err(podnet::exit::fault(
                Fault::Usage,
                anyhow::anyhow!("--version {tag:?}: give a tag like v0.3.0-beta.11"),
            ));
        }
    }
    match podnet::update::run(args.version.as_deref(), args.check, args.force)
        .await
        .fault(Fault::Unavailable)?
    {
        Outcome::UpToDate(tag) => println!("podnet {tag} is the newest release"),
        Outcome::Same(tag) => {
            println!("podnet {tag} is installed; nothing to do (--force installs it again)")
        }
        Outcome::Available { current, tag } => {
            println!("podnet {current}; release {tag} is available (podnet update)")
        }
        Outcome::Updated { from, to, path } => {
            println!(
                "podnet {from} -> {to}: {} (signature and SHA-256 checked)",
                path.display()
            )
        }
    }
    Ok(())
}

/// `podnet completions SHELL`.
pub(crate) fn completions(shell: clap_complete::Shell) -> Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut cmd, "podnet", &mut script);
    match std::io::Write::write_all(&mut std::io::stdout(), &script) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.context("writing the completion script"),
    }
}

/// `podnet ports`.
pub(crate) async fn ports(args: PortsArgs) -> Result<()> {
    let mut ports = podnet::ports::listening_ports();
    if args.probe {
        // Issue 119: a port in the LISTEN table can refuse each
        // connection.
        let (open, unreachable) = podnet::ports::probe(&ports).await;
        ports = open;
        if args.json {
            println!(
                "{}",
                serde_json::json!({ "ports": ports, "probed": true, "unreachable": unreachable })
            );
            return Ok(());
        }
        for port in &unreachable {
            eprintln!("podnet: ports: {port} listens, and refuses a connection");
        }
    }
    if args.json {
        println!(
            "{}",
            podnet::status::stamped(serde_json::json!({ "ports": ports }))
        );
    } else {
        for port in ports {
            println!("{port}");
        }
    }
    Ok(())
}

/// `podnet qr URL`.
pub(crate) fn qr(args: QrArgs) -> Result<()> {
    // Issue 95: a text over the limit is a usage mistake; a text
    // that is not a URL gets a warning (a QR code of any text is
    // valid).
    if args.url.len() > podnet::qr::MAX_BYTES {
        return Err(podnet::exit::fault(
            Fault::Usage,
            anyhow::anyhow!(
                "the text is {} bytes; a QR code holds at most {} bytes",
                args.url.len(),
                podnet::qr::MAX_BYTES
            ),
        ));
    }
    if !podnet::qr::looks_like_url(&args.url) {
        eprintln!(
            "podnet: warning: {:?} is not a URL (scheme://...); the QR code holds the text as it is",
            args.url
        );
    }
    print!("{}", podnet::qr::render_terminal(&args.url)?);
    Ok(())
}

/// `podnet man`.
pub(crate) fn man(args: ManArgs) -> Result<()> {
    use clap::CommandFactory;
    let manual = podnet::manual::model::build(Cli::command());
    let request = podnet::manual::Request {
        section: (!args.section.is_empty()).then(|| args.section.join(" ")),
        no_pager: args.no_pager,
        roff: args.roff,
        json: args.json,
    };
    let text = podnet::manual::body(&manual, &request)
        .map_err(|e| podnet::exit::fault(podnet::exit::Fault::Usage, anyhow::anyhow!(e)))?;
    let paged = !request.roff && !request.json;
    podnet::manual::pager::show(&text, request.no_pager || !paged)?;
    Ok(())
}

/// `podnet doctor`, and `podnet doctor --agent`.
pub(crate) async fn doctor(args: DoctorArgs) -> Result<()> {
    if args.agent {
        let report = podnet::agent::run(Duration::from_secs(args.timeout.max(3))).await;
        if args.json {
            println!(
                "{}",
                podnet::status::stamped(serde_json::to_value(&report)?)
            );
        } else {
            print!("{}", podnet::agent::text(&report));
        }
        return Ok(());
    }
    podnet::udp::check_edge_env()?;
    podnet::udp::Choice::from_env()?;
    let report = podnet::doctor::run(podnet::doctor::Options {
        samples: args.samples as usize,
        timeout: Duration::from_secs(args.timeout),
        ..podnet::doctor::Options::default()
    })
    .await;
    if args.json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.text());
    }
    if !report.ok() {
        bail!("no leg can work on this host; the doctor gives the reason for each");
    }
    Ok(())
}

/// `podnet status`.
pub(crate) fn status() -> Result<()> {
    println!("{}", podnet::status::document());
    Ok(())
}

/// `podnet bug-report`.
pub(crate) async fn bug_report(doctor: bool) -> Result<()> {
    let report = if doctor {
        let options = podnet::doctor::Options {
            samples: 3,
            ..Default::default()
        };
        Some(podnet::doctor::run(options).await.to_json())
    } else {
        None
    };
    print!("{}", podnet::bug_report::text(report.as_ref()));
    Ok(())
}
