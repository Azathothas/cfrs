//! `podnet autostart`: start a podnet command at boot.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use podnet::exit::{Fault, ResultExt};

use crate::cli::Cli;

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
pub(crate) struct AutostartArgs {
    #[command(subcommand)]
    pub(crate) command: AutostartCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AutostartCommand {
    /// Add an entry that runs `podnet ARGS`. The token and a proxy password
    /// go to a private env file (mode 0600), not to the unit, the crontab
    /// or the command line. Exit 69 when this host has no systemd user
    /// manager and no crontab.
    Add {
        /// The name of the entry (letters, digits, - and _).
        name: String,
        /// The podnet command and its arguments, after `--`, with no leading
        /// `podnet` (one is dropped). The command must parse.
        #[arg(last = true, required_unless_present = "from")]
        args: Vec<String>,
        /// Take the command and its arguments from the detached instance
        /// INSTANCE (podnet ps), with no --detach options.
        #[arg(long, value_name = "INSTANCE", conflicts_with = "args")]
        from: Option<String>,
    },
    /// Remove an entry: its unit or its crontab line, and its files. Other
    /// units and crontab lines stay as they are.
    Remove {
        /// The name of the entry.
        name: String,
    },
    /// List the entries.
    List,
    /// Run an entry in the place of this process: the unit and the crontab
    /// line call this. It reads NAME.args and NAME.env in DIR.
    Run {
        /// The name of the entry.
        name: String,
        /// The directory of the entries (`<state>/autostart`).
        #[arg(long)]
        dir: PathBuf,
    },
}

/// The arguments of `autostart add` (issue 117): a first argument `podnet`
/// (or a path to it) is dropped, and the rest must parse as a podnet command.
/// Before, `-- podnet warp up` was kept as `podnet podnet warp up`, which failed
/// at each boot with no message.
pub(crate) fn autostart_args(mut args: Vec<String>) -> Result<Vec<String>> {
    let is_podnet = |arg: &str| std::path::Path::new(arg).file_name() == Some("podnet".as_ref());
    if args.first().is_some_and(|a| is_podnet(a)) {
        args.remove(0);
    }
    // Issue 265: an entry with --detach forked at each boot, and its
    // service manager saw the parent end.
    let kept = podnet::detach::without_start_options(&args);
    if kept != args {
        eprintln!("podnet: autostart add: --detach, --name, --ready-timeout and --no-restart are removed; the entry runs in the foreground");
        args = kept;
    }
    if let Err(err) = Cli::try_parse_from(std::iter::once("podnet".to_string()).chain(args.clone()))
    {
        let first = err.to_string();
        let first = first
            .lines()
            .next()
            .unwrap_or_default()
            .trim_start_matches("error: ");
        return Err(podnet::exit::fault(
            Fault::Usage,
            anyhow::anyhow!(
                "autostart add: `podnet {}` is not a podnet command: {first}",
                args.join(" ")
            ),
        ));
    }
    Ok(args)
}

pub(crate) fn autostart(command: AutostartCommand) -> Result<()> {
    use podnet::autostart;
    match command {
        AutostartCommand::Add { name, args, from } => {
            let (args, secrets) = match from {
                Some(instance) => {
                    let dir = podnet::instances::run_dir().fault(Fault::Config)?;
                    let record = podnet::instances::read(&dir, &instance).ok_or_else(|| {
                        podnet::exit::fault(
                            Fault::Usage,
                            anyhow::anyhow!("no detached instance {instance} (podnet ps)"),
                        )
                    })?;
                    // Issue 265: the record has no secret; NAME.secrets has them.
                    (
                        record.args,
                        podnet::instances::read_secrets(&dir, &instance),
                    )
                }
                None => (args, Vec::new()),
            };
            let args = autostart_args(args)?;
            let added = autostart::add(&name, &args, &secrets, autostart::PROGRAM_LIMIT)?;
            println!(
                "podnet: autostart {name} added ({}): {}",
                added.way.name(),
                added.detail
            );
            Ok(())
        }
        AutostartCommand::Remove { name } => {
            for line in autostart::remove(&name, autostart::PROGRAM_LIMIT)? {
                println!("podnet: {line}");
            }
            Ok(())
        }
        AutostartCommand::List => {
            for name in autostart::list()? {
                println!("{name}");
            }
            Ok(())
        }
        AutostartCommand::Run { name, dir } => {
            use std::os::unix::process::CommandExt;
            let (args, vars) = autostart::load(&name, &dir).fault(Fault::Config)?;
            let exe = std::env::current_exe().context("the path of this binary")?;
            let err = std::process::Command::new(exe)
                .args(&args)
                .envs(vars)
                .exec();
            Err(anyhow::anyhow!("starting podnet {}: {err}", args.join(" ")))
        }
    }
}
