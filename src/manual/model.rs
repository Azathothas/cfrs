//! The manual as data. The commands, their arguments and their flags come
//! from the clap command tree of the binary, which `--help` also uses. The
//! other sections come from [`super::facts`] and [`crate::exit::TABLE`].

use serde::Serialize;

use super::facts::{EnvVar, Example, FileEntry, ENVIRONMENT, EXAMPLES, FILES};
use crate::exit::{ExitCode, TABLE};

/// One flag or positional argument.
#[derive(Clone, Debug, Serialize)]
pub struct ArgPage {
    /// For example `-x, --proxy <SPEC>` or `<PROGRAM>...`.
    pub synopsis: String,
    /// The long name without dashes, or the value name of a positional.
    pub id: String,
    pub positional: bool,
    pub required: bool,
    pub repeatable: bool,
    pub takes_value: bool,
    pub help: String,
    pub default: Option<String>,
    pub env: Option<String>,
    pub values: Vec<String>,
}

/// One command, for example `cfrs warp run`.
#[derive(Clone, Debug, Serialize)]
pub struct CommandPage {
    /// The words after `cfrs`, for example `["warp", "run"]`.
    pub path: Vec<String>,
    pub usage: String,
    pub about: String,
    pub long_about: String,
    pub args: Vec<ArgPage>,
    pub subcommands: Vec<String>,
}

impl CommandPage {
    /// `warp run`, or the empty string for the root.
    pub fn name(&self) -> String {
        self.path.join(" ")
    }
}

/// The whole manual.
#[derive(Clone, Debug, Serialize)]
pub struct Manual {
    pub name: String,
    pub version: String,
    pub about: String,
    pub description: Vec<String>,
    pub commands: Vec<CommandPage>,
    pub pod_usage: String,
    pub environment: &'static [EnvVar],
    pub files: &'static [FileEntry],
    pub exit_status: Vec<ExitRow>,
    pub examples: &'static [Example],
}

/// A row of EXIT STATUS, in a form that serde writes.
#[derive(Clone, Debug, Serialize)]
pub struct ExitRow {
    pub code: i32,
    pub name: &'static str,
    pub meaning: &'static str,
}

impl From<&ExitCode> for ExitRow {
    fn from(row: &ExitCode) -> Self {
        Self {
            code: row.code,
            name: row.name,
            meaning: row.meaning,
        }
    }
}

/// The paragraphs of DESCRIPTION.
const DESCRIPTION: &[&str] = &[
    "cfrs is one binary for Cloudflare quick tunnels (trycloudflare), named tunnels and the Cloudflare WARP client. It is made for hosts with strong network limits: no root, no TUN device, no network namespace, no UDP, no AF_INET bind, or only TCP 443 out.",
    "A tunnel reaches the edge with one of three legs: QUIC on UDP 7844, HTTP/2 on TCP 7844 (directly or through HTTPS_PROXY), or QUIC inside a WARP MASQUE tunnel on TCP 443. With --protocol auto and --transport auto, cfrs tries them in that order.",
    "cfrs pod runs a program with all its traffic sent through a proxy, with no LD_PRELOAD (pod-netns). cfrs net gives programs virtual IP addresses on a host that refuses AF_INET binds.",
    "This manual is generated from the command tree of the binary. cfrs man --roff writes it as a man(7) page, and cfrs man --json writes its tables.",
];

fn text(s: Option<&clap::builder::StyledStr>) -> String {
    s.map(|s| s.to_string()).unwrap_or_default()
}

fn arg_page(arg: &clap::Arg) -> ArgPage {
    let positional = arg.is_positional();
    let takes_value = arg
        .get_num_args()
        .map(|n| n.takes_values())
        .unwrap_or(false)
        || positional;
    let value_names: Vec<String> = arg
        .get_value_names()
        .map(|v| v.iter().map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec![arg.get_id().as_str().to_ascii_uppercase()]);
    let value = value_names
        .iter()
        .map(|v| format!("<{v}>"))
        .collect::<Vec<_>>()
        .join(" ");
    let repeatable = matches!(
        arg.get_action(),
        clap::ArgAction::Append | clap::ArgAction::Count
    ) || arg.get_num_args().is_some_and(|n| n.max_values() > 1);
    let synopsis = if positional {
        format!("{value}{}", if repeatable { "..." } else { "" })
    } else {
        let mut names = Vec::new();
        if let Some(short) = arg.get_short() {
            names.push(format!("-{short}"));
        }
        if let Some(long) = arg.get_long() {
            names.push(format!("--{long}"));
        }
        let mut s = names.join(", ");
        if takes_value {
            s.push(' ');
            s.push_str(&value);
        }
        s
    };
    let help = {
        let long = text(arg.get_long_help());
        if long.is_empty() {
            text(arg.get_help())
        } else {
            long
        }
    };
    let default = {
        let values: Vec<String> = arg
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy().into_owned())
            .collect();
        (!values.is_empty() && takes_value).then(|| values.join(","))
    };
    let values = arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_string())
        .collect();
    ArgPage {
        synopsis,
        id: arg
            .get_long()
            .map(str::to_string)
            .unwrap_or_else(|| arg.get_id().as_str().to_string()),
        positional,
        required: arg.is_required_set(),
        repeatable,
        takes_value,
        help,
        default,
        env: arg.get_env().map(|e| e.to_string_lossy().into_owned()),
        values,
    }
}

fn walk(cmd: &mut clap::Command, path: Vec<String>, out: &mut Vec<CommandPage>) {
    let usage = cmd
        .render_usage()
        .to_string()
        .trim_start_matches("Usage:")
        .trim()
        .to_string();
    let args = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set())
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version"
        })
        .map(arg_page)
        .collect();
    let subcommands: Vec<String> = cmd
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .map(|c| c.get_name().to_string())
        .collect();
    out.push(CommandPage {
        path: path.clone(),
        usage,
        about: text(cmd.get_about()),
        long_about: text(cmd.get_long_about()),
        args,
        subcommands: subcommands.clone(),
    });
    for name in subcommands {
        if let Some(sub) = cmd.find_subcommand_mut(&name) {
            let mut sub_path = path.clone();
            sub_path.push(name.clone());
            walk(sub, sub_path, out);
        }
    }
}

/// Build the manual from the command tree `cmd` of the binary.
pub fn build(mut cmd: clap::Command) -> Manual {
    cmd.build();
    let mut commands = Vec::new();
    walk(&mut cmd, Vec::new(), &mut commands);
    Manual {
        name: cmd.get_name().to_string(),
        version: cmd.get_version().unwrap_or_default().to_string(),
        about: text(cmd.get_about()),
        description: DESCRIPTION.iter().map(|s| s.to_string()).collect(),
        commands,
        pod_usage: pod_netns::usage(),
        environment: ENVIRONMENT,
        files: FILES,
        exit_status: TABLE.iter().map(ExitRow::from).collect(),
        examples: EXAMPLES,
    }
}

/// The topics that are not commands.
pub const TOPICS: &[&str] = &["environment", "files", "exit-status", "examples", "pod"];

impl Manual {
    /// The command whose path is `name`: `warp run` or `warp/run`.
    pub fn command(&self, name: &str) -> Option<&CommandPage> {
        let words: Vec<&str> = name.split([' ', '/']).filter(|w| !w.is_empty()).collect();
        self.commands.iter().find(|c| {
            !c.path.is_empty() && c.path.iter().map(String::as_str).eq(words.iter().copied())
        })
    }
}
