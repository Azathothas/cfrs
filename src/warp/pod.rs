//! `podnet warp exec` and `podnet warp shell`: a program under the pod of
//! the running `podnet warp up` (issue 78, T-071).
//!
//! The pod gets `--backend` of the command, and `--name-backend`: it prints
//! one line on stderr that names the backend that runs and its limits.
//! `podnet -q` removes the line (the quiet variable of podnet-netns). With
//! `podnet -v`, the pod gets `-v` and logs each flow and each emulation of
//! the seccomp backend.

use std::path::Path;

use super::find::At;
use super::up::{env_path, CA_VARIABLES, SHELL_VARIABLE};

/// The options of `warp exec` and `warp shell` for the pod.
#[derive(clap::Args, Debug, Clone)]
pub struct PodOptions {
    #[command(flatten)]
    pub at: At,
    /// The backend of the pod: auto, netns or seccomp (see podnet pod
    /// --help). The pod names the backend that runs and its limits in one
    /// line on stderr; -q removes the line
    #[arg(long, value_name = "NAME", default_value = "auto", value_parser = ["auto", "netns", "seccomp"])]
    pub backend: String,
}

/// True when podnet logs at the debug level (`podnet -v`): the pod then
/// gets `-v`.
fn verbose() -> bool {
    tracing::enabled!(target: "podnet", tracing::Level::DEBUG)
}

/// The arguments of `podnet pod` for the socket of `podnet warp up`.
/// `--prefer-udp` keeps the order of `auto`: seccomp first when it works.
pub fn pod_args(
    socket: &Path,
    backend: &str,
    verbose: bool,
    rules: &[String],
    program: &[String],
) -> Vec<String> {
    let mut argv = vec![
        "pod".to_string(),
        "--prefer-udp".to_string(),
        "--backend".to_string(),
        backend.to_string(),
        "--name-backend".to_string(),
    ];
    if verbose {
        argv.push("-v".into());
    }
    argv.push("-x".into());
    argv.push(format!("socks5://unix:{}", socket.display()));
    for rule in rules {
        argv.push("-r".into());
        argv.push(rule.clone());
    }
    argv.push("--".into());
    argv.extend(program.iter().cloned());
    argv
}

/// The CA variables of the env file (the fix of issue 86), for a command
/// that runs under the pod and does not read the env file.
fn ca_exports() -> Vec<(String, String)> {
    let Ok(text) = env_path().and_then(|p| Ok(std::fs::read_to_string(p)?)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| line.strip_prefix("export ")?.split_once('='))
        .filter(|(k, _)| CA_VARIABLES.contains(k))
        .map(|(k, v)| (k.to_string(), v.trim_matches('\'').to_string()))
        .collect()
}

/// `podnet warp exec -- CMD`: run CMD under the pod (this process becomes
/// it). Gives the error when it cannot.
pub fn exec_in_pod(options: &PodOptions, rules: &[String], program: &[String]) -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;
    let socket = match super::find::running(&options.at) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return e.into(),
    };
    let err = pod_command(exe, &socket, &options.backend, rules, program).exec();
    anyhow::Error::new(err).context("running podnet pod")
}

/// The command of `warp exec` (issue 116): the program gets
/// PODNET_WARP_SOCKET, also when the shell did not read the env file.
fn pod_command(
    exe: std::path::PathBuf,
    socket: &Path,
    backend: &str,
    rules: &[String],
    program: &[String],
) -> std::process::Command {
    let mut command = std::process::Command::new(exe);
    command
        .args(pod_args(socket, backend, verbose(), rules, program))
        .env("PODNET_WARP_SOCKET", socket)
        .envs(ca_exports());
    command
}

/// `podnet warp shell`: `$SHELL` under the pod; when the proxy does not
/// answer, `$SHELL` as it is, with the proxy variables of the env file.
pub fn shell(options: &PodOptions) -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into());
    match (super::find::running(&options.at), std::env::current_exe()) {
        (Ok(socket), Ok(exe)) => {
            let program = std::slice::from_ref(&shell);
            let err = pod_command(exe, &socket, &options.backend, &[], program)
                .env(SHELL_VARIABLE, "1")
                .exec();
            eprintln!("podnet: warp shell: {err}; the shell starts with no pod");
        }
        (Err(err), _) => eprintln!("podnet: warp shell: {err}; the shell starts with no pod"),
        (_, Err(err)) => eprintln!("podnet: warp shell: {err}; the shell starts with no pod"),
    }
    let mut cmd = std::process::Command::new(&shell);
    cmd.env(SHELL_VARIABLE, "1");
    if let Ok(text) = env_path().and_then(|p| Ok(std::fs::read_to_string(p)?)) {
        for line in text.lines() {
            if let Some((k, v)) = line.strip_prefix("export ").and_then(|l| l.split_once('=')) {
                cmd.env(k, v.trim_matches('\''));
            }
        }
    }
    let err = cmd.exec();
    if err.kind() == std::io::ErrorKind::NotFound {
        return anyhow::anyhow!("no shell at {shell}");
    }
    anyhow::Error::new(err).context(format!("running {shell}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_arguments() {
        let argv = pod_args(
            Path::new("/r/warp.sock"),
            "auto",
            false,
            &["cidr:10.0.0.0/8=direct".into()],
            &["git".into(), "fetch".into()],
        );
        assert_eq!(
            argv,
            [
                "pod",
                "--prefer-udp",
                "--backend",
                "auto",
                "--name-backend",
                "-x",
                "socks5://unix:/r/warp.sock",
                "-r",
                "cidr:10.0.0.0/8=direct",
                "--",
                "git",
                "fetch"
            ]
        );
    }

    // Issue 116: the program of warp exec gets PODNET_WARP_SOCKET.
    #[test]
    fn warp_exec_gives_the_socket() {
        let command = pod_command(
            "/b/podnet".into(),
            Path::new("/r/warp.sock"),
            "auto",
            &[],
            &["sh".to_string()],
        );
        assert!(command
            .get_envs()
            .any(|(k, v)| k == "PODNET_WARP_SOCKET" && v == Some("/r/warp.sock".as_ref())));
    }

    /// T-071: the backend and `-v` of `warp exec` go to the pod.
    #[test]
    fn warp_exec_passes_the_backend_to_the_pod() {
        let argv = pod_args(Path::new("/s"), "netns", true, &[], &["true".into()]);
        let end = argv.iter().position(|a| a == "--").unwrap();
        let options = &argv[..end];
        assert!(
            options.windows(2).any(|w| w == ["--backend", "netns"]),
            "{argv:?}"
        );
        assert!(options.iter().any(|a| a == "-v"), "{argv:?}");
        assert!(options.iter().any(|a| a == "--name-backend"), "{argv:?}");
        let quiet = pod_args(Path::new("/s"), "seccomp", false, &[], &["true".into()]);
        assert!(!quiet.iter().any(|a| a == "-v"), "{quiet:?}");
        assert!(quiet.windows(2).any(|w| w == ["--backend", "seccomp"]));
    }
}
