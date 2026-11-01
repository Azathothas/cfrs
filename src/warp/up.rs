//! `cfrs warp up` and the ways that later shells join it (issue 78).
//!
//! `cfrs warp up` starts `cfrs warp proxy` detached (instance [`INSTANCE`])
//! with a TCP listener on 127.0.0.1 and a unix socket in the run directory,
//! and writes `warp.env` there: the proxy variables for the tools that read
//! them. Later shells join it in one of three ways:
//!
//! * `eval "$(cfrs warp env)"`: the proxy variables;
//! * `cfrs warp exec -- CMD` and `cfrs warp shell`: the command runs under
//!   the pod of the socket (TCP, DNS and UDP, also static binaries);
//! * `cfrs warp up --persist`: a marked block in `~/.bashrc` and
//!   `~/.profile` loads the env file, and an interactive shell runs under
//!   the pod. `cfrs warp down` removes it.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// The name of the detached instance of `cfrs warp up`.
pub const INSTANCE: &str = "warp";
/// Set in a shell that `cfrs warp shell` started, so that the hook does not
/// start it again.
pub const SHELL_VARIABLE: &str = "CFRS_WARP_SHELL";
const BEGIN: &str = "# >>> cfrs warp up >>>";
const END: &str = "# <<< cfrs warp up <<<";

/// The unix socket of the proxy of `cfrs warp up`.
pub fn socket_path() -> Result<PathBuf> {
    Ok(crate::instances::run_dir()?.join("warp.sock"))
}

/// The env file of `cfrs warp up`.
pub fn env_path() -> Result<PathBuf> {
    Ok(crate::instances::run_dir()?.join("warp.env"))
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run `cfrs ARGV` (a `warp proxy --detach`), print its lines, and give its
/// ready document (the last line).
pub fn start(argv: &[String]) -> Result<serde_json::Value> {
    let exe = std::env::current_exe().context("the path of this binary")?;
    let out = std::process::Command::new(&exe)
        .args(argv)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("starting cfrs warp proxy --detach")?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let code = out.status.code().unwrap_or(1);
        return Err(crate::exit::fault(
            if code == crate::exit::USAGE {
                crate::exit::Fault::Usage
            } else {
                crate::exit::Fault::Unavailable
            },
            anyhow::anyhow!("cfrs warp proxy --detach exited {code}"),
        ));
    }
    let last = text.lines().last().unwrap_or("");
    serde_json::from_str(last).with_context(|| format!("the ready document: {last:?}"))
}

/// The text of the env file for a proxy on `127.0.0.1:port` and `socket`.
pub fn env_file_text(port: u16, socket: &Path) -> String {
    let socks = format!("socks5h://127.0.0.1:{port}");
    let http = format!("http://127.0.0.1:{port}");
    let no_proxy = "localhost,127.0.0.1,::1";
    let mut out = String::from("# cfrs warp up: the proxy variables of the WARP proxy\n");
    for (k, v) in [
        ("ALL_PROXY", socks.as_str()),
        ("all_proxy", socks.as_str()),
        ("HTTPS_PROXY", http.as_str()),
        ("https_proxy", http.as_str()),
        ("HTTP_PROXY", http.as_str()),
        ("http_proxy", http.as_str()),
        ("NO_PROXY", no_proxy),
        ("no_proxy", no_proxy),
        ("CARGO_HTTP_PROXY", http.as_str()),
        ("npm_config_proxy", http.as_str()),
        ("npm_config_https_proxy", http.as_str()),
        ("CFRS_WARP_SOCKET", &socket.display().to_string()),
    ] {
        out.push_str(&format!("export {k}={}\n", quote(v)));
    }
    out
}

/// Write the env file (mode 0600).
pub fn write_env(port: u16, socket: &Path) -> Result<PathBuf> {
    let path = env_path()?;
    crate::warp::write_private(&path, env_file_text(port, socket).as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// The env file, when `cfrs warp up` runs.
pub fn env_text() -> Result<String> {
    let dir = crate::instances::run_dir()?;
    if !crate::instances::is_alive(&dir, INSTANCE) {
        return Err(crate::exit::fault(
            crate::exit::Fault::Unavailable,
            anyhow::anyhow!("cfrs warp up is not running; start it with: cfrs warp up"),
        ));
    }
    let path = env_path()?;
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// The block of `--persist` for `env`, `socket` and the binary `exe`.
pub fn hook_block(env: &Path, socket: &Path, exe: &Path) -> String {
    let env = quote(&env.display().to_string());
    let socket = quote(&socket.display().to_string());
    let exe = quote(&exe.display().to_string());
    format!(
        "{BEGIN}\n\
[ -f {env} ] && . {env}\n\
case \"$-\" in *i*) if [ -z \"${{{SHELL_VARIABLE}:-}}\" ] && [ -S {socket} ] && [ -x {exe} ]; then exec {exe} warp shell; fi ;; esac\n\
{END}\n"
    )
}

/// `text` with no block of cfrs warp up.
pub fn without_block(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches('\n');
        if bare == BEGIN {
            inside = true;
            continue;
        }
        if bare == END && inside {
            inside = false;
            continue;
        }
        if !inside {
            out.push_str(line);
        }
    }
    out
}

fn shell_files() -> Result<Vec<PathBuf>> {
    let home = std::env::var_os("HOME").context("no HOME")?;
    let home = PathBuf::from(home);
    Ok(vec![home.join(".bashrc"), home.join(".profile")])
}

/// Add the block to `~/.bashrc` and `~/.profile` (an old block is
/// replaced; the rest of each file stays). Gives the files.
pub fn persist(env: &Path) -> Result<Vec<PathBuf>> {
    let socket = socket_path()?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let block = hook_block(env, &socket, &exe);
    let mut done = Vec::new();
    for file in shell_files()? {
        let old = std::fs::read_to_string(&file).unwrap_or_default();
        let mut text = without_block(&old);
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&block);
        std::fs::write(&file, text).with_context(|| format!("writing {}", file.display()))?;
        done.push(file);
    }
    Ok(done)
}

/// `cfrs warp down`: stop the instance, remove the env file, the socket and
/// the blocks.
pub fn down() -> Result<()> {
    let dir = crate::instances::run_dir()?;
    if crate::instances::read(&dir, INSTANCE).is_some() {
        crate::detach::stop(&dir, INSTANCE, std::time::Duration::from_secs(10))?;
        println!("cfrs: warp down: stopped the instance {INSTANCE}");
    }
    for path in [env_path()?, socket_path()?] {
        if std::fs::remove_file(&path).is_ok() {
            println!("cfrs: warp down: removed {}", path.display());
        }
    }
    for file in shell_files()? {
        let Ok(old) = std::fs::read_to_string(&file) else {
            continue;
        };
        let new = without_block(&old);
        if new != old {
            std::fs::write(&file, new).with_context(|| format!("writing {}", file.display()))?;
            println!("cfrs: warp down: removed the block in {}", file.display());
        }
    }
    Ok(())
}

/// The arguments of `cfrs pod` for the socket of `cfrs warp up`.
pub fn pod_args(socket: &Path, rules: &[String], program: &[String]) -> Vec<String> {
    let mut argv = vec![
        "pod".to_string(),
        "--prefer-udp".to_string(),
        "-x".to_string(),
        format!("socks5://unix:{}", socket.display()),
    ];
    for rule in rules {
        argv.push("-r".into());
        argv.push(rule.clone());
    }
    argv.push("--".into());
    argv.extend(program.iter().cloned());
    argv
}

fn socket_answers(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// `cfrs warp exec -- CMD`: run CMD under the pod (this process becomes
/// it). Gives the error when it cannot.
pub fn exec_in_pod(rules: &[String], program: &[String]) -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;
    let socket = match socket_path() {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !socket_answers(&socket) {
        return crate::exit::fault(
            crate::exit::Fault::Unavailable,
            anyhow::anyhow!(
                "cfrs warp up is not running (no answer on {}); start it with: cfrs warp up",
                socket.display()
            ),
        );
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return e.into(),
    };
    let err = std::process::Command::new(exe)
        .args(pod_args(&socket, rules, program))
        .exec();
    anyhow::Error::new(err).context("running cfrs pod")
}

/// `cfrs warp shell`: `$SHELL` under the pod; when the proxy does not
/// answer, `$SHELL` as it is, with the proxy variables of the env file.
pub fn shell() -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into());
    let socket = socket_path().ok();
    let exe = std::env::current_exe().ok();
    if let (Some(socket), Some(exe)) = (socket.as_ref(), exe) {
        if socket_answers(socket) {
            let err = std::process::Command::new(exe)
                .args(pod_args(socket, &[], std::slice::from_ref(&shell)))
                .env(SHELL_VARIABLE, "1")
                .exec();
            eprintln!("cfrs: warp shell: {err}; the shell starts with no pod");
        } else {
            eprintln!(
                "cfrs: warp shell: cfrs warp up is not running; the shell starts with no pod"
            );
        }
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
    fn the_env_file_has_the_proxy_variables() {
        let text = env_file_text(40000, Path::new("/run/u/cfrs/run/warp.sock"));
        assert!(text.contains("export ALL_PROXY='socks5h://127.0.0.1:40000'\n"));
        assert!(text.contains("export HTTPS_PROXY='http://127.0.0.1:40000'\n"));
        assert!(text.contains("export http_proxy='http://127.0.0.1:40000'\n"));
        assert!(text.contains("export NO_PROXY='localhost,127.0.0.1,::1'\n"));
        assert!(text.contains("export CFRS_WARP_SOCKET='/run/u/cfrs/run/warp.sock'\n"));
    }

    #[test]
    fn the_block_is_added_once_and_removed_with_the_rest_kept() {
        let block = hook_block(
            Path::new("/r/warp.env"),
            Path::new("/r/warp.sock"),
            Path::new("/b/cfrs"),
        );
        assert!(block.starts_with(BEGIN) && block.trim_end().ends_with(END));
        assert!(block.contains("exec '/b/cfrs' warp shell"));
        assert!(block.contains("CFRS_WARP_SHELL"));
        let user = "alias ll='ls -l'\nexport EDITOR=vi\n";
        let once = format!("{user}{block}");
        let twice = format!("{}{block}", without_block(&once));
        assert_eq!(once, twice, "a second --persist adds nothing");
        assert_eq!(without_block(&once), user, "down keeps the rest");
    }

    #[test]
    fn the_block_is_valid_sh() {
        let block = hook_block(
            Path::new("/nonexistent/warp.env"),
            Path::new("/nonexistent/warp.sock"),
            Path::new("/nonexistent/cfrs"),
        );
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&block)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // An interactive sh runs the block: nothing exists, so no exec.
        let out = std::process::Command::new("sh")
            .arg("-i")
            .arg("-c")
            .arg(format!("{block}\necho still-here"))
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("still-here"));
    }

    #[test]
    fn pod_arguments() {
        let argv = pod_args(
            Path::new("/r/warp.sock"),
            &["cidr:10.0.0.0/8=direct".into()],
            &["git".into(), "fetch".into()],
        );
        assert_eq!(
            argv,
            [
                "pod",
                "--prefer-udp",
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
}
