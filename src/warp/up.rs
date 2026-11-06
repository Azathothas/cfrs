//! `podnet warp up` and the ways that later shells join it (issue 78).
//!
//! `podnet warp up` starts `podnet warp proxy` detached (instance [`INSTANCE`])
//! with a TCP listener on 127.0.0.1 and a unix socket in the run directory,
//! and writes `warp.env` there: the proxy variables for the tools that read
//! them. Later shells join it in one of three ways:
//!
//! * `eval "$(podnet warp env)"`: the proxy variables;
//! * `podnet warp exec -- CMD` and `podnet warp shell`: the command runs under
//!   the pod of the socket (TCP, DNS and UDP, also static binaries);
//! * `podnet warp up --persist`: a marked block in `~/.bashrc` and
//!   `~/.profile` loads the env file, and an interactive shell runs under
//!   the pod. `podnet warp down` removes it.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};

/// The name of the detached instance of `podnet warp up`.
pub const INSTANCE: &str = "warp";
/// The name of the detached instance of `podnet warp up --tun`.
pub const TUN_INSTANCE: &str = "warp-tun";
/// Set in a shell that `podnet warp shell` started, so that the hook does not
/// start it again.
pub const SHELL_VARIABLE: &str = "PODNET_WARP_SHELL";
const BEGIN: &str = "# >>> podnet warp up >>>";
const END: &str = "# <<< podnet warp up <<<";

/// The unix socket of the proxy of `podnet warp up`.
pub fn socket_path() -> Result<PathBuf> {
    Ok(crate::instances::run_dir()?.join("warp.sock"))
}

/// The env file of `podnet warp up`.
pub fn env_path() -> Result<PathBuf> {
    Ok(crate::instances::run_dir()?.join("warp.env"))
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run `podnet ARGV` (the command `label`, for example `podnet warp proxy
/// --detach`), print its lines, and give its ready document (the last line).
/// The lines of stderr go to stderr at once and are kept for the text of a
/// failure ([`failure_text`]).
pub fn start(label: &str, argv: &[String]) -> Result<serde_json::Value> {
    use std::io::{BufRead as _, BufReader};
    let exe = std::env::current_exe().context("the path of this binary")?;
    let mut command = std::process::Command::new(&exe);
    // A shell that read the env file of an earlier warp up has proxy
    // variables that point at the listeners of this proxy: the proxy must
    // not send its own session through them.
    for key in own_proxy_variables(argv, std::env::vars()) {
        command.env_remove(key);
    }
    let mut child = command
        .args(argv)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {label}"))?;
    let stderr = child.stderr.take();
    let tee = std::thread::spawn(move || {
        let mut kept = String::new();
        if let Some(stderr) = stderr {
            for line in BufReader::new(stderr).split(b'\n').map_while(Result::ok) {
                let line = String::from_utf8_lossy(&line).into_owned();
                eprintln!("{line}");
                kept.push_str(&line);
                kept.push('\n');
            }
        }
        kept
    });
    let out = child
        .wait_with_output()
        .with_context(|| format!("waiting for {label}"))?;
    let stderr = tee.join().unwrap_or_default();
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let code = out.status.code().unwrap_or(1);
        // SAFETY: geteuid() has no precondition.
        let root = unsafe { libc::geteuid() } == 0;
        return Err(crate::exit::fault(
            match code {
                crate::exit::USAGE => crate::exit::Fault::Usage,
                crate::exit::CONFIG => crate::exit::Fault::Config,
                _ => crate::exit::Fault::Unavailable,
            },
            anyhow::anyhow!(failure_text(label, code, &stderr, root)),
        ));
    }
    let last = text.lines().last().unwrap_or("");
    serde_json::from_str(last).with_context(|| format!("the ready document: {last:?}"))
}

/// Why `podnet warp tun` could not run, when stderr says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunFault {
    /// No right to make the TUN (CAP_NET_ADMIN, or the mode of /dev/net/tun).
    Privilege,
    /// The host has no /dev/net/tun.
    NoDevice,
    /// `--default-route` needs an IPv4 default route.
    NoDefaultRoute,
}

fn tun_fault(stderr: &str) -> Option<TunFault> {
    if stderr.contains("no IPv4 default route") {
        return Some(TunFault::NoDefaultRoute);
    }
    if !(stderr.contains("TUNSETIFF") || stderr.contains("/dev/net/tun")) {
        return None;
    }
    if stderr.contains("No such file or directory") || stderr.contains("No such device") {
        Some(TunFault::NoDevice)
    } else if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
        Some(TunFault::Privilege)
    } else {
        None
    }
}

/// The last error line of the child (a line `podnet: TEXT`), without the
/// prefix. The log lines before it have no such prefix.
fn cause_of(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .rev()
        .filter_map(|l| l.strip_prefix("podnet: "))
        .find(|l| !l.starts_with("--detach:"))
}

/// The text of the error when the command `label` exited with `code` and
/// wrote `stderr`. The first line names the command and the cause. When the
/// command is `warp tun` and stderr shows a refusal of the TUN, the next
/// lines say what happened and the last lines name the recovery. `root` is
/// whether this process runs as root (sudo does not help then).
pub fn failure_text(label: &str, code: i32, stderr: &str, root: bool) -> String {
    let mut text = format!("{label} exited {code}");
    if let Some(cause) = cause_of(stderr) {
        text.push_str(": ");
        text.push_str(cause);
    }
    if !label.contains("warp tun") {
        return text;
    }
    let (why, sudo) = match tun_fault(stderr) {
        Some(TunFault::Privilege) => (
            "the host refused the TUN interface: this process has no CAP_NET_ADMIN",
            !root,
        ),
        Some(TunFault::NoDevice) => ("the host has no /dev/net/tun", false),
        Some(TunFault::NoDefaultRoute) => (
            "warp up --tun needs an IPv4 default route; sudo does not add one",
            false,
        ),
        None => return text,
    };
    text.push_str(&format!("\npodnet: warp up --tun: {why}"));
    if sudo {
        text.push_str("\npodnet: with root: sudo podnet warp up --tun");
    }
    text.push_str("\npodnet: with no root: podnet warp up (proxy mode)");
    text.push_str("\npodnet: one command with no root: podnet warp run -- CMD");
    text
}

/// The state of the instance of `podnet warp up` (issue 116): for `warp
/// status`.
pub fn instance_state() -> serde_json::Value {
    // Issue 178: a read makes no directory.
    let Some(dir) = crate::instances::existing_run_dir() else {
        return serde_json::json!({"running": false});
    };
    match crate::instances::read(&dir, INSTANCE) {
        Some(record) if crate::instances::is_alive(&dir, INSTANCE) => serde_json::json!({
            "running": true,
            "pid": record.pid,
            "state": record.state,
            "started": record.started,
            "restarts": record.restarts,
            "listens": record.ready.as_ref().and_then(|d| d.get("listens")).cloned(),
        }),
        _ => serde_json::json!({"running": false}),
    }
}

/// The line of [`instance_state`] for `warp status`.
pub fn instance_line(state: &serde_json::Value) -> String {
    if state["running"] != true {
        return "not running (podnet warp up starts it)".into();
    }
    let listens: Vec<&str> = state["listens"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    format!(
        "{}, pid {}, restarts {}, listens {}",
        state["state"].as_str().unwrap_or("?"),
        state["pid"],
        state["restarts"],
        if listens.is_empty() {
            "-".into()
        } else {
            listens.join(" ")
        }
    )
}

/// The variables of `vars` whose value is a listener of `argv` (a
/// `--listen tcp://ADDR` or `unix:PATH`): the env file of warp up wrote
/// them.
fn own_proxy_variables(
    argv: &[String],
    vars: impl Iterator<Item = (String, String)>,
) -> Vec<String> {
    let own: Vec<String> = argv
        .iter()
        .filter_map(|a| {
            a.strip_prefix("tcp://")
                .or_else(|| a.strip_prefix("unix:"))
                .map(str::to_string)
        })
        .collect();
    vars.filter(|(key, value)| {
        key != "PODNET_WARP_SOCKET" && own.iter().any(|o| value.ends_with(o.as_str()))
    })
    .map(|(key, _)| key)
    .collect()
}

/// The text of the env file for a proxy on `127.0.0.1:port` and `socket`.
/// With no port (issue 97: the host refused the TCP listener), the file has
/// no proxy variables for other tools: a program goes through WARP with
/// `podnet warp exec`. podnet itself gets PODNET_PROXY on the unix socket (issue
/// 116).
pub fn env_file_text(port: Option<u16>, socket: &Path) -> String {
    let mut out = String::from("# podnet warp up: the proxy variables of the WARP proxy\n");
    let Some(port) = port else {
        out.push_str(
            "# The host refused the TCP listener: there are no proxy variables.\n\
             # Run a program through WARP with: podnet warp exec -- CMD\n\
             # podnet itself uses the unix socket (PODNET_PROXY).\n",
        );
        out.push_str(&format!(
            "export PODNET_WARP_SOCKET={}\n",
            quote(&socket.display().to_string())
        ));
        out.push_str(&format!(
            "export PODNET_PROXY={}\n",
            quote(&format!("socks5h+unix:{}", socket.display()))
        ));
        return out;
    };
    let socks = format!("socks5h://127.0.0.1:{port}");
    let http = format!("http://127.0.0.1:{port}");
    let no_proxy = "localhost,127.0.0.1,::1";
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
        ("PODNET_WARP_SOCKET", &socket.display().to_string()),
    ] {
        out.push_str(&format!("export {k}={}\n", quote(v)));
    }
    out
}

/// The TCP port and whether the unix socket is up, from the ready document
/// of the `warp proxy` of `podnet warp up` (its `listens`).
pub fn listeners_of(doc: &serde_json::Value) -> (Option<u16>, bool) {
    let listens: Vec<&str> = doc["listens"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let port = listens.iter().find_map(|l| {
        l.strip_prefix("tcp://")
            .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
            .map(|a| a.port())
    });
    let socket = listens.iter().any(|l| l.starts_with("unix:"));
    (port, socket)
}

/// The variables that name a bundle of TLS roots (issue 86).
pub const CA_VARIABLES: [&str; 4] = [
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];
/// A bundle with fewer certificates than this is taken as the roots of a
/// proxy that terminates TLS, not a public bundle.
pub const SMALL_BUNDLE: usize = 10;
/// The system bundles, the first that exists is used.
pub const SYSTEM_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

fn certificates_in(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

/// The fix of the CA bundle for WARP: when a variable of [`CA_VARIABLES`]
/// names a small bundle (the roots of a proxy that terminates TLS), the
/// tools that use it fail through WARP, which shows the real chains. The
/// fix is one bundle of that bundle and the system bundle, so that the
/// proxy and WARP both work. Gives the merged text and the variables to
/// set to it, or `None` when no variable needs it. `system` is the system
/// bundle, when there is one.
pub fn ca_fix(
    env: &dyn Fn(&str) -> Option<String>,
    system: Option<&Path>,
) -> Option<(String, Vec<&'static str>)> {
    let mut small: Vec<(&'static str, String)> = Vec::new();
    for var in CA_VARIABLES {
        let Some(path) = env(var).filter(|p| !p.is_empty()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let n = certificates_in(&text);
        if n > 0 && n < SMALL_BUNDLE {
            small.push((var, text));
        }
    }
    if small.is_empty() {
        return None;
    }
    let Some(system) = system.and_then(|p| std::fs::read_to_string(p).ok()) else {
        tracing::warn!(
            variables = ?small.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
            "a CA bundle has only the roots of a proxy, and this host has no system bundle: through WARP, the tools that use it fail; unset the variable in a shell that uses WARP"
        );
        return None;
    };
    let mut merged =
        String::from("# podnet warp up: the bundle of the proxy and the system bundle\n");
    let mut seen = std::collections::BTreeSet::new();
    for (_, text) in &small {
        if seen.insert(text.clone()) {
            merged.push_str(text);
            if !text.ends_with('\n') {
                merged.push('\n');
            }
        }
    }
    merged.push_str(&system);
    Some((merged, small.into_iter().map(|(v, _)| v).collect()))
}

/// The CA bundle of `podnet warp up` in the run directory.
pub fn ca_path() -> Result<PathBuf> {
    Ok(crate::instances::run_dir()?.join("warp-ca.pem"))
}

/// Write the env file (mode 0600), with the CA fix when one is needed.
pub fn write_env(port: Option<u16>, socket: &Path) -> Result<PathBuf> {
    let path = env_path()?;
    let mut text = env_file_text(port, socket);
    let system = SYSTEM_BUNDLES.iter().map(Path::new).find(|p| p.exists());
    if let Some((bundle, vars)) = ca_fix(&|k| std::env::var(k).ok(), system) {
        let ca = ca_path()?;
        crate::warp::write_private(&ca, bundle.as_bytes())
            .with_context(|| format!("writing {}", ca.display()))?;
        for var in &vars {
            text.push_str(&format!(
                "export {var}={}\n",
                quote(&ca.display().to_string())
            ));
        }
        tracing::info!(variables = ?vars, bundle = %ca.display(), "a CA bundle had only the roots of a proxy; the env file names a bundle with the system roots too");
    }
    crate::warp::write_private(&path, text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    super::find::write_pointer(socket).context("writing the pointer file of warp up")?;
    Ok(path)
}

/// The env file, when `podnet warp up` runs.
pub fn env_text() -> Result<String> {
    let dir = crate::instances::run_dir()?;
    if !crate::instances::is_alive(&dir, INSTANCE) {
        return Err(crate::exit::fault(
            crate::exit::Fault::Unavailable,
            anyhow::anyhow!("podnet warp up is not running; start it with: podnet warp up"),
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

/// `text` with no block of podnet warp up.
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
    let home = PathBuf::from(std::env::var_os("HOME").context("no HOME")?);
    // podssh #118: no file of root in the home of another user.
    crate::state::check_own(&home)?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    Ok(shell_files_in(&home, &shell))
}

/// The files of the sh block (issue 115): `~/.bashrc`, `~/.profile`, and
/// `~/.zshrc` when it exists or the shell is zsh (the block is valid zsh).
fn shell_files_in(home: &Path, shell: &str) -> Vec<PathBuf> {
    let mut files = vec![home.join(".bashrc"), home.join(".profile")];
    let zshrc = home.join(".zshrc");
    if shell.ends_with("zsh") || zshrc.exists() {
        files.push(zshrc);
    }
    files
}

/// The file of fish (issue 115): a file of its own in conf.d, when fish is
/// the shell or its config directory exists.
fn fish_file() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    crate::state::check_own(&home).ok()?;
    let dir = home.join(".config/fish");
    let shell = std::env::var("SHELL").unwrap_or_default();
    (shell.ends_with("fish") || dir.exists()).then(|| dir.join("conf.d/podnet-warp.fish"))
}

/// The fish form of [`hook_block`]. fish has `export`, so the env file
/// works with `source`.
pub fn fish_block(env: &Path, socket: &Path, exe: &Path) -> String {
    let env = quote(&env.display().to_string());
    let socket = quote(&socket.display().to_string());
    let exe = quote(&exe.display().to_string());
    format!(
        "{BEGIN}\n\
if test -f {env}; source {env}; end\n\
if status is-interactive; and not set -q {SHELL_VARIABLE}; and test -S {socket}; and test -x {exe}; exec {exe} warp shell; end\n\
{END}\n"
    )
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
    if let Some(file) = fish_file() {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("making {}", dir.display()))?;
        }
        std::fs::write(&file, fish_block(env, &socket, &exe))
            .with_context(|| format!("writing {}", file.display()))?;
        done.push(file);
    }
    Ok(done)
}

/// The first line of the environment.d file of podnet (issue 138): only a
/// file with it is changed or removed.
pub const ENV_D_MARK: &str = "# podnet warp up --env-d: the proxy of the WARP proxy";

/// `$XDG_CONFIG_HOME/environment.d/90-podnet-warp.conf`, or
/// `~/.config/environment.d/90-podnet-warp.conf`.
pub fn env_d_path() -> Result<PathBuf> {
    let config = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    let path = config.join("environment.d/90-podnet-warp.conf");
    crate::state::check_own(&path)?;
    Ok(path)
}

/// The text of the environment.d file for the proxy on 127.0.0.1:`port`
/// (`KEY=VALUE` lines, as environment.d(5)).
pub fn env_d_text(port: u16) -> String {
    let socks = format!("socks5h://127.0.0.1:{port}");
    let http = format!("http://127.0.0.1:{port}");
    let no_proxy = "localhost,127.0.0.1,::1";
    let mut out = format!("{ENV_D_MARK}\n# podnet warp down removes this file.\n");
    for (k, v) in [
        ("ALL_PROXY", socks.as_str()),
        ("all_proxy", socks.as_str()),
        ("HTTPS_PROXY", http.as_str()),
        ("https_proxy", http.as_str()),
        ("HTTP_PROXY", http.as_str()),
        ("http_proxy", http.as_str()),
        ("NO_PROXY", no_proxy),
        ("no_proxy", no_proxy),
    ] {
        out.push_str(&format!("{k}={v}\n"));
    }
    out
}

/// True when `text` is a file of podnet (or there is no text).
fn env_d_is_ours(text: Option<&str>) -> bool {
    text.is_none_or(|t| t.lines().next() == Some(ENV_D_MARK))
}

/// The path of the environment.d file; an error when a file of that name
/// is not a file of podnet. `warp up` calls it before it starts the proxy.
pub fn check_env_d() -> Result<PathBuf> {
    let path = env_d_path()?;
    let old = std::fs::read_to_string(&path).ok();
    if !env_d_is_ours(old.as_deref()) {
        bail!(
            "{} exists and podnet did not write it; remove it, or do not give --env-d",
            path.display()
        );
    }
    Ok(path)
}

/// Write the environment.d file for the proxy on 127.0.0.1:`port`. A file
/// of that name that podnet did not write is an error, and stays.
pub fn write_env_d(port: u16) -> Result<PathBuf> {
    let path = check_env_d()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("making {}", dir.display()))?;
    }
    std::fs::write(&path, env_d_text(port))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// `podnet warp down`: stop the instance, remove the env file, the socket and
/// the blocks.
pub fn down() -> Result<()> {
    let dir = crate::instances::run_dir()?;
    for name in [INSTANCE, TUN_INSTANCE] {
        if crate::instances::read(&dir, name).is_some() {
            crate::detach::stop(&dir, name, std::time::Duration::from_secs(10))?;
            println!("podnet: warp down: stopped the instance {name}");
        }
    }
    super::find::remove_pointer(&socket_path()?);
    for path in [env_path()?, socket_path()?, ca_path()?] {
        if std::fs::remove_file(&path).is_ok() {
            println!("podnet: warp down: removed {}", path.display());
        }
    }
    for file in shell_files()? {
        let Ok(old) = std::fs::read_to_string(&file) else {
            continue;
        };
        let new = without_block(&old);
        if new != old {
            std::fs::write(&file, new).with_context(|| format!("writing {}", file.display()))?;
            println!("podnet: warp down: removed the block in {}", file.display());
        }
    }
    if let Some(file) = fish_file() {
        if std::fs::remove_file(&file).is_ok() {
            println!("podnet: warp down: removed {}", file.display());
        }
    }
    // Issue 138: the environment.d file, when podnet wrote it.
    if let Ok(file) = env_d_path() {
        if let Ok(text) = std::fs::read_to_string(&file) {
            if env_d_is_ours(Some(&text)) {
                if std::fs::remove_file(&file).is_ok() {
                    println!(
                        "podnet: warp down: removed {} (the programs of this login keep the variables until the next login)",
                        file.display()
                    );
                }
            } else {
                println!(
                    "podnet: warp down: {} is not a file of podnet; it stays",
                    file.display()
                );
            }
        }
    }
    Ok(())
}

/// The arguments of `podnet pod` for the socket of `podnet warp up`.
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
pub fn exec_in_pod(at: &super::find::At, rules: &[String], program: &[String]) -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;
    let socket = match super::find::running(at) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return e.into(),
    };
    let err = pod_command(exe, &socket, rules, program).exec();
    anyhow::Error::new(err).context("running podnet pod")
}

/// The command of `warp exec` (issue 116): the program gets
/// PODNET_WARP_SOCKET, also when the shell did not read the env file.
fn pod_command(
    exe: std::path::PathBuf,
    socket: &Path,
    rules: &[String],
    program: &[String],
) -> std::process::Command {
    let mut command = std::process::Command::new(exe);
    command
        .args(pod_args(socket, rules, program))
        .env("PODNET_WARP_SOCKET", socket)
        .envs(ca_exports());
    command
}

/// `podnet warp shell`: `$SHELL` under the pod; when the proxy does not
/// answer, `$SHELL` as it is, with the proxy variables of the env file.
pub fn shell(at: &super::find::At) -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into());
    match (super::find::running(at), std::env::current_exe()) {
        (Ok(socket), Ok(exe)) => {
            let err = pod_command(exe, &socket, &[], std::slice::from_ref(&shell))
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
    fn the_environment_d_file() {
        let text = env_d_text(40001);
        assert!(text.starts_with(ENV_D_MARK));
        assert!(text.contains("\nALL_PROXY=socks5h://127.0.0.1:40001\n"));
        assert!(text.contains("\nHTTPS_PROXY=http://127.0.0.1:40001\n"));
        assert!(!text.contains("export"));
        assert!(text
            .lines()
            .all(|l| l.starts_with('#') || l.split_once('=').is_some_and(|(k, _)| !k.is_empty())));
        assert!(env_d_is_ours(None));
        assert!(env_d_is_ours(Some(&text)));
        assert!(!env_d_is_ours(Some("HTTPS_PROXY=http://corp:3128\n")));
    }

    #[test]
    fn the_env_file_has_the_proxy_variables() {
        let text = env_file_text(Some(40000), Path::new("/run/u/podnet/run/warp.sock"));
        assert!(text.contains("export ALL_PROXY='socks5h://127.0.0.1:40000'\n"));
        assert!(text.contains("export HTTPS_PROXY='http://127.0.0.1:40000'\n"));
        assert!(text.contains("export http_proxy='http://127.0.0.1:40000'\n"));
        assert!(text.contains("export NO_PROXY='localhost,127.0.0.1,::1'\n"));
        assert!(text.contains("export PODNET_WARP_SOCKET='/run/u/podnet/run/warp.sock'\n"));
    }

    /// Issue 97: with no TCP listener, the env file has no proxy variables
    /// (they would name a port that does not listen), only the socket.
    #[test]
    fn with_no_tcp_listener_the_env_file_has_the_socket_only() {
        let text = env_file_text(None, Path::new("/r/warp.sock"));
        assert!(text.contains("export PODNET_WARP_SOCKET='/r/warp.sock'\n"));
        // Issue 116: podnet gets a proxy URL on the unix socket, and it parses.
        assert!(text.contains("export PODNET_PROXY='socks5h+unix:/r/warp.sock'\n"));
        assert!(crate::egress::Proxy::parse("socks5h+unix:/r/warp.sock").is_ok());
        for var in ["ALL_PROXY", "HTTPS_PROXY", "http_proxy", "CARGO_HTTP_PROXY"] {
            assert!(!text.contains(var), "{var}: {text}");
        }
        assert!(text.contains("podnet warp exec"));
        let doc = serde_json::json!({"listens": ["unix:/r/warp.sock"]});
        assert_eq!(listeners_of(&doc), (None, true));
        let doc = serde_json::json!({"listens": ["tcp://127.0.0.1:40000", "unix:/r/warp.sock"]});
        assert_eq!(listeners_of(&doc), (Some(40000), true));
    }

    // Issue 116: warp status shows the instance of warp up.
    #[test]
    fn the_instance_line() {
        assert!(instance_line(&serde_json::json!({"running": false})).starts_with("not running"));
        let state = serde_json::json!({
            "running": true, "pid": 42, "state": "ready", "restarts": 0,
            "listens": ["tcp://127.0.0.1:40000", "unix:/r/warp.sock"],
        });
        assert_eq!(
            instance_line(&state),
            "ready, pid 42, restarts 0, listens tcp://127.0.0.1:40000 unix:/r/warp.sock"
        );
    }

    // Issue 115: zsh gets the block too; fish gets a file of its own.
    #[test]
    fn the_shell_files_follow_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        assert_eq!(shell_files_in(home, "/bin/bash").len(), 2);
        assert!(shell_files_in(home, "/usr/bin/zsh").contains(&home.join(".zshrc")));
        std::fs::write(home.join(".zshrc"), "").unwrap();
        assert!(shell_files_in(home, "/bin/bash").contains(&home.join(".zshrc")));
        let fish = fish_block(
            Path::new("/r/warp.env"),
            Path::new("/r/warp.sock"),
            Path::new("/b/podnet"),
        );
        assert!(
            fish.contains("if test -f '/r/warp.env'; source '/r/warp.env'; end\n"),
            "{fish}"
        );
        assert!(fish.contains("exec '/b/podnet' warp shell; end"), "{fish}");
    }

    // Issue 116: the program of warp exec gets PODNET_WARP_SOCKET.
    #[test]
    fn warp_exec_gives_the_socket() {
        let command = pod_command(
            "/b/podnet".into(),
            Path::new("/r/warp.sock"),
            &[],
            &["sh".to_string()],
        );
        assert!(command
            .get_envs()
            .any(|(k, v)| k == "PODNET_WARP_SOCKET" && v == Some("/r/warp.sock".as_ref())));
    }

    // Issue 116: warp up does not send its own session through the proxy
    // variables of an earlier warp up.
    #[test]
    fn the_own_proxy_variables_are_not_given_to_the_proxy() {
        let argv: Vec<String> = [
            "warp",
            "proxy",
            "--listen",
            "tcp://127.0.0.1:40000",
            "--listen",
            "unix:/r/warp.sock",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let vars = [
            ("ALL_PROXY", "socks5h://127.0.0.1:40000"),
            ("HTTPS_PROXY", "http://127.0.0.1:40000"),
            ("PODNET_PROXY", "socks5h+unix:/r/warp.sock"),
            ("PODNET_WARP_SOCKET", "/r/warp.sock"),
            ("http_proxy", "http://corp.example:3128"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let mut own = own_proxy_variables(&argv, vars.into_iter());
        own.sort();
        assert_eq!(own, ["ALL_PROXY", "HTTPS_PROXY", "PODNET_PROXY"]);
    }

    #[test]
    fn the_block_is_added_once_and_removed_with_the_rest_kept() {
        let block = hook_block(
            Path::new("/r/warp.env"),
            Path::new("/r/warp.sock"),
            Path::new("/b/podnet"),
        );
        assert!(block.starts_with(BEGIN) && block.trim_end().ends_with(END));
        assert!(block.contains("exec '/b/podnet' warp shell"));
        assert!(block.contains("PODNET_WARP_SHELL"));
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
            Path::new("/nonexistent/podnet"),
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

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    #[test]
    fn a_small_bundle_is_merged_with_the_system_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let proxy = dir.path().join("proxy.pem");
        std::fs::write(&proxy, CERT).unwrap();
        let big = dir.path().join("big.pem");
        std::fs::write(&big, CERT.repeat(40)).unwrap();
        let system = dir.path().join("system.pem");
        std::fs::write(&system, CERT.repeat(120)).unwrap();
        let (p, b) = (proxy.display().to_string(), big.display().to_string());
        let env = |k: &str| match k {
            "SSL_CERT_FILE" => Some(p.clone()),
            "REQUESTS_CA_BUNDLE" => Some(p.clone()),
            "CURL_CA_BUNDLE" => Some(b.clone()),
            _ => None,
        };
        let (merged, vars) = ca_fix(&env, Some(&system)).unwrap();
        assert_eq!(vars, ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]);
        // The proxy root one time, and the 120 roots of the system.
        assert_eq!(certificates_in(&merged), 121);
        // A big bundle (a public bundle) needs no fix.
        let only_big = |k: &str| (k == "SSL_CERT_FILE").then(|| b.clone());
        assert!(ca_fix(&only_big, Some(&system)).is_none());
        // No system bundle: no fix (a warning).
        assert!(ca_fix(&env, None).is_none());
        assert!(ca_fix(&|_| None, Some(&system)).is_none());
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

    const TUN_LABEL: &str = "podnet warp tun --default-route --detach";
    const NOISE: &str =
        "2026-11-02T10:00:00Z  INFO podnet: the routes and the resolver are as before tun=podnet0\n";

    /// Issue 106, case A: the last line names the recovery, and the first
    /// line names the real command (`warp tun`, not `warp proxy`).
    #[test]
    fn a_tun_refusal_names_the_command_and_the_recovery() {
        let stderr =
            format!("{NOISE}podnet: TUNSETIFF (needs CAP_NET_ADMIN): Operation not permitted\n");
        let text = failure_text(TUN_LABEL, 69, &stderr, false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "podnet warp tun --default-route --detach exited 69: TUNSETIFF (needs CAP_NET_ADMIN): Operation not permitted"
        );
        assert!(!text.contains("warp proxy"), "{text}");
        assert!(text.contains("sudo podnet warp up --tun"), "{text}");
        assert!(text.contains("podnet warp up (proxy mode)"), "{text}");
        assert_eq!(
            *lines.last().unwrap(),
            "podnet: one command with no root: podnet warp run -- CMD"
        );
    }

    /// As root, sudo gives nothing: it is not advised.
    #[test]
    fn root_is_not_told_to_use_sudo() {
        let stderr = "podnet: TUNSETIFF (needs CAP_NET_ADMIN): Operation not permitted\n";
        let text = failure_text(TUN_LABEL, 69, stderr, true);
        assert!(!text.contains("sudo"), "{text}");
        assert!(text.contains("CAP_NET_ADMIN"), "{text}");
        assert!(text.contains("podnet warp run -- CMD"), "{text}");
    }

    /// Issue 106, case B: the route guard. sudo does not help.
    #[test]
    fn no_default_route_is_not_a_privilege_problem() {
        let stderr = format!("{NOISE}podnet: no IPv4 default route: podnet cannot keep the MASQUE connection outside the tunnel\n");
        let text = failure_text(TUN_LABEL, 69, &stderr, false);
        assert!(text.contains("exited 69: no IPv4 default route"), "{text}");
        assert!(text.contains("needs an IPv4 default route"), "{text}");
        assert!(!text.contains("sudo podnet"), "{text}");
        assert!(text.ends_with("podnet warp run -- CMD"), "{text}");
    }

    #[test]
    fn a_missing_tun_device_is_named() {
        let stderr = "podnet: opening /dev/net/tun: No such file or directory (os error 2)\n";
        let text = failure_text(TUN_LABEL, 69, stderr, false);
        assert!(text.contains("the host has no /dev/net/tun"), "{text}");
        assert!(!text.contains("sudo podnet"), "{text}");
    }

    /// A failure of the proxy, or a `warp tun` failure that is not a TUN
    /// refusal, gets the command and the cause only.
    #[test]
    fn other_failures_get_no_recovery_lines() {
        let proxy = failure_text(
            "podnet warp proxy --detach",
            69,
            "podnet: the MASQUE endpoint did not answer\n",
            false,
        );
        assert_eq!(
            proxy,
            "podnet warp proxy --detach exited 69: the MASQUE endpoint did not answer"
        );
        let tun = failure_text(
            TUN_LABEL,
            69,
            "podnet: the device is not registered\n",
            false,
        );
        assert_eq!(tun.lines().count(), 1, "{tun}");
        assert_eq!(
            failure_text("podnet warp proxy --detach", 1, "", false),
            "podnet warp proxy --detach exited 1"
        );
    }
}
