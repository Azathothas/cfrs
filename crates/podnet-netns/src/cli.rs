#[allow(unused_imports)]
use crate::prelude::*;

// ── command line ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendKind {
    Auto,
    Netns,
    Seccomp,
}

pub(crate) struct Args {
    pub(crate) proxies: Vec<Proxy>,
    pub(crate) rules: Vec<Rule>,
    pub(crate) maps: Vec<(String, IpAddr)>,
    pub(crate) program: Vec<String>,
    pub(crate) doctor: bool,
    pub(crate) doctor_json: bool,
    pub(crate) verbose: bool,
    pub(crate) inbound_dir: std::path::PathBuf,
    /// `--inbound-dir` was given (the seccomp backend only uses it).
    pub(crate) inbound_dir_given: bool,
    /// `--keep-proxy-env`: the program keeps the proxy variables.
    pub(crate) keep_proxy_env: bool,
    pub(crate) serve: Option<crate::listen::ProxyListen>,
    pub(crate) backend: BackendKind,
    /// `--prefer-udp`: `auto` takes the seccomp backend first (it carries
    /// all UDP; the netns backend carries DNS only).
    pub(crate) prefer_udp: bool,
    /// `--name-backend`: print one line that names the backend that runs
    /// and its limits (T-071).
    pub(crate) name_backend: bool,
}

/// The name in the help and the usage lines: `podnet-netns`, or `podnet pod`
/// when podnet runs the pod ([`set_program_name`]).
static PROGRAM_NAME: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Set the name that the help shows (once, before [`crate::main_with_args`]).
pub fn set_program_name(name: &'static str) {
    let _ = PROGRAM_NAME.set(name);
}

fn program_name() -> &'static str {
    PROGRAM_NAME.get().copied().unwrap_or("podnet-netns")
}

/// The help, in the layout of the other podnet commands (issue 95).
pub fn usage() -> String {
    usage_for(program_name())
}

/// The help with `name` as the name of the program.
pub fn usage_for(name: &str) -> String {
    format!(
        "\
Run a program with all egress through a proxy, without shims

Usage: {name} [OPTIONS] -- <PROGRAM> [ARGS]...
       {name} doctor [--json]
       {name} --serve <LISTEN> -x <PROXY>

Arguments:
  <PROGRAM> [ARGS]...  The program to run, and its arguments

Options:
  -x, --proxy <SPEC>       Upstream proxy, repeatable; more than one chains:
                             socks5://[user:pass@]host:port
                             http://[user:pass@]host:port
                             socks5://unix:/path     (unix-socket proxy)
                             http://unix:/path       (HTTP CONNECT on a unix socket)
                             tailscale:/path/to/tailscaled.sock
                           Default: $ALL_PROXY, $HTTPS_PROXY or $HTTP_PROXY
  -r, --rule <SPEC>        Per-destination route; first match wins:
                             domain:NAME=socks5://host:port
                             domain:.example.com=...  (the name and each
                                                       name under it)
                             cidr:10.0.0.0/8=socks5://host:port
                             cidr:10.0.0.0/8=direct   (no proxy)
                           With the seccomp backend, 127.0.0.0/8 goes direct
                           (or to a listener of the program itself)
      --map <NAME=ADDR>    Resolve NAME to ADDR locally, repeatable
      --keep-proxy-env     Keep HTTPS_PROXY, HTTP_PROXY, ALL_PROXY and NO_PROXY
                           (and the lower-case forms) for the program; by
                           default the program does not get them
      --backend <NAME>     auto (default), netns or seccomp. With netns, a
                           listener of the program is in the network of the
                           pod: a loopback TCP listener is not seen from
                           outside; use a unix socket (connect -L unix:///PATH)
      --prefer-udp         With auto: seccomp first when it works (all UDP
                           goes through; netns carries DNS only)
      --name-backend       Print one line on stderr that names the backend
                           that runs and its limits (also after auto)
      --inbound-dir <DIR>  Where a bound port is exposed as a unix socket
                           (seccomp backend only). The directory must be of
                           this user and not writable by the group or by
                           others; a new one gets mode 0700
                           [default: $XDG_RUNTIME_DIR/podnet-netns-inbound,
                           else $TMPDIR/podnet-netns-inbound-UID]
      --serve <LISTEN>     Serve SOCKS5, HTTP CONNECT and UDP ASSOCIATE on
                           unix:/path or tcp://host:port, forwarding through
                           the -x chain
  -v, --verbose            Log each flow; with seccomp, also each socket and
                           each setsockopt that the pod emulates
  -V, --version            Print the version
  -h, --help               Print help

Exit status: the exit code of the program; 64 for a usage mistake (also no
proxy at all); 3 when no backend can run on this host. doctor measures what
the host permits and exits 3 when no backend can run.
"
    )
}

pub(crate) fn parse_args(argv: &[String]) -> Result<Args> {
    let mut proxies = Vec::new();
    let mut rules = Vec::new();
    let mut program = Vec::new();
    let mut doctor = false;
    let mut doctor_json = false;
    let mut verbose = false;
    let mut maps: Vec<(String, IpAddr)> = Vec::new();
    let mut backend = BackendKind::Auto;
    let mut prefer_udp = false;
    let mut name_backend = false;
    let mut inbound_dir = crate::listen::default_inbound_dir();
    let mut inbound_dir_given = false;
    let mut keep_proxy_env = false;
    let mut serve: Option<crate::listen::ProxyListen> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--" => {
                program = argv[i + 1..].to_vec();
                break;
            }
            "doctor" if i == 0 => {
                doctor = true;
                i += 1;
                if argv.get(i).map(String::as_str) == Some("--json") {
                    doctor_json = true;
                    i += 1;
                }
            }
            "-V" | "--version" => {
                println!(
                    "podnet-netns {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    env!("PODNET_BUILD_COMMIT")
                );
                std::process::exit(0);
            }
            "--keep-proxy-env" => {
                keep_proxy_env = true;
                i += 1;
            }
            "--prefer-udp" => {
                prefer_udp = true;
                i += 1;
            }
            "--name-backend" => {
                name_backend = true;
                i += 1;
            }
            "--map" => {
                let spec = argv.get(i + 1).context("--map needs NAME=ADDR")?;
                let (name, addr) = spec.split_once('=').context("--map needs NAME=ADDR")?;
                if name.is_empty() {
                    bail!("--map has an empty name");
                }
                maps.push((name.to_string(), addr.parse().context("--map address")?));
                i += 2;
            }
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "-v" | "--verbose" => {
                verbose = true;
                i += 1;
            }
            "-x" | "--proxy" => {
                let spec = argv.get(i + 1).context("--proxy needs a value")?;
                proxies.push(Proxy::parse(spec)?);
                i += 2;
            }
            "-r" | "--rule" => {
                let spec = argv.get(i + 1).context("--rule needs a value")?;
                let (lhs, rhs) = spec
                    .split_once('=')
                    .context("--rule needs KIND:VALUE=PROXY")?;
                let matcher = RuleMatch::parse(lhs)?;
                rules.push(Rule {
                    matcher,
                    proxy: Proxy::parse(rhs)?,
                });
                i += 2;
            }
            "--serve" => {
                let spec = argv.get(i + 1).context("--serve needs a listen spec")?;
                serve = Some(
                    crate::listen::ProxyListen::parse(spec).map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                i += 2;
            }
            "--inbound-dir" => {
                inbound_dir = std::path::PathBuf::from(
                    argv.get(i + 1).context("--inbound-dir needs a value")?,
                );
                inbound_dir_given = true;
                i += 2;
            }
            "--backend" => {
                let value = argv.get(i + 1).context("--backend needs a value")?;
                backend = match value.as_str() {
                    "auto" => BackendKind::Auto,
                    "netns" => BackendKind::Netns,
                    "seccomp" => BackendKind::Seccomp,
                    other => bail!("unknown backend {other:?} (auto, netns, seccomp)"),
                };
                i += 2;
            }
            other => bail!("unexpected argument {other:?}; see --help"),
        }
    }
    // An ambient proxy is used when no -x is given, so the tool composes with
    // whatever the environment already names.
    if proxies.is_empty() {
        for var in [
            "ALL_PROXY",
            "all_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
        ] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() {
                    if let Ok(proxy) = Proxy::parse(&value) {
                        proxies.push(proxy);
                        break;
                    }
                }
            }
        }
    }
    if !doctor && serve.is_none() && program.is_empty() {
        bail!(
            "nothing to run; usage: {} [OPTIONS] -- PROGRAM",
            program_name()
        );
    }
    Ok(Args {
        proxies,
        rules,
        maps,
        program,
        doctor,
        doctor_json,
        verbose,
        inbound_dir,
        inbound_dir_given,
        keep_proxy_env,
        serve,
        backend,
        prefer_udp,
        name_backend,
    })
}
