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
    pub(crate) serve: Option<crate::listen::ProxyListen>,
    pub(crate) backend: BackendKind,
}

pub fn usage() -> String {
    "\
pod-netns — run a program with all egress through a proxy, without shims

USAGE:
    pod-netns [OPTIONS] -- PROGRAM [ARGS...]
    pod-netns doctor [--json]
    pod-netns --serve LISTEN -x PROXY

OPTIONS:
    -x, --proxy SPEC       Upstream proxy, repeatable; more than one chains:
                             socks5://[user:pass@]host:port
                             http://[user:pass@]host:port
                             socks5://unix:/path     (unix-socket proxy)
                             tailscale:/path/to/tailscaled.sock
                           Default: $ALL_PROXY, $HTTPS_PROXY or $HTTP_PROXY
    -r, --rule SPEC        Per-destination route; first match wins:
                             domain:NAME=socks5://host:port
                             cidr:10.0.0.0/8=socks5://host:port
        --map NAME=ADDR    Resolve NAME to ADDR locally, repeatable
        --backend NAME     auto (default), netns or seccomp
        --inbound-dir DIR  Where a bound port is exposed as a unix socket
                           [default: /tmp/pod-netns-inbound]
        --serve LISTEN     Serve SOCKS5, HTTP CONNECT and UDP ASSOCIATE on
                           unix:/path or tcp://host:port, forwarding through
                           the -x chain
    -v, --verbose          Log each flow
    -V, --version          Print the version and exit
    -h, --help             This text

doctor measures what the host permits and exits 3 when no backend can run.
"
    .to_string()
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
    let mut inbound_dir = std::path::PathBuf::from("/tmp/pod-netns-inbound");
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
                println!("pod-netns {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
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
                let (kind, value) = lhs.split_once(':').context("--rule needs KIND:VALUE")?;
                let matcher = match kind {
                    "domain" => RuleMatch::Domain(value.to_string()),
                    "cidr" => {
                        let (net, prefix) = value
                            .split_once('/')
                            .context("cidr rule needs ADDR/PREFIX")?;
                        RuleMatch::Cidr(
                            net.parse().context("cidr address")?,
                            prefix.parse().context("cidr prefix")?,
                        )
                    }
                    other => bail!("unknown rule kind {other:?} (domain, cidr)"),
                };
                rules.push(Rule {
                    matcher,
                    proxy: Proxy::parse(rhs)?,
                });
                i += 2;
            }
            "--serve" => {
                let spec = argv.get(i + 1).context("--serve needs a listen spec")?;
                serve = Some(
                    crate::listen::ProxyListen::parse(spec)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                );
                i += 2;
            }
            "--inbound-dir" => {
                inbound_dir = std::path::PathBuf::from(
                    argv.get(i + 1).context("--inbound-dir needs a value")?,
                );
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
        bail!("nothing to run; usage: pod-netns [OPTIONS] -- PROGRAM");
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
        serve,
        backend,
    })
}
