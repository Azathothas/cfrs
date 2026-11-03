//! The agent doctor: what dev work can do on this host, and the command to
//! run (issue 82).
//!
//! For each task of an agent (git over HTTPS and over SSH, the package
//! registries, UDP DNS, IPv6, localhost) the doctor tries each path:
//!
//! * `direct`: a kernel socket, no proxy;
//! * `proxy`: the proxy of the environment (`HTTPS_PROXY`, `--proxy`);
//! * `warp`: the running `cfrs warp up` (its SOCKS5 socket).
//!
//! A TLS check is a full handshake with the public roots, so a proxy that
//! terminates TLS shows as `intercepted`. The verdict of each task names
//! the paths that work, and the advice gives the commands.

use std::time::Duration;

use anyhow::{Context as _, Result};
use serde::Serialize;

use crate::net::BoxedIo;

/// One task of an agent and its target.
#[derive(Clone, Copy, Debug)]
pub struct Task {
    pub name: &'static str,
    pub host: &'static str,
    pub port: u16,
    pub check: Check,
}

/// How a target is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// A TLS handshake with the public roots.
    Tls,
    /// An SSH server sends its version line (`SSH-2.0-`).
    Ssh,
}

/// The tasks of the doctor.
pub const TASKS: &[Task] = &[
    Task {
        name: "git (HTTPS)",
        host: "github.com",
        port: 443,
        check: Check::Tls,
    },
    Task {
        name: "git (SSH)",
        host: "github.com",
        port: 22,
        check: Check::Ssh,
    },
    Task {
        name: "pip (pypi.org)",
        host: "pypi.org",
        port: 443,
        check: Check::Tls,
    },
    Task {
        name: "npm",
        host: "registry.npmjs.org",
        port: 443,
        check: Check::Tls,
    },
    Task {
        name: "cargo (crates.io)",
        host: "index.crates.io",
        port: 443,
        check: Check::Tls,
    },
    Task {
        name: "go modules",
        host: "proxy.golang.org",
        port: 443,
        check: Check::Tls,
    },
    Task {
        name: "docker pull",
        host: "registry-1.docker.io",
        port: 443,
        check: Check::Tls,
    },
];

/// The result of one task on one path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    /// The chain is not one of the public roots, but the CA bundle of this
    /// host (SSL_CERT_FILE) trusts it: a proxy terminates TLS.
    Intercepted,
    Failed(String),
    /// The path is not there (no proxy, no `warp up`).
    NotTried,
}

impl Outcome {
    /// It works for a tool that trusts the CA bundle of this host (an
    /// intercepted chain is trusted there).
    pub fn works(&self) -> bool {
        matches!(self, Outcome::Ok | Outcome::Intercepted)
    }
}

/// The paths of the doctor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Path {
    Direct,
    Proxy,
    Warp,
}

pub const PATHS: [Path; 3] = [Path::Direct, Path::Proxy, Path::Warp];

/// One row of the report.
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub task: &'static str,
    pub target: String,
    pub direct: Outcome,
    pub proxy: Outcome,
    pub warp: Outcome,
}

impl Row {
    fn get(&self, path: Path) -> &Outcome {
        match path {
            Path::Direct => &self.direct,
            Path::Proxy => &self.proxy,
            Path::Warp => &self.warp,
        }
    }

    /// The paths that work for this task.
    pub fn working(&self) -> Vec<Path> {
        PATHS.into_iter().filter(|p| self.get(*p).works()).collect()
    }
}

/// The report of the doctor.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub proxy: Option<String>,
    pub warp_up: bool,
    /// The running `cfrs warp up` has its TCP listener, so `cfrs warp env`
    /// has proxy variables (issue 110).
    pub warp_tcp: bool,
    pub rows: Vec<Row>,
    pub udp_dns: Outcome,
    pub ipv6: Outcome,
    pub localhost: Outcome,
    pub advice: Vec<String>,
}

async fn dial(path: Path, host: &str, port: u16, timeout: Duration) -> Result<BoxedIo> {
    match path {
        Path::Direct => Ok(Box::new(
            crate::egress::dial_direct(host, port, timeout).await?,
        )),
        Path::Proxy => {
            let proxy = crate::egress::proxy_for(host, port).context("no proxy")?;
            proxy.connect(host, port, timeout).await
        }
        Path::Warp => {
            let io = tokio::time::timeout(timeout, crate::warp::nc::via_running(host, port))
                .await
                .context("no answer in time")??
                .context("cfrs warp up does not run")?;
            Ok(io)
        }
    }
}

/// Check `task` on `path`.
pub async fn check(task: &Task, path: Path, timeout: Duration) -> Outcome {
    let io = match dial(path, task.host, task.port, timeout).await {
        Ok(io) => io,
        Err(err) => return Outcome::Failed(short(&err)),
    };
    let checked = tokio::time::timeout(timeout, async {
        match task.check {
            Check::Tls => tls(io, task.host).await,
            Check::Ssh => ssh(io).await,
        }
    })
    .await;
    match checked {
        Ok(Outcome::Intercepted) => tls_with_bundle(task, path, timeout).await,
        Ok(outcome) => outcome,
        Err(_) => Outcome::Failed(format!("no answer in {} s", timeout.as_secs())),
    }
}

fn short(err: &anyhow::Error) -> String {
    let text = format!("{err:#}");
    text.chars().take(160).collect()
}

/// A TLS handshake checked against the public roots alone; when that
/// fails on the chain, the certificate is checked again against the CA
/// bundle of this host (a second connection is not needed: the chain is
/// in the error of the first check).
async fn tls(io: BoxedIo, host: &str) -> Outcome {
    let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_string()) else {
        return Outcome::Failed("a bad TLS name".into());
    };
    crate::init_crypto();
    let public = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(public)
        .with_no_client_auth();
    match tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(name, io)
        .await
    {
        Ok(_) => Outcome::Ok,
        Err(err) => {
            let text = err.to_string();
            if text.contains("UnknownIssuer") || text.contains("invalid peer certificate") {
                Outcome::Intercepted
            } else {
                Outcome::Failed(text.chars().take(160).collect())
            }
        }
    }
}

/// [`check`] for a TLS task where the public roots failed on the chain:
/// a second handshake with the CA bundle of this host tells an
/// interception (trusted here) from a bad chain.
async fn tls_with_bundle(task: &Task, path: Path, timeout: Duration) -> Outcome {
    let io = match dial(path, task.host, task.port, timeout).await {
        Ok(io) => io,
        Err(err) => return Outcome::Failed(short(&err)),
    };
    let config = match crate::trust::client_config(&[], &[b"http/1.1"]) {
        Ok(config) => config,
        Err(err) => return Outcome::Failed(short(&err)),
    };
    let Ok(name) = rustls::pki_types::ServerName::try_from(task.host.to_string()) else {
        return Outcome::Failed("a bad TLS name".into());
    };
    match tokio::time::timeout(
        timeout,
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect(name, io),
    )
    .await
    {
        Ok(Ok(_)) => Outcome::Intercepted,
        Ok(Err(err)) => Outcome::Failed(format!(
            "the chain is not trusted (not the public roots, not the CA bundle of this host): {}",
            err.to_string().chars().take(120).collect::<String>()
        )),
        Err(_) => Outcome::Failed(format!("no answer in {} s", timeout.as_secs())),
    }
}

async fn ssh(mut io: BoxedIo) -> Outcome {
    use tokio::io::AsyncReadExt as _;
    let mut buf = [0u8; 64];
    match io.read(&mut buf).await {
        Ok(n) if buf[..n].starts_with(b"SSH-") => Outcome::Ok,
        Ok(0) => Outcome::Failed("the connection closed with no SSH banner".into()),
        Ok(_) => Outcome::Failed("no SSH banner".into()),
        Err(err) => Outcome::Failed(err.to_string()),
    }
}

/// A DNS query for `example.com` (A) over UDP to 1.1.1.1:53, direct.
async fn udp_dns(timeout: Duration) -> Outcome {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(err) => return Outcome::Failed(format!("a UDP socket: {err}")),
    };
    let query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    if let Err(err) = socket.send_to(&query, "1.1.1.1:53").await {
        return Outcome::Failed(format!("send: {err}"));
    }
    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 12 && buf[0] == 0x12 && buf[1] == 0x34 => Outcome::Ok,
        Ok(Ok(_)) => Outcome::Failed("a bad answer".into()),
        Ok(Err(err)) => Outcome::Failed(err.to_string()),
        Err(_) => Outcome::Failed(format!("no answer in {} s", timeout.as_secs())),
    }
}

/// TCP to the IPv6 address of 1.1.1.1 (2606:4700:4700::1111) on 443.
async fn ipv6(timeout: Duration) -> Outcome {
    match tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect("[2606:4700:4700::1111]:443"),
    )
    .await
    {
        Ok(Ok(_)) => Outcome::Ok,
        Ok(Err(err)) => Outcome::Failed(err.to_string()),
        Err(_) => Outcome::Failed(format!("no answer in {} s", timeout.as_secs())),
    }
}

/// A TCP listener on 127.0.0.1 and a connect to it.
async fn localhost() -> Outcome {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(err) => return Outcome::Failed(format!("bind: {err}")),
    };
    let Ok(addr) = listener.local_addr() else {
        return Outcome::Failed("no local address".into());
    };
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => Outcome::Ok,
        Err(err) => Outcome::Failed(format!("connect: {err}")),
    }
}

/// Run each check, at the same time.
pub async fn run(timeout: Duration) -> Report {
    let proxy = crate::egress::proxy_for("github.com", 443).map(|p| p.to_string());
    let warp_up = crate::warp::up::socket_path()
        .map(|s| std::os::unix::net::UnixStream::connect(s).is_ok())
        .unwrap_or(false);
    // Issue 110: with no TCP listener, the env file has no ALL_PROXY.
    let warp_tcp = warp_up
        && crate::warp::up::env_text()
            .map(|text| text.contains("ALL_PROXY"))
            .unwrap_or(true);
    let rows = futures::future::join_all(TASKS.iter().map(|task| {
        let proxy = proxy.is_some();
        async move {
            let on = |path: Path, there: bool| async move {
                if there {
                    check(task, path, timeout).await
                } else {
                    Outcome::NotTried
                }
            };
            let (direct, via_proxy, warp) = tokio::join!(
                on(Path::Direct, true),
                on(Path::Proxy, proxy),
                on(Path::Warp, warp_up)
            );
            Row {
                task: task.name,
                target: format!("{}:{}", task.host, task.port),
                direct,
                proxy: via_proxy,
                warp,
            }
        }
    }))
    .await;
    let (udp_dns, ipv6, localhost) = tokio::join!(udp_dns(timeout), ipv6(timeout), localhost());
    let mut report = Report {
        proxy,
        warp_up,
        warp_tcp,
        rows,
        udp_dns,
        ipv6,
        localhost,
        advice: Vec::new(),
    };
    report.advice = advice(&report);
    report
}

/// The commands to run, from the results.
pub fn advice(report: &Report) -> Vec<String> {
    let mut out = Vec::new();
    let all_direct = report.rows.iter().all(|r| r.direct == Outcome::Ok);
    let ssh = report.rows.iter().find(|r| r.task == "git (SSH)");
    let any_failing_everywhere = report.rows.iter().any(|r| r.working().is_empty());
    if all_direct && report.udp_dns.works() {
        out.push("direct networking works for each task: nothing to do".into());
        return out;
    }
    if report.warp_up && report.warp_tcp {
        out.push("cfrs warp up runs: in a new shell, eval \"$(cfrs warp env)\"; for a static binary or UDP, cfrs warp exec -- CMD (or cfrs warp shell, or cfrs warp run -- CMD)".into());
    } else if report.warp_up {
        // Issue 110: no TCP listener, so no proxy variables to eval.
        out.push("cfrs warp up runs on its unix socket only (this host refused its TCP listener), so there are no proxy variables: use cfrs warp exec -- CMD (or cfrs warp shell, or cfrs warp run -- CMD)".into());
    } else if any_failing_everywhere || !report.udp_dns.works() {
        out.push(
            "start WARP for this sandbox: cfrs warp up (add --persist so that new shells use it)"
                .into(),
        );
    }
    if let Some(ssh) = ssh {
        if !ssh.direct.works() {
            if ssh.warp.works() || !report.warp_up {
                out.push("git over SSH: cfrs warp ssh-config --write --host github.com".into());
            } else {
                out.push("git over SSH: use HTTPS remotes, or cfrs warp nc --via-relay %h %p as ProxyCommand".into());
            }
        }
    }
    if report
        .rows
        .iter()
        .any(|r| r.proxy == Outcome::Intercepted || r.direct == Outcome::Intercepted)
    {
        out.push("a proxy or a gateway terminates TLS (the CA bundle of this host trusts it): through WARP the tools see the real chains; cfrs warp up names a merged CA bundle when SSL_CERT_FILE has only the proxy root".into());
    }
    if !report.localhost.works() {
        out.push(
            "TCP on 127.0.0.1 does not work here: use unix sockets (cfrs tunnel --unix, cfrs net)"
                .into(),
        );
    }
    if !report.ipv6.works() && !report.warp_up {
        out.push("no IPv6 here; IPv4 targets work through WARP".into());
    }
    out.push("to expose a dev server: cfrs tunnel --port PORT --detach (add --transport relay when TCP 7844 is closed)".into());
    out
}

fn mark(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Ok => "ok".into(),
        Outcome::Intercepted => "tls-intercepted".into(),
        Outcome::Failed(_) => "fail".into(),
        Outcome::NotTried => "-".into(),
    }
}

/// The report as text.
pub fn text(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "proxy: {}   cfrs warp up: {}\n\n",
        report.proxy.as_deref().unwrap_or("none"),
        if report.warp_up {
            "runs"
        } else {
            "does not run"
        }
    ));
    out.push_str(&format!(
        "{:<20} {:<28} {:<16} {:<16} {:<16}\n",
        "TASK", "TARGET", "DIRECT", "PROXY", "WARP"
    ));
    for row in &report.rows {
        out.push_str(&format!(
            "{:<20} {:<28} {:<16} {:<16} {:<16}\n",
            row.task,
            row.target,
            mark(&row.direct),
            mark(&row.proxy),
            mark(&row.warp)
        ));
    }
    out.push_str(&format!(
        "\nThis host, direct (no WARP): UDP DNS (1.1.1.1:53): {}   IPv6: {}   localhost: {}\n",
        mark(&report.udp_dns),
        mark(&report.ipv6),
        mark(&report.localhost)
    ));
    if !report.udp_dns.works() {
        out.push_str(if report.warp_up {
            "  UDP fails for a program that runs on this host. Under WARP it has UDP: cfrs warp exec -- CMD, cfrs warp shell, or cfrs warp run -- CMD.\n"
        } else {
            "  UDP fails for a program that runs on this host. Under WARP it has UDP: cfrs warp run -- CMD, or start cfrs warp up and use cfrs warp exec -- CMD or cfrs warp shell.\n"
        });
    }
    out.push('\n');
    for line in &report.advice {
        out.push_str(&format!("* {line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(task: &'static str, direct: Outcome, proxy: Outcome, warp: Outcome) -> Row {
        Row {
            task,
            target: "x:1".into(),
            direct,
            proxy,
            warp,
        }
    }

    fn report(rows: Vec<Row>, warp_up: bool, udp: Outcome) -> Report {
        Report {
            proxy: Some("http://127.0.0.1:3128".into()),
            warp_up,
            warp_tcp: warp_up,
            rows,
            udp_dns: udp,
            ipv6: Outcome::Failed("no".into()),
            localhost: Outcome::Ok,
            advice: Vec::new(),
        }
    }

    // Issue 110: with no TCP listener of warp up, the advice has no eval.
    #[test]
    fn a_unix_only_warp_up_gets_no_eval_advice() {
        let rows = vec![row(
            "git (HTTPS)",
            Outcome::Failed("refused".into()),
            Outcome::NotTried,
            Outcome::Ok,
        )];
        let mut r = report(rows.clone(), true, Outcome::Failed("no".into()));
        r.warp_tcp = false;
        let advice = advice(&r);
        assert!(!advice[0].contains("eval"), "{advice:?}");
        assert!(advice[0].contains("cfrs warp exec -- CMD"), "{advice:?}");
        let r = report(rows, true, Outcome::Failed("no".into()));
        assert!(advice_has(&r, "eval \"$(cfrs warp env)\""));
    }

    fn advice_has(r: &Report, text: &str) -> bool {
        advice(r).iter().any(|line| line.contains(text))
    }

    #[test]
    fn open_networking_needs_nothing() {
        let r = report(
            vec![row(
                "git (HTTPS)",
                Outcome::Ok,
                Outcome::NotTried,
                Outcome::NotTried,
            )],
            false,
            Outcome::Ok,
        );
        assert_eq!(
            advice(&r),
            ["direct networking works for each task: nothing to do"]
        );
    }

    #[test]
    fn a_proxy_only_sandbox_gets_warp_up_and_ssh_config() {
        let failed = || Outcome::Failed("refused".into());
        let r = report(
            vec![
                row("git (HTTPS)", failed(), Outcome::Ok, Outcome::NotTried),
                row("git (SSH)", failed(), failed(), Outcome::NotTried),
            ],
            false,
            failed(),
        );
        let advice = advice(&r);
        assert!(
            advice[0].starts_with("start WARP for this sandbox: cfrs warp up"),
            "{advice:?}"
        );
        assert!(advice.iter().any(|a| a.contains("cfrs warp ssh-config")));
        assert!(advice.iter().any(|a| a.contains("no IPv6")));
    }

    #[test]
    fn an_intercepting_proxy_is_named() {
        let r = report(
            vec![row(
                "pip (pypi.org)",
                Outcome::Failed("x".into()),
                Outcome::Intercepted,
                Outcome::Ok,
            )],
            true,
            Outcome::Failed("x".into()),
        );
        let advice = advice(&r);
        assert!(advice[0].contains("cfrs warp up runs"));
        assert!(advice.iter().any(|a| a.contains("terminates TLS")));
        assert_eq!(r.rows[0].working(), [Path::Proxy, Path::Warp]);
    }

    #[test]
    fn the_report_serialises() {
        let r = report(
            vec![row(
                "npm",
                Outcome::Ok,
                Outcome::Intercepted,
                Outcome::NotTried,
            )],
            false,
            Outcome::Ok,
        );
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["rows"][0]["direct"], "ok");
        assert_eq!(json["rows"][0]["proxy"], "intercepted");
        assert_eq!(json["rows"][0]["warp"], "not_tried");
        assert!(text(&r).contains("tls-intercepted"));
    }

    /// Issue 107: the UDP fail is for the host; the text names the commands
    /// that give UDP through WARP.
    #[test]
    fn a_udp_fail_says_it_is_the_host_and_names_the_commands() {
        let failed = || Outcome::Failed("no answer in 4 s".into());
        let r = report(vec![], true, failed());
        let t = text(&r);
        let line = t.lines().find(|l| l.contains("UDP DNS")).unwrap();
        assert!(line.starts_with("This host, direct (no WARP): UDP DNS (1.1.1.1:53): fail"));
        for cmd in [
            "cfrs warp exec -- CMD",
            "cfrs warp shell",
            "cfrs warp run -- CMD",
        ] {
            assert!(t.contains(cmd), "{cmd}: {t}");
        }
        // No cfrs warp up yet: it is named before exec and shell.
        let t = text(&report(vec![], false, failed()));
        assert!(
            t.contains("start cfrs warp up and use cfrs warp exec"),
            "{t}"
        );
        // The host UDP works: no note, the line keeps its fields.
        let t = text(&report(vec![], false, Outcome::Ok));
        assert!(t.contains("UDP DNS (1.1.1.1:53): ok"), "{t}");
        assert!(!t.contains("UDP fails"), "{t}");
        // The JSON names do not change.
        let json = serde_json::to_value(report(vec![], true, failed())).unwrap();
        assert!(json.get("udp_dns").is_some() && json.get("ipv6").is_some());
    }
}
