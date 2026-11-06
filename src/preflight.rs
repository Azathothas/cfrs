//! The preflight check (`--check`) of `tunnel`, `serve`, `share` and `demo`.
//!
//! The check reads the plan of a tunnel and tests each local part of it:
//! the origins, the files and the directories, the edge legs, `PODNET_EDGE`.
//! It makes no call to the Cloudflare API, opens no edge connection, opens
//! no listening socket, sends no HTTP request to an origin, and writes no
//! file. It makes one DNS lookup: the SRV record of the edge, with the
//! system resolver (#277). It prints no token, no secret and no PIN.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::{Config, Credentials};
use crate::ingress::{ForwardTarget, OriginOptions, Service};
use crate::share::ShareMode;

/// The time limit of each connection to an origin.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(3);

/// The result of one check.
/// The time for the DNS lookup of the edge.
const EDGE_LOOKUP: Duration = Duration::from_secs(5);

/// The row of the edge for the lookup `found` (the number of addresses).
/// A failure is a warning: the run tries DNS over HTTPS, then the static
/// list.
fn edge_row(found: anyhow::Result<usize>) -> (Status, String) {
    match found {
        Ok(n) if n > 0 => (
            Status::Pass,
            format!(
                "{n} edge address(es) by DNS ({})",
                crate::edge_discovery::edge_srv()
            ),
        ),
        Ok(_) => (
            Status::Warn,
            "the system resolver gives no edge address; the run tries DNS over HTTPS, then the static list".into(),
        ),
        Err(err) => (
            Status::Warn,
            format!("the system resolver cannot find the edge ({err:#}); the run tries DNS over HTTPS, then the static list"),
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

/// One check: its name, its result and what it found.
#[derive(Clone, Debug)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    /// The class of a failed check of the configuration (issue 173).
    pub fault: Option<crate::exit::Fault>,
}

/// Each check, and the plan of the tunnel.
#[derive(Clone, Debug)]
pub struct Report {
    pub checks: Vec<Check>,
    pub plan: Value,
}

impl Report {
    /// The class of the failed checks: Config when each failed check is a
    /// check of the configuration; else none (exit 1).
    pub fn fault(&self) -> Option<crate::exit::Fault> {
        let mut failed = self.checks.iter().filter(|c| c.status == Status::Fail);
        let first = failed.next()?.fault?;
        failed.all(|c| c.fault == Some(first)).then_some(first)
    }

    /// True when no check failed. A warning does not fail the check.
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.status != Status::Fail)
    }

    /// `{"ok", "plan", "checks": [{"name", "status", "detail"}]}`.
    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok(),
            "plan": self.plan,
            "checks": self.checks.iter().map(|c| json!({
                "name": c.name,
                "status": c.status.name(),
                "detail": c.detail,
            })).collect::<Vec<_>>(),
        })
    }

    /// One line for each check, then the result.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for check in &self.checks {
            out.push_str(&format!(
                "  {:<4}  {:<12}  {}\n",
                check.status.name(),
                check.name,
                check.detail
            ));
        }
        if self.ok() {
            out.push_str("podnet: the check passed; nothing was started\n");
        }
        out
    }

    fn push(&mut self, name: impl Into<String>, status: Status, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status,
            detail: detail.into(),
            fault: None,
        });
    }

    /// A failed check of the configuration.
    fn config_fail(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            fault: Some(crate::exit::Fault::Config),
        });
    }

    fn result(&mut self, name: impl Into<String>, result: Result<String, String>) {
        match result {
            Ok(detail) => self.push(name, Status::Pass, detail),
            Err(detail) => self.push(name, Status::Fail, detail),
        }
    }
}

/// Check `config`. The caller already parsed the command line and the
/// configuration file: an error there stops the command before the check.
pub async fn check(config: &Config) -> Report {
    let mut report = Report {
        checks: Vec::new(),
        plan: Value::Null,
    };

    let tunnel = match &config.credentials {
        Credentials::Quick => {
            json!({"kind": "quick", "service": config.service_url})
        }
        Credentials::Token(_) => json!({"kind": "named", "credentials": "token"}),
        Credentials::File(path) => {
            json!({"kind": "named", "credentials": path.display().to_string()})
        }
        Credentials::Explicit { tunnel_id, .. } => {
            json!({"kind": "named", "tunnel_id": tunnel_id.to_string()})
        }
    };
    report.push(
        "tunnel",
        Status::Pass,
        match &config.credentials {
            Credentials::Quick => format!(
                "a quick tunnel; {} is not called in a check",
                config.service_url
            ),
            Credentials::Explicit { tunnel_id, .. } => format!("the named tunnel {tunnel_id}"),
            _ => "a named tunnel".to_string(),
        },
    );

    // Issue 269: a run with no ingress rules fails, so the check fails too.
    if config.ingress.is_empty() {
        report.config_fail("ingress", crate::tunnel::NO_INGRESS);
    }

    match crate::tunnel::edge_override() {
        Ok(Some(list)) => report.push(
            "edge",
            Status::Pass,
            format!("PODNET_EDGE gives {} address(es)", list.len()),
        ),
        Ok(None) => {
            // #277: the row names a lookup, so it makes the lookup.
            let found = tokio::time::timeout(
                EDGE_LOOKUP,
                crate::edge_discovery::discover_system(crate::cloudflare::IpVersionFilter::Auto),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("no answer in {} s", EDGE_LOOKUP.as_secs())));
            let (status, detail) = edge_row(found.map(|edges| edges.len()));
            report.push("edge", status, detail);
        }
        Err(err) => report.config_fail("edge", format!("{err:#}")),
    }

    let legs = match crate::tunnel::leg_plan(config.protocol, config.transport) {
        Ok(plan) => {
            let proxy = crate::egress::proxy_for(crate::tunnel::edge_region_name(), 7844);
            let (plan, mut note) =
                crate::tunnel::plan_with_proxy(plan, config.protocol, proxy.as_ref());
            // The check sends no UDP probe: only PODNET_UDP=off applies here.
            let udp = crate::udp::Choice::from_env().map_err(|e| format!("{e:#}"));
            match udp.and_then(|u| {
                crate::tunnel::plan_with_udp(plan, u, None).map_err(|e| format!("{e:#}"))
            }) {
                Ok((plan, udp_note)) => {
                    note = note.or(udp_note);
                    let names: Vec<String> = plan.iter().map(ToString::to_string).collect();
                    let failover = match config.failover {
                        crate::race::Failover::Staggered(d) => {
                            format!("staggered by {}s", d.as_secs())
                        }
                        crate::race::Failover::Serial => "serial".to_string(),
                    };
                    // Issue 182: the row is the plan; the check makes no
                    // edge connection (podnet doctor tests the reach).
                    let mut detail = format!(
                        "planned: {} ({failover}); no edge connection is made (podnet doctor tests the reach)",
                        names.join(", then ")
                    );
                    if let Some(note) = note {
                        detail.push_str(&format!("; {note}"));
                    }
                    if let Some(relay) = crate::ws_relay::active() {
                        detail.push_str(&format!("; relay {}", relay.url()));
                    }
                    report.push("legs", Status::Pass, detail);
                    names
                }
                // One row: before, a fail row and then a pass row with an
                // empty plan (issue 66).
                Err(err) => {
                    report.push("legs", Status::Fail, err);
                    Vec::new()
                }
            }
        }
        Err(err) => {
            report.push("legs", Status::Fail, format!("{err:#}"));
            Vec::new()
        }
    };

    // Issue 173 row 11: the roots of --ca-file and SSL_CERT_FILE.
    match crate::trust::context().roots() {
        Ok(roots) => report.push("tls-roots", Status::Pass, roots.sources.join(", ")),
        Err(err) => report.config_fail("tls-roots", format!("{err:#}")),
    }

    let mut files = Vec::new();
    if let Some(path) = &config.warp_identity {
        files.push(path.display().to_string());
        report.result("warp-identity", identity_file(path));
    }
    if let Credentials::File(path) = &config.credentials {
        files.push(path.display().to_string());
        match crate::config::parse_credentials_file(path) {
            Ok(_) => report.push(
                "credentials",
                Status::Pass,
                format!("{} parses", path.display()),
            ),
            Err(e) => report.config_fail("credentials", format!("{e:#}")),
        }
    }

    let mut ingress = Vec::new();
    for (i, rule) in config.ingress.rules.iter().enumerate() {
        let name = format!("origin {}", i + 1);
        ingress.push(json!({
            "hostname": rule.hostname,
            "path": rule.path.as_ref().map(|p| p.as_str()),
            "service": crate::net::origin_label(&rule.service),
        }));
        files.extend(service_files(&rule.service));
        let result = service(&rule.service, &rule.origin).await;
        // Issue 199: a quick tunnel receives HTTP; a raw TCP origin answers
        // each request with 501.
        match (&result, &rule.service, &config.credentials) {
            (Ok(detail), Service::Tcp(_), Credentials::Quick) => report.push(
                name,
                Status::Warn,
                format!("{detail}; a quick tunnel receives HTTP, and a raw TCP origin answers 501 to a browser or curl (use --forward and podnet connect)"),
            ),
            _ => report.result(name, result),
        }
    }

    report.plan = json!({
        "tunnel": tunnel,
        "legs": legs,
        "ha_connections": config.ha_connections,
        "verify": config.verify,
        "ingress": ingress,
        "files": files,
    });
    report
}

/// The files and directories that a service reads or writes.
fn service_files(service: &Service) -> Vec<String> {
    match service {
        Service::Unix(path) | Service::UnixTls(path) => vec![path.display().to_string()],
        Service::Forward(ForwardTarget::Unix(path)) => vec![path.display().to_string()],
        Service::Static { root, .. } => vec![root.display().to_string()],
        Service::Share(share) => match share.mode {
            ShareMode::Upload => vec![share.dest.display().to_string()],
            ShareMode::Download => share.file.iter().map(|p| p.display().to_string()).collect(),
            ShareMode::Proxy => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Check one service of the ingress.
async fn service(service: &Service, origin: &OriginOptions) -> Result<String, String> {
    let label = crate::net::origin_label(service);
    match service {
        Service::Http(_) | Service::Unix(_) | Service::UnixTls(_) | Service::Tcp(_) => {
            dial(service, origin).await?;
            let tls = match service {
                Service::Http(url) if url.starts_with("https://") => true,
                Service::UnixTls(_) => true,
                _ => false,
            };
            Ok(match (tls, origin.no_tls_verify) {
                (true, false) => format!("{label}: connects; TLS handshake and certificate pass"),
                (true, true) => format!("{label}: connects; TLS handshake passes (not verified)"),
                _ => format!("{label}: connects"),
            })
        }
        Service::Forward(target) => {
            let inner = match target {
                ForwardTarget::Tcp(addr) => Service::Tcp(addr.clone()),
                ForwardTarget::Unix(path) => Service::Unix(path.clone()),
            };
            dial(&inner, origin).await?;
            Ok(format!("{label}: connects"))
        }
        Service::HelloWorld | Service::Status(_) | Service::Metrics => {
            Ok(format!("{label}: built in"))
        }
        Service::Static { root, spa } => static_dir(root, *spa),
        Service::Share(share) => match share.mode {
            ShareMode::Upload => upload_dir(&share.dest),
            ShareMode::Download => match &share.file {
                Some(file) => regular_file(file),
                None => Err("download mode needs --file".to_string()),
            },
            ShareMode::Proxy => {
                let target = share.target.clone().unwrap_or_default();
                let service = match crate::proxy::share_origin(&target) {
                    Service::Http(_) => Service::Tcp(target.clone()),
                    unix => unix,
                };
                dial(&service, origin).await?;
                Ok(format!("{target}: connects"))
            }
        },
    }
}

/// Connect to an origin and close the connection. No request is sent.
async fn dial(service: &Service, origin: &OriginOptions) -> Result<(), String> {
    let mut options = origin.clone();
    options.connect_timeout = Some(options.connect_timeout.unwrap_or(CONNECT_LIMIT));
    crate::net::dial(service, &options)
        .await
        .map(drop)
        .map_err(|e| format!("{}: {e:#}", crate::net::origin_label(service)))
}

fn static_dir(root: &Path, spa: bool) -> Result<String, String> {
    let shown = root.display();
    let meta = std::fs::metadata(root).map_err(|e| format!("--dir {shown}: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("--dir {shown}: not a directory"));
    }
    std::fs::read_dir(root).map_err(|e| format!("--dir {shown}: cannot read it: {e}"))?;
    if spa {
        let index = root.join("index.html");
        if !index.is_file() {
            return Err(format!(
                "--spa needs an index.html in {shown}: each unknown path answers it"
            ));
        }
        std::fs::File::open(&index)
            .map_err(|e| format!("{}: cannot read it: {e}", index.display()))?;
        return Ok(format!("{shown}: a readable directory with index.html"));
    }
    Ok(format!("{shown}: a readable directory"))
}

fn upload_dir(dest: &Path) -> Result<String, String> {
    let shown = dest.display();
    match std::fs::metadata(dest) {
        Ok(meta) if meta.is_dir() => {
            if writable(dest) {
                Ok(format!("{shown}: a writable directory"))
            } else {
                Err(format!("--dir {shown}: podnet cannot write in it"))
            }
        }
        Ok(_) => Err(format!("--dir {shown}: not a directory")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // The share makes the directory. Find the nearest parent that is.
            let mut parent = dest.parent();
            while let Some(p) = parent {
                let p = if p.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    p
                };
                match std::fs::metadata(p) {
                    Ok(meta) if meta.is_dir() => {
                        return if writable(p) {
                            Ok(format!(
                                "{shown}: does not exist; the share makes it in {}",
                                p.display()
                            ))
                        } else {
                            Err(format!(
                                "--dir {shown}: does not exist, and podnet cannot write in {}",
                                p.display()
                            ))
                        };
                    }
                    Ok(_) => {
                        return Err(format!("--dir {shown}: {} is not a directory", p.display()))
                    }
                    Err(_) => parent = p.parent(),
                }
            }
            Err(format!("--dir {shown}: no parent directory exists"))
        }
        Err(err) => Err(format!("--dir {shown}: {err}")),
    }
}

fn regular_file(file: &Path) -> Result<String, String> {
    let shown = file.display();
    let meta = std::fs::metadata(file).map_err(|e| format!("--file {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("--file {shown}: not a regular file"));
    }
    std::fs::File::open(file).map_err(|e| format!("--file {shown}: cannot read it: {e}"))?;
    Ok(format!("{shown}: a readable file of {} bytes", meta.len()))
}

/// The WARP identity: a file that podnet can read, or a path that podnet can
/// write on the first run.
fn identity_file(path: &Path) -> Result<String, String> {
    let shown = path.display();
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            std::fs::read(path).map_err(|e| format!("{shown}: cannot read it: {e}"))?;
            Ok(format!("{shown}: present; podnet resumes this device"))
        }
        Ok(_) => Err(format!("{shown}: not a regular file")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let parent = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            if parent.is_dir() && writable(parent) {
                Ok(format!(
                    "{shown}: absent; the first WARP run writes it (a check registers no device)"
                ))
            } else {
                Err(format!(
                    "{shown}: absent, and podnet cannot write in {}",
                    parent.display()
                ))
            }
        }
        Err(err) => Err(format!("{shown}: {err}")),
    }
}

/// True when this process can write in `dir` (access(2) with W_OK and X_OK).
fn writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid C string that lives for the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #277: the edge row comes from a lookup; a failed lookup warns.
    #[test]
    fn the_edge_row_comes_from_a_lookup() {
        let (status, detail) = edge_row(Ok(20));
        assert_eq!(status.name(), Status::Pass.name());
        assert!(detail.starts_with("20 edge address(es)"), "{detail}");
        let (status, detail) = edge_row(Err(anyhow::anyhow!("SERVFAIL")));
        assert_eq!(status.name(), Status::Warn.name());
        assert!(
            detail.contains("SERVFAIL") && detail.contains("static list"),
            "{detail}"
        );
        assert_eq!(edge_row(Ok(0)).0.name(), Status::Warn.name());
    }
    use crate::config::Config;
    use crate::ingress::Ingress;
    use crate::share::ShareConfig;

    fn with(service: Service) -> Config {
        Config {
            ingress: Ingress::new().catch_all(service),
            ..Config::default()
        }
    }

    fn failed(report: &Report) -> Vec<String> {
        report
            .checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.detail.clone())
            .collect()
    }

    // Issue 269: a config with no ingress rules fails the check (exit 78),
    // as a run does.
    #[tokio::test]
    async fn an_empty_ingress_fails_the_check() {
        let report = check(&Config::default()).await;
        assert!(!report.ok());
        assert!(
            failed(&report)
                .iter()
                .any(|d| d.contains("no ingress rules")),
            "{:?}",
            report.checks
        );
        assert_eq!(report.fault(), Some(crate::exit::Fault::Config));
    }

    #[tokio::test]
    async fn a_closed_port_fails_with_its_address() {
        crate::test_host::need_loopback!();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let report = check(&with(Service::Http(format!("http://127.0.0.1:{port}")))).await;
        assert!(!report.ok());
        let failed = failed(&report);
        assert!(
            failed
                .iter()
                .any(|d| d.contains(&format!("127.0.0.1:{port}"))),
            "{failed:?}"
        );
    }

    #[tokio::test]
    async fn an_open_port_passes_and_gets_no_request() {
        crate::test_host::need_loopback!();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let report = check(&with(Service::Http(format!("http://127.0.0.1:{port}")))).await;
        assert!(report.ok(), "{:?}", report.checks);
        assert!(peer.await.unwrap().is_empty(), "the check sent bytes");
        let json = report.to_json();
        assert_eq!(json["ok"], true);
        assert_eq!(json["plan"]["tunnel"]["kind"], "quick");
    }

    #[tokio::test]
    async fn files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // --spa with no index.html.
        let report = check(&with(Service::Static {
            root: root.to_path_buf(),
            spa: true,
        }))
        .await;
        assert!(failed(&report)[0].contains("--spa needs an index.html"));
        std::fs::write(root.join("index.html"), "x").unwrap();
        let report = check(&with(Service::Static {
            root: root.to_path_buf(),
            spa: true,
        }))
        .await;
        assert!(report.ok(), "{:?}", report.checks);

        // An upload --dir that is a file.
        let file = root.join("index.html");
        let report = check(&with(Service::Share(ShareConfig::upload(&file)))).await;
        assert!(
            failed(&report)[0].ends_with("not a directory"),
            "{:?}",
            report.checks
        );
        // An upload --dir that does not exist yet: the check makes nothing.
        let fresh = root.join("a/b");
        let report = check(&with(Service::Share(ShareConfig::upload(&fresh)))).await;
        assert!(report.ok(), "{:?}", report.checks);
        assert!(!root.join("a").exists());

        // A download --file that is a directory.
        let report = check(&with(Service::Share(ShareConfig::download(root)))).await;
        assert!(failed(&report)[0].ends_with("not a regular file"));
    }

    #[tokio::test]
    async fn no_secret_is_in_the_report() {
        let mut config = with(Service::HelloWorld);
        config.credentials = Credentials::Explicit {
            account_tag: "account-tag-secret".into(),
            tunnel_id: uuid::Uuid::nil(),
            secret: b"tunnel-secret-bytes".to_vec(),
        };
        let mut share = ShareConfig::proxy("127.0.0.1:1".to_string());
        share.gate = crate::gate::Gate::pin();
        config.ingress = Ingress::new().catch_all(Service::Share(share.clone()));
        let report = check(&config).await;
        let all = format!("{}{}", report.text(), report.to_json());
        assert!(!all.contains("account-tag-secret"));
        assert!(!all.contains("tunnel-secret"));
        assert!(!all.contains(&share.token));
        if let Some(pin) = share.gate.pin_display() {
            assert!(!all.contains(pin));
        }
    }
}
