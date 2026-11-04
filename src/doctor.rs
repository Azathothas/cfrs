//! `cfrs doctor`: the path from this host to the Cloudflare edge.
//!
//! The doctor tests each hop that a tunnel needs, and gives a verdict for
//! each: `ok`, `refused` or `unknown`.
//!
//! * The proxy: which proxy each target uses, and if the URL has credentials
//!   (they are never printed).
//! * The TCP path (through the proxy when one applies) to the quick-tunnel
//!   API, the WARP API, the edge on 7844 by name and by address, and the
//!   MASQUE front door on 443. Each path is sampled up to 9 times, 125 ms
//!   apart, in at most 10 s for all paths: best, median, p95, jitter, loss.
//!   A refusal (a proxy 403, a TCP reset) is an answer, not a loss.
//! * TLS on each open path: the issuer of the chain, and if the chain ends at
//!   the roots that cfrs expects. A proxy that answers 200 and sends no byte
//!   is named.
//! * UDP 7844: one QUIC packet (see [`crate::udp`]). A bind is not a test.
//!
//! The end is a table of the legs (`quic`, `http2`, `quic+warp`) with the
//! reason for each that cannot work.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::net::BoxedIo;
use crate::udp::Egress;

/// The limits of the doctor.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Samples of each TCP path.
    pub samples: usize,
    /// The time between two samples of one path.
    pub gap: Duration,
    /// The time limit of all samples.
    pub budget: Duration,
    /// The time limit of one connection, and of one TLS handshake.
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            samples: 9,
            gap: Duration::from_millis(125),
            budget: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
        }
    }
}

/// A verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Refused,
    Unknown,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Refused => "refused",
            Verdict::Unknown => "unknown",
        }
    }
}

/// The TLS that a target speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls {
    /// A public web name: the roots of cfrs (`--ca-file`, the system, webpki).
    Web,
    /// The edge: SNI `h2.cftunnel.com`, and the Cloudflare edge roots.
    Edge,
    /// The MASQUE front door: SNI of MASQUE, ALPN h2. Its certificate is
    /// pinned to a key that only a registered device knows, so the doctor
    /// gives the issuer and does not judge it.
    Masque,
}

/// One target of the doctor.
#[derive(Clone, Debug)]
pub struct Target {
    pub id: &'static str,
    pub host: String,
    pub port: u16,
    pub tls: Tls,
}

impl Target {
    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// The address of the MASQUE front door.
pub const MASQUE_ADDRESS: &str = "162.159.198.2";
/// The IPv6 address of the MASQUE front door (the IPv6-only kit: the doctor
/// gave "0 of 3 legs" on a host where the tunnel worked over IPv6).
pub const MASQUE_ADDRESS_V6: &str = "2606:4700:103::2";

/// The targets: the APIs, the edge by name and by address, and MASQUE.
pub fn targets() -> Vec<Target> {
    let edge = crate::udp::probe_target();
    vec![
        Target {
            id: "api",
            host: "api.trycloudflare.com".into(),
            port: 443,
            tls: Tls::Web,
        },
        Target {
            id: "warp-api",
            host: "api.cloudflareclient.com".into(),
            port: 443,
            tls: Tls::Web,
        },
        Target {
            id: "edge-name",
            host: crate::tunnel::EDGE_REGION_NAME.into(),
            port: 7844,
            tls: Tls::Edge,
        },
        Target {
            id: "edge-address",
            host: edge.ip().to_string(),
            port: edge.port(),
            tls: Tls::Edge,
        },
        Target {
            id: "masque",
            host: MASQUE_ADDRESS.into(),
            port: crate::warp::register::MASQUE_PORT,
            tls: Tls::Masque,
        },
    ]
    .into_iter()
    .chain(
        (crate::resolve::has_default_route(true)
            || crate::egress::proxy_for(MASQUE_ADDRESS_V6, crate::warp::register::MASQUE_PORT)
                .is_some())
        .then(|| Target {
            id: "masque-v6",
            host: MASQUE_ADDRESS_V6.into(),
            port: crate::warp::register::MASQUE_PORT,
            tls: Tls::Masque,
        }),
    )
    // Issue 128: the WebSocket relay is a road of its own (CFRS_RELAY).
    .chain(
        crate::ws_relay::Relay::from_env(None)
            .ok()
            .filter(|r| r.url().starts_with("https://"))
            .map(|relay| Target {
                id: "relay",
                host: relay.host().to_string(),
                port: relay.port(),
                tls: Tls::Web,
            }),
    )
    .collect()
}

/// One sample of a TCP path.
#[derive(Clone, Debug)]
enum Sample {
    Open(Duration),
    Refused(Duration, String),
    Lost(String),
}

/// The result of one TCP path.
#[derive(Clone, Debug)]
pub struct Path {
    pub target: Target,
    pub via: Option<String>,
    pub verdict: Verdict,
    pub detail: String,
    pub sent: usize,
    pub answered: usize,
    pub best: Option<Duration>,
    pub median: Option<Duration>,
    pub p95: Option<Duration>,
    pub jitter: Option<Duration>,
    pub tls: Option<TlsResult>,
    /// The answer of the resolver chain for the host (issue 128): the
    /// addresses and the time, or the error. None for an address, and for
    /// a path through a proxy (the proxy resolves the name).
    pub dns: Option<Result<(Vec<std::net::IpAddr>, Duration), String>>,
}

impl Path {
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.answered) as f64 / self.sent as f64
        }
    }

    /// The verdict of the path and of its TLS together.
    pub fn usable(&self) -> (Verdict, String) {
        match (&self.verdict, &self.tls) {
            (Verdict::Ok, Some(tls)) => (tls.verdict, tls.detail.clone()),
            (Verdict::Ok, None) => (Verdict::Unknown, "no TLS result".into()),
            (verdict, _) => (*verdict, self.detail.clone()),
        }
    }
}

/// The result of a TLS handshake.
#[derive(Clone, Debug)]
pub struct TlsResult {
    pub verdict: Verdict,
    pub issuer: Option<String>,
    pub detail: String,
}

/// One leg and its verdict.
#[derive(Clone, Debug)]
pub struct Leg {
    pub name: &'static str,
    pub verdict: Verdict,
    pub reason: String,
}

/// The report of the doctor.
#[derive(Clone, Debug)]
pub struct Report {
    pub proxy: Value,
    pub paths: Vec<Path>,
    pub udp: (std::net::SocketAddr, Egress),
    pub names: Option<String>,
    pub legs: Vec<Leg>,
    /// The clock of this host against the Date of an API (issue 128).
    pub clock: Clock,
}

/// The clock of this host against the `Date` header of an answer.
#[derive(Clone, Debug)]
pub struct Clock {
    pub verdict: Verdict,
    /// This host minus the remote, in seconds.
    pub skew: Option<i64>,
    pub detail: String,
}

/// A skew of the clock above this breaks TLS (certificates) and tokens.
pub const CLOCK_LIMIT: i64 = 300;

/// The roads of cfrs and their legs: a road works when one of its legs
/// works.
pub const ROADS: &[(&str, &[&str])] = &[
    ("direct", &["quic", "http2"]),
    ("warp", &["quic+warp"]),
    ("relay", &["http2+relay"]),
];

impl Report {
    /// True when at least one leg can work.
    pub fn ok(&self) -> bool {
        self.legs.iter().any(|l| l.verdict == Verdict::Ok)
    }

    /// The verdict of each road of [`ROADS`], with the reason of its first
    /// leg.
    pub fn roads(&self) -> Vec<(&'static str, Verdict, String)> {
        ROADS
            .iter()
            .filter_map(|(road, legs)| {
                let legs: Vec<&Leg> = self
                    .legs
                    .iter()
                    .filter(|l| legs.contains(&l.name))
                    .collect();
                let first = legs.first()?;
                Some(match legs.iter().find(|l| l.verdict == Verdict::Ok) {
                    Some(ok) => (*road, Verdict::Ok, format!("{}: {}", ok.name, ok.reason)),
                    None => (
                        *road,
                        first.verdict,
                        format!("{}: {}", first.name, first.reason),
                    ),
                })
            })
            .collect()
    }

    pub fn to_json(&self) -> Value {
        let ms = |d: Option<Duration>| d.map(|d| (d.as_secs_f64() * 10000.0).round() / 10.0);
        json!({
            "ok": self.ok(),
            "roads": self.roads().iter().map(|(road, verdict, reason)| json!({
                "road": road,
                "verdict": verdict.name(),
                "reason": reason,
            })).collect::<Vec<_>>(),
            "clock": {
                "verdict": self.clock.verdict.name(),
                "skew_s": self.clock.skew,
                "detail": self.clock.detail,
            },
            "proxy": self.proxy,
            "paths": self.paths.iter().map(|p| json!({
                "id": p.target.id,
                "target": p.target.authority(),
                "via": p.via,
                "verdict": p.verdict.name(),
                "detail": p.detail,
                "samples": {
                    "sent": p.sent,
                    "answered": p.answered,
                    "loss": p.loss(),
                    "best_ms": ms(p.best),
                    "median_ms": ms(p.median),
                    "p95_ms": ms(p.p95),
                    "jitter_ms": ms(p.jitter),
                },
                "tls": p.tls.as_ref().map(|t| json!({
                    "verdict": t.verdict.name(),
                    "issuer": t.issuer,
                    "detail": t.detail,
                })),
                "dns": p.dns.as_ref().map(|d| match d {
                    Ok((addrs, took)) => json!({
                        "addresses": addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                        "ms": ms(Some(*took)),
                    }),
                    Err(e) => json!({ "error": e }),
                }),
            })).collect::<Vec<_>>(),
            "udp": {
                "target": self.udp.0.to_string(),
                "verdict": self.udp.1.name(),
                "detail": self.udp.1.detail(),
            },
            "names": self.names,
            "next": self.next(),
            "legs": self.legs.iter().map(|l| json!({
                "leg": l.name,
                "verdict": l.verdict.name(),
                "reason": l.reason,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn text(&self) -> String {
        let ms = |d: Option<Duration>| match d {
            Some(d) => format!("{:.1}", d.as_secs_f64() * 1000.0),
            None => "-".into(),
        };
        let mut out = String::new();
        out.push_str(&format!(
            "proxy  {}\n\n",
            self.proxy["text"].as_str().unwrap_or("")
        ));
        out.push_str(
            "path                                  verdict  best ms  median   p95  jitter  loss\n",
        );
        for p in &self.paths {
            out.push_str(&format!(
                "{:<37} {:<8} {:>7} {:>7} {:>5} {:>7} {:>4.0}%\n",
                p.target.authority(),
                p.verdict.name(),
                ms(p.best),
                ms(p.median),
                ms(p.p95),
                ms(p.jitter),
                p.loss() * 100.0
            ));
            match &p.dns {
                Some(Ok((addrs, took))) => out.push_str(&format!(
                    "    dns {} ({} ms)\n",
                    addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    ms(Some(*took))
                )),
                Some(Err(e)) => out.push_str(&format!("    dns failed: {e}\n")),
                None => {}
            }
            if p.verdict != Verdict::Ok && !matches!(p.dns, Some(Err(_))) {
                out.push_str(&format!("    {}\n", p.detail));
            }
            if let Some(tls) = &p.tls {
                out.push_str(&format!("    tls {}: {}\n", tls.verdict.name(), tls.detail));
            }
        }
        out.push_str(&format!(
            "\nudp    {}  {}: {}\n",
            self.udp.0,
            self.udp.1.name(),
            self.udp.1.detail()
        ));
        if let Some(names) = &self.names {
            out.push_str(&format!("names  {names}\n"));
        }
        out.push_str("\nlegs\n");
        for leg in &self.legs {
            out.push_str(&format!(
                "  {:<10} {:<8} {}\n",
                leg.name,
                leg.verdict.name(),
                leg.reason
            ));
        }
        out.push_str(&format!(
            "\nclock  {}: {}\n",
            self.clock.verdict.name(),
            self.clock.detail
        ));
        out.push_str("\nroads\n");
        for (road, verdict, reason) in self.roads() {
            out.push_str(&format!("  {road:<10} {:<8} {reason}\n", verdict.name()));
        }
        let can = self
            .legs
            .iter()
            .filter(|l| l.verdict == Verdict::Ok)
            .count();
        out.push_str(&format!(
            "\ncfrs doctor: {can} of {} legs can work on this host\n",
            self.legs.len()
        ));
        out.push_str(&format!("next: {}\n", self.next()));
        out
    }

    /// The step to take now (E5): the command that uses a leg that can
    /// work, else what to look at first.
    pub fn next(&self) -> String {
        if self.clock.verdict == Verdict::Refused {
            // The detail names the fix (timedatectl, ntpdate).
            return self.clock.detail.clone();
        }
        let ok = |name: &str| {
            self.legs
                .iter()
                .any(|l| l.name == name && l.verdict == Verdict::Ok)
        };
        let url = "--url http://localhost:8080";
        if ok("quic") || ok("http2") || ok("quic+warp") {
            // --transport auto tries quic, http2 and quic+warp in turn.
            format!("cfrs tunnel {url} (the default legs work here)")
        } else if ok("http2+relay") {
            format!("cfrs tunnel --transport relay {url} (only the relay works here)")
        } else {
            "no leg works: read the proxy and path lines above, then cfrs bug-report --doctor for an issue".to_string()
        }
    }
}

/// Run the doctor.
pub async fn run(options: Options) -> Report {
    crate::init_crypto();
    let targets = targets();
    let proxy = proxy_report(&targets);
    let start = Instant::now();
    let udp_target = crate::udp::probe_target();
    let udp = tokio::task::spawn_blocking(move || {
        crate::udp::probe(udp_target, crate::udp::DOCTOR_DEADLINE)
    });
    let paths =
        futures::future::join_all(targets.into_iter().map(|t| path(t, options, start))).await;
    let udp = udp
        .await
        .unwrap_or_else(|e| Egress::Unknown(format!("the probe did not run: {e}")));
    let names = names(&paths);
    let legs = legs(&paths, &udp);
    let clock = clock(&paths, options.timeout).await;
    Report {
        proxy,
        paths,
        udp: (udp_target, udp),
        names,
        legs,
        clock,
    }
}

/// The clock of this host against the `Date` of the first API that answers
/// TLS (issue 128).
async fn clock(paths: &[Path], timeout: Duration) -> Clock {
    let Some(path) = paths
        .iter()
        .filter(|p| matches!(p.target.tls, Tls::Web))
        .find(|p| p.tls.as_ref().is_some_and(|t| t.verdict == Verdict::Ok))
    else {
        return Clock {
            verdict: Verdict::Unknown,
            skew: None,
            detail: "no API answered TLS".into(),
        };
    };
    let url = format!("https://{}/", path.target.authority());
    let answer = crate::fetch::Request::new("HEAD", url.clone())
        .timeout(timeout)
        .send()
        .await;
    let date = match &answer {
        Ok(r) => r.header("date").map(str::to_string),
        Err(_) => None,
    };
    match date.as_deref().and_then(parse_imf_fixdate) {
        Some(remote) => clock_of(now_unix(), remote, &path.target.host),
        None => Clock {
            verdict: Verdict::Unknown,
            skew: None,
            detail: format!("no Date header from {url}"),
        },
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The verdict of a skew of `host_time - remote` seconds.
fn clock_of(host_time: i64, remote: i64, from: &str) -> Clock {
    let skew = host_time - remote;
    let (verdict, detail) = if skew.abs() > CLOCK_LIMIT {
        (
            Verdict::Refused,
            format!("this host is {skew} s off the Date of {from}: TLS certificates and tokens can fail; set the clock (timedatectl, ntpdate)"),
        )
    } else {
        (Verdict::Ok, format!("{skew} s off the Date of {from}"))
    };
    Clock {
        verdict,
        skew: Some(skew),
        detail,
    }
}

/// Unix seconds of an IMF-fixdate (RFC 9110): `Sun, 06 Nov 1994 08:49:37
/// GMT`.
pub fn parse_imf_fixdate(text: &str) -> Option<i64> {
    let mut parts = text.split_whitespace();
    let _weekday = parts.next()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == month_name)? as i64
        + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut hms = parts.next()?.split(':').map(|x| x.parse::<i64>().ok());
    let (h, m, s) = (hms.next()??, hms.next()??, hms.next()??);
    if parts.next()? != "GMT" {
        return None;
    }
    // Days from the civil date (H. Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + s)
}

fn proxy_report(targets: &[Target]) -> Value {
    let mut used = Vec::new();
    for t in targets {
        if let Some(p) = crate::egress::proxy_for(&t.host, t.port) {
            used.push((t.id, p));
        }
    }
    let direct: Vec<&str> = targets
        .iter()
        .filter(|t| crate::egress::proxy_for(&t.host, t.port).is_none())
        .map(|t| t.id)
        .collect();
    let first = used.first().map(|(_, p)| p.clone());
    let text = match &first {
        None => "none: each connection is direct".to_string(),
        Some(p) => {
            let mut text = format!(
                "{p} (credentials: {})",
                if p.has_credentials() {
                    "present"
                } else {
                    "none"
                }
            );
            if !direct.is_empty() {
                text.push_str(&format!("; direct by NO_PROXY: {}", direct.join(", ")));
            }
            text
        }
    };
    json!({
        "url": first.as_ref().map(|p| p.to_string()),
        "credentials": first.as_ref().map(|p| p.has_credentials()),
        "direct": direct,
        "text": text,
    })
}

async fn path(target: Target, options: Options, start: Instant) -> Path {
    let via = crate::egress::proxy_for(&target.host, target.port).map(|p| p.to_string());
    // Issue 128: the answer of the resolver chain, before the samples.
    let dns = if via.is_none() && target.host.parse::<std::net::IpAddr>().is_err() {
        let took = Instant::now();
        Some(
            match tokio::time::timeout(options.timeout * 3, crate::resolve::resolve(&target.host))
                .await
            {
                Ok(Ok(addrs)) => Ok((addrs, took.elapsed())),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Err(_) => Err(format!(
                    "no answer in {:.1} s",
                    (options.timeout * 3).as_secs_f64()
                )),
            },
        )
    } else {
        None
    };
    let mut samples = Vec::new();
    // Issue 180: a failed lookup is the answer; the samples would only
    // fail the same lookup again (a second line for one failure).
    let dns_failed = matches!(dns, Some(Err(_)));
    for i in 0..if dns_failed {
        0
    } else {
        options.samples.max(1)
    } {
        let left = options.budget.saturating_sub(start.elapsed());
        if left.is_zero() {
            break;
        }
        if i > 0 {
            tokio::time::sleep(options.gap.min(left)).await;
        }
        let limit = options
            .timeout
            .min(options.budget.saturating_sub(start.elapsed()));
        if limit.is_zero() {
            break;
        }
        samples.push(sample(&target, limit).await);
    }
    let times: Vec<Duration> = samples
        .iter()
        .filter_map(|s| match s {
            Sample::Open(d) | Sample::Refused(d, _) => Some(*d),
            Sample::Lost(_) => None,
        })
        .collect();
    let (verdict, detail) = if samples.iter().any(|s| matches!(s, Sample::Open(_))) {
        (Verdict::Ok, "open".to_string())
    } else if let Some(Sample::Refused(_, why)) =
        samples.iter().find(|s| matches!(s, Sample::Refused(..)))
    {
        (Verdict::Refused, why.clone())
    } else if let Some(Sample::Lost(why)) = samples.first() {
        (Verdict::Unknown, why.clone())
    } else if dns_failed {
        (
            Verdict::Unknown,
            "the name does not resolve (see dns)".to_string(),
        )
    } else {
        (Verdict::Unknown, "no sample in the time limit".to_string())
    };
    let tls = if verdict == Verdict::Ok {
        Some(tls(&target, options.timeout).await)
    } else {
        None
    };
    let (best, median, p95, jitter) = stats(&times);
    Path {
        sent: samples.len(),
        answered: times.len(),
        target,
        via,
        verdict,
        detail,
        best,
        median,
        p95,
        jitter,
        tls,
        dns,
    }
}

/// Best, median, 95th percentile, and jitter (the mean difference of two
/// samples in a row).
fn stats(
    times: &[Duration],
) -> (
    Option<Duration>,
    Option<Duration>,
    Option<Duration>,
    Option<Duration>,
) {
    if times.is_empty() {
        return (None, None, None, None);
    }
    let mut sorted = times.to_vec();
    sorted.sort();
    let at = |q: f64| sorted[((sorted.len() - 1) as f64 * q).round() as usize];
    let jitter = (times.len() > 1).then(|| {
        let sum: Duration = times.windows(2).map(|w| w[1].abs_diff(w[0])).sum();
        sum / (times.len() - 1) as u32
    });
    (Some(sorted[0]), Some(at(0.5)), Some(at(0.95)), jitter)
}

async fn sample(target: &Target, limit: Duration) -> Sample {
    let t = Instant::now();
    let result = tokio::time::timeout(
        limit,
        crate::egress::dial(&target.host, target.port, None, limit),
    )
    .await;
    let took = t.elapsed();
    match result {
        Err(_) => Sample::Lost(format!("no answer in {} ms", limit.as_millis())),
        Ok(Ok(_)) => Sample::Open(took),
        Ok(Err(err)) => classify(&err, took),
    }
}

fn classify(err: &anyhow::Error, took: Duration) -> Sample {
    if let Some(refusal) = crate::egress::refusal(err) {
        let text = if refusal.status > 0 {
            format!("proxy {}: {}", refusal.status, refusal.text)
        } else {
            format!("proxy: {}", refusal.text)
        };
        return Sample::Refused(took, text);
    }
    // Issue 180: a local answer is a refusal: the port is closed, the
    // network or the host is unreachable, a firewall refused (EPERM).
    let refused = err.chain().find_map(|e| {
        e.downcast_ref::<std::io::Error>().and_then(|io| {
            use std::io::ErrorKind::*;
            match io.kind() {
                ConnectionRefused => Some("connection refused"),
                NetworkUnreachable => Some("network unreachable"),
                HostUnreachable => Some("host unreachable"),
                PermissionDenied => Some("not permitted"),
                _ => None,
            }
        })
    });
    if let Some(what) = refused {
        return Sample::Refused(took, format!("{what}: {err:#}"));
    }
    Sample::Lost(format!("{err:#}"))
}

/// A verifier that keeps the chain of the server, then asks `inner` (or
/// accepts, with no `inner`).
#[derive(Debug)]
struct Recorder {
    inner: Option<Arc<dyn ServerCertVerifier>>,
    seen: Mutex<Vec<CertificateDer<'static>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(end_entity.clone().into_owned());
            seen.extend(intermediates.iter().map(|c| c.clone().into_owned()));
        }
        match &self.inner {
            Some(inner) => {
                inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            }
            None => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A stream that counts the bytes it reads.
struct Counting {
    inner: BoxedIo,
    read: Arc<AtomicU64>,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.read.fetch_add(n as u64, Ordering::Relaxed);
        poll
    }
}

impl AsyncWrite for Counting {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn issuer_of(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(cert.issuer().to_string())
}

fn verifier(tls: Tls) -> Result<Option<Arc<dyn ServerCertVerifier>>, String> {
    let extra: &[&[u8]] = match tls {
        Tls::Web => &[],
        Tls::Edge => &[crate::cloudflare::CF_EDGE_ROOTS_PEM],
        Tls::Masque => return Ok(None),
    };
    let roots = crate::trust::roots().map_err(|e| format!("{e:#}"))?;
    let mut store = (*roots.store).clone();
    for pem in extra {
        for cert in CertificateDer::pem_slice_iter(pem).flatten() {
            let _ = store.add(cert);
        }
    }
    let v = rustls::client::WebPkiServerVerifier::builder(Arc::new(store))
        .build()
        .map_err(|e| e.to_string())?;
    Ok(Some(v as Arc<dyn ServerCertVerifier>))
}

/// One TLS handshake on the path to `target`.
async fn tls(target: &Target, timeout: Duration) -> TlsResult {
    let unknown = |detail: String| TlsResult {
        verdict: Verdict::Unknown,
        issuer: None,
        detail,
    };
    let inner = match verifier(target.tls) {
        Ok(v) => v,
        Err(e) => return unknown(format!("the roots of cfrs: {e}")),
    };
    let recorder = Arc::new(Recorder {
        inner,
        seen: Mutex::new(Vec::new()),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    });
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let sni = match target.tls {
        Tls::Web => target.host.clone(),
        Tls::Edge => crate::cloudflare::H2_SNI.to_string(),
        Tls::Masque => {
            config.alpn_protocols = vec![b"h2".to_vec()];
            crate::warp::register::MASQUE_SNI.to_string()
        }
    };
    let Ok(name) = ServerName::try_from(sni.clone()) else {
        return unknown(format!("the name {sni} is not a TLS name"));
    };
    let read = Arc::new(AtomicU64::new(0));
    let work = async {
        let io = crate::egress::dial(&target.host, target.port, None, timeout).await?;
        let io = Counting {
            inner: io,
            read: read.clone(),
        };
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, io)
            .await
            .map_err(anyhow::Error::from)
    };
    let result = tokio::time::timeout(timeout, work).await;
    let issuer = recorder
        .seen
        .lock()
        .ok()
        .and_then(|s| s.first().and_then(|c| issuer_of(c)));
    let got = read.load(Ordering::Relaxed);
    let carries_nothing = || TlsResult {
        verdict: Verdict::Refused,
        issuer: None,
        detail: format!(
            "the {} answers and carries nothing: no TLS byte came back",
            if crate::egress::proxy_for(&target.host, target.port).is_some() {
                "proxy"
            } else {
                "peer"
            }
        ),
    };
    match result {
        Ok(Ok(_)) => TlsResult {
            verdict: Verdict::Ok,
            detail: match (&issuer, target.tls) {
                (Some(i), Tls::Masque) => {
                    format!("issuer {i} (pinned per device; not judged here)")
                }
                (Some(i), _) => format!("issuer {i}; the chain is valid"),
                (None, _) => "the chain is valid".into(),
            },
            issuer,
        },
        Err(_) if got == 0 => carries_nothing(),
        Err(_) => unknown(format!(
            "the TLS handshake took more than {} ms",
            timeout.as_millis()
        )),
        Ok(Err(err)) => {
            let cert_fault = err.chain().any(|e| {
                e.downcast_ref::<std::io::Error>()
                    .and_then(|io| io.get_ref())
                    .and_then(|i| i.downcast_ref::<rustls::Error>())
                    .is_some_and(|r| matches!(r, rustls::Error::InvalidCertificate(_)))
            });
            if cert_fault {
                let who = issuer.clone().unwrap_or_else(|| "an unknown issuer".into());
                let hint = match target.tls {
                    Tls::Web => "a proxy terminates TLS: give its root with --ca-file",
                    _ => "a proxy terminates TLS: the edge legs cannot pass through it",
                };
                TlsResult {
                    verdict: Verdict::Refused,
                    issuer,
                    detail: format!("the certificate is issued by {who}, not by a root that cfrs expects; {hint}"),
                }
            } else if got == 0 {
                carries_nothing()
            } else {
                TlsResult {
                    verdict: Verdict::Unknown,
                    issuer,
                    detail: format!("{err:#}"),
                }
            }
        }
    }
}

/// What the proxy does with names and with addresses (the edge on 7844).
fn names(paths: &[Path]) -> Option<String> {
    let find = |id: &str| paths.iter().find(|p| p.target.id == id);
    let (name, address) = (find("edge-name")?, find("edge-address")?);
    name.via.as_ref()?;
    let text = match (name.verdict, address.verdict) {
        (Verdict::Ok, Verdict::Ok) => "the proxy carries names and IP addresses",
        (Verdict::Ok, Verdict::Refused) => {
            "the proxy allows names and refuses IP addresses; the edge legs dial addresses"
        }
        (Verdict::Refused, Verdict::Ok) => "the proxy refuses names and allows IP addresses",
        (Verdict::Refused, Verdict::Refused) => "the proxy refuses names and IP addresses on 7844",
        _ => "no answer for a name or an address on 7844",
    };
    Some(text.to_string())
}

fn legs(paths: &[Path], udp: &Egress) -> Vec<Leg> {
    let find = |id: &str| paths.iter().find(|p| p.target.id == id);
    let via_proxy = crate::egress::proxy_for(crate::tunnel::EDGE_REGION_NAME, 7844).is_some();
    let udp_off = crate::udp::Choice::from_env().ok() == Some(crate::udp::Choice::Off);
    let quic = if udp_off {
        Leg {
            name: "quic",
            verdict: Verdict::Refused,
            reason: "CFRS_UDP=off".into(),
        }
    } else if via_proxy {
        Leg {
            name: "quic",
            verdict: Verdict::Refused,
            reason: "a proxy is set, and no proxy carries UDP".into(),
        }
    } else {
        match udp {
            Egress::Answered(d) => Leg {
                name: "quic",
                verdict: Verdict::Ok,
                reason: format!("UDP 7844 answered: {d}"),
            },
            Egress::Refused(d) => Leg {
                name: "quic",
                verdict: Verdict::Refused,
                reason: format!("UDP 7844: {d}"),
            },
            Egress::Unknown(d) => Leg {
                name: "quic",
                verdict: Verdict::Unknown,
                reason: format!("UDP 7844: {d}"),
            },
        }
    };
    let leg = |name: &'static str, ids: &[&str]| {
        for id in ids {
            let Some(p) = find(id) else { continue };
            let (verdict, why) = p.usable();
            if verdict != Verdict::Ok {
                return Leg {
                    name,
                    verdict,
                    reason: format!("{}: {why}", p.target.authority()),
                };
            }
        }
        Leg {
            name,
            verdict: Verdict::Ok,
            reason: ids
                .iter()
                .filter_map(|id| find(id).map(|p| p.target.authority()))
                .collect::<Vec<_>>()
                .join(" and ")
                + ": TCP and TLS work",
        }
    };
    // The front door of IPv6 counts when the one of IPv4 does not work.
    let masque = match find("masque-v6") {
        Some(p)
            if p.usable().0 == Verdict::Ok
                && find("masque").is_none_or(|m| m.usable().0 != Verdict::Ok) =>
        {
            "masque-v6"
        }
        _ => "masque",
    };
    let mut legs = vec![
        quic,
        leg("http2", &["edge-address"]),
        leg("quic+warp", &[masque, "warp-api"]),
    ];
    if find("relay").is_some() {
        let mut relay = leg("http2+relay", &["relay"]);
        if relay.verdict == Verdict::Ok {
            relay.reason.push_str("; the relay protocol is not tried");
        }
        legs.push(relay);
    }
    legs
}

#[cfg(test)]
mod tests {
    use super::*;

    // Issue 180: a refused direct dial is an answer, not unknown.
    #[tokio::test]
    async fn a_direct_refusal_is_an_answer() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        let err = crate::egress::dial_addrs(&[addr], Duration::from_secs(5))
            .await
            .unwrap_err();
        match classify(&err, Duration::from_millis(1)) {
            Sample::Refused(_, why) => assert!(why.contains("connection refused"), "{why}"),
            other => panic!("not a refusal: {:?}", std::mem::discriminant(&other)),
        }
    }

    // Issue 128: the Date of an answer gives the skew of the clock.
    #[test]
    fn the_date_header_gives_the_skew() {
        assert_eq!(
            parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        let now = std::time::SystemTime::now();
        let unix = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        assert_eq!(
            parse_imf_fixdate(&crate::trust::imf_fixdate(now)),
            Some(unix)
        );
        assert_eq!(parse_imf_fixdate("yesterday"), None);
        assert_eq!(clock_of(1000, 990, "api").verdict, Verdict::Ok);
        let off = clock_of(4600, 1000, "api");
        assert_eq!((off.verdict, off.skew), (Verdict::Refused, Some(3600)));
        assert!(off.detail.contains("set the clock"));
    }

    fn path(id: &'static str, host: &str, port: u16, ok: bool) -> Path {
        Path {
            target: Target {
                id,
                host: host.into(),
                port,
                tls: Tls::Web,
            },
            via: None,
            verdict: if ok { Verdict::Ok } else { Verdict::Unknown },
            detail: if ok {
                "open".into()
            } else {
                "Network is unreachable".into()
            },
            sent: 1,
            answered: ok as usize,
            best: None,
            median: None,
            p95: None,
            jitter: None,
            tls: ok.then(|| TlsResult {
                verdict: Verdict::Ok,
                issuer: None,
                detail: "ok".into(),
            }),
            dns: None,
        }
    }

    // The IPv6-only kit: with no IPv4 route, the front door of IPv6 makes
    // the leg quic+warp work.
    #[test]
    fn the_ipv6_front_door_makes_quic_warp_work() {
        let udp = Egress::Unknown("x".into());
        let paths = vec![
            path("masque", MASQUE_ADDRESS, 443, false),
            path("masque-v6", MASQUE_ADDRESS_V6, 443, true),
            path("warp-api", "api.cloudflareclient.com", 443, true),
        ];
        let warp = legs(&paths, &udp)
            .into_iter()
            .find(|l| l.name == "quic+warp")
            .unwrap();
        assert_eq!(warp.verdict, Verdict::Ok, "{}", warp.reason);
        assert!(warp.reason.contains("2606:4700:103::2"), "{}", warp.reason);
        let paths = vec![
            path("masque", MASQUE_ADDRESS, 443, false),
            path("warp-api", "api.cloudflareclient.com", 443, true),
        ];
        let warp = legs(&paths, &udp)
            .into_iter()
            .find(|l| l.name == "quic+warp")
            .unwrap();
        assert_ne!(warp.verdict, Verdict::Ok);
    }

    // Issue 128: a road works when one of its legs works.
    #[test]
    fn the_roads_follow_the_legs() {
        let leg = |name, verdict| Leg {
            name,
            verdict,
            reason: "r".into(),
        };
        let report = Report {
            proxy: Value::Null,
            paths: Vec::new(),
            udp: ("1.2.3.4:7844".parse().unwrap(), Egress::Unknown("x".into())),
            names: None,
            legs: vec![
                leg("quic", Verdict::Refused),
                leg("http2", Verdict::Ok),
                leg("quic+warp", Verdict::Refused),
                leg("http2+relay", Verdict::Unknown),
            ],
            clock: Clock {
                verdict: Verdict::Unknown,
                skew: None,
                detail: String::new(),
            },
        };
        let roads = report.roads();
        assert_eq!(roads[0].0, "direct");
        assert_eq!(roads[0].1, Verdict::Ok);
        assert!(roads[0].2.starts_with("http2:"));
        assert_eq!((roads[1].0, roads[1].1), ("warp", Verdict::Refused));
        assert_eq!((roads[2].0, roads[2].1), ("relay", Verdict::Unknown));
        let json = report.to_json();
        assert_eq!(json["roads"][2]["road"], "relay");
        assert!(report.text().contains("roads\n  direct"));

        // E5: the last line names the step to take.
        assert!(report.text().ends_with(
            "next: cfrs tunnel --url http://localhost:8080 (the default legs work here)\n"
        ));
        assert_eq!(json["next"], report.next());
        let mut relay_only = report.clone();
        relay_only.legs = vec![
            leg("http2", Verdict::Refused),
            leg("http2+relay", Verdict::Ok),
        ];
        assert!(relay_only.next().contains("--transport relay"));
        let mut none = report.clone();
        none.legs = vec![leg("http2", Verdict::Refused)];
        assert!(none.next().contains("cfrs bug-report --doctor"));
        let mut clock = report.clone();
        clock.clock = clock_of(1000, 100, "api.example");
        assert!(clock.next().contains("set the clock"), "{}", clock.next());
    }

    #[test]
    fn the_statistics() {
        let ms = Duration::from_millis;
        let (best, median, p95, jitter) = stats(&[ms(10), ms(30), ms(20), ms(20)]);
        assert_eq!(best, Some(ms(10)));
        assert_eq!(median, Some(ms(20)));
        assert_eq!(p95, Some(ms(30)));
        // |30-10| + |20-30| + |20-20| = 30, over 3.
        assert_eq!(jitter, Some(ms(10)));
        assert_eq!(stats(&[]).0, None);
    }

    #[test]
    fn a_proxy_refusal_is_an_answer() {
        let err = anyhow::Error::new(crate::egress::Refusal {
            status: 403,
            text: "the proxy refused CONNECT with HTTP 403".into(),
        })
        .context("x through the proxy");
        assert!(
            matches!(classify(&err, Duration::ZERO), Sample::Refused(_, t) if t.starts_with("proxy 403"))
        );
        let lost = anyhow::anyhow!("connection reset by peer");
        assert!(matches!(classify(&lost, Duration::ZERO), Sample::Lost(_)));
    }
}
