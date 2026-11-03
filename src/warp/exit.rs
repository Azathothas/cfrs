//! The exit of a WARP session (issue 147): the colo, the country and the
//! address that a destination sees, from `/cdn-cgi/trace` of 1.1.1.1
//! through the tunnel, over HTTPS (plain HTTP on port 80 gave no trace in
//! live run 41599321447). The request goes to an address, so no DNS step
//! comes first. The certificate must have the name `one.one.one.one`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The address of the trace.
pub const TRACE_ADDRESS: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
/// The name of the trace (the certificate and the Host header).
pub const TRACE_NAME: &str = "one.one.one.one";
/// The time limit of the trace.
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(15);
/// The most bytes of the answer.
const MAX_ANSWER: u64 = 16 * 1024;

/// The exit of a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    /// The data center (IATA code), as `AMS`.
    pub colo: String,
    /// The country (ISO 3166), as `NL`.
    pub loc: Option<String>,
    /// The address that the destination saw.
    pub ip: Option<String>,
    /// `on` or `plus` through WARP.
    pub warp: Option<String>,
    /// The time of the request.
    pub rtt: Duration,
}

impl Exit {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "colo": self.colo,
            "loc": self.loc,
            "ip": self.ip,
            "warp": self.warp,
            "rtt_ms": self.rtt.as_millis() as u64,
        })
    }
}

/// The exit of the body of a trace (`key=value` lines). `None` with no
/// colo of 3 capital letters.
pub fn parse(body: &str, rtt: Duration) -> Option<Exit> {
    let get = |key: &str| {
        body.lines().find_map(|l| {
            l.strip_prefix(key)
                .and_then(|r| r.strip_prefix('='))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
    };
    let colo = get("colo")?;
    if colo.len() != 3 || !colo.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    Some(Exit {
        colo,
        loc: get("loc"),
        ip: get("ip"),
        warp: get("warp"),
        rtt,
    })
}

/// The exit of the session of `stack`.
pub async fn trace(stack: &super::WarpStack) -> Result<Exit> {
    let start = Instant::now();
    let work = async {
        let stream = super::proxy::dial(
            Arc::new(stack.clone()),
            pod_netns::socks::ProxyHost::Ip(TRACE_ADDRESS),
            443,
        )
        .await?;
        let config = crate::trust::client_config(&[], &[b"http/1.1"])?;
        let name = rustls::pki_types::ServerName::try_from(TRACE_NAME).expect("a name");
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .context("TLS with 1.1.1.1 through WARP")?;
        // HTTP/1.0: the body is not chunked, and ends with the connection.
        let request = format!(
            "GET /cdn-cgi/trace HTTP/1.0\r\nHost: {TRACE_NAME}\r\nUser-Agent: cfrs\r\n\r\n"
        );
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;
        let mut answer = Vec::new();
        // A server that closes with no close_notify is an error of rustls;
        // the bytes before it count.
        let _ = (&mut tls).take(MAX_ANSWER).read_to_end(&mut answer).await;
        anyhow::Ok(answer)
    };
    let answer = tokio::time::timeout(TRACE_TIMEOUT, work)
        .await
        .map_err(|_| anyhow::anyhow!("no trace in {} s", TRACE_TIMEOUT.as_secs()))??;
    let text = String::from_utf8_lossy(&answer);
    let status = text.lines().next().unwrap_or("").trim().to_string();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .with_context(|| format!("the trace answer has no body ({status:?})"))?;
    match parse(body, start.elapsed()) {
        Some(exit) => Ok(exit),
        None => bail!(
            "the trace answer has no colo ({status:?}, {} bytes)",
            answer.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trace_body_gives_the_exit() {
        let body = "fl=12f\nh=1.1.1.1\nip=2a09:bac1::7\nts=1.2\nvisit_scheme=http\ncolo=AMS\nsliver=none\nhttp=http/1.1\nloc=NL\ntls=off\nsni=off\nwarp=on\ngateway=off\n";
        let exit = parse(body, Duration::from_millis(42)).unwrap();
        assert_eq!(exit.colo, "AMS");
        assert_eq!(exit.loc.as_deref(), Some("NL"));
        assert_eq!(exit.warp.as_deref(), Some("on"));
        assert_eq!(exit.ip.as_deref(), Some("2a09:bac1::7"));
        assert_eq!(exit.to_json()["rtt_ms"], 42);
        assert!(parse("loc=NL\n", Duration::ZERO).is_none());
        assert!(parse("colo=amsterdam\n", Duration::ZERO).is_none());
        assert!(parse("colo=\n", Duration::ZERO).is_none());
    }
}
