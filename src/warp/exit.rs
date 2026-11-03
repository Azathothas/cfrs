//! The exit of a WARP session (issue 147): the colo, the country and the
//! address that a destination sees, from `/cdn-cgi/trace` of 1.1.1.1
//! through the tunnel. The request goes to an address, so no DNS step comes
//! first.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};

/// The target of the trace: plain HTTP on an address of Cloudflare.
pub const TRACE_TARGET: &str = "1.1.1.1:80";
/// The time limit of the trace.
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(10);
/// The most bytes of the answer.
const MAX_ANSWER: usize = 16 * 1024;

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
    let target: SocketAddr = TRACE_TARGET.parse().expect("an address");
    let start = Instant::now();
    let work = async {
        let conn = stack.tcp_connect(target).await?;
        let request = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: cfrs\r\nConnection: close\r\n\r\n";
        conn.send(request.to_vec()).await?;
        let mut answer = Vec::new();
        loop {
            let data = conn.recv(4096).await?;
            if data.is_empty() || answer.len() > MAX_ANSWER {
                break;
            }
            answer.extend_from_slice(&data);
            if answer.windows(4).any(|w| w == b"\r\n\r\n") && answer.ends_with(b"\n") {
                let text = String::from_utf8_lossy(&answer);
                if text.contains("\nwarp=") || text.contains("\nkex=") {
                    break;
                }
            }
        }
        conn.close().await;
        anyhow::Ok(answer)
    };
    let answer = tokio::time::timeout(TRACE_TIMEOUT, work)
        .await
        .map_err(|_| anyhow::anyhow!("no trace in {} s", TRACE_TIMEOUT.as_secs()))??;
    let text = String::from_utf8_lossy(&answer);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .context("the trace answer has no body")?;
    match parse(body, start.elapsed()) {
        Some(exit) => Ok(exit),
        None => bail!("the trace answer has no colo"),
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
