//! The path decisions of this process (issue 137), counted by decision and
//! outcome: `podnet_decisions_total{decision="dns",outcome="doh"}`.
//!
//! | decision | outcomes |
//! |---|---|
//! | `dns` | `ip`, `pin`, `system`, `doh`, `fail` |
//! | `egress` | `direct` (`--no-proxy`), `no_proxy` (a `NO_PROXY` match), `none` (no proxy is set), `via` (given by the caller), `http`, `socks5`, `unix`, `exec` |
//! | `dispatch` | `socks_connect`, `udp_associate`, `udp_in_stream`, `socks_unsupported`, `http_connect`, `http_forward`, `tls_client` |
//! | `rule` | `tunnel`, `direct`, `reject` |
//! | `masque` | `direct`, `relay`, `relay_first`, `no_relay` |
//! | `leg` | the leg that won the race (`quic`, `http2`, `quic+warp`, ...) |

use std::collections::BTreeMap;
use std::sync::Mutex;

static COUNTS: Mutex<BTreeMap<(&'static str, String), u64>> = Mutex::new(BTreeMap::new());

/// Count one decision.
pub fn count(decision: &'static str, outcome: &str) {
    let mut counts = COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    match counts.get_mut(&(decision, outcome.to_string())) {
        Some(n) => *n += 1,
        None => {
            counts.insert((decision, outcome.to_string()), 1);
        }
    }
}

/// The count of one decision and outcome.
pub fn get(decision: &'static str, outcome: &str) -> u64 {
    COUNTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(decision, outcome.to_string()))
        .copied()
        .unwrap_or(0)
}

/// The Prometheus text of the counters (empty with no decision).
pub fn prometheus() -> String {
    let counts = COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    if counts.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "# HELP podnet_decisions_total The path decisions of this process.\n\
         # TYPE podnet_decisions_total counter\n",
    );
    for ((decision, outcome), n) in counts.iter() {
        out.push_str(&format!(
            "podnet_decisions_total{{decision=\"{decision}\",outcome=\"{}\"}} {n}\n",
            label(outcome)
        ));
    }
    out
}

/// The counters on one line, for a health line: `dns.system=3 egress.none=2`.
pub fn summary() -> String {
    let counts = COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    counts
        .iter()
        .map(|((decision, outcome), n)| format!("{decision}.{outcome}={n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A label value of the Prometheus text: `\`, `"` and a new line escaped.
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_are_counted_with_labels() {
        let before = get("test", "a\"b");
        count("test", "a\"b");
        count("test", "a\"b");
        count("test", "other");
        assert_eq!(get("test", "a\"b"), before + 2);
        let text = prometheus();
        assert!(text.contains("# TYPE podnet_decisions_total counter\n"));
        assert!(text.contains(&format!(
            "podnet_decisions_total{{decision=\"test\",outcome=\"a\\\"b\"}} {}\n",
            before + 2
        )));
        assert!(summary().contains("test.other="));
        assert!(text.lines().all(|l| l.starts_with('#') || l.contains("} ")));
    }
}
