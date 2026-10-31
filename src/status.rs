//! `cfrs status`: one line of JSON about this host, for a program to read
//! before anything else. It opens no connection, asks no DNS, starts no
//! process and writes nothing. It never shows a credential: the proxy is
//! shown as its variable, host, port and kind, and the WARP identity as its
//! path and device id.

use serde_json::{json, Value};

/// The variables of the proxy, in the order that cfrs reads them.
const PROXY_VARIABLES: &[&str] = &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];

fn proxy() -> Value {
    for key in PROXY_VARIABLES {
        let Ok(value) = std::env::var(key) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        return match crate::egress::Proxy::parse(&value) {
            Ok(p) => json!({
                "variable": key,
                "address": format!("{}:{}", p.address().0, p.address().1),
                "kind": "http",
                "credentials": p.has_credentials(),
            }),
            Err(err) => json!({ "variable": key, "error": err.to_string() }),
        };
    }
    Value::Null
}

fn edge_override() -> Value {
    match std::env::var("CFRS_EDGE") {
        Ok(list) if !list.trim().is_empty() => {
            let items: Vec<&str> = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            let bad: Vec<&&str> = items
                .iter()
                .filter(|i| i.parse::<std::net::SocketAddr>().is_err())
                .collect();
            json!({ "addresses": items, "valid": bad.is_empty() })
        }
        _ => Value::Null,
    }
}

fn warp_identity() -> Value {
    let path = crate::warp::WarpClient::default_identity_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return json!({ "path": path, "exists": path.exists() });
    };
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    json!({
        "path": path,
        "exists": true,
        "device": parsed["device"]["id"],
        "tunnel_type": parsed["device"]["tunnel_type"],
    })
}

fn tty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// The status of this host.
pub fn document() -> Value {
    json!({
        "schema": 1,
        "cfrs": concat!(env!("CARGO_PKG_VERSION"), " (", env!("CFRS_BUILD_COMMIT"), ")"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "proxy": proxy(),
        "edge_override": edge_override(),
        "warp_identity": warp_identity(),
        "tls_roots": match crate::trust::roots() {
            Ok(roots) => json!(roots.sources),
            Err(err) => json!({"error": format!("{err:#}")}),
        },
        "error_program": std::env::var(crate::report::PROGRAM_VARIABLE).ok().filter(|v| !v.is_empty()),
        "stdin_tty": tty(0),
        "stdout_tty": tty(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_has_its_fields_and_no_credentials() {
        let doc = document();
        assert_eq!(doc["schema"], 1);
        for key in ["cfrs", "os", "arch", "proxy", "warp_identity", "stdin_tty"] {
            assert!(doc.get(key).is_some(), "{key}");
        }
        let text = doc.to_string();
        for key in PROXY_VARIABLES {
            if let Ok(v) = std::env::var(key) {
                if v.contains('@') {
                    assert!(
                        !text.contains(&v),
                        "the proxy URL with credentials is shown"
                    );
                }
            }
        }
    }
}
