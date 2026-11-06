//! The text of `podnet ps` and of `podnet warp forward --list`.

use super::Entry;

/// The forwards of the ready document `ready`. A string `forward` (issue
/// 203: the endpoint for `podnet connect`) is one item, as it is. An array
/// `forward` (`warp forward`) gives `LISTEN -> TO` for each item (T-073).
pub fn forwards(ready: Option<&serde_json::Value>) -> Vec<String> {
    let field = |item: &serde_json::Value, key: &str| match item.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "?".into(),
    };
    match ready.and_then(|d| d.get("forward")) {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|f| format!("{} -> {}", field(f, "listen"), field(f, "to")))
            .collect(),
        _ => Vec::new(),
    }
}

/// The table of `podnet ps` for `list`, at `now` (Unix seconds).
pub fn table(list: &[Entry], now: u64) -> String {
    if list.is_empty() {
        return "podnet: no detached instance\n".into();
    }
    let mut out =
        String::from("NAME                     STATE          PID RST     AGE  URL/LISTEN\n");
    for e in list {
        let r = &e.record;
        let at = r
            .ready
            .as_ref()
            .and_then(|d| d.get("url").or_else(|| d.get("listen")))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let age = now.saturating_sub(r.started);
        let age = if age >= 3600 {
            format!("{}h{:02}m", age / 3600, age % 3600 / 60)
        } else {
            format!("{}m{:02}s", age / 60, age % 60)
        };
        out.push_str(&format!(
            "{:<24} {:<9} {:>8} {:>3} {:>7}  {}\n",
            r.name, r.state, r.pid, r.restarts, age, at
        ));
        // Issue 203 and T-073: each forward on its own line.
        for forward in forwards(r.ready.as_ref()) {
            out.push_str(&format!("{:<24} forward {forward}\n", ""));
        }
    }
    out
}

/// The text of `warp forward --list`: one line `NAME  LISTEN -> TO` for
/// each forward of an instance whose ready document has an array
/// `forward`, else a line that tells that no forward runs.
pub fn forward_list(list: &[Entry]) -> String {
    let mut out = String::new();
    for e in list {
        let ready = e.record.ready.as_ref();
        if ready
            .and_then(|d| d.get("forward"))
            .is_some_and(|f| f.is_array())
        {
            for forward in forwards(ready) {
                out.push_str(&format!("{}  {forward}\n", e.record.name));
            }
        }
    }
    if out.is_empty() {
        out.push_str("podnet: no forward runs (podnet warp forward --detach)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, ready: serde_json::Value) -> Entry {
        Entry {
            record: super::super::Record {
                name: name.into(),
                state: "ready".into(),
                ready: Some(ready),
                ..Default::default()
            },
            alive: true,
        }
    }

    /// T-073: an array `forward` gives one row for each item; a string
    /// `forward` (issue 203) stays one row.
    #[test]
    fn each_forward_has_a_row() {
        let list = [
            entry(
                "fw",
                serde_json::json!({ "forward": [
                    { "listen": "tcp://127.0.0.1:1", "to": "a.example:22" },
                    { "listen": "tcp://127.0.0.1:2", "to": "b.example:80" },
                ]}),
            ),
            entry("c", serde_json::json!({ "forward": "ws://h/__podnet/ws" })),
        ];
        let table = table(&list, 0);
        for row in [
            "forward tcp://127.0.0.1:1 -> a.example:22",
            "forward tcp://127.0.0.1:2 -> b.example:80",
            "forward ws://h/__podnet/ws",
        ] {
            assert!(table.contains(row), "{table}");
        }
        assert_eq!(
            forward_list(&list),
            "fw  tcp://127.0.0.1:1 -> a.example:22\nfw  tcp://127.0.0.1:2 -> b.example:80\n"
        );
        assert!(forward_list(&list[1..]).starts_with("podnet: no forward runs"));
    }
}
