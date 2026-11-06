//! The data path of a WARP session in the record of its instance (T-140).
//!
//! `warp status` and `podnet status` run in another process than `warp
//! proxy`: they read the record of the instance. The first [`Live`] of a
//! process writes its [`Report`] (`data_path` and `last_probe`) in the ready
//! document of that record on each change: after each TCP probe, and when a
//! new session opens. The ready document of `warp proxy` (and so of `warp
//! up`) has the two keys from the start.

use std::path::Path;
use std::sync::OnceLock;

use serde_json::{json, Value};
use tokio::sync::watch;

use super::{Closable, Live, Report};
use crate::instances::{self, Record};

/// The report of the first [`Live`] of this process: the session of `warp
/// proxy`, before the sessions of `--listen-identity`.
static OWN: OnceLock<watch::Receiver<Report>> = OnceLock::new();

/// Write the report of `live` in the record of this instance on each change.
/// Only the first [`Live`] of a process does it. In a process that is not an
/// instance, the record stays as it is.
pub fn publish_own<T: Closable>(live: &Live<T>) {
    if OWN.set(live.report()).is_err() {
        return;
    }
    publish(live, |report| {
        crate::detach::update_record(|record| amend(record, report))
    });
}

/// Give each new report of `live` to `sink`, until `live` ends.
pub fn publish<T: Closable>(live: &Live<T>, sink: impl Fn(Report) + Send + 'static) {
    let mut changes = live.report();
    tokio::spawn(async move {
        while changes.changed().await.is_ok() {
            let report = *changes.borrow_and_update();
            sink(report);
        }
    });
}

fn insert(doc: &mut serde_json::Map<String, Value>, report: Report) {
    doc.insert("data_path".into(), report.data_path.into());
    doc.insert("last_probe".into(), report.last_probe.into());
}

/// Write `report` in the ready document of `record`. A record with no ready
/// document stays as it is.
pub fn amend(record: &mut Record, report: Report) {
    if let Some(doc) = record.ready.as_mut().and_then(Value::as_object_mut) {
        insert(doc, report);
    }
}

/// `doc` (a ready document) with the data path of the session of this
/// process, when it has one.
pub fn with_data_path(mut doc: Value) -> Value {
    if let (Some(own), Some(map)) = (OWN.get(), doc.as_object_mut()) {
        insert(map, *own.borrow());
    }
    doc
}

/// The state of the instance of `podnet warp up` (issue 116): for `warp
/// status`.
pub fn instance_state() -> Value {
    // Issue 178: a read makes no directory.
    match instances::existing_run_dir() {
        Some(dir) => instance_state_in(&dir, crate::warp::up::INSTANCE),
        None => json!({"running": false}),
    }
}

/// [`instance_state`] of the instance `name` in `dir`.
pub fn instance_state_in(dir: &Path, name: &str) -> Value {
    match instances::read(dir, name) {
        Some(record) if instances::is_alive(dir, name) => {
            let ready = |key: &str| record.ready.as_ref().and_then(|d| d.get(key)).cloned();
            json!({
                "running": true,
                "pid": record.pid,
                "state": record.state,
                "started": record.started,
                "restarts": record.restarts,
                "listens": ready("listens"),
                "data_path": ready("data_path"),
                "last_probe": ready("last_probe"),
            })
        }
        _ => json!({"running": false}),
    }
}

/// The line of [`instance_state`] for `warp status`.
pub fn instance_line(state: &Value) -> String {
    instance_line_at(state, instances::now())
}

/// [`instance_line`] at the Unix time `now`.
fn instance_line_at(state: &Value, now: u64) -> String {
    if state["running"] != true {
        return "not running (podnet warp up starts it)".into();
    }
    let listens: Vec<&str> = state["listens"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let mut line = format!(
        "{}, pid {}, restarts {}, listens {}",
        state["state"].as_str().unwrap_or("?"),
        state["pid"],
        state["restarts"],
        if listens.is_empty() {
            "-".into()
        } else {
            listens.join(" ")
        }
    );
    if let Some(path) = state["data_path"].as_str() {
        let probe = match state["last_probe"].as_u64() {
            Some(at) => format!("{} s ago", now.saturating_sub(at)),
            None => "-".into(),
        };
        line.push_str(&format!(", data path {path}, last probe {probe}"));
    }
    line
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::warp::live::{Connect, ProbeFuture, DEFAULT_PROBE};

    // Issue 116: warp status shows the instance of warp up; T-140: with
    // the data path.
    #[test]
    fn the_instance_line() {
        assert!(instance_line(&json!({"running": false})).starts_with("not running"));
        let mut state = json!({
            "running": true, "pid": 42, "state": "ready", "restarts": 0,
            "listens": ["tcp://127.0.0.1:40000", "unix:/r/warp.sock"],
        });
        assert_eq!(
            instance_line(&state),
            "ready, pid 42, restarts 0, listens tcp://127.0.0.1:40000 unix:/r/warp.sock"
        );
        state["data_path"] = "tcp-dead".into();
        state["last_probe"] = 1000.into();
        assert!(instance_line_at(&state, 1012)
            .ends_with("unix:/r/warp.sock, data path tcp-dead, last probe 12 s ago"));
        state["last_probe"] = Value::Null;
        assert!(instance_line_at(&state, 1012).ends_with(", data path tcp-dead, last probe -"));
    }

    /// A session whose TCP probe fails when `tcp` is false.
    struct Fake {
        tcp: bool,
        closed: AtomicBool,
    }

    impl Closable for Fake {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn close(&self, _why: &str) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn probe_tcp(&self, _target: std::net::SocketAddr, _limit: Duration) -> ProbeFuture<'_> {
            let tcp = self.tcp;
            Box::pin(async move { tcp })
        }
    }

    /// T-140: the record of the instance, and so `warp status`, names the
    /// data path: `tcp-dead` after the failed probes, `ok` after the new
    /// session, with the time of the last probe.
    #[tokio::test(start_paused = true)]
    async fn warp_status_names_the_data_path() {
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().to_path_buf();
        let paths = instances::paths(&at, "warp").unwrap();
        let _held = instances::lock(&paths.lock).unwrap();
        let record = Record {
            name: "warp".into(),
            pid: 1,
            state: "ready".into(),
            ready: Some(json!({"listens": ["unix:/r/warp.sock"]})),
            ..Default::default()
        };
        instances::write(&at, &record).unwrap();
        // The new session opens only when the test allows it.
        let allow = Arc::new(AtomicBool::new(false));
        let connect: Connect<Fake> = {
            let allow = allow.clone();
            Box::new(move || {
                let allow = allow.clone();
                Box::pin(async move {
                    if !allow.load(Ordering::SeqCst) {
                        anyhow::bail!("the front door does not answer");
                    }
                    Ok(Fake {
                        tcp: true,
                        closed: AtomicBool::new(false),
                    })
                })
            })
        };
        let first = Fake {
            tcp: false,
            closed: AtomicBool::new(false),
        };
        let live = Live::start_with(
            first,
            connect,
            Duration::from_millis(50),
            Duration::from_millis(200),
        )
        .probed(Some(DEFAULT_PROBE));
        let sink_dir = at.clone();
        publish(&live, move |report| {
            let mut record = instances::read(&sink_dir, "warp").unwrap();
            amend(&mut record, report);
            instances::write(&sink_dir, &record).unwrap();
        });
        let started = instances::now();
        // One failed probe: the data path is still ok.
        tokio::time::sleep(DEFAULT_PROBE.every + Duration::from_secs(1)).await;
        let state = instance_state_in(&at, "warp");
        assert_eq!(state["data_path"], "ok", "{state}");
        assert!(state["last_probe"].as_u64().unwrap() >= started, "{state}");
        // The third failed probe: tcp-dead, while no new session opens.
        tokio::time::sleep(DEFAULT_PROBE.every * 2).await;
        let state = instance_state_in(&at, "warp");
        assert_eq!(state["data_path"], "tcp-dead", "{state}");
        assert!(instance_line(&state).contains("data path tcp-dead, last probe"));
        // The new session: ok.
        allow.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(live.reconnects(), 1);
        let state = instance_state_in(&at, "warp");
        assert_eq!(state["data_path"], "ok", "{state}");
        assert_eq!(state["listens"][0], "unix:/r/warp.sock", "{state}");
    }

    /// T-140: the ready document of `warp proxy` has the two keys.
    #[tokio::test]
    async fn the_ready_document_names_the_data_path() {
        let connect: Connect<Fake> = Box::new(|| Box::pin(async { anyhow::bail!("no session") }));
        let first = Fake {
            tcp: true,
            closed: AtomicBool::new(false),
        };
        let live = Live::start_with(
            first,
            connect,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        publish_own(&live);
        let doc = with_data_path(json!({"listen": "unix:/r/warp.sock"}));
        assert_eq!(doc["data_path"], "ok", "{doc}");
        assert!(doc.get("last_probe").is_some(), "{doc}");
        assert_eq!(doc["listen"], "unix:/r/warp.sock");
    }
}
