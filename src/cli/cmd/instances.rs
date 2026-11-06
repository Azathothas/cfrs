//! The commands of the detached instances: `ps`, `stop`, `logs` and `wait`.

use anyhow::Result;

use podnet::exit::Fault;

use crate::cli::signals::shutdown_signal;

/// `podnet ps`: the instances of the run directory.
pub(crate) fn instances_ps(json: bool) -> Result<()> {
    let dir = podnet::instances::lookup_dir();
    podnet::instances::prune(&dir);
    let list = podnet::instances::list(&dir);
    if json {
        let items: Vec<serde_json::Value> = list
            .iter()
            .map(|e| {
                let r = &e.record;
                serde_json::json!({
                    "name": r.name,
                    "state": r.state,
                    "pid": r.pid,
                    "supervisor": r.supervisor,
                    "command": r.command,
                    "args": r.args,
                    "cwd": r.cwd,
                    "started": r.started,
                    "restarts": r.restarts,
                    "log": r.log,
                    "ready": r.ready,
                })
            })
            .collect();
        println!(
            "{}",
            podnet::status::stamped(serde_json::json!({
                "instances": items,
                "dir": dir.display().to_string(),
            }))
        );
        return Ok(());
    }
    let now = podnet::instances::now();
    print!("{}", podnet::instances::text::table(&list, now));
    Ok(())
}

/// `podnet stop`.
pub(crate) fn instances_stop(name: Option<String>, all: bool, timeout: u64) -> Result<()> {
    let dir = podnet::instances::lookup_dir();
    let names: Vec<String> = if all {
        podnet::instances::list(&dir)
            .into_iter()
            .map(|e| e.record.name)
            .collect()
    } else {
        let name = name.unwrap_or_default();
        podnet::instances::check_name(&name).map_err(|e| podnet::exit::fault(Fault::Usage, e))?;
        let alive = podnet::instances::is_alive(&dir, &name);
        if alive && podnet::instances::read(&dir, &name).is_none() {
            // Issue 264: the locks of a live instance stay.
            return Err(podnet::detach::unreadable(&dir, &name));
        }
        if !alive {
            podnet::instances::remove(&dir, &name);
            return Err(podnet::exit::fault(
                Fault::Unavailable,
                anyhow::anyhow!("no instance {name} runs (podnet ps)"),
            ));
        }
        vec![name]
    };
    let mut failed = None;
    for name in names {
        match podnet::detach::stop(&dir, &name, std::time::Duration::from_secs(timeout)) {
            Ok(()) => println!("podnet: stopped  {name}"),
            // --all: one instance that cannot stop does not keep the
            // others running.
            Err(err) if all => {
                eprintln!("podnet: stop {name}: {err:#}");
                failed = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    match failed {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// `podnet logs`.
pub(crate) async fn instances_logs(name: &str, follow: bool, lines: Option<usize>) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let dir = podnet::instances::lookup_dir();
    let path = podnet::instances::paths(&dir, name)
        .map_err(|e| podnet::exit::fault(Fault::Usage, e))?
        .log;
    let text = std::fs::read(&path).map_err(|e| {
        podnet::exit::fault(
            Fault::Unavailable,
            anyhow::anyhow!("no log of {name} at {}: {e}", path.display()),
        )
    })?;
    let shown: Vec<u8> = match lines {
        Some(n) => {
            let all: Vec<&[u8]> = text.split_inclusive(|b| *b == b'\n').collect();
            all[all.len().saturating_sub(n)..].concat()
        }
        None => text.clone(),
    };
    {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let _ = out.write_all(&shown);
        let _ = out.flush();
    }
    if !follow {
        return Ok(());
    }
    // Follow: read what comes after the end; a log that became shorter was
    // rotated (cut to 0), so read it from its start.
    let mut offset = text.len() as u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            _ = shutdown_signal() => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
        }
        let Ok(mut file) = tokio::fs::File::open(&path).await else {
            continue;
        };
        let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
        }
        if len == offset {
            continue;
        }
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            offset += n as u64;
            use std::io::Write as _;
            let mut out = std::io::stdout();
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
        }
    }
}

/// `podnet wait`.
pub(crate) fn instances_wait(name: &str, timeout: u64) -> Result<()> {
    podnet::instances::check_name(name).map_err(|e| podnet::exit::fault(Fault::Usage, e))?;
    let dir = podnet::instances::lookup_dir();
    let doc =
        podnet::detach::wait_ready_record(&dir, name, std::time::Duration::from_secs(timeout))?;
    println!("{doc}");
    Ok(())
}
