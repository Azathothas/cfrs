//! The stop signals of the commands (SIGINT, SIGTERM, SIGHUP) and the waits
//! that end at a stop signal or at the end of `--run-for`.

use std::time::Duration;

/// The stop request: false until SIGINT, SIGTERM or SIGHUP comes.
static STOP: std::sync::OnceLock<tokio::sync::watch::Receiver<bool>> = std::sync::OnceLock::new();

/// Whether the action of `signal` is SIG_IGN (`nohup` gives it for SIGHUP).
fn signal_ignored(signal: libc::c_int) -> bool {
    // SAFETY: sigaction() with no new action only reads the old action.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(signal, std::ptr::null(), &mut old) == 0
            && old.sa_sigaction == libc::SIG_IGN
    }
}

/// At the start of the runtime: take SIGINT, SIGTERM and SIGHUP (issue
/// 91). After the ready of a command (or its first wait), each is in the
/// stop request, also when it comes between two waits. Before, and in a
/// command that does not wait, each has the default action. A second
/// signal during the shutdown also has the default action. SIGHUP stays ignored in a detached instance
/// and when the parent ignored it (`nohup`).
pub(crate) fn install_signals() {
    use tokio::signal::unix::{signal, SignalKind};
    STOP.get_or_init(|| {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut kinds = vec![
            (SignalKind::interrupt(), libc::SIGINT, "SIGINT"),
            (SignalKind::terminate(), libc::SIGTERM, "SIGTERM"),
        ];
        if !podnet::detach::is_child() && !signal_ignored(libc::SIGHUP) {
            kinds.push((SignalKind::hangup(), libc::SIGHUP, "SIGHUP"));
        }
        let tx = std::sync::Arc::new(tx);
        for (kind, number, name) in kinds {
            match signal(kind) {
                Ok(mut stream) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        while stream.recv().await.is_some() {
                            // No command waits, or the second signal
                            // during the shutdown: the default action.
                            if !podnet::detach::stop_armed() || *tx.borrow() {
                                // SAFETY: signal() and raise() with a
                                // valid signal number.
                                unsafe {
                                    libc::signal(number, libc::SIG_DFL);
                                    libc::raise(number);
                                    // Issue 208: PID 1 of a namespace (a
                                    // container with no init) drops a
                                    // signal with the default action, and
                                    // raise returns. Exit as a shell does.
                                    libc::_exit(128 + number);
                                }
                            }
                            if number == libc::SIGINT {
                                tracing::info!("Ctrl-C: stopping");
                            } else {
                                tracing::info!("{name}: stopping");
                            }
                            let _ = tx.send(true);
                        }
                    });
                }
                Err(err) => tracing::warn!("{name}: cannot take the signal ({err})"),
            }
        }
        rx
    });
}

/// Ready on SIGINT (Ctrl-C), SIGTERM (systemd, Docker, Kubernetes, podnet
/// stop) or SIGHUP (the terminal closed): each starts the same clean
/// shutdown, and the exit code is 0. A detached instance ignores SIGHUP.
/// A signal that came before this call is not lost.
pub(crate) async fn shutdown_signal() -> std::io::Result<()> {
    install_signals();
    podnet::detach::arm_stop();
    let mut rx = STOP.get().expect("installed").clone();
    let _ = rx.wait_for(|stop| *stop).await;
    Ok(())
}

/// Ready after `run_for` seconds (when given), or on a stop signal. The end
/// of `run_for` is a planned end (issue 195).
pub(crate) async fn sleep_or_signal(run_for: Option<u64>) {
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => podnet::detach::planned_end(),
                _ = shutdown_signal() => {}
            }
        }
        None => {
            let _ = shutdown_signal().await;
        }
    }
}

/// The deadline of `--run-for` from now (issue 179).
pub(crate) fn deadline_of(run_for: Option<u64>) -> Option<tokio::time::Instant> {
    run_for.map(|s| tokio::time::Instant::now() + Duration::from_secs(s))
}

/// Ready at `deadline`, never with none.
pub(crate) async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// `Some(out)` when `work` ends; `None` when a stop signal comes first
/// (issue 101: the verify after the ready line can be stopped cleanly), or
/// at `deadline` (issue 179: `--run-for` during the verify; a planned end).
pub(crate) async fn until_stop_or<T>(
    deadline: Option<tokio::time::Instant>,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = shutdown_signal() => None,
        _ = sleep_until_opt(deadline) => {
            podnet::detach::planned_end();
            None
        }
        out = work => Some(out),
    }
}
