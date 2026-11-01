//! Run attempts in a staggered race: start attempt 0; start the next one
//! when the one before has not completed after the stagger, or at once when
//! it fails. The first attempt that succeeds wins. When more attempts
//! succeed in the same turn, the earliest one wins. Each other attempt that
//! succeeded is given to `close`, so that no second registration stays on
//! the tunnel; the attempts that still run are cancelled.
//!
//! With no stagger, the attempts run one after the other (serial).

use std::time::Duration;
use tokio::time::Instant;

use anyhow::Error;
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;

/// The way to start the next attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failover {
    /// Start the next attempt after `stagger`, or at once on a failure.
    Staggered(Duration),
    /// Start the next attempt only after the one before failed.
    Serial,
}

/// The default stagger between two edge legs.
pub const LEG_STAGGER: Duration = Duration::from_secs(2);

impl Failover {
    /// Parse `staggered` or `serial`.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "staggered" | "" => Ok(Self::Staggered(LEG_STAGGER)),
            "serial" => Ok(Self::Serial),
            other => anyhow::bail!("the failover mode {other:?} is not staggered or serial"),
        }
    }
}

/// The result of a race.
pub struct Won<T> {
    /// The index of the attempt that won.
    pub index: usize,
    pub value: T,
    /// The time from the start of the race to the win.
    pub after: Duration,
    /// The failures of the other attempts, by index.
    pub failures: Vec<(usize, Error)>,
}

/// Run `attempts` as [`Failover`] says. On success, the other successes go
/// to `close`. On failure, each failure is given, by index.
pub async fn race<'a, 'c, T: Send + 'a>(
    attempts: Vec<BoxFuture<'a, anyhow::Result<T>>>,
    failover: Failover,
    close: impl Fn(usize, T) -> BoxFuture<'c, ()>,
) -> Result<Won<T>, Vec<(usize, Error)>> {
    let start = Instant::now();
    let total = attempts.len();
    let mut queue = attempts.into_iter().enumerate();
    let mut running = FuturesUnordered::new();
    let mut failures = Vec::new();
    let launch = |running: &mut FuturesUnordered<_>, queue: &mut std::iter::Enumerate<_>| {
        if let Some((i, attempt)) = Iterator::next(queue) {
            tracing::debug!(attempt = i, after = ?start.elapsed(), "starting an attempt");
            let attempt: BoxFuture<'a, anyhow::Result<T>> = attempt;
            running.push(attempt.map(move |r| (i, r)));
            true
        } else {
            false
        }
    };
    launch(&mut running, &mut queue);
    let mut launched = 1.min(total);
    loop {
        if running.is_empty() {
            if launched >= total {
                failures.sort_by_key(|(i, _)| *i);
                return Err(failures);
            }
            launch(&mut running, &mut queue);
            launched += 1;
            continue;
        }
        let stagger = match failover {
            Failover::Staggered(d) if launched < total => Some(d),
            _ => None,
        };
        let next = match stagger {
            Some(d) => tokio::select! {
                biased;
                done = running.next() => done,
                _ = tokio::time::sleep(d) => {
                    launch(&mut running, &mut queue);
                    launched += 1;
                    continue;
                }
            },
            None => running.next().await,
        };
        let Some((index, result)) = next else {
            continue;
        };
        match result {
            Err(err) => {
                tracing::debug!(attempt = index, error = %format!("{err:#}"), "an attempt failed");
                failures.push((index, err));
                // A failure starts the next attempt at once.
                if launched < total {
                    launch(&mut running, &mut queue);
                    launched += 1;
                }
            }
            Ok(value) => {
                // Other attempts that are ready in this turn: the earliest wins.
                let mut ready = vec![(index, value)];
                while let Some(Some((i, r))) = running.next().now_or_never() {
                    match r {
                        Ok(v) => ready.push((i, v)),
                        Err(e) => failures.push((i, e)),
                    }
                }
                ready.sort_by_key(|(i, _)| *i);
                let mut ready = ready.into_iter();
                let (index, value) = ready.next().expect("one value");
                drop(running);
                for (i, loser) in ready {
                    tracing::debug!(attempt = i, "closing an attempt that also succeeded");
                    close(i, loser).await;
                }
                failures.sort_by_key(|(i, _)| *i);
                return Ok(Won {
                    index,
                    value,
                    after: start.elapsed(),
                    failures,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn never() -> BoxFuture<'static, anyhow::Result<u32>> {
        futures::future::pending().boxed()
    }

    fn after(ms: u64, v: u32) -> BoxFuture<'static, anyhow::Result<u32>> {
        async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(v)
        }
        .boxed()
    }

    fn fail(ms: u64) -> BoxFuture<'static, anyhow::Result<u32>> {
        async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            anyhow::bail!("refused")
        }
        .boxed()
    }

    fn no_close(_: usize, _: u32) -> BoxFuture<'static, ()> {
        async {}.boxed()
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_attempt_costs_one_stagger() {
        let won = race(
            vec![never(), after(100, 2)],
            Failover::Staggered(Duration::from_secs(2)),
            no_close,
        )
        .await
        .ok()
        .unwrap();
        assert_eq!((won.index, won.value), (1, 2));
        assert_eq!(won.after, Duration::from_millis(2100));
    }

    #[tokio::test(start_paused = true)]
    async fn serial_waits_for_the_failure() {
        let won = race(vec![fail(8000), after(100, 2)], Failover::Serial, no_close)
            .await
            .ok()
            .unwrap();
        assert_eq!(won.index, 1);
        assert_eq!(won.after, Duration::from_millis(8100));
        assert_eq!(won.failures.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_starts_the_next_attempt_at_once() {
        let won = race(
            vec![fail(300), after(100, 2)],
            Failover::Staggered(Duration::from_secs(2)),
            no_close,
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(won.after, Duration::from_millis(400));
    }

    /// Two attempts that succeed in the same turn: the earlier one stays,
    /// and the other is closed.
    #[tokio::test(start_paused = true)]
    async fn the_earlier_attempt_wins_and_the_other_is_closed() {
        let closed = Arc::new(AtomicUsize::new(0));
        let seen = closed.clone();
        // Attempt 1 starts at 1 s and ends at 3 s; attempt 0 ends at 3 s.
        let won = race(
            vec![after(3000, 10), after(2000, 11)],
            Failover::Staggered(Duration::from_secs(1)),
            move |i, v| {
                assert_eq!((i, v), (1, 11));
                seen.fetch_add(1, Ordering::SeqCst);
                async {}.boxed()
            },
        )
        .await
        .ok()
        .unwrap();
        assert_eq!((won.index, won.value), (0, 10));
        assert_eq!(closed.load(Ordering::SeqCst), 1, "the loser was not closed");
    }

    #[tokio::test(start_paused = true)]
    async fn all_failures_are_given_in_order() {
        let failures = race(
            vec![fail(500), fail(100)],
            Failover::Staggered(Duration::from_millis(50)),
            no_close,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failures.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 1]);
    }

    #[test]
    fn parse() {
        assert_eq!(Failover::parse("serial").unwrap(), Failover::Serial);
        assert_eq!(
            Failover::parse("Staggered").unwrap(),
            Failover::Staggered(LEG_STAGGER)
        );
        assert!(Failover::parse("parallel").is_err());
    }
}
