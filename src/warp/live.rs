//! A WARP session that comes back (issue 75).
//!
//! `warp proxy`, `warp run` and `warp tun` held one MASQUE session. When it
//! ended (a network change, the front door, the 64 MiB limit of a relay),
//! each new connection failed until a restart. [`Live`] holds the current
//! session, and a watcher task opens a new one when it closes: the first
//! try at once, then a backoff of 1 s doubled to 30 s. A caller that asks
//! for the session while it is down waits for the new one, for
//! [`WAIT_FOR_NEW`] at most.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

/// How long a caller waits for a new session while the session is down.
pub const WAIT_FOR_NEW: Duration = Duration::from_secs(20);
/// How often the watcher looks at the session.
const CHECK: Duration = Duration::from_millis(500);

/// A session that can close.
pub trait Closable: Send + Sync + 'static {
    fn is_closed(&self) -> bool;
    /// Why it closed (issue 178), when it is known.
    fn reason(&self) -> Option<String> {
        None
    }
    /// Close it on purpose (issue 185).
    fn close(&self, _why: &str) {}
}

impl Closable for super::WarpStack {
    fn is_closed(&self) -> bool {
        super::WarpStack::is_closed(self)
    }
    fn reason(&self) -> Option<String> {
        self.close_reason()
    }
    fn close(&self, why: &str) {
        self.close_session(why)
    }
}

/// `--session-max-age` (issue 185): each session of [`Live`] is closed on
/// purpose at this age, and a new one opens. Seconds; 0 is off.
static MAX_AGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set the age at which a session of [`Live`] is renewed (None: never).
pub fn set_max_age(age: Option<Duration>) {
    MAX_AGE.store(age.map_or(0, |a| a.as_secs().max(1)), Ordering::SeqCst);
}

fn max_age() -> Option<Duration> {
    match MAX_AGE.load(Ordering::SeqCst) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    }
}

/// Opens a new session.
pub type Connect<T> =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<T>> + Send>> + Send + Sync>;

/// The current session, and a watcher that replaces it when it closes.
pub struct Live<T: Closable> {
    current: Mutex<Arc<T>>,
    generation: watch::Sender<u64>,
    reconnects: AtomicU32,
    watcher: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl<T: Closable> Live<T> {
    /// Start with `first`; `connect` opens each new session.
    pub fn start(first: T, connect: Connect<T>) -> Arc<Self> {
        Self::start_aged(
            first,
            connect,
            Duration::from_secs(1),
            Duration::from_secs(30),
            max_age(),
        )
    }

    /// [`Live::start`] with the first and the largest delay of the backoff.
    pub fn start_with(first: T, connect: Connect<T>, base: Duration, max: Duration) -> Arc<Self> {
        Self::start_aged(first, connect, base, max, None)
    }

    /// [`Live::start_with`], and each session ends at `max_age`.
    pub fn start_aged(
        first: T,
        connect: Connect<T>,
        base: Duration,
        max: Duration,
        max_age: Option<Duration>,
    ) -> Arc<Self> {
        let (generation, _) = watch::channel(0u64);
        let live = Arc::new(Self {
            current: Mutex::new(Arc::new(first)),
            generation,
            reconnects: AtomicU32::new(0),
            watcher: std::sync::Mutex::new(None),
        });
        let weak = Arc::downgrade(&live);
        let task = tokio::spawn(async move {
            let mut delay = Duration::ZERO;
            let mut opened = tokio::time::Instant::now();
            let check = max_age.map_or(CHECK, |age| {
                CHECK.min(age / 4).max(Duration::from_millis(10))
            });
            loop {
                tokio::time::sleep(check).await;
                let Some(live) = weak.upgrade() else { return };
                {
                    let current = live.current.lock().await;
                    if !current.is_closed() {
                        match max_age {
                            Some(age) if opened.elapsed() >= age => {
                                info!("the WARP session ends on purpose (--session-max-age)");
                                current.close("--session-max-age");
                            }
                            _ => {
                                delay = Duration::ZERO;
                                continue;
                            }
                        }
                    }
                }
                if delay.is_zero() {
                    // Issue 116: the log of warp up shows each close; issue
                    // 178: with its cause.
                    let reason = live.current.lock().await.reason();
                    info!(
                        reason = reason.as_deref().unwrap_or("unknown"),
                        "the WARP session is closed; cfrs opens a new one"
                    );
                } else {
                    tokio::time::sleep(delay).await;
                }
                match connect().await {
                    Ok(next) => {
                        *live.current.lock().await = Arc::new(next);
                        opened = tokio::time::Instant::now();
                        let n = live.reconnects.fetch_add(1, Ordering::SeqCst) + 1;
                        live.generation.send_modify(|g| *g += 1);
                        info!(reconnects = n, "a new WARP session is open");
                        delay = Duration::ZERO;
                    }
                    Err(err) => {
                        delay = if delay.is_zero() {
                            base
                        } else {
                            (delay * 2).min(max)
                        };
                        warn!(
                            error = %format!("{err:#}"),
                            next_try_ms = delay.as_millis() as u64,
                            "the WARP session is closed; a new one failed"
                        );
                    }
                }
            }
        });
        *live.watcher.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        live
    }

    /// The current session. While it is closed, wait for the new one (at
    /// most `WAIT_FOR_NEW`).
    pub async fn get(&self) -> Result<Arc<T>> {
        self.get_within(WAIT_FOR_NEW).await
    }

    /// [`Live::get`] with a time limit.
    pub async fn get_within(&self, limit: Duration) -> Result<Arc<T>> {
        let mut changes = self.generation.subscribe();
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            {
                let current = self.current.lock().await;
                if !current.is_closed() {
                    return Ok(current.clone());
                }
            }
            match tokio::time::timeout_at(deadline, changes.changed()).await {
                Ok(Ok(())) => continue,
                _ => bail!(
                    "the WARP session is closed, and no new session opened in {} s",
                    limit.as_secs()
                ),
            }
        }
    }

    /// How many new sessions were opened.
    pub fn reconnects(&self) -> u32 {
        self.reconnects.load(Ordering::SeqCst)
    }
}

impl<T: Closable> Drop for Live<T> {
    fn drop(&mut self) {
        if let Some(task) = self
            .watcher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

/// A `WarpClient` that gives a [`Live`] stack.
impl super::WarpClient {
    /// Open the stack, and keep it open: see [`Live`].
    pub async fn connect_live(self: Arc<Self>) -> Result<Arc<Live<super::WarpStack>>> {
        let first = self.connect().await?;
        let client = self.clone();
        let connect: Connect<super::WarpStack> = Box::new(move || {
            let client = client.clone();
            Box::pin(async move { client.connect().await })
        });
        Ok(Live::start(first, connect))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct Fake {
        id: u32,
        closed: Arc<AtomicBool>,
    }

    impl Closable for Fake {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    /// A session that closes is replaced; a caller during the gap waits
    /// for the new one; failed opens are tried again.
    #[tokio::test]
    async fn a_closed_session_is_replaced() {
        let first_closed = Arc::new(AtomicBool::new(false));
        let opens = Arc::new(AtomicU32::new(0));
        let failures_left = Arc::new(AtomicU32::new(2));
        let connect: Connect<Fake> = {
            let opens = opens.clone();
            let failures_left = failures_left.clone();
            Box::new(move || {
                let opens = opens.clone();
                let failures_left = failures_left.clone();
                Box::pin(async move {
                    if failures_left
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                    {
                        bail!("the front door does not answer");
                    }
                    let id = opens.fetch_add(1, Ordering::SeqCst) + 2;
                    Ok(Fake {
                        id,
                        closed: Arc::new(AtomicBool::new(false)),
                    })
                })
            })
        };
        let live = Live::start_with(
            Fake {
                id: 1,
                closed: first_closed.clone(),
            },
            connect,
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        assert_eq!(live.get().await.unwrap().id, 1);
        first_closed.store(true, Ordering::SeqCst);
        let next = live.get_within(Duration::from_secs(10)).await.unwrap();
        assert_eq!(next.id, 2, "two failed opens, then a new session");
        assert_eq!(live.reconnects(), 1);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
    }

    struct Aged {
        id: u32,
        closed: AtomicBool,
    }

    impl Closable for Aged {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn reason(&self) -> Option<String> {
            self.is_closed().then(|| "max age".into())
        }
        fn close(&self, _why: &str) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    /// Issue 185: a session is replaced at its max age, with no backoff.
    #[tokio::test]
    async fn a_session_is_replaced_at_max_age() {
        let opens = Arc::new(AtomicU32::new(1));
        let connect: Connect<Aged> = {
            let opens = opens.clone();
            Box::new(move || {
                let opens = opens.clone();
                Box::pin(async move {
                    let id = opens.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Aged {
                        id,
                        closed: AtomicBool::new(false),
                    })
                })
            })
        };
        let live = Live::start_aged(
            Aged {
                id: 1,
                closed: AtomicBool::new(false),
            },
            connect,
            Duration::from_secs(30),
            Duration::from_secs(30),
            Some(Duration::from_millis(200)),
        );
        assert_eq!(live.get().await.unwrap().id, 1);
        let started = std::time::Instant::now();
        while live.reconnects() == 0 {
            assert!(started.elapsed() < Duration::from_secs(5), "no renewal");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(live.get().await.unwrap().id >= 2);
    }

    /// A caller does not wait for ever while no session opens.
    #[tokio::test]
    async fn a_caller_gets_an_error_when_no_session_opens() {
        let connect: Connect<Fake> =
            Box::new(|| Box::pin(async { bail!("no route to the front door") }));
        let live = Live::start_with(
            Fake {
                id: 1,
                closed: Arc::new(AtomicBool::new(true)),
            },
            connect,
            Duration::from_millis(20),
            Duration::from_millis(50),
        );
        let err = live
            .get_within(Duration::from_millis(400))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("no new session"), "{err:#}");
    }
}
