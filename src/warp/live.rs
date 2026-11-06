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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use pod_tls::fragment::{Part, Split};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

pub mod instance;

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
    /// Whether a new session must take the new flows while this one goes
    /// on: the budget of the relay is spent.
    fn renew_due(&self) -> bool {
        false
    }
    /// The TCP probe of the data path (T-068): whether a TCP connect to
    /// `target` through the session succeeds within `limit`.
    fn probe_tcp(&self, _target: std::net::SocketAddr, _limit: Duration) -> ProbeFuture<'_> {
        Box::pin(async { true })
    }
}

/// The result of [`Closable::probe_tcp`].
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// The TCP probe of the data path (T-068). A MASQUE session can carry ICMP
/// and UDP but no TCP; the pongs and the UDP replies keep it alive. Each
/// `every`, a task connects to `target` through the session. After
/// `misses` failures in a row, the data path is `tcp-dead`, and a new
/// session takes the new flows (the path of the relay budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub target: std::net::SocketAddr,
    pub every: Duration,
    pub limit: Duration,
    pub misses: u32,
}

/// The default probe: TCP to 1.1.1.1:443 each 30 s, 5 s each, 3 misses.
pub const DEFAULT_PROBE: Probe = Probe {
    target: std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        443,
    ),
    every: Duration::from_secs(30),
    limit: Duration::from_secs(5),
    misses: 3,
};

static PROBE: std::sync::Mutex<Option<Probe>> = std::sync::Mutex::new(Some(DEFAULT_PROBE));

/// `--probe IP:PORT` or `--probe off` (T-068).
pub fn parse_probe(spec: &str) -> Result<Option<Probe>> {
    if spec == "off" {
        return Ok(None);
    }
    match spec.parse() {
        Ok(target) => Ok(Some(Probe {
            target,
            ..DEFAULT_PROBE
        })),
        Err(_) => bail!("--probe={spec:?}: give IP:PORT or off"),
    }
}

/// Set the probe of the sessions of this process (None: no probe).
pub fn set_probe(probe: Option<Probe>) {
    *PROBE.lock().unwrap_or_else(|e| e.into_inner()) = probe;
}

/// The option `--probe` for `probe` (warp up gives it to its child).
pub fn probe_arg(probe: Option<Probe>) -> String {
    format!(
        "--probe={}",
        probe.map_or("off".into(), |p| p.target.to_string())
    )
}

/// The probe of this process (None: no probe).
pub fn probe() -> Option<Probe> {
    *PROBE.lock().unwrap_or_else(|e| e.into_inner())
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
    fn renew_due(&self) -> bool {
        super::WarpStack::renew_due(self)
    }
    fn probe_tcp(&self, target: std::net::SocketAddr, limit: Duration) -> ProbeFuture<'_> {
        Box::pin(async move {
            matches!(
                tokio::time::timeout(limit, self.tcp_connect(target)).await,
                Ok(Ok(_))
            )
        })
    }
}

/// After a planned replacement, the old session carries its open flows for
/// this long, then it is closed.
pub const RENEW_DRAIN: Duration = Duration::from_secs(90);

/// `--session-max-age` (issue 185): each session of [`Live`] is closed on
/// purpose at this age, and a new one opens. Seconds; 0 is off.
static MAX_AGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set the age at which a session of [`Live`] is renewed (None: never).
pub fn set_max_age(age: Option<Duration>) {
    MAX_AGE.store(age.map_or(0, |a| a.as_secs().max(1)), Ordering::SeqCst);
}

/// The age at which a session is renewed (None: never).
pub fn max_age() -> Option<Duration> {
    match MAX_AGE.load(Ordering::SeqCst) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    }
}

/// `--fragment-client-hello` and `--fragment-size` (issue 135): the split of
/// the first ClientHello of each MASQUE connection, when one is set.
static SPLIT: std::sync::OnceLock<Split> = std::sync::OnceLock::new();

/// The split of `--fragment-client-hello` (`off`, `record` or `sni`; `off`
/// gives `None`) and `--fragment-size` (`N` or `MIN-MAX`). A bad size is an
/// error also with `off` (issue 252).
pub fn parse_split(mode: &str, size: Option<&str>) -> Result<Option<Split>> {
    Split::parse(mode, size).map_err(|err| match err {
        pod_tls::Error::Split {
            part: Part::Mode,
            value,
        } => anyhow::anyhow!(
            "--fragment-client-hello={value:?}: give {}",
            Part::Mode.accepted()
        ),
        pod_tls::Error::Split {
            part: Part::Size,
            value,
        } => anyhow::anyhow!("--fragment-size={value}: give {}", Part::Size.accepted()),
        other => other.into(),
    })
}

/// Set the split of this process. A later call does nothing.
pub fn set_split(split: Split) {
    if SPLIT.set(split).is_ok() {
        info!(mode = ?split.mode, min = split.min, max = split.max, "the first ClientHello of each MASQUE connection is split across records");
    }
}

/// The split of the MASQUE connections, when one is set.
pub fn split() -> Option<Split> {
    SPLIT.get().copied()
}

/// Opens a new session.
pub type Connect<T> =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<T>> + Send>> + Send + Sync>;

/// What `warp status` shows of a [`Live`] (T-140).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// [`Live::data_path`]: `ok` or `tcp-dead`.
    pub data_path: &'static str,
    /// The Unix time of the last TCP probe, when one ran.
    pub last_probe: Option<u64>,
}

/// The current session, and a watcher that replaces it when it closes.
pub struct Live<T: Closable> {
    current: Mutex<Arc<T>>,
    generation: watch::Sender<u64>,
    reconnects: AtomicU32,
    /// The TCP probe found no data path (T-068): renew the session.
    tcp_dead: AtomicBool,
    report: watch::Sender<Report>,
    watcher: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl<T: Closable> Live<T> {
    /// Start with `first`; `connect` opens each new session.
    pub fn start(first: T, connect: Connect<T>) -> Arc<Self> {
        let live = Self::start_aged(
            first,
            connect,
            Duration::from_secs(1),
            Duration::from_secs(30),
            max_age(),
        )
        .probed(probe());
        instance::publish_own(&live);
        live
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
            tcp_dead: AtomicBool::new(false),
            report: watch::Sender::new(Report {
                data_path: "ok",
                last_probe: None,
            }),
            watcher: std::sync::Mutex::new(Vec::new()),
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
                // The owner ruling of 2026-11-04: before the relay ends a
                // session (64 MiB, 12 h), a new session takes the new flows;
                // the open flows go on in the old one, which closes after
                // RENEW_DRAIN. No gap: the old one stays current until the
                // new one is open.
                // T-068: the same path when the TCP probe found no data path.
                let due = {
                    let current = live.current.lock().await;
                    let reason = if current.renew_due() {
                        "relay-budget"
                    } else {
                        "tcp-probe"
                    };
                    (!current.is_closed()
                        && (current.renew_due() || live.tcp_dead.load(Ordering::SeqCst)))
                    .then(|| (current.clone(), reason))
                };
                if let Some((old, reason)) = due {
                    match connect().await {
                        Ok(next) => {
                            *live.current.lock().await = Arc::new(next);
                            live.tell(false, false);
                            opened = tokio::time::Instant::now();
                            let n = live.reconnects.fetch_add(1, Ordering::SeqCst) + 1;
                            live.generation.send_modify(|g| *g += 1);
                            info!(
                                reconnects = n,
                                reason,
                                drain_s = RENEW_DRAIN.as_secs(),
                                "a new WARP session takes the new flows; the old one carries its open flows"
                            );
                            tokio::spawn(async move {
                                tokio::time::sleep(RENEW_DRAIN).await;
                                old.close(&format!("{reason}: the drain ended"));
                            });
                            delay = Duration::ZERO;
                        }
                        Err(err) => {
                            warn!(
                                error = %format!("{err:#}"),
                                reason,
                                "the WARP session must be renewed; a new one failed, podnet tries again"
                            );
                            tokio::time::sleep(base.max(Duration::from_secs(1))).await;
                        }
                    }
                    continue;
                }
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
                        "the WARP session is closed; podnet opens a new one"
                    );
                } else {
                    tokio::time::sleep(delay).await;
                }
                match connect().await {
                    Ok(next) => {
                        *live.current.lock().await = Arc::new(next);
                        opened = tokio::time::Instant::now();
                        live.tell(false, false);
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
        live.watcher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(task);
        live
    }

    /// Start the TCP probe of the data path (T-068) on each session.
    pub fn probed(self: Arc<Self>, probe: Option<Probe>) -> Arc<Self> {
        let Some(probe) = probe else { return self };
        let weak = Arc::downgrade(&self);
        let task = tokio::spawn(async move {
            let mut missed = 0u32;
            let mut generation = 0u64;
            loop {
                tokio::time::sleep(probe.every).await;
                let Some(live) = weak.upgrade() else { return };
                let current = live.current.lock().await.clone();
                let now = *live.generation.borrow();
                if now != generation {
                    generation = now;
                    missed = 0;
                }
                if current.is_closed() || live.tcp_dead.load(Ordering::SeqCst) {
                    continue;
                }
                drop(live);
                let ok = current.probe_tcp(probe.target, probe.limit).await;
                let Some(live) = weak.upgrade() else { return };
                if ok || *live.generation.borrow() != generation {
                    if ok {
                        live.tell(false, true);
                    }
                    missed = 0;
                    continue;
                }
                missed += 1;
                live.tell(missed >= probe.misses, true);
                warn!(target = %probe.target, missed, "the TCP probe of the WARP session failed");
                if missed >= probe.misses {
                    warn!(
                        reason = "tcp-probe",
                        "the WARP session carries no TCP; a new session takes the new flows"
                    );
                    missed = 0;
                }
            }
        });
        self.watcher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(task);
        self
    }

    /// The state of the data path: `ok`, or `tcp-dead` until a new session
    /// opens (T-068).
    pub fn data_path(&self) -> &'static str {
        if self.tcp_dead.load(Ordering::SeqCst) {
            "tcp-dead"
        } else {
            "ok"
        }
    }

    /// The data path and the time of the last probe, on each change
    /// (T-140).
    pub fn report(&self) -> watch::Receiver<Report> {
        self.report.subscribe()
    }

    /// Set the state of the data path; `probed`: a probe ended now.
    fn tell(&self, tcp_dead: bool, probed: bool) {
        self.tcp_dead.store(tcp_dead, Ordering::SeqCst);
        let now = probed.then(crate::instances::now);
        self.report.send_modify(|r| {
            r.data_path = self.data_path();
            r.last_probe = now.or(r.last_probe);
        });
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
        for task in self
            .watcher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
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
                    // #214: no fetch_update (deprecated in a later Rust).
                    let mut left = failures_left.load(Ordering::SeqCst);
                    let took = loop {
                        if left == 0 {
                            break false;
                        }
                        match failures_left.compare_exchange_weak(
                            left,
                            left - 1,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(_) => break true,
                            Err(now) => left = now,
                        }
                    };
                    if took {
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

    struct Budgeted {
        id: u32,
        closed: AtomicBool,
        due: Arc<AtomicBool>,
    }

    impl Closable for Budgeted {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn close(&self, _why: &str) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn renew_due(&self) -> bool {
            self.due.load(Ordering::SeqCst)
        }
    }

    /// The owner ruling of 2026-11-04: at the relay budget, a new session
    /// takes the new flows with no gap; the old one closes after the drain.
    #[tokio::test(start_paused = true)]
    async fn a_spent_relay_budget_renews_with_no_gap() {
        let opens = Arc::new(AtomicU32::new(1));
        let connect: Connect<Budgeted> = {
            let opens = opens.clone();
            Box::new(move || {
                let opens = opens.clone();
                Box::pin(async move {
                    let id = opens.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Budgeted {
                        id,
                        closed: AtomicBool::new(false),
                        due: Arc::new(AtomicBool::new(false)),
                    })
                })
            })
        };
        let due = Arc::new(AtomicBool::new(false));
        let live = Live::start_with(
            Budgeted {
                id: 1,
                closed: AtomicBool::new(false),
                due: due.clone(),
            },
            connect,
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        let old = live.get().await.unwrap();
        assert_eq!(old.id, 1);
        due.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        // A new flow gets the new session; the old one is still open.
        let next = live.get_within(Duration::ZERO).await.unwrap();
        assert_eq!(next.id, 2);
        assert!(!old.is_closed(), "the open flows go on in the old session");
        assert_eq!(live.reconnects(), 1);
        tokio::time::sleep(RENEW_DRAIN + Duration::from_secs(1)).await;
        assert!(old.is_closed(), "the old session closes after the drain");
        assert_eq!(live.get_within(Duration::ZERO).await.unwrap().id, 2);
        assert_eq!(opens.load(Ordering::SeqCst), 2, "one new session only");
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

    /// A session that carries no TCP: its probe fails.
    struct Silenced {
        id: u32,
        closed: AtomicBool,
        tcp: bool,
        probes: Arc<AtomicU32>,
    }

    impl Closable for Silenced {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn close(&self, _why: &str) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn probe_tcp(&self, _target: std::net::SocketAddr, _limit: Duration) -> ProbeFuture<'_> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            let tcp = self.tcp;
            Box::pin(async move { tcp })
        }
    }

    /// T-068: a session that carries ICMP and UDP but no TCP stays open.
    /// After three failed probes, a new session takes the new flows, and
    /// the old one drains.
    #[tokio::test(start_paused = true)]
    async fn warp_probe_renews_a_session_with_no_tcp() {
        let probes = Arc::new(AtomicU32::new(0));
        let opens = Arc::new(AtomicU32::new(1));
        let connect: Connect<Silenced> = {
            let (opens, probes) = (opens.clone(), probes.clone());
            Box::new(move || {
                let (opens, probes) = (opens.clone(), probes.clone());
                Box::pin(async move {
                    let id = opens.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Silenced {
                        id,
                        closed: AtomicBool::new(false),
                        tcp: true,
                        probes,
                    })
                })
            })
        };
        let first = Silenced {
            id: 1,
            closed: AtomicBool::new(false),
            tcp: false,
            probes: probes.clone(),
        };
        let live = Live::start_with(
            first,
            connect,
            Duration::from_millis(50),
            Duration::from_millis(200),
        )
        .probed(Some(DEFAULT_PROBE));
        let old = live.get().await.unwrap();
        // Two misses: the session stays.
        tokio::time::sleep(DEFAULT_PROBE.every * 2 + Duration::from_secs(1)).await;
        assert_eq!(live.get_within(Duration::ZERO).await.unwrap().id, 1);
        assert_eq!(live.data_path(), "ok");
        // The third miss: a new session takes the new flows.
        tokio::time::sleep(DEFAULT_PROBE.every + Duration::from_secs(1)).await;
        assert_eq!(live.get_within(Duration::ZERO).await.unwrap().id, 2);
        assert_eq!(live.reconnects(), 1);
        assert_eq!(live.data_path(), "ok");
        assert!(!old.is_closed(), "the open flows go on in the old session");
        tokio::time::sleep(RENEW_DRAIN + Duration::from_secs(1)).await;
        assert!(old.is_closed(), "the old session closes after the drain");
        // The new session passes its probes: no other renewal.
        tokio::time::sleep(DEFAULT_PROBE.every * 4).await;
        assert_eq!(live.reconnects(), 1);
        assert!(probes.load(Ordering::SeqCst) >= 6);
    }

    #[test]
    fn the_probe_option() {
        assert_eq!(parse_probe("off").unwrap(), None);
        let p = parse_probe("9.9.9.9:53").unwrap().unwrap();
        assert_eq!(p.target, "9.9.9.9:53".parse().unwrap());
        assert_eq!(p.misses, 3);
        assert!(parse_probe("one.one.one.one:443").is_err());
    }
}
