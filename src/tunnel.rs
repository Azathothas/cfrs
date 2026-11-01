//! The tunnel engine: credentials, edge registration, HA reactors, reconnect
//! and dispatch to the service runtime.

use std::sync::Arc;
use std::time::Duration;

use crate::cloudflare as edge;
use crate::cloudflare::{quic as quic_dial, rpc, IpVersionFilter};
use anyhow::{bail, Context, Result};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{
    parse_credentials_file, parse_token, Config, Credentials, Protocol, ReconnectPolicy, Transport,
};
use crate::ingress::{Ingress, Service};
use crate::metrics::Metrics;
use crate::proxy;
use crate::service::ServiceRuntime;
use crate::share::ShareControl;
use crate::util::validate_quick_hostname;
use crate::warp::WarpClient;

pub const CLIENT_VERSION: &str = concat!("cfrs/", env!("CARGO_PKG_VERSION"));
const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a direct attempt gets before `auto` falls back to WARP.
const DIRECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Fluent builder for a [`Tunnel`].
pub struct TunnelBuilder {
    config: Config,
}

impl TunnelBuilder {
    pub fn quick() -> Self {
        Self {
            config: Config::default(),
        }
    }

    pub fn token(token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            config: Config {
                credentials: parse_token(&token.into())?,
                ..Config::default()
            },
        })
    }

    pub fn credentials_file(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        Ok(Self {
            config: Config {
                credentials: parse_credentials_file(&path.into())?,
                ..Config::default()
            },
        })
    }

    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.config.credentials = credentials;
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn service(mut self, service: Service) -> Self {
        self.config.ingress = Ingress::default().catch_all(service);
        self
    }

    pub fn ingress(mut self, ingress: Ingress) -> Self {
        self.config.ingress = ingress;
        self
    }

    pub fn ha_connections(mut self, count: u8) -> Self {
        self.config.ha_connections = count.clamp(1, 8);
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.config.protocol = protocol;
        self
    }

    /// How the edge connection is reached: direct on 7844, or carried by WARP
    /// over TCP 443. See [`Transport`].
    pub fn transport(mut self, transport: Transport) -> Self {
        self.config.transport = transport;
        self
    }

    pub fn reconnect(mut self, policy: ReconnectPolicy) -> Self {
        self.config.reconnect = policy;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = user_agent.into();
        self
    }

    pub fn service_url(mut self, url: impl Into<String>) -> Self {
        self.config.service_url = url.into();
        self
    }

    pub fn verify(mut self, yes: bool) -> Self {
        self.config.verify = yes;
        self
    }

    pub fn build(self) -> Result<Tunnel> {
        if self.config.ingress.is_empty() {
            bail!("no ingress rules configured");
        }
        Ok(Tunnel {
            config: self.config,
        })
    }
}

pub struct Tunnel {
    config: Config,
}

impl Tunnel {
    pub fn builder() -> TunnelBuilder {
        TunnelBuilder::quick()
    }

    pub fn quick() -> TunnelBuilder {
        TunnelBuilder::quick()
    }

    pub fn token(token: impl Into<String>) -> Result<TunnelBuilder> {
        TunnelBuilder::token(token)
    }

    /// Provision/load credentials, register with the edge and start serving.
    pub async fn start(self) -> Result<TunnelHandle> {
        crate::init_crypto();
        let Config {
            service_url,
            user_agent,
            credentials,
            protocol,
            transport,
            warp_identity,
            ha_connections,
            reconnect,
            ingress,
            verify,
            failover,
        } = self.config;

        // A bad CFRS_EDGE is a configuration error: check it before the
        // quick tunnel is provisioned.
        edge_override()?;

        // Build the services before the quick tunnel is provisioned: a bad
        // --dir, a --spa with no index.html or a missing --file stops here.
        let metrics = Metrics::new();
        let runtime = Arc::new(ServiceRuntime::build(&ingress, metrics.clone())?);

        // CFRS_UDP: the UDP probe runs while the quick tunnel is provisioned.
        let udp = crate::udp::Choice::from_env()?;
        let udp_probe = (udp == crate::udp::Choice::Probe
            && protocol == Protocol::Auto
            && leg_plan(protocol, transport).is_ok_and(|p| p.contains(&LegKind::QuicDirect)))
        .then(|| {
            let target = crate::udp::probe_target();
            tokio::task::spawn_blocking(move || {
                crate::udp::probe(target, crate::udp::START_DEADLINE)
            })
        });

        let (auth, tunnel_id, public_url) =
            resolve_credentials(&credentials, &service_url, &user_agent).await?;
        let account_tag = auth.account_tag.clone();
        let ingress = Arc::new(ingress);

        // The edge legs to try, in order. QUIC on UDP 7844 is the fastest.
        // HTTP/2 on TCP 7844 works where UDP is blocked. WARP carries QUIC
        // inside a MASQUE tunnel on TCP 443, for hosts that reach only 443.
        //
        // Do not probe TCP 7844 to choose: a firewall can close TCP 7844 and
        // keep UDP 7844 open. Each attempt is a real registration. With the
        // staggered failover (the default), the next leg starts when the one
        // before has not registered in 2 s, or at once when it fails; the
        // first leg that registers stays.
        let plan = leg_plan(protocol, transport)?;
        let proxy = crate::egress::proxy_for(EDGE_REGION_NAME, 7844);
        let (plan, note) = plan_with_proxy(plan, protocol, proxy.as_ref());
        if let Some(note) = note {
            info!("{note}");
        }
        let egress = match udp_probe {
            Some(task) => task.await.ok(),
            None => None,
        };
        let (plan, note) = plan_with_udp(plan, udp, egress.as_ref())?;
        if let Some(note) = note {
            info!("{note}");
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (legs, stopped) = Legs::new();
        let mut tasks = Vec::new();
        type Kept = Option<Arc<WarpLink>>;
        let limited = plan.len() > 1 && failover == crate::race::Failover::Serial;
        let mut attempts: Vec<futures::future::BoxFuture<'_, Result<(First, Kept)>>> = Vec::new();
        for kind in &plan {
            let auth = &auth;
            let runtime = runtime.clone();
            let ingress = ingress.clone();
            let warp_identity = warp_identity.clone();
            let attempt: futures::future::BoxFuture<'_, Result<(First, Kept)>> = match kind {
                LegKind::QuicDirect => Box::pin(bounded(limited, async move {
                    let edges = direct_targets().await?;
                    let endpoint = quic_dial::build_endpoint()?;
                    let (conn, control, location) =
                        connect_once(&endpoint, auth, tunnel_id, 0, false, &edges).await?;
                    Ok((First::Quic(edges, endpoint, conn, control, location), None))
                })),
                LegKind::H2Direct | LegKind::H2Relay => Box::pin(bounded(limited, async move {
                    let edges = direct_targets().await?;
                    let options = rpc::ConnectionOptions::default_for_quick_tunnel(CLIENT_VERSION);
                    let leg = crate::edge_h2::connect(
                        &edges, auth, tunnel_id, 0, &options, runtime, ingress,
                    )
                    .await?;
                    Ok((First::H2(edges, leg), None))
                })),
                LegKind::QuicWarp => Box::pin(async move {
                    let (edges, link, endpoint) = warp_targets(warp_identity.as_deref()).await?;
                    let (conn, control, location) =
                        connect_once(&endpoint, auth, tunnel_id, 0, false, &edges).await?;
                    let kept = Some(link);
                    Ok((First::Quic(edges, endpoint, conn, control, location), kept))
                }),
            };
            attempts.push(attempt);
        }
        // A loser that also registered: unregister it, then close it.
        let close = |index: usize,
                     (first, _kept): (First, Kept)|
         -> futures::future::BoxFuture<'static, ()> {
            Box::pin(async move {
                info!(attempt = index, "closing a second registered leg");
                match first {
                    First::Quic(_, _, conn, control, _) => {
                        control.shutdown_graceful(Duration::from_secs(2)).await;
                        conn.close(0u32.into(), b"another leg won");
                    }
                    First::H2(_, leg) => {
                        leg.control.shutdown_graceful(Duration::from_secs(2)).await;
                        leg.serve.abort();
                    }
                }
            })
        };
        let won = match crate::race::race(attempts, failover, close).await {
            Ok(won) => won,
            Err(failed) => {
                let text: Vec<String> = failed
                    .iter()
                    .map(|(i, err)| format!("{}: {err:#}", plan[*i]))
                    .collect();
                return Err(crate::exit::fault(
                    crate::exit::Fault::Unavailable,
                    anyhow::anyhow!("no edge leg worked: {}", text.join("; ")),
                ));
            }
        };
        for (i, err) in &won.failures {
            warn!(leg = %plan[*i], error = %format!("{err:#}"), "edge leg failed");
        }
        let kind = plan[won.index];
        info!(leg = %kind, after = ?won.after, "the leg won the race");
        let (first, warp_keepalive) = won.value;
        metrics.connection_opened();

        let location = match first {
            First::Quic(edges, endpoint, conn, control, location) => {
                info!(leg = %kind, %location, "registered with the edge");
                let edges = Arc::new(edges);
                let source = match &warp_keepalive {
                    Some(link) => EndpointSource::Warp(link.clone()),
                    None => EndpointSource::Fixed(endpoint.clone()),
                };
                tasks.push(spawn_leg(
                    &legs,
                    reactor(
                        runtime.clone(),
                        ingress.clone(),
                        auth.clone(),
                        tunnel_id,
                        source.clone(),
                        conn,
                        control,
                        metrics.clone(),
                        shutdown_rx.clone(),
                        reconnect.clone(),
                        0,
                        edges.clone(),
                    ),
                ));
                // The other HA legs register in the background.
                for index in 1..ha_connections {
                    let runtime = runtime.clone();
                    let ingress = ingress.clone();
                    let auth = auth.clone();
                    let source = source.clone();
                    let metrics = metrics.clone();
                    let shutdown_rx = shutdown_rx.clone();
                    let reconnect = reconnect.clone();
                    let edges = edges.clone();
                    tasks.push(spawn_leg(&legs, async move {
                        let endpoint = match source.endpoint(1).await {
                            Ok(endpoint) => endpoint,
                            Err(err) => {
                                warn!(conn_index = index, error = %format!("{err:#}"), "HA leg failed to register");
                                return None;
                            }
                        };
                        match connect_once(&endpoint, &auth, tunnel_id, index, false, &edges).await
                        {
                            Ok((conn, control, location)) => {
                                metrics.connection_opened();
                                info!(conn_index = index, %location, "HA leg registered");
                                reactor(
                                    runtime,
                                    ingress,
                                    auth,
                                    tunnel_id,
                                    source,
                                    conn,
                                    control,
                                    metrics,
                                    shutdown_rx,
                                    reconnect,
                                    index,
                                    edges,
                                )
                                .await
                            }
                            Err(err) => {
                                warn!(conn_index = index, error = %err, "HA leg failed to register");
                                None
                            }
                        }
                    }));
                }
                location
            }
            First::H2(edges, leg) => {
                info!(leg = %kind, location = %leg.location, "registered with the edge");
                let location = leg.location.clone();
                let edges = Arc::new(edges);
                let mut first_leg = Some(leg);
                for index in 0..ha_connections {
                    let runtime = runtime.clone();
                    let ingress = ingress.clone();
                    let auth = auth.clone();
                    let metrics = metrics.clone();
                    let shutdown_rx = shutdown_rx.clone();
                    let reconnect = reconnect.clone();
                    let edges = edges.clone();
                    let leg = first_leg.take();
                    tasks.push(spawn_leg(&legs, async move {
                        let leg = match leg {
                            Some(leg) => Some(leg),
                            None => {
                                let options = rpc::ConnectionOptions::default_for_quick_tunnel(
                                    CLIENT_VERSION,
                                );
                                match crate::edge_h2::connect(
                                    &edges,
                                    &auth,
                                    tunnel_id,
                                    index,
                                    &options,
                                    runtime.clone(),
                                    ingress.clone(),
                                )
                                .await
                                {
                                    Ok(leg) => {
                                        metrics.connection_opened();
                                        info!(conn_index = index, location = %leg.location, "HA leg registered");
                                        Some(leg)
                                    }
                                    Err(err) => {
                                        warn!(conn_index = index, error = %err, "HA leg failed to register");
                                        return None;
                                    }
                                }
                            }
                        };
                        crate::edge_h2::reactor(
                            leg,
                            edges,
                            auth,
                            tunnel_id,
                            index,
                            runtime,
                            ingress,
                            metrics,
                            shutdown_rx,
                            reconnect,
                            SHUTDOWN_GRACE,
                        )
                        .await
                    }));
                }
                location
            }
        };
        let locations = vec![location];

        Ok(TunnelHandle {
            url: public_url,
            tunnel_id,
            account_tag,
            locations,
            metrics,
            runtime,
            shutdown: shutdown_tx,
            tasks,
            stopped,
            verify,
            _warp: warp_keepalive,
        })
    }
}

async fn resolve_credentials(
    credentials: &Credentials,
    service_url: &str,
    user_agent: &str,
) -> Result<(rpc::TunnelAuth, Uuid, Option<String>)> {
    match credentials {
        Credentials::Quick => {
            let tunnel = crate::quicktunnel::provision(
                service_url,
                crate::quicktunnel::AuthMode::Public,
                user_agent,
                Duration::from_secs(30),
                crate::quicktunnel::PROVISION_BUDGET,
            )
            .await
            .context("provisioning quick tunnel")
            .map_err(|e| crate::exit::fault(crate::exit::Fault::Unavailable, e))?;
            let secret = tunnel
                .secret_bytes()
                .map_err(|e| anyhow::anyhow!(e))
                .context("the quick tunnel secret")?;
            let url = validate_quick_hostname(&tunnel.hostname)?;
            let tunnel_id = Uuid::parse_str(&tunnel.id).context("quick tunnel id is not a UUID")?;
            Ok((
                rpc::TunnelAuth {
                    account_tag: tunnel.account_tag,
                    tunnel_secret: secret,
                },
                tunnel_id,
                Some(url),
            ))
        }
        Credentials::Token(token) => {
            let (auth, tunnel_id) = split_explicit(parse_token(token)?)?;
            Ok((auth, tunnel_id, None))
        }
        Credentials::File(path) => {
            let (auth, tunnel_id) = split_explicit(parse_credentials_file(path)?)?;
            Ok((auth, tunnel_id, None))
        }
        Credentials::Explicit {
            account_tag,
            tunnel_id,
            secret,
        } => Ok((
            rpc::TunnelAuth {
                account_tag: account_tag.clone(),
                tunnel_secret: secret.clone(),
            },
            *tunnel_id,
            None,
        )),
    }
}

fn split_explicit(credentials: Credentials) -> Result<(rpc::TunnelAuth, Uuid)> {
    match credentials {
        Credentials::Explicit {
            account_tag,
            tunnel_id,
            secret,
        } => Ok((
            rpc::TunnelAuth {
                account_tag,
                tunnel_secret: secret,
            },
            tunnel_id,
        )),
        _ => bail!("expected explicit credentials"),
    }
}

/// Edge addresses for a direct dial on port 7844.
///
/// `CFRS_EDGE` overrides discovery with a comma-separated `host:port` list, the
/// way `cloudflared --edge` does. It exists for a self-hosted or pinned edge,
/// and it is also the only way to test the `auto` fallback deliberately: point
/// it at an address nothing answers on and direct must fail where discovery
/// would have succeeded.
/// One way to reach the edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegKind {
    /// QUIC on UDP 7844.
    QuicDirect,
    /// HTTP/2 on TCP 7844.
    H2Direct,
    /// QUIC inside a WARP MASQUE tunnel on TCP 443.
    QuicWarp,
    /// HTTP/2 to TCP 7844 in a WebSocket to a relay on TCP 443.
    H2Relay,
}

impl std::fmt::Display for LegKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LegKind::QuicDirect => "quic",
            LegKind::H2Direct => "http2",
            LegKind::QuicWarp => "quic+warp",
            LegKind::H2Relay => "http2+relay",
        })
    }
}

/// The edge legs to try, in order, for a protocol and a transport.
pub fn leg_plan(protocol: Protocol, transport: Transport) -> Result<Vec<LegKind>> {
    use LegKind::*;
    Ok(match (transport, protocol) {
        (Transport::Direct, Protocol::Quic) => vec![QuicDirect],
        (Transport::Direct, Protocol::Http2) => vec![H2Direct],
        (Transport::Direct, Protocol::Auto) => vec![QuicDirect, H2Direct],
        (Transport::Warp, Protocol::Http2) => {
            bail!("the WARP transport carries QUIC only; use --protocol quic or auto")
        }
        (Transport::Warp, _) => vec![QuicWarp],
        (Transport::Auto, Protocol::Quic) => vec![QuicDirect, QuicWarp],
        (Transport::Auto, Protocol::Http2) => vec![H2Direct],
        (Transport::Auto, Protocol::Auto) => vec![QuicDirect, H2Direct, QuicWarp],
        (Transport::Relay, Protocol::Quic) => {
            bail!("the relay carries TCP only; use --protocol http2 or auto")
        }
        (Transport::Relay, _) => vec![H2Relay],
    })
}

/// A name of the edge, for the choice of the proxy (`NO_PROXY` may name it).
pub(crate) const EDGE_REGION_NAME: &str = "region1.v2.argotunnel.com";

/// With a proxy, `--protocol auto` does not try QUIC on UDP 7844: no proxy
/// carries UDP, so the packets go around the proxy or are lost. QUIC inside
/// WARP stays, because MASQUE runs on TCP 443 through the proxy. Gives the
/// plan and the line that says why.
pub fn plan_with_proxy(
    plan: Vec<LegKind>,
    protocol: Protocol,
    proxy: Option<&crate::egress::Proxy>,
) -> (Vec<LegKind>, Option<String>) {
    let Some(proxy) = proxy else {
        return (plan, None);
    };
    if !matches!(protocol, Protocol::Auto) || !plan.contains(&LegKind::QuicDirect) {
        return (plan, None);
    }
    let kept: Vec<LegKind> = plan
        .into_iter()
        .filter(|k| *k != LegKind::QuicDirect)
        .collect();
    (
        kept,
        Some(format!(
            "a proxy is set ({proxy}); no proxy carries UDP, so cfrs does not try QUIC on UDP 7844"
        )),
    )
}

/// Apply `CFRS_UDP` and the result of the UDP probe to the plan. `off`
/// removes QUIC on UDP 7844. With `probe`, a refused probe removes it; an
/// unknown or answered probe keeps the order. The probe runs only for
/// `--protocol auto`, so `egress` is `None` for an explicit protocol.
pub fn plan_with_udp(
    plan: Vec<LegKind>,
    udp: crate::udp::Choice,
    egress: Option<&crate::udp::Egress>,
) -> Result<(Vec<LegKind>, Option<String>)> {
    use crate::udp::{Choice, Egress};
    if !plan.contains(&LegKind::QuicDirect) {
        return Ok((plan, None));
    }
    let why = match (udp, egress) {
        (Choice::Off, _) => "CFRS_UDP=off".to_string(),
        (Choice::Probe, Some(Egress::Refused(detail))) => {
            format!("the UDP probe was refused ({detail})")
        }
        (Choice::Probe, Some(other)) => {
            tracing::debug!(result = other.name(), detail = other.detail(), "UDP probe");
            return Ok((plan, None));
        }
        _ => return Ok((plan, None)),
    };
    let kept: Vec<LegKind> = plan
        .into_iter()
        .filter(|k| *k != LegKind::QuicDirect)
        .collect();
    if kept.is_empty() {
        return Err(crate::exit::fault(
            crate::exit::Fault::Config,
            anyhow::anyhow!(
                "{why}, and the only leg is QUIC on UDP 7844: use --protocol auto or http2"
            ),
        ));
    }
    Ok((
        kept,
        Some(format!("{why}: cfrs does not try QUIC on UDP 7844")),
    ))
}

/// The first registered leg.
enum First {
    Quic(
        Vec<edge::EdgeAddr>,
        quinn::Endpoint,
        quinn::Connection,
        rpc::ControlSession,
        String,
    ),
    H2(Vec<edge::EdgeAddr>, crate::edge_h2::H2Leg),
}

/// Give `attempt` a time limit when another leg can follow it. A filtered
/// port does not answer, so do not wait for the transport's own timeout.
async fn bounded<T>(
    limited: bool,
    attempt: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if !limited {
        return attempt.await;
    }
    match tokio::time::timeout(DIRECT_ATTEMPT_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => bail!(
            "the attempt did not complete in {}s",
            DIRECT_ATTEMPT_TIMEOUT.as_secs()
        ),
    }
}

/// Read `CFRS_EDGE`, a comma-separated `host:port` list that replaces edge
/// discovery (as `cloudflared --edge` does).
pub(crate) fn edge_override() -> Result<Option<Vec<edge::EdgeAddr>>> {
    let Ok(list) = std::env::var("CFRS_EDGE") else {
        return Ok(None);
    };
    let mut overridden = Vec::new();
    for item in list.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let socket: std::net::SocketAddr = item
            .parse()
            .with_context(|| format!("CFRS_EDGE entry {item:?} is not host:port"))
            .map_err(|e| crate::exit::fault(crate::exit::Fault::Config, e))?;
        overridden.push(edge::EdgeAddr {
            ip: socket.ip(),
            port: socket.port(),
            version: if socket.is_ipv4() {
                edge::EdgeIpVersion::V4
            } else {
                edge::EdgeIpVersion::V6
            },
        });
    }
    Ok((!overridden.is_empty()).then_some(overridden))
}

async fn direct_targets() -> Result<Vec<edge::EdgeAddr>> {
    if let Some(list) = edge_override()? {
        return Ok(list);
    }
    let discovered = crate::edge_discovery::discover(IpVersionFilter::Auto)
        .await
        .context("edge discovery")?;
    if discovered.is_empty() {
        bail!("edge discovery returned no addresses");
    }
    Ok(discovered)
}

async fn warp_targets(
    identity: Option<&std::path::Path>,
) -> Result<(Vec<edge::EdgeAddr>, Arc<WarpLink>, quinn::Endpoint)> {
    let discovered = match edge_override()? {
        Some(list) => list,
        None => crate::edge_discovery::discover(IpVersionFilter::V4Only)
            .await
            .context("edge discovery")?,
    };
    let Some(first) = discovered.first() else {
        bail!("edge discovery returned no addresses");
    };
    let client = match identity {
        Some(path) => WarpClient::register_or_load(path)
            .await
            .context("registering with WARP")?,
        None => WarpClient::register()
            .await
            .context("registering with WARP")?,
    };
    let stack = client
        .connect()
        .await
        .context("opening the WARP MASQUE tunnel on TCP 443")?;
    let endpoint = crate::warp::quic::endpoint(&stack)
        .await
        .context("building the QUIC socket inside the WARP session")?;
    info!(
        edge = %first.socket(),
        "the tunnel edge is reached through WARP on TCP 443"
    );
    let link = Arc::new(WarpLink {
        client,
        current: tokio::sync::Mutex::new((stack, endpoint.clone(), std::time::Instant::now())),
    });
    Ok((discovered, link, endpoint))
}

/// The WARP session of the `quic+warp` leg, and the QUIC endpoint in it.
/// When the session closes, or a reconnect fails twice, the next reconnect
/// opens a new session with the same device (no new registration).
pub(crate) struct WarpLink {
    client: WarpClient,
    current: tokio::sync::Mutex<(crate::warp::WarpStack, quinn::Endpoint, std::time::Instant)>,
}

/// A new session at most this often for failed reconnects (an HA leg must
/// not replace the session that another leg just opened).
const WARP_REBUILD_GAP: Duration = Duration::from_secs(10);

impl WarpLink {
    async fn endpoint(&self, stale: bool) -> Result<quinn::Endpoint> {
        let mut current = self.current.lock().await;
        let closed = current.0.is_closed();
        if closed || (stale && current.2.elapsed() >= WARP_REBUILD_GAP) {
            warn!(
                session_closed = closed,
                "opening a new WARP session for the edge leg"
            );
            let stack = self
                .client
                .connect()
                .await
                .context("opening the WARP MASQUE tunnel on TCP 443 again")?;
            let endpoint = crate::warp::quic::endpoint(&stack)
                .await
                .context("building the QUIC socket inside the new WARP session")?;
            *current = (stack, endpoint, std::time::Instant::now());
        }
        Ok(current.1.clone())
    }
}

/// Where the QUIC reactor gets its endpoint for each reconnect.
#[derive(Clone)]
enum EndpointSource {
    /// A kernel UDP socket: always the same endpoint.
    Fixed(quinn::Endpoint),
    /// The WARP session: a new one when it closed (see [`WarpLink`]).
    Warp(Arc<WarpLink>),
}

impl EndpointSource {
    /// The endpoint for reconnect attempt `attempt` (1 for the first).
    async fn endpoint(&self, attempt: u32) -> Result<quinn::Endpoint> {
        match self {
            EndpointSource::Fixed(endpoint) => Ok(endpoint.clone()),
            EndpointSource::Warp(link) => link.endpoint(attempt >= 3).await,
        }
    }
}

async fn connect_once(
    endpoint: &quinn::Endpoint,
    auth: &rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    replace_existing: bool,
    edges: &[edge::EdgeAddr],
) -> Result<(quinn::Connection, rpc::ControlSession, String)> {
    if edges.is_empty() {
        bail!("no edge addresses to dial");
    }
    let candidates = edges.len().min(5);
    let conn = quic_dial::dial_any(endpoint, &edges[..candidates])
        .await
        .context("QUIC handshake with the Cloudflare edge")?;

    let mut options = rpc::ConnectionOptions::default_for_quick_tunnel(CLIENT_VERSION);
    options.replace_existing = replace_existing;

    let (details, control) = tokio::time::timeout(
        REGISTER_TIMEOUT,
        rpc::register_connection(&conn, auth, tunnel_id, conn_index, &options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("register_connection timed out"))??;
    Ok((conn, control, details.location))
}

#[allow(clippy::too_many_arguments)]
async fn reactor(
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
    auth: rpc::TunnelAuth,
    tunnel_id: Uuid,
    source: EndpointSource,
    mut conn: quinn::Connection,
    mut control: rpc::ControlSession,
    metrics: Metrics,
    mut shutdown: watch::Receiver<bool>,
    policy: ReconnectPolicy,
    conn_index: u8,
    edges: Arc<Vec<edge::EdgeAddr>>,
) -> Option<String> {
    use crate::config::Next;
    let mut attempt = 0u32;
    let mut started = std::time::Instant::now();
    loop {
        if *shutdown.borrow() {
            control.shutdown_graceful(SHUTDOWN_GRACE).await;
            return None;
        }
        let lost = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                control.shutdown_graceful(SHUTDOWN_GRACE).await;
                return None;
            }
            accepted = conn.accept_bi() => {
                match accepted {
                    Ok((send, recv)) => {
                        let runtime = runtime.clone();
                        let ingress = ingress.clone();
                        tokio::spawn(async move {
                            proxy::serve_stream(runtime, ingress, send, recv).await;
                        });
                        false
                    }
                    Err(err) => {
                        // The reason (who closed it, and why) and the path
                        // state help to find an edge limit (issue 92).
                        let stats = conn.stats();
                        warn!(
                            conn_index,
                            error = %err,
                            rtt_ms = stats.path.rtt.as_millis() as u64,
                            received = stats.udp_rx.bytes,
                            sent = stats.udp_tx.bytes,
                            lost_packets = stats.path.lost_packets,
                            "edge closed the connection; a reconnect follows"
                        );
                        true
                    }
                }
            }
        };
        if !lost {
            continue;
        }

        drop(control);
        if started.elapsed() >= policy.stable {
            attempt = 0;
        }
        // The first attempt goes at once: the edge may only have moved the
        // connection.
        let mut delay = Duration::ZERO;
        loop {
            if !delay.is_zero() {
                let mut wait = shutdown.clone();
                tokio::select! {
                    biased;
                    _ = wait.changed() => return None,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            attempt += 1;
            let result = async {
                let endpoint = source.endpoint(attempt).await?;
                connect_once(&endpoint, &auth, tunnel_id, conn_index, true, &edges).await
            }
            .await;
            match result {
                Ok((new_conn, new_control, location)) => {
                    info!(conn_index, attempt, %location, "reconnected");
                    metrics.reconnect();
                    metrics.connection_opened();
                    conn = new_conn;
                    control = new_control;
                    started = std::time::Instant::now();
                    break;
                }
                Err(err) => {
                    metrics.error();
                    match policy.next(attempt, &err) {
                        Next::Retry(wait) => {
                            warn!(conn_index, attempt, error = %format!("{err:#}"), retry_in = ?wait, "reconnect failed");
                            delay = wait;
                        }
                        Next::Stop(reason) => {
                            tracing::error!(conn_index, %reason, "the QUIC leg stops");
                            return Some(reason);
                        }
                    }
                }
            }
        }
    }
}

/// The legs that run. When the last one stops for a cause (not a
/// shutdown), [`TunnelHandle::stopped`] gives the cause.
#[derive(Clone)]
struct Legs(Arc<LegsInner>);

struct LegsInner {
    live: std::sync::atomic::AtomicUsize,
    last: std::sync::Mutex<Option<String>>,
    tx: watch::Sender<Option<String>>,
}

impl Legs {
    fn new() -> (Self, watch::Receiver<Option<String>>) {
        let (tx, rx) = watch::channel(None);
        (
            Self(Arc::new(LegsInner {
                live: Default::default(),
                last: Default::default(),
                tx,
            })),
            rx,
        )
    }
}

/// Run one leg as a task. Its result is the reason that it stopped, or
/// `None` for a shutdown.
fn spawn_leg(
    legs: &Legs,
    leg: impl std::future::Future<Output = Option<String>> + Send + 'static,
) -> JoinHandle<()> {
    use std::sync::atomic::Ordering;
    let legs = legs.clone();
    legs.0.live.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let reason = leg.await;
        if let Some(reason) = reason {
            *legs.0.last.lock().unwrap() = Some(reason);
        }
        if legs.0.live.fetch_sub(1, Ordering::SeqCst) == 1 {
            if let Some(reason) = legs.0.last.lock().unwrap().clone() {
                let _ = legs.0.tx.send(Some(reason));
            }
        }
    })
}

/// A running tunnel.
pub struct TunnelHandle {
    url: Option<String>,
    tunnel_id: Uuid,
    account_tag: String,
    locations: Vec<String>,
    metrics: Metrics,
    runtime: Arc<ServiceRuntime>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    stopped: watch::Receiver<Option<String>>,
    verify: bool,
    /// Kept alive for the tunnel's lifetime: dropping either tears down the
    /// WARP session and the QUIC endpoint the edge connection rides on.
    _warp: Option<Arc<WarpLink>>,
}

impl TunnelHandle {
    /// Ready when each leg has stopped for a cause, for example a refusal of
    /// the edge with no retry. Gives the cause. It is not ready after a
    /// shutdown.
    pub async fn stopped(&self) -> String {
        let mut rx = self.stopped.clone();
        loop {
            if let Some(reason) = rx.borrow().clone() {
                return reason;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Public URL for a quick tunnel; `None` for a named tunnel (the hostname
    /// is configured in the Cloudflare dashboard).
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn tunnel_id(&self) -> Uuid {
        self.tunnel_id
    }

    pub fn account_tag(&self) -> &str {
        &self.account_tag
    }

    pub fn locations(&self) -> &[String] {
        &self.locations
    }

    pub fn metrics(&self) -> Metrics {
        self.metrics.clone()
    }

    pub fn share_controls(&self) -> Vec<Arc<ShareControl>> {
        self.runtime.share_controls()
    }

    /// Fetch the public URL and confirm the tunnel is reachable. For quick
    /// tunnels the expected token may be checked against the body.
    pub async fn verify(&self, expected: Option<&str>) -> Result<()> {
        let Some(url) = self.url.as_deref() else {
            return Ok(());
        };
        self.verify_url(url, expected).await
    }

    /// Like [`verify`](Self::verify) but for a specific path on the public
    /// URL (a share session lives under `/s/<token>/`, not at the root).
    ///
    /// With no `expected` text, an answer of the origin that is not 2xx (for
    /// example 401 or 404 of an app behind a login) is a warning: the
    /// request crossed the tunnel. Only 530 (the edge has no connection of
    /// the tunnel) and transport errors are fatal after the last attempt.
    pub async fn verify_url(&self, url: &str, expected: Option<&str>) -> Result<()> {
        let mut last = String::from("no attempt");
        let mut last_status = None;
        for attempt in 1..=20 {
            let request = crate::fetch::Request::new("GET", url).timeout(Duration::from_secs(15));
            match request.send().await {
                Ok(response) => {
                    let body = response.text();
                    let ok = response.is_success()
                        && expected.map(|token| body.contains(token)).unwrap_or(true);
                    if ok {
                        info!(%url, status = response.status, "verified public URL");
                        return Ok(());
                    }
                    last = format!("HTTP {}", response.status);
                    last_status = Some(response.status);
                    // A status of the origin crossed the tunnel: the tunnel is up.
                    let edge_error = matches!(response.status, 502..=504 | 520..=530);
                    if expected.is_none() && !edge_error {
                        tracing::warn!(%url, status = response.status, "the origin answered HTTP {}; the tunnel is up", response.status);
                        return Ok(());
                    }
                }
                Err(err) => {
                    last = format!("{err:#}");
                    last_status = None;
                }
            }
            tracing::debug!(attempt, %last, "verification retry");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        if expected.is_none() && matches!(last_status, Some(s) if s != 530) {
            tracing::warn!(%url, "the public URL answers {last}; the tunnel is up, check the origin");
            return Ok(());
        }
        bail!("could not verify {url}: {last}")
    }

    pub fn wants_verify(&self) -> bool {
        self.verify
    }

    /// Signal every reactor and wait for them to drain.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(2), task).await;
        }
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfrs_udp_and_the_probe_shape_the_plan() {
        use crate::udp::{Choice, Egress};
        use LegKind::*;
        let all = || vec![QuicDirect, H2Direct, QuicWarp];
        let plan = |udp, egress: Option<Egress>| plan_with_udp(all(), udp, egress.as_ref());
        assert_eq!(plan(Choice::Off, None).unwrap().0, vec![H2Direct, QuicWarp]);
        assert_eq!(plan(Choice::On, None).unwrap().0, all());
        let refused = Egress::Refused("EPERM".into());
        let (kept, note) = plan(Choice::Probe, Some(refused.clone())).unwrap();
        assert_eq!(kept, vec![H2Direct, QuicWarp]);
        assert!(note.unwrap().contains("refused"));
        // No answer, or an answer, keeps the order.
        for egress in [Egress::Unknown("x".into()), Egress::Answered("x".into())] {
            assert_eq!(plan(Choice::Probe, Some(egress)).unwrap().0, all());
        }
        // CFRS_UDP=off with QUIC on UDP 7844 as the only leg is an error.
        let err = plan_with_udp(vec![QuicDirect], Choice::Off, None).unwrap_err();
        assert_eq!(crate::exit::code_of(&err), crate::exit::CONFIG);
        assert_eq!(
            plan_with_udp(vec![H2Direct], Choice::Off, None).unwrap().0,
            vec![H2Direct]
        );
        let _ = refused;
    }

    #[test]
    fn the_leg_plan_tries_quic_then_http2_then_warp() {
        use LegKind::*;
        let plan = |p, t| leg_plan(p, t).unwrap();
        assert_eq!(
            plan(Protocol::Auto, Transport::Auto),
            vec![QuicDirect, H2Direct, QuicWarp]
        );
        assert_eq!(
            plan(Protocol::Quic, Transport::Auto),
            vec![QuicDirect, QuicWarp]
        );
        assert_eq!(plan(Protocol::Http2, Transport::Auto), vec![H2Direct]);
        assert_eq!(
            plan(Protocol::Auto, Transport::Direct),
            vec![QuicDirect, H2Direct]
        );
        assert_eq!(plan(Protocol::Quic, Transport::Warp), vec![QuicWarp]);
        assert!(leg_plan(Protocol::Http2, Transport::Warp).is_err());
        assert_eq!(plan(Protocol::Auto, Transport::Relay), vec![H2Relay]);
        assert_eq!(plan(Protocol::Http2, Transport::Relay), vec![H2Relay]);
        assert!(leg_plan(Protocol::Quic, Transport::Relay).is_err());
    }
}
