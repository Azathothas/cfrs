//! The `connect` call of the program under the seccomp backend.
//!
//! The dial of a TCP socket runs in its own task (T-067). The supervisor
//! does not answer the notification of the call: the kernel keeps the
//! caller blocked, and the supervisor serves the other calls of the
//! program. When the dial ends, the task sends a [`Dialed`] to the
//! notification loop. The loop then changes the entry of the socket and
//! answers each call that waits for the dial ([`finish`]).
//!
//! More than one call can wait for one dial: a second thread that connects
//! the same socket, or the same thread when the kernel starts its call
//! again after a signal. The kernel does the same for a blocking connect
//! on a socket in the state `SYN_SENT`. When no waiting call is pending at
//! the end of the dial (the caller exited, or a signal stopped the call),
//! the loop drops the connection. A later `connect` dials again.
//!
//! A plain upstream on a Unix socket goes to the program itself at the end
//! of the dial (T-065, [`crate::handoff`]). Another upstream gets a relay.

use crate::handoff::{dial_plain, Caller, Link};
use crate::prelude::*;
use crate::seccomp::{
    notif_continue, notif_id_valid, notif_respond, parse_sockaddr, read_mem, spawn_relay, Sock,
};

/// The end of the dial of one socket.
pub(crate) struct Dialed {
    key: Key,
    /// The first call: its descriptor number gives the ephemeral port.
    caller: Caller,
    peer: (IpAddr, u16),
    target: String,
    result: Result<Link>,
}

/// The dials in progress.
pub(crate) struct Dials {
    /// For each socket with a dial in progress: the calls that wait for it.
    waiting: HashMap<Key, Vec<u64>>,
    tx: tokio::sync::mpsc::UnboundedSender<Dialed>,
    rx: tokio::sync::mpsc::UnboundedReceiver<Dialed>,
}

impl Dials {
    pub(crate) fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Dials {
            waiting: HashMap::new(),
            tx,
            rx,
        }
    }

    /// The next dial that ends.
    pub(crate) async fn next(&mut self) -> Option<Dialed> {
        self.rx.recv().await
    }
}

/// The settings of the pod that a dial uses.
pub(crate) struct Route<'a> {
    pub(crate) proxies: &'a [Proxy],
    pub(crate) rules: &'a [Rule],
    pub(crate) inbound_dir: &'a std::path::Path,
    pub(crate) verbose: bool,
}

/// The `connect` call. A datagram socket gets its answer now. A stream
/// socket gets its answer when its dial ends.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_connect(
    lfd: RawFd,
    id: u64,
    a: [u64; 6],
    mem: RawFd,
    (map, key, pid): (&mut HashMap<Key, Sock>, Key, u32),
    dns: &mut FakeDns,
    dials: &mut Dials,
    route: &Route<'_>,
) -> Result<()> {
    let fd = a[0] as i32;
    let is_datagram = matches!(map.get(&key), Some(Sock::Datagram { .. }));
    match map.get(&key) {
        None => return notif_continue(lfd, id),
        Some(Sock::Connected(_)) => return notif_respond(lfd, id, -1, libc::EISCONN),
        Some(_) => {}
    }
    if let Some(waiting) = dials.waiting.get_mut(&key) {
        // A dial of this socket is in progress: this call waits for it.
        waiting.push(id);
        return Ok(());
    }
    let addr = read_mem(mem, a[1], (a[2] as usize).min(128))?;
    let Some((_family, ip, port)) = parse_sockaddr(&addr) else {
        return notif_respond(lfd, id, -1, libc::EAFNOSUPPORT);
    };
    if is_datagram {
        if let Some(Sock::Datagram { dest, .. }) = map.get_mut(&key) {
            *dest = Some((ip, port));
        }
        return notif_respond(lfd, id, 0, 0);
    }
    let target = match (dns.name_for_ip(ip), ip) {
        (Some(name), _) => format!("{name}:{port}"),
        (None, IpAddr::V4(v4)) => format!("{v4}:{port}"),
        (None, IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
    };
    dials.waiting.insert(key, vec![id]);
    let tx = dials.tx.clone();
    let mut done = Dialed {
        key,
        caller: Caller { id, pid, fd },
        peer: (ip, port),
        target: target.clone(),
        result: Err(anyhow::anyhow!("no dial")),
    };
    if ip.is_loopback() {
        // Loopback does not go to the proxy (issue 80): a listener of the
        // program itself (its inbound socket), else TCP on this host.
        if route.verbose {
            eprintln!("podnet-netns: connect {target} direct (loopback)");
        }
        let inbound_dir = route.inbound_dir.to_path_buf();
        tokio::spawn(async move {
            let dial = connect_loopback(&inbound_dir, ip, port);
            done.result = within_timeout("loopback connect", dial)
                .await
                .map(Link::Relay);
            let _ = tx.send(done);
        });
    } else {
        let chain = select_chain(route.rules, route.proxies, &target).to_vec();
        if route.verbose {
            eprintln!("podnet-netns: connect {target} via {}", chain[0].endpoint());
        }
        tokio::spawn(async move {
            done.result = match crate::handoff::plain_hop(&chain) {
                Some(hop) => within_timeout("upstream connect", dial_plain(hop, &target)).await,
                None => {
                    let dial = connect_upstream_async(&chain, &target);
                    within_timeout("upstream connect", dial)
                        .await
                        .map(Link::Relay)
                }
            };
            let _ = tx.send(done);
        });
    }
    Ok(())
}

/// The end of a dial: change the entry of the socket and answer each call
/// that waits for the dial and is still pending.
pub(crate) fn finish(
    lfd: RawFd,
    done: Dialed,
    map: &mut crate::fdtable::Table,
    dials: &mut Dials,
    verbose: bool,
) {
    let Dialed {
        key,
        caller,
        peer,
        target,
        result,
    } = done;
    let mut waiting = dials.waiting.remove(&key).unwrap_or_default();
    waiting.retain(|&id| notif_id_valid(lfd, id));
    if waiting.is_empty() {
        // No call waits for the dial: drop the connection.
        if verbose {
            eprintln!("podnet-netns: connect {target}: the call left; drop the dial");
        }
        return;
    }
    let answer = |errno: i32| {
        for &id in &waiting {
            let _ = notif_respond(lfd, id, if errno == 0 { 0 } else { -1 }, errno);
        }
    };
    match result {
        Ok(link) => match map.remove(&key) {
            Some(Sock::Stream {
                mut pair,
                bound,
                options,
                ..
            }) => {
                // T-063: the entry stays, for the options and the addresses.
                let entry = crate::sockopt::Connected::new(caller.fd, peer, bound, options);
                let handed = match &link {
                    Link::Plain(up) => {
                        let ends = (up, &pair);
                        crate::handoff::hand_off(lfd, caller, &waiting, ends, (map, key))
                    }
                    Link::Relay(_) => None,
                };
                if let Some(new_key) = handed {
                    // T-065: the program holds the upstream; no relay.
                    if verbose {
                        let what = "the program holds the upstream socket (no relay)";
                        eprintln!("podnet-netns: connect {target}: {what}");
                    }
                    map.insert(new_key, Sock::Connected(entry));
                    answer(0);
                    return;
                }
                let Ok(mut upstream) = link.into_relay() else {
                    return answer(libc::ECONNABORTED);
                };
                map.insert(key, Sock::Connected(entry));
                spawn_relay(async move {
                    let _ = tokio::io::copy_bidirectional(&mut pair, &mut upstream).await;
                });
                answer(0);
            }
            other => {
                // The program closed the socket during the dial.
                if let Some(sock) = other {
                    map.insert(key, sock);
                }
                answer(libc::ECONNABORTED);
            }
        },
        Err(e) => {
            if verbose {
                eprintln!("podnet-netns: upstream for {target} failed: {e:#}");
            }
            // Keep the error for SO_ERROR, as the kernel does (issue 302).
            if let Some(Sock::Stream { error, .. }) = map.get_mut(&key) {
                *error = libc::ECONNREFUSED;
            }
            answer(libc::ECONNREFUSED);
        }
    }
}

/// A loopback connect of the program: its own inbound listener on `port`
/// when there is one, else TCP to `ip:port` on this host.
async fn connect_loopback(
    inbound_dir: &std::path::Path,
    ip: IpAddr,
    port: u16,
) -> Result<crate::upstream::Upstream> {
    let own = inbound_dir.join(format!("{port}.sock"));
    if let Ok(stream) = tokio::net::UnixStream::connect(&own).await {
        return Ok(Box::new(stream));
    }
    let stream =
        crate::upstream::connect_direct(&std::net::SocketAddr::new(ip, port).to_string()).await?;
    Ok(Box::new(stream))
}
