//! Test support (issue 217): the host of a test can refuse
//! `bind(AF_INET)`, have no loopback interface, or have no resolution of
//! `localhost`. A test that needs one of these skips on such a host, with a
//! line `skipping, REASON` on standard error. It does not fail, and it does
//! not wait for a time limit.
//!
//! Each probe runs one time for each test binary.
//!
//! The unit tests of `podnet` (`src/lib.rs`) and the integration tests in
//! `tests/` include this one file as the module `test_host`. Use it at the start of a test:
//! `test_host::need_loopback!();` (`crate::test_host::` in `src/`).

#![allow(dead_code, unused_imports, unused_macros)]

use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

/// The time limit of each step of a probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// `Err(reason)` when TCP or UDP on 127.0.0.1 does not work: a bind is
/// refused, or a connect or a datagram does not arrive (no loopback).
pub(crate) fn loopback() -> Result<(), String> {
    static PROBE: OnceLock<Result<(), String>> = OnceLock::new();
    PROBE.get_or_init(probe_loopback).clone()
}

/// `Err(reason)` when the system resolver gives no address for
/// `localhost`.
pub(crate) fn localhost() -> Result<(), String> {
    static PROBE: OnceLock<Result<(), String>> = OnceLock::new();
    PROBE.get_or_init(probe_localhost).clone()
}

fn probe_loopback() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("this host denies bind(AF_INET) on 127.0.0.1 (TCP): {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("this host gives no address of a TCP socket: {e}"))?;
    TcpStream::connect_timeout(&addr, PROBE_TIMEOUT)
        .map_err(|e| format!("this host has no loopback: TCP connect to {addr}: {e}"))?;

    let bind_udp = || {
        UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| format!("this host denies bind(AF_INET) on 127.0.0.1 (UDP): {e}"))
    };
    let (sender, receiver) = (bind_udp()?, bind_udp()?);
    let to: SocketAddr = receiver
        .local_addr()
        .map_err(|e| format!("this host gives no address of a UDP socket: {e}"))?;
    let no_loopback = |e: std::io::Error| format!("this host has no loopback: UDP to {to}: {e}");
    receiver
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .map_err(no_loopback)?;
    sender.send_to(b"probe", to).map_err(no_loopback)?;
    let mut buf = [0u8; 8];
    receiver.recv_from(&mut buf).map_err(no_loopback)?;
    Ok(())
}

fn probe_localhost() -> Result<(), String> {
    match ("localhost", 0).to_socket_addrs() {
        Ok(addrs) if addrs.len() > 0 => Ok(()),
        Ok(_) => Err("this host resolves localhost to no address".into()),
        Err(e) => Err(format!("this host does not resolve localhost: {e}")),
    }
}

/// Write `skipping, REASON` to the standard error of the process. The
/// test harness does not capture this write (it captures `eprintln!`), so
/// the line shows for a test that passes too.
pub(crate) fn skip_line(why: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "skipping, {why}");
}

/// Skip the test (return from it) when [`loopback`] fails. Give a value
/// for a test that returns one: `need_loopback!(Ok(()))`.
macro_rules! need_loopback {
    () => {
        $crate::test_host::need_loopback!(())
    };
    ($ret:expr) => {
        if let Err(why) = $crate::test_host::loopback() {
            $crate::test_host::skip_line(&why);
            return $ret;
        }
    };
}

/// Skip the test (return from it) when [`localhost`] fails.
macro_rules! need_localhost {
    () => {
        if let Err(why) = $crate::test_host::localhost() {
            $crate::test_host::skip_line(&why);
            return;
        }
    };
}

pub(crate) use {need_localhost, need_loopback};
