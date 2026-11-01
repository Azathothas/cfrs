//! The Cap'n Proto RPC subset that registers a tunnel connection.
//!
//! Reference: `rpc.capnp` of Cap'n Proto (the two-party protocol). The
//! control stream carries one framed RPC message after the other, in the two
//! directions. This module implements these exchanges:
//!
//! | Direction | Messages |
//! | --- | --- |
//! | cfrs to edge | `Bootstrap` (question 0); `Call registerConnection` on the bootstrap capability (question 1); `Call unregisterConnection` at shutdown; `Finish` for each answer |
//! | edge to cfrs | `Return` for each question; `Bootstrap` (cfrs answers with its capability, export 0); `Call` on that capability (cfrs answers with an `unimplemented` exception); `Finish`, `Release`, `Abort` |
//!
//! The edge uses the bootstrap of cfrs as a liveness check. Without an answer,
//! the edge marks the tunnel as down.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::capnp::{Builder, Message, StructReader};
use super::schema::{
    read_register_results, write_register_params, METHOD_REGISTER_CONNECTION,
    METHOD_UNREGISTER_CONNECTION, REGISTRATION_SERVER_ID,
};

/// A refusal of the registration by the edge, with its retry flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub cause: String,
    pub should_retry: bool,
    pub retry_after: Duration,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the edge refused the registration: {} (retry: {}, after {} s; cfrs speaks {})",
            self.cause,
            if self.should_retry { "yes" } else { "no" },
            self.retry_after.as_secs(),
            crate::cloudflare::SPEAKS
        )
    }
}

impl std::error::Error for Refused {}

pub use super::schema::{ConnectionError, ConnectionOptions, RegistrationDetails, TunnelAuth};

/// The longest time for the registration.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// The text of the edge when the same connection index is registered.
pub const DUPLICATE_CONNECTION_ERROR: &str = "connection with this index already registered";

// rpc.capnp: `Message` union tags (u16 at index 0, struct in pointer 0).
const MSG_UNIMPLEMENTED: u16 = 0;
const MSG_ABORT: u16 = 1;
const MSG_CALL: u16 = 2;
const MSG_RETURN: u16 = 3;
const MSG_FINISH: u16 = 4;
const MSG_RELEASE: u16 = 6;
const MSG_BOOTSTRAP: u16 = 8;
// `Return` union tags (u16 at index 3).
const RETURN_RESULTS: u16 = 0;
const RETURN_EXCEPTION: u16 = 1;
// `CapDescriptor` union tags (u16 at index 0).
const CAP_SENDER_HOSTED: u16 = 1;
const CAP_SENDER_PROMISE: u16 = 2;
// `Exception.Type`.
const EXCEPTION_UNIMPLEMENTED: u16 = 3;
/// The capability that cfrs exports to the edge.
const OUR_EXPORT: u32 = 0;

/// What the edge answered to a question.
#[derive(Debug)]
enum Answer {
    Results(Message),
    Exception(String),
    Other(u16),
}

/// The open control stream. Keep it while the connection is in use. Drop it,
/// or call [`ControlSession::shutdown_graceful`], to end the registration.
pub struct ControlSession {
    shutdown: Option<oneshot::Sender<Duration>>,
    task: JoinHandle<()>,
}

impl ControlSession {
    /// Send `unregisterConnection`, wait for the answer up to `grace`, then
    /// close the control stream.
    pub async fn shutdown_graceful(mut self, grace: Duration) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(grace);
        }
        let _ = tokio::time::timeout(grace + Duration::from_secs(1), &mut self.task).await;
    }
}

impl Drop for ControlSession {
    fn drop(&mut self) {
        if self.shutdown.is_some() {
            self.task.abort();
        }
    }
}

/// Open the control stream on `conn` and register the connection.
pub async fn register_connection(
    conn: &quinn::Connection,
    auth: &TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &ConnectionOptions,
) -> Result<(RegistrationDetails, ControlSession)> {
    let (send, recv) = conn.open_bi().await.context("opening the control stream")?;
    register_connection_on(recv, send, auth, tunnel_id, conn_index, options).await
}

/// Register the connection over a control stream that is already open: a
/// QUIC stream, or the bodies of the HTTP/2 control-stream request.
pub async fn register_connection_on<R, W>(
    reader: R,
    writer: W,
    auth: &TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &ConnectionOptions,
) -> Result<(RegistrationDetails, ControlSession)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (incoming_tx, incoming) = mpsc::channel(64);
    let reader_task = tokio::spawn(read_loop(reader, incoming_tx));
    let (result_tx, result_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut session = Session {
        writer,
        incoming,
        answers: HashMap::new(),
        next_question: 0,
    };
    let register = encode_register(auth, tunnel_id, conn_index, options);
    let task = tokio::spawn(async move {
        session.run(register, result_tx, shutdown_rx).await;
        reader_task.abort();
    });
    let details = tokio::time::timeout(DEFAULT_RPC_TIMEOUT, result_rx)
        .await
        .map_err(|_| anyhow::anyhow!("registerConnection timed out"))?
        .map_err(|_| anyhow::anyhow!("the control stream closed before the registration"))??;
    info!(uuid = %details.uuid, location = %details.location, conn_index, "registered with the edge");
    Ok((
        details,
        ControlSession {
            shutdown: Some(shutdown_tx),
            task,
        },
    ))
}

async fn read_loop<R>(mut reader: R, tx: mpsc::Sender<Message>)
where
    R: AsyncRead + Unpin,
{
    loop {
        match Message::read(&mut reader).await {
            Ok(Some(message)) => {
                if tx.send(message).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(err) => {
                debug!(error = %err, "the control stream sent a bad message");
                return;
            }
        }
    }
}

/// The parameters of `registerConnection`, written later into a `Call`.
struct RegisterArgs {
    auth: TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: ConnectionOptions,
}

fn encode_register(
    auth: &TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    options: &ConnectionOptions,
) -> RegisterArgs {
    RegisterArgs {
        auth: auth.clone(),
        tunnel_id,
        conn_index,
        options: options.clone(),
    }
}

struct Session<W> {
    writer: W,
    incoming: mpsc::Receiver<Message>,
    answers: HashMap<u32, Answer>,
    next_question: u32,
}

impl<W: AsyncWrite + Unpin> Session<W> {
    async fn send(&mut self, b: Builder) -> Result<()> {
        self.writer.write_all(&b.to_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    fn question(&mut self) -> u32 {
        let id = self.next_question;
        self.next_question += 1;
        id
    }

    /// Wait for the answer to `question`, and serve the messages of the edge
    /// meanwhile.
    async fn wait(&mut self, question: u32) -> Result<Answer> {
        loop {
            if let Some(answer) = self.answers.remove(&question) {
                return Ok(answer);
            }
            let message = self
                .incoming
                .recv()
                .await
                .context("the control stream closed")?;
            if !self.handle(message).await? {
                bail!("the edge aborted the control stream");
            }
        }
    }

    /// Handle one message from the edge. Return false when the stream must end.
    async fn handle(&mut self, message: Message) -> Result<bool> {
        let kind = message.root()?.get_u16(0);
        if kind == MSG_RETURN {
            let (answer_id, answer) = {
                let ret = message.root()?.get_struct(0)?.context("an empty Return")?;
                let answer = match ret.get_u16(3) {
                    RETURN_RESULTS => None,
                    RETURN_EXCEPTION => Some(Answer::Exception(exception_reason(&ret)?)),
                    other => Some(Answer::Other(other)),
                };
                (ret.get_u32(0), answer)
            };
            let answer = answer.unwrap_or(Answer::Results(message));
            self.answers.insert(answer_id, answer);
            return Ok(true);
        }
        let root = message.root()?;
        match kind {
            MSG_BOOTSTRAP => {
                let question = root
                    .get_struct(0)?
                    .context("an empty Bootstrap")?
                    .get_u32(0);
                self.send(our_bootstrap_return(question)).await?;
            }
            MSG_CALL => {
                let call = root.get_struct(0)?.context("an empty Call")?;
                let question = call.get_u32(0);
                let interface = call.get_u64(1);
                let method = call.get_u16(2);
                debug!(interface = %format!("{interface:#x}"), method, "the edge called cfrs");
                self.send(exception_return(question, "not implemented by cfrs"))
                    .await?;
            }
            MSG_FINISH | MSG_RELEASE => {}
            MSG_ABORT => {
                let reason = root
                    .get_struct(0)?
                    .map(|e| e.get_text(0).unwrap_or_default())
                    .unwrap_or_default();
                warn!(%reason, "the edge aborted the control stream");
                return Ok(false);
            }
            MSG_UNIMPLEMENTED => debug!("the edge did not understand a message of cfrs"),
            other => debug!(kind = other, "ignored an RPC message"),
        }
        Ok(true)
    }

    async fn run(
        &mut self,
        register: RegisterArgs,
        result: oneshot::Sender<Result<RegistrationDetails>>,
        shutdown: oneshot::Receiver<Duration>,
    ) {
        let import = match self.bootstrap().await {
            Ok(import) => import,
            Err(err) => {
                let _ = result.send(Err(err));
                return;
            }
        };
        let registered = self.register(import, &register).await;
        let ok = registered.is_ok();
        let _ = result.send(registered);
        if !ok {
            return;
        }
        // Serve the edge until the stream ends or a shutdown is asked.
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                grace = &mut shutdown => {
                    if let Ok(grace) = grace {
                        self.unregister(import, grace).await;
                    }
                    let _ = self.writer.shutdown().await;
                    return;
                }
                message = self.incoming.recv() => {
                    let Some(message) = message else {
                        debug!("the edge closed the control stream");
                        return;
                    };
                    match self.handle(message).await {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(err) => {
                            debug!(error = %err, "control stream error");
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Ask for the bootstrap capability of the edge. Return its import id.
    async fn bootstrap(&mut self) -> Result<u32> {
        let question = self.question();
        let mut b = Builder::new();
        let root = b.init_root(1, 1);
        b.set_u16(root, 0, MSG_BOOTSTRAP);
        let boot = b.init_struct(root, 0, 1, 1);
        b.set_u32(boot, 0, question);
        self.send(b).await?;
        let import = match self.wait(question).await? {
            Answer::Results(message) => imported_capability(&message)?,
            Answer::Exception(reason) => bail!("the edge refused the bootstrap: {reason}"),
            Answer::Other(kind) => bail!("the edge answered the bootstrap with kind {kind}"),
        };
        // Keep the capability: releaseResultCaps = false.
        self.send(finish(question, false)).await?;
        Ok(import)
    }

    async fn call(
        &mut self,
        import: u32,
        method: u16,
        params: impl FnOnce(&mut Builder, super::capnp::StructRef),
    ) -> Result<u32> {
        let question = self.question();
        let mut b = Builder::new();
        let root = b.init_root(1, 1);
        b.set_u16(root, 0, MSG_CALL);
        // Call: 3 data words, 3 pointers.
        let call = b.init_struct(root, 0, 3, 3);
        b.set_u32(call, 0, question);
        b.set_u64(call, 1, REGISTRATION_SERVER_ID);
        b.set_u16(call, 2, method);
        // sendResultsTo = caller (u16 at index 3 stays 0).
        // MessageTarget: 1 data word, 1 pointer; importedCap.
        let target = b.init_struct(call, 0, 1, 1);
        b.set_u32(target, 0, import);
        // Payload: content (pointer 0), capTable (pointer 1, empty).
        let payload = b.init_struct(call, 1, 0, 2);
        params(&mut b, payload);
        self.send(b).await?;
        Ok(question)
    }

    async fn register(&mut self, import: u32, args: &RegisterArgs) -> Result<RegistrationDetails> {
        let question = self
            .call(import, METHOD_REGISTER_CONNECTION, |b, payload| {
                write_register_params(
                    b,
                    payload,
                    0,
                    &args.auth,
                    args.tunnel_id,
                    args.conn_index,
                    &args.options,
                );
            })
            .await?;
        let answer = self.wait(question).await?;
        self.send(finish(question, true)).await?;
        match answer {
            Answer::Results(message) => {
                let results = results_struct(&message)?;
                match read_register_results(&results)? {
                    Ok(details) => Ok(details),
                    Err(err) => Err(anyhow::Error::new(Refused {
                        cause: err.cause.clone(),
                        should_retry: err.should_retry,
                        retry_after: Duration::from_nanos(err.retry_after.max(0) as u64),
                    })),
                }
            }
            Answer::Exception(reason) => bail!(
                "registerConnection failed: {reason} (cfrs speaks {})",
                crate::cloudflare::SPEAKS
            ),
            Answer::Other(kind) => bail!(
                "registerConnection answered with kind {kind} (cfrs speaks {})",
                crate::cloudflare::SPEAKS
            ),
        }
    }

    async fn unregister(&mut self, import: u32, grace: Duration) {
        let Ok(question) = self
            .call(import, METHOD_UNREGISTER_CONNECTION, |b, payload| {
                b.init_struct(payload, 0, 0, 0);
            })
            .await
        else {
            return;
        };
        match tokio::time::timeout(grace, self.wait(question)).await {
            Ok(Ok(_)) => {
                let _ = self.send(finish(question, true)).await;
                debug!("unregistered the connection");
            }
            Ok(Err(err)) => debug!(error = %err, "unregisterConnection failed"),
            Err(_) => debug!("unregisterConnection timed out"),
        }
    }
}

fn exception_reason(ret: &StructReader<'_>) -> Result<String> {
    Ok(ret
        .get_struct(0)?
        .map(|e| e.get_text(0).unwrap_or_default())
        .unwrap_or_default())
}

/// The `Payload` of a `Return` with results.
fn payload<'a>(message: &'a Message) -> Result<StructReader<'a>> {
    message
        .root()?
        .get_struct(0)?
        .context("an empty Return")?
        .get_struct(0)?
        .context("a Return with no payload")
}

/// The content struct of the results.
fn results_struct(message: &Message) -> Result<StructReader<'_>> {
    payload(message)?
        .get_struct(0)?
        .context("the results have no content")
}

/// The import id of the capability in the results of a bootstrap.
fn imported_capability(message: &Message) -> Result<u32> {
    let payload = payload(message)?;
    let index = payload
        .get_capability(0)?
        .context("the bootstrap answer has no capability")?;
    let table = payload.get_struct_list(1)?;
    let descriptor = table
        .get(index as usize)
        .context("the capability is not in the cap table")?;
    match descriptor.get_u16(0) {
        CAP_SENDER_HOSTED | CAP_SENDER_PROMISE => Ok(descriptor.get_u32(1)),
        other => bail!("unsupported capability descriptor {other}"),
    }
}

/// `Finish` for `question`.
fn finish(question: u32, release_result_caps: bool) -> Builder {
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_FINISH);
    let f = b.init_struct(root, 0, 1, 0);
    b.set_u32(f, 0, question);
    // The default of releaseResultCaps is true: the stored bit is the XOR.
    b.set_bool(f, 32, !release_result_caps);
    b
}

/// The answer to a `Bootstrap` of the edge: our capability, export 0.
fn our_bootstrap_return(question: u32) -> Builder {
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_RETURN);
    // Return: 2 data words, 1 pointer.
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, question);
    b.set_u16(ret, 3, RETURN_RESULTS);
    let payload = b.init_struct(ret, 0, 0, 2);
    b.set_capability(payload, 0, 0);
    // CapDescriptor: 1 data word, 1 pointer.
    let table = b.init_struct_list(payload, 1, 1, 1, 1);
    b.set_u16(table[0], 0, CAP_SENDER_HOSTED);
    b.set_u32(table[0], 1, OUR_EXPORT);
    b
}

/// A `Return` with an `unimplemented` exception for `question`.
fn exception_return(question: u32, reason: &str) -> Builder {
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_RETURN);
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, question);
    b.set_u16(ret, 3, RETURN_EXCEPTION);
    // Exception: 1 data word, 2 pointers; type is u16 at index 2.
    let exception = b.init_struct(ret, 0, 1, 2);
    b.set_text(exception, 0, reason);
    b.set_u16(exception, 2, EXCEPTION_UNIMPLEMENTED);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake edge on the other end of an in-memory stream. It does what the
    /// edge does: it bootstraps cfrs, answers the bootstrap of cfrs, and
    /// answers registerConnection with connection details.
    async fn fake_edge(
        stream: tokio::io::DuplexStream,
        seen: oneshot::Sender<(u8, String, Vec<String>, bool)>,
    ) {
        let (mut read, mut write) = tokio::io::split(stream);
        let send = |b: Builder| b.to_bytes();
        // The edge asks for the bootstrap of cfrs (question 7).
        let mut b = Builder::new();
        let root = b.init_root(1, 1);
        b.set_u16(root, 0, MSG_BOOTSTRAP);
        let boot = b.init_struct(root, 0, 1, 1);
        b.set_u32(boot, 0, 7);
        write.write_all(&send(b)).await.unwrap();

        let mut answered_ours = false;
        let mut seen = Some(seen);
        let mut unregistered = false;
        while let Some(message) = Message::read(&mut read).await.unwrap() {
            let root = message.root().unwrap();
            match root.get_u16(0) {
                MSG_BOOTSTRAP => {
                    let q = root.get_struct(0).unwrap().unwrap().get_u32(0);
                    let mut b = Builder::new();
                    let r = b.init_root(1, 1);
                    b.set_u16(r, 0, MSG_RETURN);
                    let ret = b.init_struct(r, 0, 2, 1);
                    b.set_u32(ret, 0, q);
                    let payload = b.init_struct(ret, 0, 0, 2);
                    b.set_capability(payload, 0, 0);
                    let table = b.init_struct_list(payload, 1, 1, 1, 1);
                    b.set_u16(table[0], 0, CAP_SENDER_HOSTED);
                    b.set_u32(table[0], 1, 42);
                    write.write_all(&send(b)).await.unwrap();
                }
                MSG_RETURN => {
                    // The answer of cfrs to question 7: one capability.
                    let ret = root.get_struct(0).unwrap().unwrap();
                    assert_eq!(ret.get_u32(0), 7);
                    let payload = ret.get_struct(0).unwrap().unwrap();
                    assert_eq!(payload.get_capability(0).unwrap(), Some(0));
                    answered_ours = true;
                }
                MSG_CALL => {
                    let call = root.get_struct(0).unwrap().unwrap();
                    let q = call.get_u32(0);
                    assert_eq!(call.get_u64(1), REGISTRATION_SERVER_ID);
                    let target = call.get_struct(0).unwrap().unwrap();
                    assert_eq!(target.get_u32(0), 42, "the call targets the import");
                    if call.get_u16(2) == METHOD_UNREGISTER_CONNECTION {
                        unregistered = true;
                    } else {
                        let params = call
                            .get_struct(1)
                            .unwrap()
                            .unwrap()
                            .get_struct(0)
                            .unwrap()
                            .unwrap();
                        let auth = params.get_struct(0).unwrap().unwrap();
                        let client = params
                            .get_struct(2)
                            .unwrap()
                            .unwrap()
                            .get_struct(0)
                            .unwrap()
                            .unwrap();
                        if let Some(tx) = seen.take() {
                            let _ = tx.send((
                                params.get_u8(0),
                                auth.get_text(0).unwrap(),
                                client.get_text_list(1).unwrap(),
                                answered_ours,
                            ));
                        }
                    }
                    let mut b = Builder::new();
                    let r = b.init_root(1, 1);
                    b.set_u16(r, 0, MSG_RETURN);
                    let ret = b.init_struct(r, 0, 2, 1);
                    b.set_u32(ret, 0, q);
                    let payload = b.init_struct(ret, 0, 0, 2);
                    let results = b.init_struct(payload, 0, 0, 1);
                    let response = b.init_struct(results, 0, 1, 1);
                    b.set_u16(response, 0, 1);
                    let details = b.init_struct(response, 0, 1, 2);
                    b.set_data(details, 0, Uuid::nil().as_bytes());
                    b.set_text(details, 1, "test1");
                    write.write_all(&send(b)).await.unwrap();
                }
                MSG_FINISH => {}
                other => panic!("unexpected message {other}"),
            }
        }
        assert!(unregistered, "cfrs unregisters at shutdown");
    }

    #[tokio::test]
    async fn registers_against_a_fake_edge() {
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let (seen_tx, seen_rx) = oneshot::channel();
        let edge = tokio::spawn(fake_edge(theirs, seen_tx));
        let (read, write) = tokio::io::split(ours);
        let auth = TunnelAuth {
            account_tag: "acct".into(),
            tunnel_secret: vec![1; 32],
        };
        let options = ConnectionOptions::default_for_quick_tunnel("cfrs/test");
        let (details, session) =
            register_connection_on(read, write, &auth, Uuid::new_v4(), 2, &options)
                .await
                .unwrap();
        assert_eq!(details.location, "test1");
        let (index, account, features, answered) = seen_rx.await.unwrap();
        assert_eq!(index, 2);
        assert_eq!(account, "acct");
        assert_eq!(features, ["support_datagram_v2".to_string()]);
        assert!(answered, "cfrs answered the bootstrap of the edge first");
        session.shutdown_graceful(Duration::from_secs(2)).await;
        edge.await.unwrap();
    }

    #[test]
    fn finish_stores_the_xor_of_the_default() {
        let (msg, _) = Message::parse(&finish(3, false).to_bytes())
            .unwrap()
            .unwrap();
        let f = msg.root().unwrap().get_struct(0).unwrap().unwrap();
        assert_eq!(f.get_u32(0), 3);
        assert!(f.get_bool(32), "releaseResultCaps = false is stored as 1");
        let (msg, _) = Message::parse(&finish(3, true).to_bytes())
            .unwrap()
            .unwrap();
        let f = msg.root().unwrap().get_struct(0).unwrap().unwrap();
        assert!(!f.get_bool(32));
    }

    #[test]
    fn the_edge_gets_an_exception_for_its_calls() {
        let (msg, _) = Message::parse(&exception_return(9, "no").to_bytes())
            .unwrap()
            .unwrap();
        let ret = msg.root().unwrap().get_struct(0).unwrap().unwrap();
        assert_eq!(ret.get_u32(0), 9);
        assert_eq!(ret.get_u16(3), RETURN_EXCEPTION);
        let e = ret.get_struct(0).unwrap().unwrap();
        assert_eq!(e.get_text(0).unwrap(), "no");
        assert_eq!(e.get_u16(2), EXCEPTION_UNIMPLEMENTED);
    }
}
