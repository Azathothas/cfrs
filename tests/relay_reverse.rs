//! The reverse mode of the relay (issue 88) against a local fake relay:
//! two sessions at the same time through one node, a refused session, and
//! a node socket that the relay drops (the node opens it again).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cfrs::relay_reverse::{connect, node, Pair, Target};
use cfrs::ws_relay::Relay;
use futures::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

const NAME: &str = "testnode";

#[derive(Default)]
struct State {
    /// The messages to the node socket of now.
    node: Option<mpsc::UnboundedSender<Message>>,
    /// The messages to each operator socket, by session id.
    operators: HashMap<String, mpsc::UnboundedSender<Message>>,
    /// How many node sockets came.
    node_sockets: usize,
    /// Drop the first node socket after this many ms.
    drop_first_after: Option<u64>,
}

/// A relay on loopback with the reverse protocol of tcp.ssh.relay.ajam.dev:
/// `/v1/node/NAME` (token "node") and `/v1/connect/NAME` (token "connect").
async fn fake_relay(drop_first_after: Option<u64>) -> (String, Arc<Mutex<State>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(State {
        drop_first_after,
        ..State::default()
    }));
    let shared = state.clone();
    tokio::spawn(async move {
        let mut next_id = 0u32;
        while let Ok((socket, _)) = listener.accept().await {
            next_id += 1;
            let state = shared.clone();
            let id = format!("{next_id:032x}");
            tokio::spawn(serve(socket, state, id));
        }
    });
    (url, state)
}

#[allow(clippy::result_large_err)] // the callback type of tungstenite
async fn serve(socket: tokio::net::TcpStream, state: Arc<Mutex<State>>, id: String) {
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    let path = Arc::new(Mutex::new(String::new()));
    let seen = path.clone();
    let check = move |request: &Request, response: Response| {
        let token = request
            .headers()
            .get("x-relay-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let path = request.uri().path().to_string();
        let good = (path == format!("/v1/node/{NAME}") && token == "node")
            || (path == format!("/v1/connect/{NAME}") && token == "connect");
        *seen.lock().unwrap() = path;
        if good {
            Ok(response)
        } else {
            let mut refused = ErrorResponse::new(Some("missing or wrong token".into()));
            *refused.status_mut() = http::StatusCode::FORBIDDEN;
            Err(refused)
        }
    };
    let Ok(ws) = tokio_tungstenite::accept_hdr_async(socket, check).await else {
        return;
    };
    let path = path.lock().unwrap().clone();
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let close = matches!(message, Message::Close(_));
            if sink.send(message).await.is_err() || close {
                break;
            }
        }
    });
    if path.starts_with("/v1/node/") {
        let drop_after = {
            let mut state = state.lock().unwrap();
            state.node = Some(tx.clone());
            state.node_sockets += 1;
            if state.node_sockets == 1 {
                state.drop_first_after
            } else {
                None
            }
        };
        let _ = tx.send(Message::text(r#"{"type":"hello"}"#));
        if let Some(ms) = drop_after {
            let tx = tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let _ = tx.send(Message::Close(Some(CloseFrame {
                    code: CloseCode::from(1011),
                    reason: "socket error".into(),
                })));
            });
        }
        while let Some(Ok(message)) = stream.next().await {
            match message {
                Message::Text(text) => {
                    let doc: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                    let id = doc["id"].as_str().unwrap_or("").to_string();
                    let operator = state.lock().unwrap().operators.get(&id).cloned();
                    let Some(operator) = operator else { continue };
                    match doc["type"].as_str() {
                        Some("ready") => {
                            let _ = operator.send(Message::text(r#"{"type":"ready"}"#));
                        }
                        Some("reject") => {
                            let _ = operator.send(Message::text(text.to_string()));
                            let _ = operator.send(Message::Close(Some(CloseFrame {
                                code: CloseCode::from(1011),
                                reason: "reject".into(),
                            })));
                        }
                        Some("close") => {
                            let _ = operator.send(Message::Close(Some(CloseFrame {
                                code: CloseCode::Normal,
                                reason: "close".into(),
                            })));
                        }
                        _ => {}
                    }
                }
                Message::Binary(data) => {
                    assert!(data.len() > 32, "a node frame has the id first");
                    let id = std::str::from_utf8(&data[..32]).unwrap().to_string();
                    let operator = state.lock().unwrap().operators.get(&id).cloned();
                    if let Some(operator) = operator {
                        let _ = operator.send(Message::binary(data[32..].to_vec()));
                    }
                }
                _ => {}
            }
        }
    } else {
        state
            .lock()
            .unwrap()
            .operators
            .insert(id.clone(), tx.clone());
        let node = state.lock().unwrap().node.clone();
        let Some(node) = node else {
            let _ = tx.send(Message::Close(Some(CloseFrame {
                code: CloseCode::from(1011),
                reason: "node offline".into(),
            })));
            return;
        };
        let _ = node.send(Message::text(format!(r#"{{"type":"open","id":"{id}"}}"#)));
        while let Some(Ok(message)) = stream.next().await {
            match message {
                Message::Binary(data) => {
                    let mut frame = id.as_bytes().to_vec();
                    frame.extend_from_slice(&data);
                    let _ = node.send(Message::binary(frame));
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = node.send(Message::text(format!(r#"{{"type":"close","id":"{id}"}}"#)));
        let _ = tx.send(Message::Close(None));
    }
    let _ = writer.await;
}

fn pair(url: &str) -> Pair {
    Pair {
        name: NAME.into(),
        node_token: "node".into(),
        connect_token: "connect".into(),
        stop_token: String::new(),
        expires: (std::time::SystemTime::now() + Duration::from_secs(3600))
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        relay: url.into(),
    }
}

/// A TCP echo server; gives its address.
async fn echo() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// One operator session: send `data`, read the same bytes back.
async fn round_trip(relay: Arc<Relay>, data: Vec<u8>) -> Vec<u8> {
    let (ours, theirs) = tokio::io::duplex(1 << 20);
    let session = tokio::spawn(async move {
        let (read, write) = tokio::io::split(theirs);
        connect(&relay, NAME, "connect", read, write).await
    });
    let (mut read, mut write) = tokio::io::split(ours);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        write.write_all(&sent).await.unwrap();
        write
    });
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(20), read.read_exact(&mut back))
        .await
        .expect("the bytes come back")
        .unwrap();
    let write = writer.await.unwrap();
    drop(write);
    drop(read);
    let _ = tokio::time::timeout(Duration::from_secs(10), session).await;
    back
}

/// A TCP target that reads one line, answers HELLO:<line> after 300 ms,
/// and closes.
async fn hello() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while socket.read_exact(&mut byte).await.is_ok() {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                let mut answer = b"HELLO:".to_vec();
                answer.extend_from_slice(&line);
                let _ = socket.write_all(&answer).await;
            });
        }
    });
    addr
}

// Issue 109: an input that ends at once (printf PING | cfrs relay connect)
// still gets the answer of the target. Before, the close of the input
// closed the session, and the output was empty.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_comes_back_after_the_input_ends() {
    let (url, state) = fake_relay(None).await;
    let target = Target::parse(&hello().await).unwrap();
    let node_relay = Relay::new(&url, None).unwrap();
    let node_pair = pair(&url);
    tokio::spawn(async move { node(&node_relay, &node_pair, &target).await });
    wait_for_node(&state, 1).await;
    let relay = Relay::new(&url, None).unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(20),
        connect(&relay, NAME, "connect", &b"PING\n"[..], &mut out),
    )
    .await
    .expect("the session ends")
    .unwrap();
    assert_eq!(out, b"HELLO:PING\n");
}

// Issue 109: a target that waits for the end of the input (it has no
// half-close) ends the session after EOF_IDLE.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_ends_after_the_idle_time_when_the_input_ended() {
    let (url, state) = fake_relay(None).await;
    let target = Target::parse(&echo().await).unwrap();
    let node_relay = Relay::new(&url, None).unwrap();
    let node_pair = pair(&url);
    tokio::spawn(async move { node(&node_relay, &node_pair, &target).await });
    wait_for_node(&state, 1).await;
    let relay = Relay::new(&url, None).unwrap();
    let mut out = Vec::new();
    let start = std::time::Instant::now();
    tokio::time::timeout(
        cfrs::relay_reverse::EOF_IDLE + Duration::from_secs(10),
        connect(&relay, NAME, "connect", &b"PING\n"[..], &mut out),
    )
    .await
    .expect("the session ends")
    .unwrap();
    assert_eq!(out, b"PING\n");
    assert!(start.elapsed() >= cfrs::relay_reverse::EOF_IDLE);
}

async fn wait_for_node(state: &Arc<Mutex<State>>, sockets: usize) {
    for _ in 0..200 {
        if state.lock().unwrap().node_sockets >= sockets {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no node socket {sockets}");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_sessions_at_the_same_time_through_one_node() {
    let (url, state) = fake_relay(None).await;
    let target = Target::parse(&echo().await).unwrap();
    let node_relay = Relay::new(&url, None).unwrap();
    let node_pair = pair(&url);
    tokio::spawn(async move { node(&node_relay, &node_pair, &target).await });
    wait_for_node(&state, 1).await;
    let relay = Arc::new(Relay::new(&url, None).unwrap());
    let a: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let b: Vec<u8> = (0..200_000u32).map(|i| (i % 13) as u8 + 100).collect();
    let (back_a, back_b) = tokio::join!(
        round_trip(relay.clone(), a.clone()),
        round_trip(relay.clone(), b.clone())
    );
    assert!(back_a == a, "session a");
    assert!(back_b == b, "session b");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_to_a_closed_port_is_refused_with_the_reason() {
    let (url, state) = fake_relay(None).await;
    // A port with no listener.
    let closed = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let target = Target::parse(&closed).unwrap();
    let node_relay = Relay::new(&url, None).unwrap();
    let node_pair = pair(&url);
    tokio::spawn(async move { node(&node_relay, &node_pair, &target).await });
    wait_for_node(&state, 1).await;
    let relay = Relay::new(&url, None).unwrap();
    let err = connect(
        &relay,
        NAME,
        "connect",
        tokio::io::empty(),
        tokio::io::sink(),
    )
    .await
    .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("refused the session"), "{text}");
    assert!(
        text.contains(&closed),
        "the reason names the target: {text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_node_socket_is_opened_again() {
    let (url, state) = fake_relay(Some(300)).await;
    let target = Target::parse(&echo().await).unwrap();
    let node_relay = Relay::new(&url, None).unwrap();
    let node_pair = pair(&url);
    tokio::spawn(async move { node(&node_relay, &node_pair, &target).await });
    // The relay drops the first socket; the node comes back in 1 to 2 s.
    wait_for_node(&state, 2).await;
    let relay = Arc::new(Relay::new(&url, None).unwrap());
    let data = b"after the reconnect".to_vec();
    assert_eq!(round_trip(relay, data.clone()).await, data);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_connect_token_is_a_config_error() {
    let (url, _state) = fake_relay(None).await;
    let relay = Relay::new(&url, None).unwrap();
    let err = connect(&relay, NAME, "wrong", tokio::io::empty(), tokio::io::sink())
        .await
        .unwrap_err();
    assert_eq!(cfrs::exit::code_of(&err), cfrs::exit::CONFIG);
}

/// A relay that sends ready, part of an answer, then the close `code`.
async fn closing_relay(code: u16) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                let _ = ws.send(Message::text(r#"{"type":"ready"}"#)).await;
                let _ = ws.send(Message::binary(b"part".to_vec())).await;
                let _ = ws
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::from(code),
                        reason: "limit".into(),
                    })))
                    .await;
                while ws.next().await.is_some() {}
            });
        }
    });
    url
}

// podssh #84: a close other than 1000 after the end of the input is an
// error (exit 69): the output can be cut. Before, it exited 0.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_with_an_error_code_after_the_input_ends_is_an_error() {
    let url = closing_relay(1009).await;
    let relay = Relay::new(&url, None).unwrap();
    let mut out = Vec::new();
    let err = tokio::time::timeout(
        Duration::from_secs(20),
        connect(&relay, NAME, "connect", &b""[..], &mut out),
    )
    .await
    .expect("the session ends")
    .unwrap_err();
    assert_eq!(out, b"part");
    assert_eq!(cfrs::exit::code_of(&err), 69, "{err:#}");
    assert!(format!("{err:#}").contains("1009"), "{err:#}");
    // A normal close is a success.
    let url = closing_relay(1000).await;
    let relay = Relay::new(&url, None).unwrap();
    let mut out = Vec::new();
    connect(&relay, NAME, "connect", &b""[..], &mut out)
        .await
        .unwrap();
    assert_eq!(out, b"part");
}
