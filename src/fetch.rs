//! A small HTTP/1.1 client for the requests of podnet: the quick-tunnel API,
//! DNS over HTTPS, the WARP API and the fetch of the public URL.
//!
//! It is the client of `pod-proxy` (PodUtils/podcrates) over the dial of
//! [`crate::egress`] (so each request takes the proxy, `NO_PROXY` and the
//! attempt delay of that module), with the roots of [`crate::trust`] for
//! `https://` (ALPN `http/1.1`) and podnet's user agent. Each request sends
//! `Connection: close`; the body of the answer is read by `Content-Length`,
//! by chunks, or to the end of the connection, up to [`MAX_BODY`] bytes, or
//! up to the limit of [`Request::max_body`]. [`send`] gives a failure
//! podnet's words and its hop.

use std::sync::OnceLock;

use anyhow::{Context as _, Result};
use pod_core::{Failure, Stage};

pub use pod_proxy::client::{Request, MAX_BODY};
pub use pod_proxy::http::Response;

use crate::egress::Refusal;
use crate::hop::{self, AtHop, Hop};

/// The client of the process.
fn client() -> &'static pod_proxy::Client {
    static CLIENT: OnceLock<pod_proxy::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        pod_proxy::Client::new(crate::trust::context().clone(), crate::egress::egress(None))
            .with_user_agent(format!("podnet/{}", env!("CARGO_PKG_VERSION")))
    })
}

/// Send `request` and read the answer, the whole within its time limit.
pub async fn send(request: Request) -> Result<Response> {
    let what = format!("{} {}", request.method, without_query(&request.url));
    client()
        .send(request)
        .await
        .map_err(|failure| failed(failure, &what))
}

/// The JSON of the body of an answer.
pub fn json<T: serde::de::DeserializeOwned>(response: &Response) -> Result<T> {
    serde_json::from_slice(&response.body).context("decoding the JSON body")
}

fn without_query(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// A failed request in podnet's words: the request and why, each cause
/// once. The dial's refusal and hop stay as [`crate::egress`] made them; a
/// handshake that the network ended is at the hop `network`, in the words of
/// [`hop::tls_text`], and one that TLS refused at the hop `tls`.
fn failed(failure: Failure, what: &str) -> anyhow::Error {
    let (mut refusal, mut dialed, mut io) = (None, None, None);
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(&failure);
    while let Some(e) = next {
        refusal = refusal.or_else(|| e.downcast_ref::<Refusal>().cloned());
        dialed = dialed.or_else(|| e.downcast_ref::<AtHop>().map(|h| h.hop));
        io = io.or_else(|| e.downcast_ref::<std::io::Error>());
        next = e.source();
    }
    let text = match (failure.stage, io) {
        (Stage::Network, Some(io)) if dialed.is_none() => {
            format!("{what}: TLS: {}", hop::tls_text(io))
        }
        _ => failure.chain(),
    };
    let hop = dialed.or(match failure.stage {
        Stage::Tls => Some(Hop::Tls),
        Stage::Network => Some(Hop::Network),
        Stage::Proxy => Some(Hop::Proxy),
        Stage::Dns => Some(Hop::Dns),
        _ => None,
    });
    let err = match refusal {
        Some(refused) => anyhow::Error::new(Refusal {
            status: refused.status,
            text,
        }),
        None => anyhow::anyhow!(text),
    };
    match hop {
        Some(hop) => hop::at(hop, err),
        None => err,
    }
}
