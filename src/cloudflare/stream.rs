//! The framing of a visitor stream (QUIC transport).
//!
//! A stream starts with the 6-byte signature, the 2-byte version `01`, and a
//! capnp `ConnectRequest`. The answer has the same preamble and a capnp
//! `ConnectResponse`. After that, the stream is a byte pipe.

use anyhow::{bail, Context, Result};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::capnp::Message;
pub use super::schema::{ConnectRequest, ConnectionType};
use super::{DATA_STREAM_SIGNATURE, DATA_STREAM_VERSION};

/// Metadata keys of a request and a response.
pub const HTTP_METHOD_KEY: &str = "HttpMethod";
pub const HTTP_HOST_KEY: &str = "HttpHost";
pub const HTTP_HEADER_KEY: &str = "HttpHeader";
pub const HTTP_STATUS_KEY: &str = "HttpStatus";

async fn read_preamble<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut signature = [0u8; 6];
    reader
        .read_exact(&mut signature)
        .await
        .context("reading the stream signature")?;
    if signature != DATA_STREAM_SIGNATURE {
        bail!("unexpected stream signature {signature:02x?}");
    }
    let mut version = [0u8; 2];
    reader
        .read_exact(&mut version)
        .await
        .context("reading the stream version")?;
    if version != DATA_STREAM_VERSION {
        tracing::debug!(version = ?version, "unknown stream version");
    }
    Ok(())
}

fn preamble() -> Vec<u8> {
    let mut out = DATA_STREAM_SIGNATURE.to_vec();
    out.extend_from_slice(DATA_STREAM_VERSION);
    out
}

/// Read the `ConnectRequest` at the start of a visitor stream.
pub async fn read_connect_request<R>(reader: &mut R) -> Result<ConnectRequest>
where
    R: AsyncRead + Unpin,
{
    read_preamble(reader).await?;
    let message = Message::read_futures(reader).await?;
    super::schema::decode_connect_request(&message.root()?)
}

/// Write a `ConnectRequest` with its preamble.
pub async fn write_connect_request<W>(writer: &mut W, request: &ConnectRequest) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = preamble();
    out.extend_from_slice(&super::schema::encode_connect_request(request));
    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Write the `ConnectResponse` of a visitor stream.
pub async fn write_connect_response<W>(
    writer: &mut W,
    error: &str,
    metadata: &[(&str, &str)],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let owned: Vec<(String, String)> = metadata
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut out = preamble();
    out.extend_from_slice(&super::schema::encode_connect_response(error, &owned));
    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a `ConnectResponse` with its preamble. Return the error text and the
/// metadata.
pub async fn read_connect_response<R>(reader: &mut R) -> Result<(String, Vec<(String, String)>)>
where
    R: AsyncRead + Unpin,
{
    read_preamble(reader).await?;
    let message = Message::read_futures(reader).await?;
    super::schema::decode_connect_response(&message.root()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[tokio::test]
    async fn request_and_response_round_trip_with_a_body() {
        let request = ConnectRequest {
            dest: "http://h/x".into(),
            conn_type: ConnectionType::Http,
            metadata: vec![(HTTP_METHOD_KEY.into(), "POST".into())],
        };
        let mut buf = Vec::new();
        write_connect_request(&mut Cursor::new(&mut buf), &request)
            .await
            .unwrap();
        let mut response = Vec::new();
        write_connect_response(
            &mut Cursor::new(&mut response),
            "",
            &[(HTTP_STATUS_KEY, "204")],
        )
        .await
        .unwrap();
        buf.extend_from_slice(b"BODY");
        let mut reader = Cursor::new(buf);
        assert_eq!(read_connect_request(&mut reader).await.unwrap(), request);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"BODY");
        let (error, meta) = read_connect_response(&mut Cursor::new(response))
            .await
            .unwrap();
        assert_eq!(error, "");
        assert_eq!(meta, vec![("HttpStatus".to_string(), "204".to_string())]);
    }

    #[tokio::test]
    async fn rejects_a_wrong_signature() {
        let mut reader = Cursor::new(vec![0u8; 16]);
        let err = read_connect_request(&mut reader).await.unwrap_err();
        assert!(err.to_string().contains("signature"));
    }
}
