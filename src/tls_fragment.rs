//! Split the TLS ClientHello into records (issue 135).
//!
//! A ClientHello is one handshake message. TLS permits a handshake message
//! in more than one record (RFC 8446, section 5.1), and a server joins them.
//! A middlebox that reads the server name from the first record only does
//! not find it when the name is cut. The split changes the records, not the
//! bytes of the handshake: the server sees the same ClientHello.
//!
//! The split applies to the first record that a connection writes, when it
//! is a ClientHello. Any other first record, or one larger than 16 KiB, goes
//! out unchanged. `cfrs warp` applies it to the MASQUE connection.

use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Where the records end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Records of a random size in the range.
    Record,
    /// The first record ends in the middle of the server name; then records
    /// of a random size.
    Sni,
}

/// The split of the first ClientHello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split {
    pub mode: Mode,
    /// The fewest bytes of handshake data in a record.
    pub min: usize,
    /// The most bytes of handshake data in a record.
    pub max: usize,
}

/// The size range when none is given.
pub const DEFAULT_SIZE: (usize, usize) = (64, 160);

impl Split {
    /// `mode` is `off`, `record` or `sni` (`off` gives `None`); `size` is
    /// `N` or `MIN-MAX`, each 16 to 4096.
    pub fn parse(mode: &str, size: Option<&str>) -> Result<Option<Self>> {
        let mode = match mode.trim().to_ascii_lowercase().as_str() {
            "" | "off" => return Ok(None),
            "record" => Mode::Record,
            "sni" => Mode::Sni,
            other => bail!("--fragment-client-hello={other:?}: give off, record or sni"),
        };
        let (min, max) = match size.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_SIZE,
            Some(text) => {
                let bad = || {
                    anyhow::anyhow!(
                        "--fragment-size={text}: give 16 to 4096 bytes, MIN-MAX or one number"
                    )
                };
                let (a, b) = text.split_once('-').unwrap_or((text, text));
                let a: usize = a.trim().parse().map_err(|_| bad())?;
                let b: usize = b.trim().parse().map_err(|_| bad())?;
                if !(16..=4096).contains(&a) || !(16..=4096).contains(&b) || a > b {
                    return Err(bad());
                }
                (a, b)
            }
        };
        Ok(Some(Split { mode, min, max }))
    }
}

static ACTIVE: OnceLock<Split> = OnceLock::new();

/// Set the split of this process. A later call does nothing.
pub fn set(split: Split) {
    if ACTIVE.set(split).is_ok() {
        tracing::info!(mode = ?split.mode, min = split.min, max = split.max, "the first ClientHello of each MASQUE connection is split across records");
    }
}

/// The split of this process, when one is set.
pub fn active() -> Option<Split> {
    ACTIVE.get().copied()
}

/// Wrap `io` with the split of this process, when one is set.
pub fn wrap(io: crate::net::BoxedIo) -> crate::net::BoxedIo {
    match active() {
        Some(split) => Box::new(Fragmenting::new(io, split)),
        None => io,
    }
}

/// A random number in `min..=max`.
fn random_in(min: usize, max: usize) -> usize {
    if max <= min {
        return min;
    }
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    min + (u32::from_le_bytes(b) as usize) % (max - min + 1)
}

/// The offset in the handshake data of the bytes of the server name, and
/// their length, when the data is a ClientHello with one.
fn server_name_at(hs: &[u8]) -> Option<(usize, usize)> {
    if *hs.first()? != 1 {
        return None;
    }
    let u16_at = |i: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*hs.get(i)?, *hs.get(i + 1)?]) as usize)
    };
    // type (1), length (3), version (2), random (32).
    let mut i = 4 + 2 + 32;
    i += 1 + *hs.get(i)? as usize; // session id
    i += 2 + u16_at(i)?; // cipher suites
    i += 1 + *hs.get(i)? as usize; // compression methods
    let end = (i + 2 + u16_at(i)?).min(hs.len());
    i += 2;
    while i + 4 <= end {
        let kind = u16_at(i)?;
        let len = u16_at(i + 2)?;
        let data = i + 4;
        if kind == 0 {
            // server_name: list length (2), name type (1), name length (2).
            let name_len = u16_at(data + 3)?;
            if *hs.get(data + 2)? != 0 || data + 5 + name_len > hs.len() {
                return None;
            }
            return Some((data + 5, name_len));
        }
        i = data + len;
    }
    None
}

/// The records of a first record `record` (header and data), when it is a
/// ClientHello of at most 16 KiB. `random(min, max)` gives the sizes.
pub fn fragment_with(
    record: &[u8],
    split: &Split,
    mut random: impl FnMut(usize, usize) -> usize,
) -> Option<Vec<u8>> {
    if record.len() < 6 || record[0] != 0x16 || record[1] != 3 {
        return None;
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let hs = &record[5..];
    if hs.len() != len || len > 16 * 1024 || hs[0] != 1 {
        return None;
    }
    let mut cuts = Vec::new();
    let mut at = 0;
    if split.mode == Mode::Sni {
        if let Some((name, name_len)) = server_name_at(hs) {
            at = name + (name_len / 2).max(1);
            cuts.push(at);
        }
    }
    while at < len {
        at = (at + random(split.min, split.max)).min(len);
        cuts.push(at);
    }
    let mut out = Vec::with_capacity(len + 5 * cuts.len());
    let mut start = 0;
    for end in cuts {
        if end <= start {
            continue;
        }
        out.extend_from_slice(&[0x16, record[1], record[2]]);
        out.extend_from_slice(&((end - start) as u16).to_be_bytes());
        out.extend_from_slice(&hs[start..end]);
        start = end;
    }
    Some(out)
}

/// A stream whose first record is split by [`fragment_with`].
pub struct Fragmenting<S> {
    inner: S,
    split: Split,
    /// The bytes of the first record, until it is whole.
    head: Vec<u8>,
    /// The bytes to write before any other.
    out: Vec<u8>,
    sent: usize,
    done: bool,
}

impl<S> Fragmenting<S> {
    pub fn new(inner: S, split: Split) -> Self {
        Fragmenting {
            inner,
            split,
            head: Vec::new(),
            out: Vec::new(),
            sent: 0,
            done: false,
        }
    }
}

impl<S: AsyncWrite + Unpin> Fragmenting<S> {
    /// Write the bytes of `out`.
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.sent < self.out.len() {
            let n = std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.out[self.sent..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.out.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    /// The first record is whole, or cannot be: put it in `out`.
    fn finish_head(&mut self, whole: usize) {
        let rest = self.head.split_off(whole.min(self.head.len()));
        let head = std::mem::take(&mut self.head);
        let split = self.split;
        match fragment_with(&head, &split, random_in) {
            Some(records) => {
                tracing::debug!(
                    bytes = head.len() - 5,
                    records = records.len() - (head.len() - 5),
                    "the ClientHello is split"
                );
                self.out.extend_from_slice(&records);
            }
            None => {
                tracing::debug!("the first record is not a ClientHello; it goes out whole");
                self.out.extend_from_slice(&head);
            }
        }
        self.out.extend_from_slice(&rest);
        self.done = true;
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmenting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        std::task::ready!(this.drain(cx))?;
        if this.done {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.head.extend_from_slice(buf);
        if this.head.len() >= 5 {
            let whole = 5 + u16::from_be_bytes([this.head[3], this.head[4]]) as usize;
            if this.head[0] != 0x16 || this.head.len() >= whole {
                this.finish_head(whole);
            }
        }
        // The bytes are taken; a write that waits ends in a later call.
        if this.done {
            let _ = this.drain(cx)?;
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if !this.done && !this.head.is_empty() {
            // A flush before the record is whole: it goes out as it is.
            this.out.extend_from_slice(&std::mem::take(&mut this.head));
            this.done = true;
        }
        std::task::ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Fragmenting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello of rustls for `name`, as the first record.
    fn client_hello(name: &str) -> Vec<u8> {
        crate::net::init_crypto();
        let roots = rustls::RootCertStore::empty();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    /// The handshake data of a run of records, and the size of each.
    fn join(records: &[u8]) -> (Vec<u8>, Vec<usize>) {
        let (mut data, mut sizes, mut i) = (Vec::new(), Vec::new(), 0);
        while i < records.len() {
            assert_eq!(records[i], 0x16);
            let len = u16::from_be_bytes([records[i + 3], records[i + 4]]) as usize;
            data.extend_from_slice(&records[i + 5..i + 5 + len]);
            sizes.push(len);
            i += 5 + len;
        }
        (data, sizes)
    }

    #[test]
    fn the_records_carry_the_same_client_hello() {
        let hello = client_hello("consumer-masque.cloudflareclient.com");
        let split = Split::parse("record", Some("16-40")).unwrap().unwrap();
        let records = fragment_with(&hello, &split, random_in).unwrap();
        let (data, sizes) = join(&records);
        assert_eq!(data, hello[5..]);
        assert!(sizes.len() > 3);
        assert!(sizes[..sizes.len() - 1]
            .iter()
            .all(|s| (16..=40).contains(s)));
    }

    #[test]
    fn the_sni_mode_cuts_the_name() {
        let name = "consumer-masque.cloudflareclient.com";
        let hello = client_hello(name);
        let (at, len) = server_name_at(&hello[5..]).unwrap();
        assert_eq!(&hello[5 + at..5 + at + len], name.as_bytes());
        let split = Split::parse("sni", Some("4096")).unwrap().unwrap();
        let records = fragment_with(&hello, &split, random_in).unwrap();
        let (data, sizes) = join(&records);
        assert_eq!(data, hello[5..]);
        assert_eq!(sizes[0], at + len / 2);
        let first = &records[5..5 + sizes[0]];
        assert!(!first.windows(name.len()).any(|w| w == name.as_bytes()));
    }

    #[test]
    fn other_records_and_bad_values() {
        let split = Split::parse("record", None).unwrap().unwrap();
        assert_eq!((split.min, split.max), DEFAULT_SIZE);
        assert!(fragment_with(&[0x17, 3, 3, 0, 1, 0], &split, random_in).is_none());
        assert!(fragment_with(&[0x16, 3, 1, 0, 2, 2, 0], &split, random_in).is_none());
        assert_eq!(Split::parse("off", Some("64")).unwrap(), None);
        for (mode, size) in [
            ("fast", None),
            ("record", Some("4-9000")),
            ("record", Some("200-100")),
            ("sni", Some("x")),
        ] {
            assert!(Split::parse(mode, size).is_err(), "{mode} {size:?}");
        }
    }

    #[tokio::test]
    async fn the_stream_splits_the_first_record_only() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let hello = client_hello("example.com");
        let split = Split::parse("record", Some("16-32")).unwrap().unwrap();
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut w = Fragmenting::new(a, split);
        // The record comes in two writes, then other bytes.
        w.write_all(&hello[..7]).await.unwrap();
        w.write_all(&hello[7..]).await.unwrap();
        w.write_all(&[0x17, 3, 3, 0, 1, 9]).await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert!(got.ends_with(&[0x17, 3, 3, 0, 1, 9]));
        let (data, sizes) = join(&got[..got.len() - 6]);
        assert_eq!(data, hello[5..]);
        assert!(sizes.len() > 1);
    }
}
