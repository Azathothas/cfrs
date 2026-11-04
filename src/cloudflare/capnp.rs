//! The Cap'n Proto wire format: the parts that the tunnel protocol uses.
//!
//! Reference: <https://capnproto.org/encoding.html>.
//!
//! * A message is a list of segments. Each segment is a list of 64-bit words.
//!   The framing is: `u32` (segment count minus 1), one `u32` size in words for
//!   each segment, padding to 8 bytes, then the segments.
//! * The first word of segment 0 is the root pointer.
//! * A struct has a data section (words) and a pointer section (pointers).
//! * Pointer kinds: struct (0), list (1), far (2), other/capability (3).
//!
//! [`Builder`] writes one segment. [`Message`] reads any number of segments,
//! with far pointers, and limits the work that a hostile message can cause.

use anyhow::{bail, Context, Result};

/// The largest message that is read, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 << 20;
/// The largest number of segments that is read.
pub const MAX_SEGMENTS: usize = 512;
/// The deepest pointer nesting that is followed.
const MAX_DEPTH: u32 = 64;

// ── list element sizes ──────────────────────────────────────────────────────

const ELEM_BYTE: u64 = 2;
const ELEM_POINTER: u64 = 6;
const ELEM_COMPOSITE: u64 = 7;

/// A struct in a [`Builder`]: where its sections are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructRef {
    data: usize,
    data_words: u16,
    ptrs: usize,
    ptr_count: u16,
}

/// Writes one message in one segment.
#[derive(Debug, Default)]
pub struct Builder {
    words: Vec<u64>,
}

impl Builder {
    /// Make a message. Word 0 is the root pointer.
    pub fn new() -> Self {
        Self { words: vec![0] }
    }

    fn alloc(&mut self, words: usize) -> usize {
        let start = self.words.len();
        self.words.resize(start + words, 0);
        start
    }

    fn struct_pointer(at: usize, target: usize, data: u16, ptrs: u16) -> u64 {
        let offset = target as i64 - at as i64 - 1;
        ((offset as u64 & 0x3fff_ffff) << 2) | (u64::from(data) << 32) | (u64::from(ptrs) << 48)
    }

    fn list_pointer(at: usize, target: usize, elem: u64, count: u64) -> u64 {
        let offset = target as i64 - at as i64 - 1;
        1 | ((offset as u64 & 0x3fff_ffff) << 2) | (elem << 32) | (count << 35)
    }

    fn new_struct(&mut self, data: u16, ptrs: u16) -> StructRef {
        let start = self.alloc(usize::from(data) + usize::from(ptrs));
        StructRef {
            data: start,
            data_words: data,
            ptrs: start + usize::from(data),
            ptr_count: ptrs,
        }
    }

    /// Make the root struct.
    pub fn init_root(&mut self, data: u16, ptrs: u16) -> StructRef {
        let root = self.new_struct(data, ptrs);
        self.words[0] = Self::struct_pointer(0, root.data, data, ptrs);
        root
    }

    fn pointer_slot(s: StructRef, index: u16) -> usize {
        assert!(index < s.ptr_count, "pointer index {index} out of range");
        s.ptrs + usize::from(index)
    }

    /// Make a struct in pointer `index` of `s`.
    pub fn init_struct(&mut self, s: StructRef, index: u16, data: u16, ptrs: u16) -> StructRef {
        let slot = Self::pointer_slot(s, index);
        let child = self.new_struct(data, ptrs);
        self.words[slot] = Self::struct_pointer(slot, child.data, data, ptrs);
        child
    }

    /// Make a list of `count` structs in pointer `index` of `s`.
    pub fn init_struct_list(
        &mut self,
        s: StructRef,
        index: u16,
        count: usize,
        data: u16,
        ptrs: u16,
    ) -> Vec<StructRef> {
        let slot = Self::pointer_slot(s, index);
        let size = usize::from(data) + usize::from(ptrs);
        let tag = self.alloc(1 + count * size);
        self.words[slot] = Self::list_pointer(slot, tag, ELEM_COMPOSITE, (count * size) as u64);
        // The tag word has the struct-pointer form; its offset is the count.
        self.words[tag] =
            ((count as u64 & 0x3fff_ffff) << 2) | (u64::from(data) << 32) | (u64::from(ptrs) << 48);
        (0..count)
            .map(|i| {
                let start = tag + 1 + i * size;
                StructRef {
                    data: start,
                    data_words: data,
                    ptrs: start + usize::from(data),
                    ptr_count: ptrs,
                }
            })
            .collect()
    }

    fn put_bytes_at(&mut self, slot: usize, bytes: &[u8], extra_nul: bool) {
        let len = bytes.len() + usize::from(extra_nul);
        let start = self.alloc(len.div_ceil(8));
        self.words[slot] = Self::list_pointer(slot, start, ELEM_BYTE, len as u64);
        for (i, byte) in bytes.iter().enumerate() {
            let word = start + i / 8;
            self.words[word] |= u64::from(*byte) << ((i % 8) * 8);
        }
    }

    /// Set pointer `index` of `s` to a Text value (a byte list with a NUL).
    pub fn set_text(&mut self, s: StructRef, index: u16, text: &str) {
        let slot = Self::pointer_slot(s, index);
        self.put_bytes_at(slot, text.as_bytes(), true);
    }

    /// Set pointer `index` of `s` to a Data value.
    pub fn set_data(&mut self, s: StructRef, index: u16, data: &[u8]) {
        let slot = Self::pointer_slot(s, index);
        self.put_bytes_at(slot, data, false);
    }

    /// Set pointer `index` of `s` to a `List(Text)`.
    pub fn set_text_list(&mut self, s: StructRef, index: u16, items: &[String]) {
        let slot = Self::pointer_slot(s, index);
        let start = self.alloc(items.len());
        self.words[slot] = Self::list_pointer(slot, start, ELEM_POINTER, items.len() as u64);
        for (i, item) in items.iter().enumerate() {
            self.put_bytes_at(start + i, item.as_bytes(), true);
        }
    }

    /// Set pointer `index` of `s` to capability `cap` of the cap table.
    pub fn set_capability(&mut self, s: StructRef, index: u16, cap: u32) {
        let slot = Self::pointer_slot(s, index);
        self.words[slot] = 3 | (u64::from(cap) << 32);
    }

    fn data_byte(&mut self, s: StructRef, byte: usize) -> (usize, u32) {
        assert!(
            byte < usize::from(s.data_words) * 8,
            "data offset {byte} out of range"
        );
        (s.data + byte / 8, ((byte % 8) * 8) as u32)
    }

    fn set_bits(&mut self, s: StructRef, byte: usize, width: u32, value: u64) {
        let (word, shift) = self.data_byte(s, byte);
        let mask = if width == 64 {
            u64::MAX
        } else {
            ((1u64 << width) - 1) << shift
        };
        self.words[word] = (self.words[word] & !mask) | ((value << shift) & mask);
    }

    /// Set the `u8` field at element index `index` (byte `index`).
    pub fn set_u8(&mut self, s: StructRef, index: usize, value: u8) {
        self.set_bits(s, index, 8, u64::from(value));
    }

    /// Set the `u16` field at element index `index` (byte `2 * index`).
    pub fn set_u16(&mut self, s: StructRef, index: usize, value: u16) {
        self.set_bits(s, index * 2, 16, u64::from(value));
    }

    /// Set the `u32` field at element index `index` (byte `4 * index`).
    pub fn set_u32(&mut self, s: StructRef, index: usize, value: u32) {
        self.set_bits(s, index * 4, 32, u64::from(value));
    }

    /// Set the `u64` field at element index `index` (word `index`).
    pub fn set_u64(&mut self, s: StructRef, index: usize, value: u64) {
        let (word, _) = self.data_byte(s, index * 8);
        self.words[word] = value;
    }

    /// Set the Bool field at bit `bit`.
    pub fn set_bool(&mut self, s: StructRef, bit: usize, value: bool) {
        let (word, _) = self.data_byte(s, bit / 8);
        let mask = 1u64 << (bit % 64);
        if value {
            self.words[word] |= mask;
        } else {
            self.words[word] &= !mask;
        }
    }

    /// The framed message: segment table and the segment.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.words.len() * 8);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(self.words.len() as u32).to_le_bytes());
        for word in &self.words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

// ── reading ─────────────────────────────────────────────────────────────────

/// A received message.
#[derive(Debug)]
pub struct Message {
    segments: Vec<Vec<u64>>,
    budget: std::sync::atomic::AtomicU64,
}

/// A struct in a [`Message`].
#[derive(Clone, Copy, Debug)]
pub struct StructReader<'a> {
    msg: &'a Message,
    segment: usize,
    data: usize,
    data_words: u16,
    ptrs: usize,
    ptr_count: u16,
    depth: u32,
}

/// What a pointer refers to.
#[derive(Clone, Copy, Debug)]
enum Target {
    Null,
    Struct {
        segment: usize,
        start: usize,
        data: u16,
        ptrs: u16,
    },
    List {
        segment: usize,
        start: usize,
        elem: u64,
        count: u64,
        /// Only for a composite list: the tag word.
        tag: u64,
    },
    Capability(u32),
}

/// Read the framing of one message from `bytes`. Return the segment words
/// and the number of bytes that the message used.
fn split_segments(bytes: &[u8]) -> Result<Option<(Vec<Vec<u64>>, usize)>> {
    if bytes.len() < 4 {
        return Ok(None);
    }
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize + 1;
    if count > MAX_SEGMENTS {
        bail!("the message has {count} segments");
    }
    let table = 4 + count * 4;
    let header = table + (table % 8);
    if bytes.len() < table {
        return Ok(None);
    }
    let mut sizes = Vec::with_capacity(count);
    let mut total = 0usize;
    for i in 0..count {
        let at = 4 + i * 4;
        let size = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        total = total.saturating_add(size.saturating_mul(8));
        sizes.push(size);
    }
    if total > MAX_MESSAGE_BYTES {
        bail!("the message is {total} bytes");
    }
    if bytes.len() < header + total {
        return Ok(None);
    }
    let mut segments = Vec::with_capacity(count);
    let mut at = header;
    for size in sizes {
        let words = bytes[at..at + size * 8]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        segments.push(words);
        at += size * 8;
    }
    Ok(Some((segments, header + total)))
}

impl Message {
    fn new(segments: Vec<Vec<u64>>) -> Self {
        let words: u64 = segments.iter().map(|s| s.len() as u64).sum();
        Self {
            segments,
            // Each word may be read a few times; more than that is an attack
            // (pointers that point at the same data again and again).
            budget: std::sync::atomic::AtomicU64::new(words.saturating_mul(8).max(1024)),
        }
    }

    /// Parse one framed message from the start of `bytes`. Return `None` when
    /// `bytes` does not hold a full message yet.
    pub fn parse(bytes: &[u8]) -> Result<Option<(Self, usize)>> {
        Ok(split_segments(bytes)?.map(|(segments, used)| (Self::new(segments), used)))
    }

    /// Read one framed message from a tokio reader.
    pub async fn read<R>(reader: &mut R) -> Result<Option<Self>>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut first = [0u8; 4];
        match reader.read_exact(&mut first).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err.into()),
        }
        Self::read_after(first, reader).await.map(Some)
    }

    async fn read_after<R>(first: [u8; 4], reader: &mut R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let count = u32::from_le_bytes(first) as usize + 1;
        if count > MAX_SEGMENTS {
            bail!("the message has {count} segments");
        }
        let table = 4 + count * 4;
        let mut header = vec![0u8; table + (table % 8) - 4];
        reader
            .read_exact(&mut header)
            .await
            .context("segment table")?;
        let mut bytes = first.to_vec();
        bytes.extend_from_slice(&header);
        let mut total = 0usize;
        for i in 0..count {
            let at = 4 + i * 4;
            let size = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            total = total.saturating_add(size.saturating_mul(8));
        }
        if total > MAX_MESSAGE_BYTES {
            bail!("the message is {total} bytes");
        }
        let start = bytes.len();
        bytes.resize(start + total, 0);
        reader
            .read_exact(&mut bytes[start..])
            .await
            .context("segments")?;
        let (segments, _) = split_segments(&bytes)?.context("short message")?;
        Ok(Self::new(segments))
    }

    /// Read one framed message from a `futures` reader.
    pub async fn read_futures<R>(reader: &mut R) -> Result<Self>
    where
        R: futures::io::AsyncRead + Unpin,
    {
        let mut compat = tokio_util::compat::FuturesAsyncReadCompatExt::compat(reader);
        let mut first = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut compat, &mut first)
            .await
            .context("segment count")?;
        Self::read_after(first, &mut compat).await
    }

    /// The root struct.
    pub fn root(&self) -> Result<StructReader<'_>> {
        let root = StructReader {
            msg: self,
            segment: 0,
            data: 0,
            data_words: 0,
            ptrs: 0,
            ptr_count: 1,
            depth: 0,
        };
        root.get_struct(0)?.context("the message has no root")
    }

    /// Take `words` from the read budget.
    fn spend(&self, words: u64) -> Result<()> {
        use std::sync::atomic::Ordering;
        let mut left = self.budget.load(Ordering::Relaxed);
        loop {
            let Some(next) = left.checked_sub(words) else {
                bail!("the message exceeds the read limit");
            };
            match self.budget.compare_exchange_weak(
                left,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => left = actual,
            }
        }
    }

    fn word(&self, segment: usize, index: usize) -> Result<u64> {
        self.spend(1)?;
        self.segments
            .get(segment)
            .and_then(|s| s.get(index))
            .copied()
            .with_context(|| format!("word {index} of segment {segment} is out of range"))
    }

    fn check_range(&self, segment: usize, start: usize, words: u64) -> Result<()> {
        let len = self.segments.get(segment).map_or(0, Vec::len) as u64;
        if start as u64 + words > len {
            bail!("an object is outside its segment");
        }
        self.spend(words)
    }

    /// Follow the pointer at `segment[at]`.
    fn follow(&self, segment: usize, at: usize) -> Result<Target> {
        let mut pointer = self.word(segment, at)?;
        let mut segment = segment;
        let mut at = at;
        if pointer == 0 {
            return Ok(Target::Null);
        }
        if pointer & 3 == 2 {
            // A far pointer: the landing pad is in another segment.
            let double = pointer & 4 != 0;
            let pad = ((pointer >> 3) & 0x1fff_ffff) as usize;
            let pad_segment = (pointer >> 32) as usize;
            if !double {
                segment = pad_segment;
                at = pad;
                pointer = self.word(segment, at)?;
            } else {
                // Two words: a far pointer to the content, then a tag.
                let far = self.word(pad_segment, pad)?;
                let tag = self.word(pad_segment, pad + 1)?;
                if far & 3 != 2 {
                    bail!("a double-far landing pad is not a far pointer");
                }
                let content_segment = (far >> 32) as usize;
                let content = ((far >> 3) & 0x1fff_ffff) as usize;
                return self.decode(content_segment, content, tag);
            }
        }
        let offset = (((pointer as u32) as i32) >> 2) as i64;
        let start = at as i64 + 1 + offset;
        if start < 0 {
            bail!("a pointer points before its segment");
        }
        self.decode(segment, start as usize, pointer)
    }

    fn decode(&self, segment: usize, start: usize, pointer: u64) -> Result<Target> {
        match pointer & 3 {
            0 => {
                let data = ((pointer >> 32) & 0xffff) as u16;
                let ptrs = (pointer >> 48) as u16;
                self.check_range(segment, start, u64::from(data) + u64::from(ptrs))?;
                Ok(Target::Struct {
                    segment,
                    start,
                    data,
                    ptrs,
                })
            }
            1 => {
                let elem = (pointer >> 32) & 7;
                let count = pointer >> 35;
                let words = match elem {
                    0 => 0,
                    1 => count.div_ceil(64),
                    2 => count.div_ceil(8),
                    3 => count.div_ceil(4),
                    4 => count.div_ceil(2),
                    5 | 6 => count,
                    _ => count + 1,
                };
                self.check_range(segment, start, words)?;
                let tag = if elem == ELEM_COMPOSITE {
                    self.word(segment, start)?
                } else {
                    0
                };
                Ok(Target::List {
                    segment,
                    start,
                    elem,
                    count,
                    tag,
                })
            }
            3 => {
                if pointer & 0xffff_fffc != 0 {
                    bail!("an unknown kind of other pointer");
                }
                Ok(Target::Capability((pointer >> 32) as u32))
            }
            _ => bail!("a far pointer points to a far pointer"),
        }
    }
}

impl<'a> StructReader<'a> {
    fn data_word(&self, byte: usize) -> Option<(u64, u32)> {
        if byte >= usize::from(self.data_words) * 8 {
            return None;
        }
        let word = self.msg.segments[self.segment][self.data + byte / 8];
        Some((word, ((byte % 8) * 8) as u32))
    }

    fn bits(&self, byte: usize, width: u32) -> u64 {
        match self.data_word(byte) {
            Some((word, shift)) => {
                let value = word >> shift;
                if width == 64 {
                    value
                } else {
                    value & ((1u64 << width) - 1)
                }
            }
            // A field outside the data section has its default value: zero.
            None => 0,
        }
    }

    pub fn get_u8(&self, index: usize) -> u8 {
        self.bits(index, 8) as u8
    }

    pub fn get_u16(&self, index: usize) -> u16 {
        self.bits(index * 2, 16) as u16
    }

    pub fn get_u32(&self, index: usize) -> u32 {
        self.bits(index * 4, 32) as u32
    }

    pub fn get_u64(&self, index: usize) -> u64 {
        self.bits(index * 8, 64)
    }

    pub fn get_bool(&self, bit: usize) -> bool {
        match self.data_word(bit / 8) {
            Some((word, _)) => word & (1u64 << (bit % 64)) != 0,
            None => false,
        }
    }

    fn pointer(&self, index: u16) -> Result<Target> {
        if index >= self.ptr_count {
            return Ok(Target::Null);
        }
        self.msg
            .follow(self.segment, self.ptrs + usize::from(index))
    }

    fn child(&self, segment: usize, start: usize, data: u16, ptrs: u16) -> Result<Self> {
        if self.depth >= MAX_DEPTH {
            bail!("the message nests too deeply");
        }
        Ok(StructReader {
            msg: self.msg,
            segment,
            data: start,
            data_words: data,
            ptrs: start + usize::from(data),
            ptr_count: ptrs,
            depth: self.depth + 1,
        })
    }

    /// The struct in pointer `index`, or `None` for a null pointer.
    pub fn get_struct(&self, index: u16) -> Result<Option<StructReader<'a>>> {
        match self.pointer(index)? {
            Target::Null => Ok(None),
            Target::Struct {
                segment,
                start,
                data,
                ptrs,
            } => self.child(segment, start, data, ptrs).map(Some),
            _ => bail!("pointer {index} is not a struct"),
        }
    }

    /// The capability index in pointer `index`, or `None`.
    pub fn get_capability(&self, index: u16) -> Result<Option<u32>> {
        match self.pointer(index)? {
            Target::Null => Ok(None),
            Target::Capability(cap) => Ok(Some(cap)),
            _ => bail!("pointer {index} is not a capability"),
        }
    }

    fn bytes(&self, index: u16) -> Result<Option<Vec<u8>>> {
        match self.pointer(index)? {
            Target::Null => Ok(None),
            Target::List {
                segment,
                start,
                elem: ELEM_BYTE,
                count,
                ..
            } => {
                let words = &self.msg.segments[segment][start..];
                let mut out = Vec::with_capacity(count as usize);
                for i in 0..count as usize {
                    out.push((words[i / 8] >> ((i % 8) * 8)) as u8);
                }
                Ok(Some(out))
            }
            _ => bail!("pointer {index} is not a byte list"),
        }
    }

    /// The Data in pointer `index` (empty for a null pointer).
    pub fn get_data(&self, index: u16) -> Result<Vec<u8>> {
        Ok(self.bytes(index)?.unwrap_or_default())
    }

    /// The Text in pointer `index` (empty for a null pointer).
    pub fn get_text(&self, index: u16) -> Result<String> {
        let mut bytes = self.bytes(index)?.unwrap_or_default();
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        String::from_utf8(bytes).context("Text is not UTF-8")
    }

    /// The `List(Struct)` in pointer `index` (empty for a null pointer).
    pub fn get_struct_list(&self, index: u16) -> Result<Vec<StructReader<'a>>> {
        match self.pointer(index)? {
            Target::Null => Ok(Vec::new()),
            Target::List {
                segment,
                start,
                elem: ELEM_COMPOSITE,
                tag,
                ..
            } => {
                if tag & 3 != 0 {
                    bail!("the tag of a struct list is not a struct pointer");
                }
                let count = ((tag as u32) >> 2) as usize;
                let data = ((tag >> 32) & 0xffff) as u16;
                let ptrs = (tag >> 48) as u16;
                let size = usize::from(data) + usize::from(ptrs);
                self.msg
                    .check_range(segment, start + 1, (count * size) as u64)?;
                // An element of 0 words reads no word: charge one word for
                // each, as the reference implementation does, so a short
                // message cannot make a long list.
                if size == 0 {
                    self.msg.spend(count as u64)?;
                }
                (0..count)
                    .map(|i| self.child(segment, start + 1 + i * size, data, ptrs))
                    .collect()
            }
            _ => bail!("pointer {index} is not a struct list"),
        }
    }

    /// The `List(Text)` in pointer `index` (empty for a null pointer).
    pub fn get_text_list(&self, index: u16) -> Result<Vec<String>> {
        match self.pointer(index)? {
            Target::Null => Ok(Vec::new()),
            Target::List {
                segment,
                start,
                elem: ELEM_POINTER,
                count,
                ..
            } => {
                if count > u64::from(u16::MAX) {
                    bail!("a text list of {count} elements");
                }
                self.msg.check_range(segment, start, count)?;
                let list = StructReader {
                    msg: self.msg,
                    segment,
                    data: start,
                    data_words: 0,
                    ptrs: start,
                    ptr_count: count as u16,
                    depth: self.depth + 1,
                };
                (0..list.ptr_count).map(|i| list.get_text(i)).collect()
            }
            _ => bail!("pointer {index} is not a pointer list"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One segment of `words`, framed.
    fn framed(words: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(words.len() as u32).to_le_bytes());
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// A struct pointer at `at` to a struct at `target`.
    fn struct_ptr(at: usize, target: usize, data: u16, ptrs: u16) -> u64 {
        let offset = (target as i64 - at as i64 - 1) as u32 & 0x3fff_ffff;
        ((offset as u64) << 2) | ((data as u64) << 32) | ((ptrs as u64) << 48)
    }

    /// A struct whose one pointer points to the struct itself: a reader
    /// that follows it again and again stops with an error (the depth
    /// limit or the read budget) and does not hang.
    #[test]
    fn a_pointer_loop_ends_with_an_error() {
        // Word 0: the root pointer to the struct at word 1 (0 data, 1 ptr).
        // Word 1: the pointer of that struct, to word 1 again.
        let bytes = framed(&[struct_ptr(0, 1, 0, 1), struct_ptr(1, 1, 0, 1)]);
        let (message, _) = Message::parse(&bytes).unwrap().unwrap();
        let mut s = message.root().unwrap();
        let mut steps = 0;
        let end = loop {
            steps += 1;
            assert!(steps < 10_000, "the loop does not end");
            match s.get_struct(0) {
                Ok(Some(child)) => s = child,
                Ok(None) => panic!("the loop has a null pointer"),
                Err(e) => break e,
            }
        };
        assert!(steps <= MAX_DEPTH as usize + 1, "{steps} steps");
        let text = format!("{end:#}");
        assert!(
            text.contains("deep") || text.contains("limit") || text.contains("depth"),
            "{text}"
        );
    }

    /// A list pointer with a count far above the size of the message is
    /// refused before any allocation of that size.
    #[test]
    fn a_huge_list_count_is_refused() {
        // A byte list (element size 2) of 2^29 - 1 elements in a 2-word
        // message, and the same count of 8-byte elements (size 5).
        for elem in [2u64, 5] {
            let list = 1 | (elem << 32) | (((1u64 << 29) - 1) << 35);
            let bytes = framed(&[struct_ptr(0, 1, 0, 1), list]);
            let (message, _) = Message::parse(&bytes).unwrap().unwrap();
            let root = message.root().unwrap();
            assert!(root.get_data(0).is_err());
            assert!(root.get_text_list(0).is_err());
            assert!(root.get_struct_list(0).is_err());
        }
        // A segment table that claims 4 GiB is refused by the framing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Message::parse(&bytes).is_err());
    }

    /// Found by the fuzz target capnp_message: a composite list of
    /// zero-size structs with a huge count. Each element reads no word, so
    /// the range check passed, and the reader made one reader for each of
    /// the 2^24 elements (an allocation of 80 MiB for 96 bytes).
    #[test]
    fn fuzz_a_zero_size_struct_list_is_charged() {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode("AAAAAA0AAAAAAAAAAQACAAAAAAAAAAAABQAAAJIAAAANAAAAFwAAAGh0dHA6Ly9sb2NhbGhvc3QvAAAAAAAAAAADAAQAAAAAAAAAAFoAAAAJAAAAIgAAAEh0dHBNZXRob2QAAAAAAABHRVQAAAAAAA==")
            .unwrap();
        crate::fuzzing::capnp_message(&bytes);
        // The same shape, made by hand: a tag of 2^29 - 1 elements of 0 words.
        let list = 1 | (7u64 << 32); // composite, 0 words
        let tag = ((1u64 << 29) - 1) << 2;
        let bytes = framed(&[struct_ptr(0, 1, 0, 1), list, tag]);
        let (message, _) = Message::parse(&bytes).unwrap().unwrap();
        let err = message.root().unwrap().get_struct_list(0).unwrap_err();
        assert!(format!("{err:#}").contains("read limit"), "{err:#}");
    }

    #[test]
    fn a_struct_round_trips() {
        let mut b = Builder::new();
        let root = b.init_root(3, 4);
        b.set_u8(root, 0, 7);
        b.set_u16(root, 1, 0xbeef);
        b.set_u32(root, 1, 0x1234_5678);
        b.set_u64(root, 1, u64::MAX - 1);
        b.set_bool(root, 130, true);
        b.set_text(root, 0, "hello");
        b.set_data(root, 1, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let child = b.init_struct(root, 2, 1, 1);
        b.set_u32(child, 0, 42);
        b.set_text_list(child, 0, &["a".into(), "bc".into()]);
        let items = b.init_struct_list(root, 3, 3, 0, 1);
        for (i, item) in items.iter().enumerate() {
            b.set_text(*item, 0, &format!("item{i}"));
        }
        let bytes = b.to_bytes();
        let (msg, used) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        let r = msg.root().unwrap();
        assert_eq!(r.get_u8(0), 7);
        assert_eq!(r.get_u16(1), 0xbeef);
        assert_eq!(r.get_u32(1), 0x1234_5678);
        assert_eq!(r.get_u64(1), u64::MAX - 1);
        assert!(r.get_bool(130));
        assert!(!r.get_bool(131));
        assert_eq!(r.get_text(0).unwrap(), "hello");
        assert_eq!(r.get_data(1).unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let c = r.get_struct(2).unwrap().unwrap();
        assert_eq!(c.get_u32(0), 42);
        assert_eq!(c.get_text_list(0).unwrap(), vec!["a", "bc"]);
        let list = r.get_struct_list(3).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[2].get_text(0).unwrap(), "item2");
        // Fields outside the sections read as defaults.
        assert_eq!(r.get_u64(9), 0);
        assert!(r.get_struct(9).unwrap().is_none());
    }

    #[test]
    fn a_capability_pointer_round_trips() {
        let mut b = Builder::new();
        let root = b.init_root(0, 1);
        b.set_capability(root, 0, 5);
        let (msg, _) = Message::parse(&b.to_bytes()).unwrap().unwrap();
        assert_eq!(msg.root().unwrap().get_capability(0).unwrap(), Some(5));
    }

    /// A message from the Cap'n Proto reference encoder (`capnp encode`):
    /// a struct with data `0x0102030405060708` and the text "hi".
    #[test]
    fn reads_a_reference_encoding() {
        let bytes: Vec<u8> = [
            0u32.to_le_bytes().to_vec(),
            4u32.to_le_bytes().to_vec(),
            // root: struct, offset 0, 1 data word, 1 pointer
            0x0001_0001_0000_0000u64.to_le_bytes().to_vec(),
            0x0102_0304_0506_0708u64.to_le_bytes().to_vec(),
            // list pointer: offset 0, byte elements, 3 bytes ("hi\0")
            (1u64 | (2u64 << 32) | (3u64 << 35)).to_le_bytes().to_vec(),
            [b'h', b'i', 0, 0, 0, 0, 0, 0].to_vec(),
        ]
        .concat();
        let (msg, _) = Message::parse(&bytes).unwrap().unwrap();
        let root = msg.root().unwrap();
        assert_eq!(root.get_u64(0), 0x0102_0304_0506_0708);
        assert_eq!(root.get_text(0).unwrap(), "hi");
    }

    #[test]
    fn follows_far_pointers() {
        // Segment 0: a far pointer to word 0 of segment 1, which is a struct
        // pointer to word 1 (offset 0) with one data word.
        let far = 2u64 | (1u64 << 32);
        let landing = 0x0000_0001_0000_0000u64;
        let bytes: Vec<u8> = [
            1u32.to_le_bytes().to_vec(),
            1u32.to_le_bytes().to_vec(),
            2u32.to_le_bytes().to_vec(),
            0u32.to_le_bytes().to_vec(),
            far.to_le_bytes().to_vec(),
            landing.to_le_bytes().to_vec(),
            99u64.to_le_bytes().to_vec(),
        ]
        .concat();
        let (msg, _) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(msg.root().unwrap().get_u64(0), 99);
    }

    #[test]
    fn refuses_hostile_messages() {
        // A pointer outside the segment.
        let bytes: Vec<u8> = [
            0u32.to_le_bytes().to_vec(),
            1u32.to_le_bytes().to_vec(),
            (0x0001_0000_0000_0000u64 | (100u64 << 2))
                .to_le_bytes()
                .to_vec(),
        ]
        .concat();
        let (msg, _) = Message::parse(&bytes).unwrap().unwrap();
        assert!(msg.root().is_err());
        // Too many segments.
        let bytes = 10_000u32.to_le_bytes();
        assert!(Message::parse(&bytes).is_err());
        // A partial message.
        let mut b = Builder::new();
        b.init_root(1, 0);
        let full = b.to_bytes();
        assert!(Message::parse(&full[..full.len() - 1]).unwrap().is_none());
    }

    #[tokio::test]
    async fn reads_framed_messages_from_a_stream() {
        let mut b = Builder::new();
        let root = b.init_root(1, 1);
        b.set_u32(root, 0, 3);
        b.set_text(root, 0, "x");
        let mut stream = b.to_bytes();
        stream.extend_from_slice(&b.to_bytes());
        let mut reader = &stream[..];
        for _ in 0..2 {
            let msg = Message::read(&mut reader).await.unwrap().unwrap();
            assert_eq!(msg.root().unwrap().get_u32(0), 3);
        }
        assert!(Message::read(&mut reader).await.unwrap().is_none());
    }
}
