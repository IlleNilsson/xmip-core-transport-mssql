//! The protocol's framing, Tabular Data Stream 7.4: an eight-byte packet
//! header — type, status, length, SPID, packet id, window — ahead of a
//! payload, and a message longer than one packet split across several,
//! the last marked end-of-message. Inside a payload integers are
//! little-endian and text is UCS-2 counted in characters, which is what
//! the `Cursor` and the helpers here read and write; what a message means
//! is `prelogin.rs`, `login.rs`, `batch.rs` and `token.rs`.

use std::io::{Read, Write};

use transport::error::{Result, classify, protocol_error};

/// A SQL batch, from the client.
pub const SQL_BATCH: u8 = 0x01;
/// A token stream, from the server — its answer to everything.
pub const TABULAR_RESULT: u8 = 0x04;
/// The login, from the client.
pub const LOGIN7: u8 = 0x10;
/// The pre-login, from the client; the server answers in a token-stream
/// packet that carries the same shape.
pub const PRELOGIN: u8 = 0x12;
/// The status bit on the last packet of a message.
pub const END_OF_MESSAGE: u8 = 0x01;
/// The header ahead of every packet.
pub const HEADER_LENGTH: usize = 8;
/// The packet size until the server negotiates another.
pub const DEFAULT_PACKET_SIZE: u16 = 4096;
/// The smallest packet the protocol allows, header included.
pub const MIN_PACKET_SIZE: u16 = 512;
/// The largest, which is also what a length field can carry.
pub const MAX_PACKET_SIZE: u16 = 32767;
/// The most one message may be.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// One packet: the header, then `payload`.
#[must_use]
pub fn packet(kind: u8, status: u8, payload: &[u8], id: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LENGTH + payload.len());
    out.push(kind);
    out.push(status);
    let length = u16::try_from(HEADER_LENGTH + payload.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // SPID
    out.push(id);
    out.push(0); // window
    out.extend_from_slice(payload);
    out
}

/// `payload` as one message of `kind`, in packets of at most `packet_size`
/// bytes header included, the last marked end-of-message.
#[must_use]
pub fn packets(kind: u8, payload: &[u8], packet_size: u16) -> Vec<u8> {
    let room = usize::from(packet_size.clamp(MIN_PACKET_SIZE, MAX_PACKET_SIZE)) - HEADER_LENGTH;
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[][..]]
    } else {
        payload.chunks(room).collect()
    };
    let last = chunks.len() - 1;
    let mut out = Vec::with_capacity(payload.len() + HEADER_LENGTH * chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let status = if index == last { END_OF_MESSAGE } else { 0 };
        let id = u8::try_from(index % 256).unwrap_or(0);
        out.extend(packet(kind, status, chunk, id));
    }
    out
}

/// Write `payload` as one message of `kind`, split at `packet_size`.
///
/// # Errors
/// Where the write failed.
pub fn write_message(
    writer: &mut impl Write,
    kind: u8,
    payload: &[u8],
    packet_size: u16,
) -> Result<()> {
    writer
        .write_all(&packets(kind, payload, packet_size))
        .map_err(|e| classify("writing a message", &e))?;
    writer
        .flush()
        .map_err(|e| classify("flushing a message", &e))
}

/// True when `kind` is a packet type the protocol has, this crate's four
/// and the rest of the table: RPC, attention, bulk load, federated
/// authentication, transaction manager, TLS.
#[must_use]
pub const fn is_packet_type(kind: u8) -> bool {
    matches!(
        kind,
        0x01 | 0x02 | 0x03 | 0x04 | 0x06 | 0x07 | 0x08 | 0x0E | 0x10 | 0x11 | 0x12
    )
}

/// One whole message: its type and the payload of every packet up to the
/// one marked end-of-message, or `None` when the peer closed between
/// messages.
///
/// # Errors
/// A read that failed, a packet shorter than its header, a change of type
/// mid-message, a message over [`MAX_MESSAGE`], or a peer that closed
/// mid-message.
pub fn read_message(reader: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut payload = Vec::new();
    let mut kind = None;
    loop {
        let mut header = [0u8; HEADER_LENGTH];
        let first = reader
            .read(&mut header[..1])
            .map_err(|e| classify("reading a packet header", &e))?;
        if first == 0 {
            return match kind {
                None => Ok(None),
                Some(_) => Err(protocol_error("the peer closed mid-message")),
            };
        }
        reader
            .read_exact(&mut header[1..])
            .map_err(|e| classify("reading a packet header", &e))?;
        match kind {
            None if !is_packet_type(header[0]) => {
                return Err(protocol_error(format!(
                    "{:#04x} is not a packet type; this is not the protocol",
                    header[0]
                )));
            }
            None => kind = Some(header[0]),
            Some(k) if k != header[0] => {
                return Err(protocol_error("a packet of another type mid-message"));
            }
            Some(_) => {}
        }
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if length > usize::from(MAX_PACKET_SIZE) {
            return Err(protocol_error("a packet longer than the protocol allows"));
        }
        let body = length
            .checked_sub(HEADER_LENGTH)
            .ok_or_else(|| protocol_error("a packet shorter than its header"))?;
        if payload.len() + body > MAX_MESSAGE {
            return Err(protocol_error("a message over what Xmip will read"));
        }
        let at = payload.len();
        payload.resize(at + body, 0);
        reader
            .read_exact(&mut payload[at..])
            .map_err(|e| classify("reading a packet body", &e))?;
        if header[1] & END_OF_MESSAGE != 0 {
            return Ok(kind.map(|k| (k, payload)));
        }
    }
}

/// `text` as UCS-2, which is UTF-16 little-endian on this wire.
#[must_use]
pub fn ucs2(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// UCS-2 `bytes` as text, lossily; an odd trailing byte is dropped.
#[must_use]
pub fn from_ucs2(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// `text` as a `B_VARCHAR`: a byte counting characters, then UCS-2. Cut at
/// 255 characters, which is what the count can say.
pub fn push_b_varchar(out: &mut Vec<u8>, text: &str) {
    let units: Vec<u16> = text.encode_utf16().take(usize::from(u8::MAX)).collect();
    out.push(u8::try_from(units.len()).unwrap_or(u8::MAX));
    out.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
}

/// `text` as a `US_VARCHAR`: a u16 counting characters, then UCS-2. Cut at
/// 65535 characters.
pub fn push_us_varchar(out: &mut Vec<u8>, text: &str) {
    let units: Vec<u16> = text.encode_utf16().take(usize::from(u16::MAX)).collect();
    out.extend_from_slice(&u16::try_from(units.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
}

/// Reads a payload's fields in order.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// True when nothing remains.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// What remains.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }

    /// The next `count` bytes.
    ///
    /// # Errors
    /// Fewer than `count` bytes remain.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol_error("a field that runs past the message"))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// Past the next `count` bytes.
    ///
    /// # Errors
    /// Fewer than `count` bytes remain.
    pub fn skip(&mut self, count: usize) -> Result<()> {
        self.take(count).map(|_| ())
    }

    /// The next byte.
    ///
    /// # Errors
    /// Nothing remains.
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// The next little-endian u16.
    ///
    /// # Errors
    /// Fewer than two bytes remain.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// The next big-endian u16, which the pre-login's table uses alone.
    ///
    /// # Errors
    /// Fewer than two bytes remain.
    pub fn u16_be(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// The next little-endian u32.
    ///
    /// # Errors
    /// Fewer than four bytes remain.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The next big-endian u32, which the login acknowledgement's version
    /// uses alone.
    ///
    /// # Errors
    /// Fewer than four bytes remain.
    pub fn u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The next little-endian i32.
    ///
    /// # Errors
    /// Fewer than four bytes remain.
    pub fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The next little-endian u64.
    ///
    /// # Errors
    /// Fewer than eight bytes remain.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut eight = [0u8; 8];
        eight.copy_from_slice(b);
        Ok(u64::from_le_bytes(eight))
    }

    /// The next `chars` characters of UCS-2 as text.
    ///
    /// # Errors
    /// Fewer than twice `chars` bytes remain.
    pub fn ucs2(&mut self, chars: usize) -> Result<String> {
        Ok(from_ucs2(self.take(chars * 2)?))
    }

    /// The next `B_VARCHAR`: a byte counting characters, then UCS-2.
    ///
    /// # Errors
    /// The text runs past the message.
    pub fn b_varchar(&mut self) -> Result<String> {
        let chars = usize::from(self.byte()?);
        self.ucs2(chars)
    }

    /// The next `US_VARCHAR`: a u16 counting characters, then UCS-2.
    ///
    /// # Errors
    /// The text runs past the message.
    pub fn us_varchar(&mut self) -> Result<String> {
        let chars = usize::from(self.u16()?);
        self.ucs2(chars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_splits_into_packets_and_reads_back_whole() {
        let payload: Vec<u8> = (0..1500u32)
            .map(|n| u8::try_from(n % 251).expect("byte"))
            .collect();
        let bytes = packets(SQL_BATCH, &payload, MIN_PACKET_SIZE);
        assert_eq!(
            bytes.len(),
            payload.len() + 3 * HEADER_LENGTH,
            "three packets"
        );
        assert_eq!(
            &bytes[..4],
            &[SQL_BATCH, 0, 0x02, 0x00],
            "512 long, not the last"
        );
        assert_eq!(bytes[6], 0, "the first packet id");
        assert_eq!(bytes[512 + 6], 1, "the second");
        let (kind, whole) = read_message(&mut bytes.as_slice())
            .expect("read")
            .expect("one");
        assert_eq!(kind, SQL_BATCH);
        assert_eq!(whole, payload);
        let empty = packets(PRELOGIN, &[], DEFAULT_PACKET_SIZE);
        assert_eq!(empty, [PRELOGIN, END_OF_MESSAGE, 0, 8, 0, 0, 0, 0]);
        assert_eq!(
            read_message(&mut empty.as_slice()).expect("read"),
            Some((PRELOGIN, Vec::new()))
        );
        assert!(read_message(&mut &b""[..]).expect("closed").is_none());
    }

    #[test]
    fn what_is_not_a_message_is_refused() {
        assert!(
            read_message(&mut &[0x01, 0x01, 0, 4, 0, 0, 0, 0][..]).is_err(),
            "under eight"
        );
        assert!(
            read_message(&mut &[0x01, 0x01, 0, 12, 0, 0, 0, 0, 1][..]).is_err(),
            "breaks off"
        );
        let mut two = packet(SQL_BATCH, 0, b"a", 0);
        two.extend(packet(LOGIN7, END_OF_MESSAGE, b"b", 1));
        assert!(read_message(&mut two.as_slice()).is_err(), "changes type");
        let open = packet(SQL_BATCH, 0, b"a", 0);
        assert!(
            read_message(&mut open.as_slice()).is_err(),
            "closed mid-message"
        );
        let error = read_message(&mut &b"HTTP/1.1 400 Bad Request\r\n\r\n"[..])
            .expect_err("not the protocol");
        assert!(error.message.contains("0x48"), "{error}");
        assert!(!error.retryable);
        assert!(
            read_message(&mut &[0x04, 0x01, 0x80, 0x01, 0, 0, 0, 0][..]).is_err(),
            "over 32767"
        );
    }

    #[test]
    fn text_and_counted_strings_round_trip() {
        assert_eq!(ucs2("ab"), [b'a', 0, b'b', 0]);
        assert_eq!(from_ucs2(&ucs2("räksmörgås")), "räksmörgås");
        assert_eq!(from_ucs2(&[b'a', 0, b'b']), "a", "an odd byte is dropped");
        let mut body = Vec::new();
        push_b_varchar(&mut body, "id");
        push_us_varchar(&mut body, "payload");
        body.extend_from_slice(&7u16.to_le_bytes());
        body.extend_from_slice(&7u16.to_be_bytes());
        body.extend_from_slice(&(-3i32).to_le_bytes());
        body.extend_from_slice(&9u64.to_le_bytes());
        let mut cursor = Cursor::new(&body);
        assert_eq!(cursor.b_varchar().expect("b"), "id");
        assert_eq!(cursor.us_varchar().expect("us"), "payload");
        assert_eq!(cursor.u16().expect("le"), 7);
        assert_eq!(cursor.u16_be().expect("be"), 7);
        assert_eq!(cursor.i32().expect("i32"), -3);
        assert_eq!(cursor.u64().expect("u64"), 9);
        assert!(cursor.is_empty());
        assert!(cursor.byte().is_err(), "past the end");
        let long = "x".repeat(300);
        let mut body = Vec::new();
        push_b_varchar(&mut body, &long);
        assert_eq!(body[0], 255, "cut at what the count can say");
        assert_eq!(body.len(), 1 + 255 * 2);
    }
}
