//! A SQL batch: the one message a client sends after the login. Since
//! TDS 7.2 it opens with `ALL_HEADERS` — a total length, then one header
//! of type 2 carrying the transaction descriptor and the count of
//! outstanding requests, both trivial here because there is no
//! transaction and one request at a time — and the SQL follows in UCS-2.
//! Read here as well as written, because the far-end [`crate::Session`]
//! reads exactly this.

use transport::error::{Result, protocol_error};

use crate::wire::{Cursor, from_ucs2, ucs2};

/// The transaction-descriptor header, the one every batch carries.
pub const TRANSACTION_HEADER: u16 = 0x0002;
/// `ALL_HEADERS` as this crate writes it: the total, then one header of
/// eighteen bytes.
const HEADERS_LENGTH: u32 = 22;

/// `sql` as the payload on the wire.
#[must_use]
pub fn encode_batch(sql: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + sql.len() * 2);
    out.extend_from_slice(&HEADERS_LENGTH.to_le_bytes());
    out.extend_from_slice(&(HEADERS_LENGTH - 4).to_le_bytes());
    out.extend_from_slice(&TRANSACTION_HEADER.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // no transaction
    out.extend_from_slice(&1u32.to_le_bytes()); // one outstanding request
    out.extend(ucs2(sql));
    out
}

/// The SQL a payload carries, its headers read past.
///
/// # Errors
/// A headers length under four or past the message.
pub fn read_batch(body: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(body);
    let total = usize::try_from(cursor.u32()?).unwrap_or(usize::MAX);
    let rest = total
        .checked_sub(4)
        .ok_or_else(|| protocol_error("a headers length under four"))?;
    cursor
        .skip(rest)
        .map_err(|_| protocol_error("headers that run past the batch"))?;
    Ok(from_ucs2(cursor.remaining()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_round_trips_behind_its_headers() {
        let bytes = encode_batch("SELECT 1");
        assert_eq!(&bytes[..4], &[22, 0, 0, 0]);
        assert_eq!(&bytes[8..10], &[2, 0], "the transaction header");
        assert_eq!(bytes.len(), 22 + 16);
        assert_eq!(read_batch(&bytes).expect("read"), "SELECT 1");
        assert_eq!(read_batch(&encode_batch("")).expect("read"), "");
    }

    #[test]
    fn headers_that_are_not_headers_are_refused() {
        assert!(read_batch(&[2, 0, 0, 0]).is_err(), "under four");
        assert!(read_batch(&[40, 0, 0, 0, 0, 0]).is_err(), "past the batch");
        assert!(read_batch(&[0, 0]).is_err(), "no length at all");
    }
}
