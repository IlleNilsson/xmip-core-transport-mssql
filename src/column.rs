//! The column types this crate serves and reads, and one value of each on
//! the wire. SQL Server has thirty-odd types and a Stream needs three: an
//! integer to name a row, text to carry it, binary to carry it when it is
//! not text. So INTN, INT and BIGINT, BIT and BITN, NVARCHAR, VARCHAR and
//! VARBINARY are read, the (MAX) forms in their partially-length-prefixed
//! chunks, and every value comes out as text — an integer in decimal, a
//! bit as `0` or `1`, binary as the `0x` literal. A column of any other
//! type is refused by its type byte when its metadata arrives, and the
//! operator casts it in the query.

use codec::cursor::Cursor;
use transport::error::{Result, protocol_error};

use crate::binary::{column_bytes, hex_literal};

/// A nullable integer of one, two, four or eight bytes.
pub const INTN: u8 = 0x26;
/// A four-byte integer, never null.
pub const INT4: u8 = 0x38;
/// An eight-byte integer, never null.
pub const INT8: u8 = 0x7F;
/// One bit, never null.
pub const BIT: u8 = 0x32;
/// One bit, or null.
pub const BITN: u8 = 0x68;
/// UCS-2 text with a collation.
pub const NVARCHAR: u8 = 0xE7;
/// Single-byte text with a collation, read as UTF-8 regardless.
pub const BIGVARCHAR: u8 = 0xA7;
/// Bytes.
pub const BIGVARBINARY: u8 = 0xA5;
/// The length a `(MAX)` column declares, and a null short value carries.
pub const MAX: u16 = 0xFFFF;
/// A partially-length-prefixed null.
const PLP_NULL: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// A partially-length-prefixed value of length the server did not know.
const PLP_UNKNOWN: u64 = 0xFFFF_FFFF_FFFF_FFFE;

/// A column's type, with what its metadata declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnType {
    /// A nullable integer this wide.
    IntN(u8),
    Int,
    BigInt,
    Bit,
    BitN,
    /// Text up to this many bytes, or [`MAX`].
    NVarChar(u16),
    VarChar(u16),
    VarBinary(u16),
}

/// One column of a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub kind: ColumnType,
}

impl Column {
    /// `name` of `kind`.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: ColumnType) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }

    /// `name` as `NVARCHAR(MAX)`, which carries any text.
    #[must_use]
    pub fn text(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::NVarChar(MAX))
    }
}

/// `kind` as the `TYPE_INFO` its metadata carries.
pub fn write_type_info(out: &mut Vec<u8>, kind: ColumnType) {
    match kind {
        ColumnType::IntN(width) => out.extend_from_slice(&[INTN, width]),
        ColumnType::Int => out.push(INT4),
        ColumnType::BigInt => out.push(INT8),
        ColumnType::Bit => out.push(BIT),
        ColumnType::BitN => out.extend_from_slice(&[BITN, 1]),
        ColumnType::NVarChar(max) | ColumnType::VarChar(max) => {
            out.push(if kind == ColumnType::NVarChar(max) {
                NVARCHAR
            } else {
                BIGVARCHAR
            });
            out.extend_from_slice(&max.to_le_bytes());
            out.extend_from_slice(&[0u8; 5]); // the collation, none
        }
        ColumnType::VarBinary(max) => {
            out.push(BIGVARBINARY);
            out.extend_from_slice(&max.to_le_bytes());
        }
    }
}

/// The type a `TYPE_INFO` declares.
///
/// # Errors
/// A type this crate does not read, or metadata that breaks off.
pub fn read_type_info(cursor: &mut Cursor<'_>) -> Result<ColumnType> {
    Ok(match cursor.byte()? {
        INTN => ColumnType::IntN(cursor.byte()?),
        INT4 => ColumnType::Int,
        INT8 => ColumnType::BigInt,
        BIT => ColumnType::Bit,
        BITN => {
            cursor.skip(1)?;
            ColumnType::BitN
        }
        NVARCHAR => {
            let max = cursor.u16_le()?;
            cursor.skip(5)?;
            ColumnType::NVarChar(max)
        }
        BIGVARCHAR => {
            let max = cursor.u16_le()?;
            cursor.skip(5)?;
            ColumnType::VarChar(max)
        }
        BIGVARBINARY => ColumnType::VarBinary(cursor.u16_le()?),
        other => {
            return Err(protocol_error(format!(
                "column type {other:#04x} is not one this crate reads; cast it in the query"
            )));
        }
    })
}

/// `value` as one cell of `kind` in a row. A fixed-width type has no
/// null, so `None` is written as zero there.
pub fn write_value(out: &mut Vec<u8>, kind: ColumnType, value: Option<&str>) {
    match kind {
        ColumnType::IntN(width) => match value {
            None => out.push(0),
            Some(text) => {
                out.push(width);
                let width = usize::from(width).min(8);
                out.extend_from_slice(&integer(text).to_le_bytes()[..width]);
            }
        },
        ColumnType::Int => {
            let value = i32::try_from(value.map_or(0, integer)).unwrap_or(0);
            out.extend_from_slice(&value.to_le_bytes());
        }
        ColumnType::BigInt => out.extend_from_slice(&value.map_or(0, integer).to_le_bytes()),
        ColumnType::Bit => out.push(u8::from(truthy(value))),
        ColumnType::BitN => match value {
            None => out.push(0),
            Some(_) => out.extend_from_slice(&[1, u8::from(truthy(value))]),
        },
        ColumnType::NVarChar(max) => {
            write_bytes(out, max, value.map(codec::utf16::encode).as_deref());
        }
        ColumnType::VarChar(max) => write_bytes(out, max, value.map(str::as_bytes)),
        ColumnType::VarBinary(max) => {
            let bytes = value.map(|text| column_bytes(text.to_string()));
            write_bytes(out, max, bytes.as_deref());
        }
    }
}

/// One cell of `kind` as text, or `None` where it is null.
///
/// # Errors
/// A width the type does not have, or a value that breaks off.
pub fn read_value(cursor: &mut Cursor<'_>, kind: ColumnType) -> Result<Option<String>> {
    Ok(match kind {
        ColumnType::IntN(_) => {
            let width = cursor.byte()?;
            let bytes = cursor.take(usize::from(width))?;
            match width {
                0 => None,
                1 => Some(i8::from_le_bytes([bytes[0]]).to_string()),
                2 => Some(i16::from_le_bytes([bytes[0], bytes[1]]).to_string()),
                4 => Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()),
                8 => {
                    let mut eight = [0u8; 8];
                    eight.copy_from_slice(bytes);
                    Some(i64::from_le_bytes(eight).to_string())
                }
                other => return Err(protocol_error(format!("an integer {other} bytes wide"))),
            }
        }
        ColumnType::Int => Some(cursor.i32_le()?.to_string()),
        ColumnType::BigInt => {
            let mut eight = [0u8; 8];
            eight.copy_from_slice(cursor.take(8)?);
            Some(i64::from_le_bytes(eight).to_string())
        }
        ColumnType::Bit => Some(u8::from(cursor.byte()? != 0).to_string()),
        ColumnType::BitN => match cursor.byte()? {
            0 => None,
            _ => Some(u8::from(cursor.byte()? != 0).to_string()),
        },
        ColumnType::NVarChar(max) => {
            read_bytes(cursor, max)?.map(|b| codec::utf16::decode_lossy(&b))
        }
        ColumnType::VarChar(max) => {
            read_bytes(cursor, max)?.map(|b| String::from_utf8_lossy(&b).into_owned())
        }
        ColumnType::VarBinary(max) => read_bytes(cursor, max)?.map(|b| hex_literal(&b)),
    })
}

/// A variable-length value: partially length-prefixed where the column is
/// `(MAX)`, a u16 length with [`MAX`] for null otherwise.
fn write_bytes(out: &mut Vec<u8>, max: u16, bytes: Option<&[u8]>) {
    if max == MAX {
        return write_plp(out, bytes);
    }
    match bytes {
        None => out.extend_from_slice(&MAX.to_le_bytes()),
        Some(bytes) => {
            let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX - 1);
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(&bytes[..usize::from(length)]);
        }
    }
}

fn read_bytes(cursor: &mut Cursor<'_>, max: u16) -> Result<Option<Vec<u8>>> {
    if max == MAX {
        return read_plp(cursor);
    }
    let length = cursor.u16_le()?;
    if length == MAX {
        return Ok(None);
    }
    Ok(Some(cursor.take(usize::from(length))?.to_vec()))
}

/// `bytes` partially length-prefixed: the total, then chunks each behind
/// a u32 length, then a zero.
pub fn write_plp(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    let Some(bytes) = bytes else {
        return out.extend_from_slice(&PLP_NULL.to_le_bytes());
    };
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    for chunk in bytes.chunks(usize::from(u16::MAX)) {
        out.extend_from_slice(&u32::try_from(chunk.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&0u32.to_le_bytes());
}

/// The bytes a partially-length-prefixed value carries, or `None`.
///
/// # Errors
/// Chunks that do not add up to the total, or that break off.
pub fn read_plp(cursor: &mut Cursor<'_>) -> Result<Option<Vec<u8>>> {
    let total = cursor.u64_le()?;
    if total == PLP_NULL {
        return Ok(None);
    }
    let mut out = Vec::new();
    loop {
        let chunk = cursor.u32_le()?;
        if chunk == 0 {
            break;
        }
        let length = usize::try_from(chunk).map_err(|_| protocol_error("a chunk too long"))?;
        out.extend_from_slice(cursor.take(length)?);
    }
    if total != PLP_UNKNOWN && total != out.len() as u64 {
        return Err(protocol_error("chunks that do not add up to their total"));
    }
    Ok(Some(out))
}

fn integer(text: &str) -> i64 {
    text.trim().parse().unwrap_or(0)
}

fn truthy(text: Option<&str>) -> bool {
    text.is_some_and(|t| matches!(t.trim(), "1" | "true" | "True" | "TRUE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(kind: ColumnType, value: Option<&str>) -> Option<String> {
        let mut out = Vec::new();
        write_type_info(&mut out, kind);
        write_value(&mut out, kind, value);
        let mut cursor = Cursor::new(&out);
        assert_eq!(read_type_info(&mut cursor).expect("type"), kind);
        let read = read_value(&mut cursor, kind).expect("value");
        assert!(cursor.is_empty(), "nothing left over");
        read
    }

    #[test]
    fn every_type_round_trips_with_its_null() {
        assert_eq!(
            round_trip(ColumnType::IntN(4), Some("41")),
            Some("41".into())
        );
        assert_eq!(
            round_trip(ColumnType::IntN(8), Some("-9")),
            Some("-9".into())
        );
        assert_eq!(
            round_trip(ColumnType::IntN(2), Some("-2")),
            Some("-2".into())
        );
        assert_eq!(round_trip(ColumnType::IntN(1), Some("7")), Some("7".into()));
        assert_eq!(round_trip(ColumnType::IntN(4), None), None);
        assert_eq!(round_trip(ColumnType::Int, Some("3")), Some("3".into()));
        assert_eq!(
            round_trip(ColumnType::BigInt, None),
            Some("0".into()),
            "no null"
        );
        assert_eq!(round_trip(ColumnType::Bit, Some("true")), Some("1".into()));
        assert_eq!(round_trip(ColumnType::BitN, Some("0")), Some("0".into()));
        assert_eq!(round_trip(ColumnType::BitN, None), None);
        assert_eq!(
            round_trip(ColumnType::NVarChar(MAX), Some("räk")),
            Some("räk".into())
        );
        assert_eq!(
            round_trip(ColumnType::NVarChar(MAX), Some("")),
            Some(String::new())
        );
        assert_eq!(round_trip(ColumnType::NVarChar(MAX), None), None);
        assert_eq!(
            round_trip(ColumnType::NVarChar(80), Some("short")),
            Some("short".into())
        );
        assert_eq!(round_trip(ColumnType::NVarChar(80), None), None);
        assert_eq!(
            round_trip(ColumnType::VarChar(MAX), Some("ISA*00*")),
            Some("ISA*00*".into())
        );
        assert_eq!(
            round_trip(ColumnType::VarChar(10), Some("x")),
            Some("x".into())
        );
        assert_eq!(
            round_trip(ColumnType::VarBinary(MAX), Some("0xfffe")),
            Some("0xfffe".into())
        );
        assert_eq!(
            round_trip(ColumnType::VarBinary(8), Some("0x00")),
            Some("0x00".into())
        );
        assert_eq!(round_trip(ColumnType::VarBinary(8), None), None);
        assert_eq!(
            round_trip(ColumnType::VarBinary(MAX), Some("ab")),
            Some("0x6162".into())
        );
        let long = "y".repeat(70_000);
        assert_eq!(
            round_trip(ColumnType::VarChar(MAX), Some(&long)),
            Some(long),
            "two chunks"
        );
    }

    #[test]
    fn what_this_crate_does_not_read_is_refused_by_name() {
        let error = read_type_info(&mut Cursor::new(&[0x2A, 7])).expect_err("datetime2");
        assert!(error.message.contains("0x2a"));
        assert!(read_value(&mut Cursor::new(&[3, 0, 0, 0]), ColumnType::IntN(3)).is_err());
        let mut plp = Vec::new();
        plp.extend_from_slice(&5u64.to_le_bytes());
        plp.extend_from_slice(&2u32.to_le_bytes());
        plp.extend_from_slice(b"ab");
        plp.extend_from_slice(&0u32.to_le_bytes());
        assert!(read_plp(&mut Cursor::new(&plp)).is_err(), "does not add up");
        plp[..8].copy_from_slice(&PLP_UNKNOWN.to_le_bytes());
        assert_eq!(
            read_plp(&mut Cursor::new(&plp)).expect("unknown total"),
            Some(b"ab".to_vec())
        );
        let short = [1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, b'a'];
        assert!(read_plp(&mut Cursor::new(&short)).is_err(), "breaks off");
    }
}
