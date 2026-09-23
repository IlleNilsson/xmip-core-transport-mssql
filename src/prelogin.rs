//! The pre-login, both ways: the first message on a connection, before
//! anyone is named. A table of options — each a token, a big-endian
//! offset and a length — then the options' bytes, in a shape the two
//! sides share. Five options are spoken here: VERSION, ENCRYPTION,
//! INSTOPT, THREADID and MARS. The client says it does not support
//! encryption and the server agrees or demands it, and a demand stops
//! this crate, because TLS is `xmip-core-tls`'s per ADR-0033.
//! MARS is off: one batch at a time is what a Location runs. Anything
//! else in the table is read past.

use transport::error::{Result, protocol_error};

use crate::wire::Cursor;

/// The sender's version: four bytes of version, two of sub-build.
pub const VERSION: u8 = 0x00;
/// One byte: one of the `ENCRYPT_*` answers.
pub const ENCRYPTION: u8 = 0x01;
/// The instance name, NUL-terminated.
pub const INSTOPT: u8 = 0x02;
/// The client's thread, four bytes; the server answers with none.
pub const THREADID: u8 = 0x03;
/// One byte: multiple active result sets, on or off.
pub const MARS: u8 = 0x04;
/// The end of the option table.
pub const TERMINATOR: u8 = 0xFF;

/// Encrypt the login only.
pub const ENCRYPT_OFF: u8 = 0x00;
/// Encrypt everything.
pub const ENCRYPT_ON: u8 = 0x01;
/// Encryption is not available on this side.
pub const ENCRYPT_NOT_SUP: u8 = 0x02;
/// Encryption is required by this side.
pub const ENCRYPT_REQ: u8 = 0x03;

/// What one side says before the login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prelogin {
    pub version: [u8; 6],
    pub encryption: u8,
    pub instance: String,
    pub thread_id: u32,
    pub mars: bool,
}

impl Default for Prelogin {
    /// What this crate says: version 0.0.1, no encryption, the default
    /// instance, no thread, MARS off.
    fn default() -> Self {
        Self {
            version: [0, 0, 0, 1, 0, 0],
            encryption: ENCRYPT_NOT_SUP,
            instance: String::new(),
            thread_id: 0,
            mars: false,
        }
    }
}

/// `prelogin` as the payload on the wire.
#[must_use]
pub fn encode_prelogin(prelogin: &Prelogin) -> Vec<u8> {
    let mut instance = prelogin.instance.as_bytes().to_vec();
    instance.push(0);
    let options: [(u8, Vec<u8>); 5] = [
        (VERSION, prelogin.version.to_vec()),
        (ENCRYPTION, vec![prelogin.encryption]),
        (INSTOPT, instance),
        (THREADID, prelogin.thread_id.to_le_bytes().to_vec()),
        (MARS, vec![u8::from(prelogin.mars)]),
    ];
    let base = options.len() * 5 + 1;
    let mut table = Vec::with_capacity(base);
    let mut data = Vec::new();
    for (token, bytes) in &options {
        table.push(*token);
        let offset = u16::try_from(base + data.len()).unwrap_or(u16::MAX);
        table.extend_from_slice(&offset.to_be_bytes());
        let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        table.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(bytes);
    }
    table.push(TERMINATOR);
    table.extend(data);
    table
}

/// The pre-login a payload carries. An option missing from the table is
/// left at its default; one this crate does not know is read past.
///
/// # Errors
/// A table without its terminator, or an option that points past the
/// payload.
pub fn read_prelogin(body: &[u8]) -> Result<Prelogin> {
    let mut cursor = Cursor::new(body);
    let mut prelogin = Prelogin::default();
    loop {
        let token = cursor.byte()?;
        if token == TERMINATOR {
            return Ok(prelogin);
        }
        let offset = usize::from(cursor.u16_be()?);
        let length = usize::from(cursor.u16_be()?);
        let bytes = body
            .get(offset..offset + length)
            .ok_or_else(|| protocol_error("a pre-login option that points past the message"))?;
        match token {
            VERSION => {
                for (slot, byte) in prelogin.version.iter_mut().zip(bytes) {
                    *slot = *byte;
                }
            }
            ENCRYPTION => {
                prelogin.encryption = *bytes
                    .first()
                    .ok_or_else(|| protocol_error("an empty encryption option"))?;
            }
            INSTOPT => {
                let name = bytes.split(|b| *b == 0).next().unwrap_or_default();
                prelogin.instance = String::from_utf8_lossy(name).into_owned();
            }
            THREADID => {
                if let Ok(four) = <[u8; 4]>::try_from(bytes) {
                    prelogin.thread_id = u32::from_le_bytes(four);
                }
            }
            MARS => prelogin.mars = bytes.first().is_some_and(|b| *b != 0),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prelogin_round_trips_and_its_table_is_where_the_spec_puts_it() {
        let prelogin = Prelogin {
            version: [16, 0, 4, 0, 0, 1],
            encryption: ENCRYPT_REQ,
            instance: "SQLEXPRESS".into(),
            thread_id: 0x1234,
            mars: true,
        };
        let bytes = encode_prelogin(&prelogin);
        assert_eq!(
            &bytes[..5],
            &[VERSION, 0, 26, 0, 6],
            "the first option at 26"
        );
        assert_eq!(bytes[25], TERMINATOR);
        assert_eq!(read_prelogin(&bytes).expect("read"), prelogin);
        let plain = encode_prelogin(&Prelogin::default());
        let read = read_prelogin(&plain).expect("read");
        assert_eq!(read.encryption, ENCRYPT_NOT_SUP);
        assert!(read.instance.is_empty());
        assert!(!read.mars);
    }

    #[test]
    fn what_is_missing_is_defaulted_and_what_is_wrong_is_refused() {
        let server = [
            ENCRYPTION,
            0,
            11,
            0,
            1,
            THREADID,
            0,
            12,
            0,
            0,
            TERMINATOR,
            ENCRYPT_OFF,
        ];
        let read = read_prelogin(&server).expect("read");
        assert_eq!(read.encryption, ENCRYPT_OFF);
        assert_eq!(read.thread_id, 0, "an empty thread id");
        assert!(
            read_prelogin(&[VERSION, 0, 6, 0, 6]).is_err(),
            "no terminator"
        );
        assert!(
            read_prelogin(&[VERSION, 0, 6, 0, 60, TERMINATOR]).is_err(),
            "past the end"
        );
        assert!(
            read_prelogin(&[ENCRYPTION, 0, 6, 0, 0, TERMINATOR]).is_err(),
            "empty"
        );
    }
}
