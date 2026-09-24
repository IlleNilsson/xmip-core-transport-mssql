//! The login, LOGIN7: one message from the client, the only one that
//! names anyone. A fixed part of versions, sizes and flags, then a table
//! of offsets and character counts into a tail of UCS-2 fields — host,
//! user, password, application, server, library, language, database.
//! The password is obscured, not encrypted: each byte's nibbles swapped
//! and the result exclusive-ORed with 0xA5, which keeps it out of a casual trace
//! and nothing more; the wire is TLS's to protect, per ADR-0033. SQL
//! Server authentication only — no SSPI, no federated token — because a
//! login on a service account is what an integration runs as. Read here
//! as well as written, because the far-end [`crate::Session`] reads it.

use codec::cursor::Cursor;
use transport::error::{Result, protocol_error};

use crate::wire::{DEFAULT_PACKET_SIZE, from_ucs2, ucs2};

/// TDS 7.4, as the login writes it.
pub const TDS_7_4: u32 = 0x7400_0004;
/// The fixed part and the offset table, before the first field.
const FIXED_LENGTH: usize = 94;
/// The fields in the order the offset table names them.
const FIELDS: usize = 9;

/// Who logs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    pub password: String,
}

impl Login {
    /// `user` with `password`.
    #[must_use]
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }
}

/// The whole login message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login7 {
    pub login: Login,
    pub database: String,
    pub hostname: String,
    pub app_name: String,
    pub server_name: String,
    pub library: String,
    pub language: String,
    pub packet_size: u32,
}

impl Login7 {
    /// `login` on `database`, the rest saying it is Xmip.
    #[must_use]
    pub fn new(login: Login, database: impl Into<String>) -> Self {
        Self {
            login,
            database: database.into(),
            hostname: "xmip".to_string(),
            app_name: "xmip".to_string(),
            server_name: String::new(),
            library: "xmip-core-transport-mssql".to_string(),
            language: String::new(),
            packet_size: u32::from(DEFAULT_PACKET_SIZE),
        }
    }
}

/// `password` as the wire carries it: nibbles swapped, then XOR 0xA5.
#[must_use]
pub fn obscure(password: &[u8]) -> Vec<u8> {
    password.iter().map(|b| b.rotate_left(4) ^ 0xA5).collect()
}

/// The password an obscured one was.
#[must_use]
pub fn reveal(obscured: &[u8]) -> Vec<u8> {
    obscured.iter().map(|b| (b ^ 0xA5).rotate_left(4)).collect()
}

/// `login` as the payload on the wire.
#[must_use]
pub fn encode_login7(login: &Login7) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIXED_LENGTH);
    out.extend_from_slice(&0u32.to_le_bytes()); // length, written last
    out.extend_from_slice(&TDS_7_4.to_le_bytes());
    out.extend_from_slice(&login.packet_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // client program version
    out.extend_from_slice(&std::process::id().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // connection id
    // fUseDB, fDatabase and fSetLang; fODBC; no type flags; nothing more.
    out.extend_from_slice(&[0xE0, 0x02, 0x00, 0x00]);
    out.extend_from_slice(&0i32.to_le_bytes()); // time zone
    out.extend_from_slice(&0u32.to_le_bytes()); // LCID
    let password = obscure(&ucs2(&login.login.password));
    let fields: [Vec<u8>; FIELDS] = [
        ucs2(&login.hostname),
        ucs2(&login.login.user),
        password,
        ucs2(&login.app_name),
        ucs2(&login.server_name),
        Vec::new(), // the extension, unused
        ucs2(&login.library),
        ucs2(&login.language),
        ucs2(&login.database),
    ];
    let mut tail = Vec::new();
    for field in &fields {
        let offset = u16::try_from(FIXED_LENGTH + tail.len()).unwrap_or(u16::MAX);
        let chars = u16::try_from(field.len() / 2).unwrap_or(u16::MAX);
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&chars.to_le_bytes());
        tail.extend_from_slice(field);
    }
    out.extend_from_slice(&[0u8; 6]); // client id
    let end = u16::try_from(FIXED_LENGTH + tail.len()).unwrap_or(u16::MAX);
    for _ in 0..3 {
        // SSPI, the attach-database file, the change of password: none.
        out.extend_from_slice(&end.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // long SSPI
    out.extend(tail);
    let length = u32::try_from(out.len()).unwrap_or(u32::MAX);
    out[..4].copy_from_slice(&length.to_le_bytes());
    out
}

/// The login a payload carries, the password revealed.
///
/// # Errors
/// A version that is not TDS 7.2 to 7.4, a message shorter than its fixed
/// part, or a field that points past the message.
pub fn read_login7(body: &[u8]) -> Result<Login7> {
    let mut cursor = Cursor::new(body);
    let _length = cursor.u32_le()?;
    let version = cursor.u32_le()?;
    if !(0x72..=0x74).contains(&(version >> 24)) {
        return Err(protocol_error(format!(
            "TDS {version:#010x} is not 7.2 to 7.4"
        )));
    }
    let packet_size = cursor.u32_le()?;
    cursor.skip(12)?; // program version, process id, connection id
    cursor.skip(4)?; // the four flag bytes
    cursor.skip(8)?; // time zone, LCID
    let mut fields: Vec<Vec<u8>> = Vec::with_capacity(FIELDS);
    for _ in 0..FIELDS {
        let offset = usize::from(cursor.u16_le()?);
        let chars = usize::from(cursor.u16_le()?);
        let bytes = body
            .get(offset..offset + chars * 2)
            .ok_or_else(|| protocol_error("a login field that points past the message"))?;
        fields.push(bytes.to_vec());
    }
    Ok(Login7 {
        login: Login {
            user: from_ucs2(&fields[1]),
            password: from_ucs2(&reveal(&fields[2])),
        },
        database: from_ucs2(&fields[8]),
        hostname: from_ucs2(&fields[0]),
        app_name: from_ucs2(&fields[3]),
        server_name: from_ucs2(&fields[4]),
        library: from_ucs2(&fields[6]),
        language: from_ucs2(&fields[7]),
        packet_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_is_obscured_the_way_the_spec_draws_it() {
        // The spec's own example: 'a' (0x61) becomes 0xB3 after the swap and XOR.
        assert_eq!(obscure(b"a"), [0xB3]);
        let secret: Vec<u8> = (0..=255).collect();
        assert_eq!(reveal(&obscure(&secret)), secret);
        assert_ne!(obscure(b"secret"), b"secret");
    }

    #[test]
    fn a_login_round_trips_with_its_table_where_the_spec_puts_it() {
        let login = Login7 {
            login: Login::new("xmip", "sec'ret"),
            database: "orders".into(),
            hostname: "node-1".into(),
            app_name: "playground".into(),
            server_name: "db.example".into(),
            library: "xmip-core-transport-mssql".into(),
            language: "us_english".into(),
            packet_size: 8000,
        };
        let bytes = encode_login7(&login);
        assert_eq!(&bytes[4..8], &[0x04, 0x00, 0x00, 0x74], "TDS 7.4");
        assert_eq!(&bytes[36..38], &[94, 0], "the first field at 94");
        assert_eq!(bytes.len(), 94 + 2 * (6 + 4 + 7 + 10 + 10 + 25 + 10 + 6));
        assert_eq!(read_login7(&bytes).expect("read"), login);
        let plain = encode_login7(&Login7::new(Login::new("xmip", ""), "orders"));
        let read = read_login7(&plain).expect("read");
        assert_eq!(read.login.user, "xmip");
        assert!(read.login.password.is_empty());
        assert_eq!(read.hostname, "xmip");
        assert_eq!(read.packet_size, 4096);
    }

    #[test]
    fn what_is_not_a_login_is_refused() {
        let mut old = encode_login7(&Login7::new(Login::new("x", "y"), "z"));
        old[7] = 0x71;
        assert!(read_login7(&old).is_err(), "TDS 7.1");
        assert!(
            read_login7(&[0; 40]).is_err(),
            "shorter than the fixed part"
        );
        let mut wild = encode_login7(&Login7::new(Login::new("x", "y"), "z"));
        wild[40] = 0xFF;
        assert!(read_login7(&wild).is_err(), "a field past the end");
    }
}
