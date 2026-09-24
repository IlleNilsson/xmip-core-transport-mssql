//! One INSERT taken apart, so the far-end [`crate::Session`] can record
//! what a client wrote without being a SQL parser. The statement's shape is
//! the capability's (`transport::sql`, ADR-0044); the T-SQL dialect is
//! here — bracketed or bare identifiers and a string or `0x` literal, the
//! doubled delimiters read by `codec::sql`. Anything else is not an insert
//! this crate serves.

use codec::sql::Delimiter;
use transport::sql;

use crate::binary::from_hex_literal;

/// `INSERT INTO <table> (<column>) VALUES (<literal>)` taken apart: the
/// table, the column and the literal's bytes — a string literal's text,
/// with or without its `N`, quotes undoubled; a `0x` literal's bytes.
/// Identifiers may be bracketed; anything else is `None`.
#[must_use]
pub fn parse_insert(statement: &str) -> Option<(String, String, Vec<u8>)> {
    sql::parse_insert(statement, identifier, literal)
}

/// One identifier, bare or bracketed with `]]` for a bracket, and what
/// follows it.
fn identifier(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if rest.starts_with('[') {
        return Delimiter::BRACKET.unquote_prefix(rest).ok();
    }
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '#' | '@')))
        .unwrap_or(rest.len());
    (end > 0).then(|| (rest[..end].to_string(), &rest[end..]))
}

/// One literal — `N'…'`, `'…'` or `0x…` — as bytes, and what follows it.
fn literal(rest: &str) -> Option<(Vec<u8>, &str)> {
    let rest = rest.trim_start();
    if rest.starts_with("0x") || rest.starts_with("0X") {
        let digits = &rest[2..];
        let end = digits
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(digits.len());
        return Some((from_hex_literal(&rest[..2 + end])?, &digits[end..]));
    }
    let quoted = rest.strip_prefix('N').unwrap_or(rest);
    let (value, after) = Delimiter::STRING.unquote_prefix(quoted).ok()?;
    Some((value.into_bytes(), after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_insert_of_one_column_is_taken_apart() {
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES (N'it''s here');"),
            Some(("inbox".into(), "payload".into(), b"it's here".to_vec()))
        );
        assert_eq!(
            parse_insert("insert into [In ]]box] ( [Payload] ) values ( '' )"),
            Some(("In ]box".into(), "Payload".into(), Vec::new()))
        );
        assert_eq!(
            parse_insert("INSERT INTO dbo.inbox (payload) VALUES (0xFFfe)"),
            Some(("dbo.inbox".into(), "payload".into(), vec![0xff, 0xfe]))
        );
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES (0x)"),
            Some(("inbox".into(), "payload".into(), Vec::new()))
        );
        assert!(parse_insert("INSERT INTO inbox (a, b) VALUES ('x', 'y')").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES ('open").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES (0xabc)").is_none());
        assert!(parse_insert("INSERT INTO [open (a) VALUES ('x')").is_none());
        assert!(parse_insert("UPDATE inbox SET a = 'x'").is_none());
    }
}
