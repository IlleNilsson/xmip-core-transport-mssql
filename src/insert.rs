//! One INSERT taken apart, so the far-end [`crate::Session`] can record
//! what a client wrote without being a SQL parser. The statement's shape is
//! the capability's (`transport::sql`, ADR-0044); the T-SQL dialect is
//! here — bracketed or bare identifiers and a string or `0x` literal, the
//! doubled delimiters read by `codec::sql`. Anything else is not an insert
//! this crate serves.

use codec::sql::Delimiter;
use transport::sql::{Dialect, Literal};

use crate::binary::from_hex_literal;

/// T-SQL as the capability writes and reads it: a target opens with
/// `mssql://` or `sqlserver://`, names a database, and an identifier is
/// bracketed with `]]` for a bracket, or bare with `_ . # @` in it.
pub const DIALECT: Dialect = Dialect {
    schemes: &["mssql", "sqlserver"],
    catalog: "database",
    identifier: Delimiter::BRACKET,
    bare: &['_', '.', '#', '@'],
};

/// `INSERT INTO <table> (<column>) VALUES (<literal>)` taken apart: the
/// table, the column and the literal — a string literal's text, with or
/// without its `N`, quotes undoubled; a `0x` literal's bytes. Identifiers
/// may be bracketed; anything else is `None`.
#[must_use]
pub fn parse_insert(statement: &str) -> Option<(String, String, Literal)> {
    DIALECT.parse_insert(statement, literal)
}

/// One literal — `N'…'`, `'…'` or `0x…` — and what follows it.
fn literal(rest: &str) -> Option<(Literal, &str)> {
    let rest = rest.trim_start();
    if rest.starts_with("0x") || rest.starts_with("0X") {
        let digits = &rest[2..];
        let end = digits
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(digits.len());
        let bytes = from_hex_literal(&rest[..2 + end])?;
        return Some((Literal::Bytes(bytes), &digits[end..]));
    }
    let quoted = rest.strip_prefix('N').unwrap_or(rest);
    let (value, after) = Delimiter::STRING.unquote_prefix(quoted).ok()?;
    Some((Literal::Text(value), after))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Literal {
        Literal::Text(value.into())
    }

    #[test]
    fn an_insert_of_one_column_is_taken_apart() {
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES (N'it''s here');"),
            Some(("inbox".into(), "payload".into(), text("it's here")))
        );
        assert_eq!(
            parse_insert("insert into [In ]]box] ( [Payload] ) values ( '' )"),
            Some(("In ]box".into(), "Payload".into(), text("")))
        );
        assert_eq!(
            parse_insert("INSERT INTO dbo.inbox (payload) VALUES (0xFFfe)"),
            Some((
                "dbo.inbox".into(),
                "payload".into(),
                Literal::Bytes(vec![0xff, 0xfe])
            ))
        );
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES (0x)"),
            Some(("inbox".into(), "payload".into(), Literal::Bytes(Vec::new())))
        );
        assert!(parse_insert("INSERT INTO inbox (a, b) VALUES ('x', 'y')").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES ('open").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES (0xabc)").is_none());
        assert!(parse_insert("INSERT INTO [open (a) VALUES ('x')").is_none());
        assert!(parse_insert("UPDATE inbox SET a = 'x'").is_none());
    }
}
