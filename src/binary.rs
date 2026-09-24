//! A Stream that is not text, carried the way T-SQL itself writes
//! binary: the `0x` literal, two digits a byte.
//!
//! A text column holds UTF-8 without a NUL and nothing else, so a Stream
//! that is anything else is inserted as the binary literal a varbinary
//! column reads as the bytes. Coming back, a value in that form is the
//! bytes again — which is how [`crate::column`] renders a varbinary
//! column, and what a text column that kept the literal answers too.
//! Text that happens to start with `0x` and run in hex is read as bytes;
//! that is the same ambiguity a T-SQL constant has, and no worse.

/// `bytes` as the binary literal: `0x` then two lower-case digits a byte.
#[must_use]
pub fn hex_literal(bytes: &[u8]) -> String {
    format!("0x{}", codec::hex::encode(bytes))
}

/// The bytes a binary literal names, or `None` when `text` is not one.
#[must_use]
pub fn from_hex_literal(text: &str) -> Option<Vec<u8>> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    codec::hex::decode(digits).ok()
}

/// A column value as the bytes it carries: decoded when a binary literal,
/// the text's bytes otherwise.
#[must_use]
pub fn column_bytes(text: String) -> Vec<u8> {
    from_hex_literal(&text).unwrap_or_else(|| text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_through_the_binary_literal() {
        let bytes: Vec<u8> = (0..=255).collect();
        let literal = hex_literal(&bytes);
        assert!(literal.starts_with("0x000102"));
        assert_eq!(from_hex_literal(&literal), Some(bytes.clone()));
        assert_eq!(column_bytes(literal), bytes);
        assert_eq!(hex_literal(b""), "0x");
        assert_eq!(from_hex_literal("0x"), Some(Vec::new()));
        assert_eq!(from_hex_literal("0XAB"), Some(vec![0xab]));
    }

    #[test]
    fn what_is_not_the_literal_is_text() {
        assert_eq!(from_hex_literal("plain"), None);
        assert_eq!(from_hex_literal("0xabc"), None, "an odd digit count");
        assert_eq!(from_hex_literal("0xzz"), None, "not hex");
        assert_eq!(column_bytes("plain".to_string()), b"plain");
    }
}
