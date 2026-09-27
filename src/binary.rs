//! A Stream in a column declared binary, carried the way T-SQL itself
//! writes binary: the `0x` literal, two digits a byte.
//!
//! Every Stream is inserted as the binary literal a varbinary column reads
//! as the bytes. Coming back, the value must be in that form — how
//! [`crate::column`] renders a varbinary column — and anything else is
//! refused rather than taken for bytes. A column that holds text is
//! declared `column = "text"` (`transport::sql::Column`).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_through_the_binary_literal() {
        let bytes: Vec<u8> = (0..=255).collect();
        let literal = hex_literal(&bytes);
        assert!(literal.starts_with("0x000102"));
        assert_eq!(from_hex_literal(&literal), Some(bytes));
        assert_eq!(hex_literal(b""), "0x");
        assert_eq!(from_hex_literal("0x"), Some(Vec::new()));
        assert_eq!(from_hex_literal("0XAB"), Some(vec![0xab]));
    }

    #[test]
    fn what_is_not_the_literal_is_not_bytes() {
        assert_eq!(from_hex_literal("plain"), None);
        assert_eq!(from_hex_literal("0xabc"), None, "an odd digit count");
        assert_eq!(from_hex_literal("0xzz"), None, "not hex");
    }
}
