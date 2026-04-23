//! Shared XRPC primitives used across `queryLabels`, `createReport`,
//! and the admin handlers. Currently just the opaque cursor codec —
//! factoring it here prevents the three callers from drifting on
//! encoding decisions (base64url vs standard, trailing newline, etc.).

use base64::Engine as _;

/// Encode an `i64` row identifier as an opaque client cursor.
/// Format: base64url-no-pad of the decimal-stringified value.
///
/// Distinct from `subscribeLabels`' bare-integer cursor by type (these
/// are strings), per §F3.
pub fn encode_cursor(id: i64) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.to_string())
}

/// Decode a client-supplied cursor. Callers map [`CursorError`] to
/// their XRPC error shape (typically `InvalidRequest` with a generic
/// message).
pub fn decode_cursor(s: &str) -> Result<i64, CursorError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| CursorError::BadBase64)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| CursorError::BadUtf8)?;
    text.parse::<i64>().map_err(|_| CursorError::NotInteger)
}

#[derive(Debug, PartialEq, Eq)]
pub enum CursorError {
    BadBase64,
    BadUtf8,
    NotInteger,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for id in [1_i64, 42, 1_000_000, i64::MAX] {
            assert_eq!(decode_cursor(&encode_cursor(id)).unwrap(), id);
        }
    }

    #[test]
    fn rejects_non_base64() {
        assert_eq!(decode_cursor("!!!").unwrap_err(), CursorError::BadBase64);
    }

    #[test]
    fn rejects_non_integer_payload() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("hello");
        assert_eq!(
            decode_cursor(&encoded).unwrap_err(),
            CursorError::NotInteger
        );
    }
}
