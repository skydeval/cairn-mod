//! Label record — in-memory shape of `com.atproto.label.defs#label` (§6.1).
//!
//! Fields mirror the wire schema exactly. `sig` is `Option` so the "pre-sign
//! representation with sig absent" required by §6.2 step 3 is directly
//! representable without shadow types.

/// A label record per §6.1.
///
/// `ver` is always `1` in Cairn v1 but kept as a field (not a const) because
/// §6.2 requires it appear in the signed bytes and in the wire output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// Label format version. Always `1` in v1 of the protocol.
    pub ver: i64,
    /// Labeler's DID (Cairn's configured service DID for emissions).
    pub src: String,
    /// Subject — an AT-URI for records or a DID for accounts.
    pub uri: String,
    /// Optional record-version pin. Present = "this specific
    /// version"; absent = "all versions / the account" per §6.1.
    pub cid: Option<String>,
    /// Label value (≤128 bytes).
    pub val: String,
    /// Negation flag. `true` marks this as a withdrawal event for
    /// the `(src, uri, val)` tuple.
    pub neg: bool,
    /// Created-at timestamp (RFC-3339 Z with millisecond
    /// precision); monotonically clamped per §6.1.
    pub cts: String,
    /// Optional expiration timestamp (RFC-3339 Z). Stored only;
    /// enforcement is v1.1.
    pub exp: Option<String>,
    /// Raw 64-byte compact `(r, s)` signature per §6.2 step 7. Absent on
    /// records that have not yet been signed.
    pub sig: Option<[u8; 64]>,
}
