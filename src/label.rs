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
    pub ver: i64,
    pub src: String,
    pub uri: String,
    pub cid: Option<String>,
    pub val: String,
    pub neg: bool,
    pub cts: String,
    pub exp: Option<String>,
    /// Raw 64-byte compact `(r, s)` signature per §6.2 step 7. Absent on
    /// records that have not yet been signed.
    pub sig: Option<[u8; 64]>,
}
