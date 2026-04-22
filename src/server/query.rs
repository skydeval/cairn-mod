//! `com.atproto.label.queryLabels` handler (§F3).
//!
//! Point-in-time query semantics: for each `(src, uri, val)` tuple, return
//! the row with `MAX(seq)` **only if** that row is an apply (`neg = 0`)
//! and not expired (`exp IS NULL OR exp > now`). Contrast with
//! subscribeLabels, which replays every surviving apply event.
//!
//! Cursor is opaque (`base64url(seq_string)`), distinct by type from
//! subscribeLabels' bare-integer cursor. The underlying value IS the
//! `latest_seq` of the last row returned; we don't pretend it's secret —
//! labels are public. Base64 is about wire-type distinctness and
//! minimal malformed-input surface, not opacity.

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use crate::label::Label;

use super::subscribe::AppState;

/// §F3: limit default 50, min 1, max 250. Values outside → InvalidRequest.
const DEFAULT_LIMIT: i64 = 50;
const MIN_LIMIT: i64 = 1;
const MAX_LIMIT: i64 = 250;

/// Cap on `uriPatterns` array length. §F3 doesn't specify; unbounded would
/// let one request produce a 25-way OR and an unbounded memory allocation.
/// 25 matches a typical moderation UI that would let an operator query a
/// batch of subjects; raise if a real use case needs more.
const MAX_URI_PATTERNS: usize = 25;

/// RFC-3339 millisecond-Z format used by `labels.cts` / `labels.exp`. Same
/// format the writer emits — a separate constant because this module
/// shouldn't reach into `crate::writer`'s internals.
const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

// ---------- Error representation ----------

/// XRPC error shape on the wire: `{ "error": "InvalidRequest", "message": ... }`.
#[derive(Debug)]
pub enum XrpcError {
    InvalidRequest(String),
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            XrpcError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "InvalidRequest",
                    message: msg,
                },
            ),
            XrpcError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "InternalServerError",
                    message: msg,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ---------- URI pattern shape ----------

/// Parsed `uriPatterns` entry. Trailing `*` → prefix; otherwise exact.
/// A `*` anywhere other than the last position is treated as a literal
/// character (matching Ozone's behavior per §F3).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UriPattern {
    Exact(String),
    Prefix(String),
}

pub(crate) fn parse_patterns(raw: Vec<String>) -> Result<Vec<UriPattern>, XrpcError> {
    if raw.is_empty() {
        return Err(XrpcError::InvalidRequest(
            "uriPatterns is required and must be non-empty".into(),
        ));
    }
    if raw.len() > MAX_URI_PATTERNS {
        return Err(XrpcError::InvalidRequest(format!(
            "uriPatterns limited to {MAX_URI_PATTERNS} entries per request"
        )));
    }
    let mut out = Vec::with_capacity(raw.len());
    for p in raw {
        if let Some(prefix) = p.strip_suffix('*') {
            // Prefix patterns are accepted as-is — any prefix the client wants
            // to match. No AT-URI validation here because a 3-char prefix
            // like "at:" is legitimate for broad scans.
            out.push(UriPattern::Prefix(prefix.to_string()));
        } else {
            // Exact patterns: minimal validation (§F3 "malformed AT-URI in
            // exact-match position returns InvalidRequest"). Match Ozone's
            // leniency — require the protocol prefix, don't fully parse.
            if !(p.starts_with("at://") || p.starts_with("did:")) {
                return Err(XrpcError::InvalidRequest(format!(
                    "malformed uriPattern (exact match must start with at:// or did:): {p}"
                )));
            }
            out.push(UriPattern::Exact(p));
        }
    }
    Ok(out)
}

// ---------- Cursor codec ----------

pub(crate) fn encode_cursor(seq: i64) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seq.to_string())
}

pub(crate) fn decode_cursor(s: &str) -> Result<i64, XrpcError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| XrpcError::InvalidRequest("malformed cursor (bad base64)".into()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| XrpcError::InvalidRequest("malformed cursor (bad utf-8)".into()))?;
    text.parse::<i64>()
        .map_err(|_| XrpcError::InvalidRequest("malformed cursor (not an integer)".into()))
}

// ---------- LabelJson + response ----------

/// ATProto typed-bytes convention: `{"$bytes": "<base64 standard>"}`.
/// Non-negotiable — `@atproto/api` and `atrium-api` produce / consume
/// this exact shape (§16.1).
#[derive(Serialize)]
struct TypedBytes {
    #[serde(rename = "$bytes")]
    bytes: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// JSON projection of `Label` matching the `com.atproto.label.defs#label`
/// lexicon. Owned to dodge lifetime friction when building a `Vec<..>` for
/// the response body.
#[derive(Serialize)]
struct LabelJson {
    ver: i64,
    src: String,
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    val: String,
    /// Omitted when false — matches ATProto `omitFalse` + the canonical
    /// encoding rule in `crate::signing::label_to_lex_value`.
    #[serde(skip_serializing_if = "is_false")]
    neg: bool,
    cts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<String>,
    sig: TypedBytes,
}

impl From<Label> for LabelJson {
    fn from(l: Label) -> Self {
        let sig_bytes = l.sig.expect("labels loaded from storage always carry sig");
        let sig = TypedBytes {
            bytes: base64::engine::general_purpose::STANDARD.encode(sig_bytes),
        };
        Self {
            ver: l.ver,
            src: l.src,
            uri: l.uri,
            cid: l.cid,
            val: l.val,
            neg: l.neg,
            cts: l.cts,
            exp: l.exp,
            sig,
        }
    }
}

#[derive(Serialize)]
struct QueryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    labels: Vec<LabelJson>,
}

// ---------- Row projection ----------

#[derive(sqlx::FromRow)]
struct LabelRow {
    seq: i64,
    ver: i64,
    src: String,
    uri: String,
    cid: Option<String>,
    val: String,
    neg: i64,
    cts: String,
    exp: Option<String>,
    sig: Vec<u8>,
}

impl LabelRow {
    fn into_label(self) -> Result<Label, XrpcError> {
        let sig: [u8; 64] = self.sig.as_slice().try_into().map_err(|_| {
            XrpcError::Internal(format!(
                "corrupt sig in labels.seq={}: expected 64 bytes, got {}",
                self.seq,
                self.sig.len()
            ))
        })?;
        Ok(Label {
            ver: self.ver,
            src: self.src,
            uri: self.uri,
            cid: self.cid,
            val: self.val,
            neg: self.neg != 0,
            cts: self.cts,
            exp: self.exp,
            sig: Some(sig),
        })
    }
}

// ---------- Handler ----------

pub(super) async fn handler(
    RawQuery(raw): RawQuery,
    Extension(state): Extension<AppState>,
) -> Response {
    match query_labels(raw.unwrap_or_default(), state).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn query_labels(raw_query: String, state: AppState) -> Result<QueryResponse, XrpcError> {
    // 1. Parse repeated query params. `form_urlencoded::parse` handles
    // duplicate keys; we bucket them into explicit lists.
    let mut uri_patterns_raw: Vec<String> = Vec::new();
    let mut sources_raw: Vec<String> = Vec::new();
    let mut limit_raw: Option<String> = None;
    let mut cursor_raw: Option<String> = None;
    for (k, v) in form_urlencoded::parse(raw_query.as_bytes()) {
        match k.as_ref() {
            "uriPatterns" => uri_patterns_raw.push(v.into_owned()),
            "sources" => sources_raw.push(v.into_owned()),
            "limit" => limit_raw = Some(v.into_owned()),
            "cursor" => cursor_raw = Some(v.into_owned()),
            _ => { /* ignore unknown params per XRPC convention */ }
        }
    }

    // Silently ignore empty-string pattern entries (form library yields
    // them for bare `?uriPatterns=` with no value). Required-ness is
    // enforced by `parse_patterns` after this filter.
    uri_patterns_raw.retain(|s| !s.is_empty());
    sources_raw.retain(|s| !s.is_empty());

    let patterns = parse_patterns(uri_patterns_raw)?;

    let limit: i64 = match limit_raw {
        None => DEFAULT_LIMIT,
        Some(s) => {
            let n = s.parse::<i64>().map_err(|_| {
                XrpcError::InvalidRequest(format!("limit must be an integer, got {s:?}"))
            })?;
            if !(MIN_LIMIT..=MAX_LIMIT).contains(&n) {
                return Err(XrpcError::InvalidRequest(format!(
                    "limit must be in [{MIN_LIMIT}, {MAX_LIMIT}], got {n}"
                )));
            }
            n
        }
    };

    let cursor_seq: i64 = match cursor_raw {
        None => 0,
        Some(c) => decode_cursor(&c)?,
    };

    // 2. Resolve `now` in the same RFC-3339 Z format as `labels.cts` /
    // `labels.exp`, so the `exp > now` comparison is a lexicographic
    // TEXT compare on an index-friendly format.
    let now = format_now_rfc3339().map_err(XrpcError::Internal)?;

    // 3. Build the SELECT.
    //
    // `sqlx::query!` is NOT viable here — the WHERE clause has dynamic
    // shape in two orthogonal dimensions:
    //   - `uriPatterns` is a list of 1..=25 entries, each either an
    //     `uri = ?` or `uri LIKE ?` predicate OR-joined.
    //   - `sources` is an optional IN clause with unbounded arity.
    //
    // The `query!` macro would require a fixed SQL text at compile time.
    // Workarounds (pre-padding placeholder slots to a max count, generating
    // per-arity query strings) either lie about the query shape or explode
    // the cache. The dynamic shape is *load-bearing* behavior, not a
    // future-cleanup target — DO NOT "fix" this by converting to query!.
    //
    // Safety: every user-controlled value below goes through
    // `QueryBuilder::push_bind`, which emits `?` placeholders and binds
    // the value positionally. No raw-SQL concatenation of user input.
    // The static SQL text uses push() only for fixed fragments.
    let mut qb = QueryBuilder::<Sqlite>::new(
        "WITH latest AS (
           SELECT src, uri, val, MAX(seq) AS latest_seq
           FROM labels
           GROUP BY src, uri, val
         )
         SELECT l.seq, l.ver, l.src, l.uri, l.cid, l.val, l.neg, l.cts, l.exp, l.sig
         FROM labels l
         JOIN latest lt
           ON l.src = lt.src
          AND l.uri = lt.uri
          AND l.val = lt.val
          AND l.seq = lt.latest_seq
         WHERE l.neg = 0
           AND (l.exp IS NULL OR l.exp > ",
    );
    qb.push_bind(now);
    qb.push(") AND l.seq > ");
    qb.push_bind(cursor_seq);

    qb.push(" AND (");
    for (i, p) in patterns.iter().enumerate() {
        if i > 0 {
            qb.push(" OR ");
        }
        match p {
            UriPattern::Exact(u) => {
                qb.push("l.uri = ");
                qb.push_bind(u.clone());
            }
            UriPattern::Prefix(prefix) => {
                // Escape LIKE metacharacters in the user-supplied prefix.
                // URIs shouldn't contain `%` or `_`, but defensive here so
                // `at://did:plc:foo_bar/*` doesn't accidentally match
                // single-char wildcards.
                let mut esc = String::with_capacity(prefix.len());
                for ch in prefix.chars() {
                    if matches!(ch, '\\' | '%' | '_') {
                        esc.push('\\');
                    }
                    esc.push(ch);
                }
                esc.push('%');
                qb.push("l.uri LIKE ");
                qb.push_bind(esc);
                qb.push(" ESCAPE '\\'");
            }
        }
    }
    qb.push(")");

    if !sources_raw.is_empty() {
        qb.push(" AND l.src IN (");
        let mut first = true;
        for src in &sources_raw {
            if !first {
                qb.push(", ");
            }
            first = false;
            qb.push_bind(src.clone());
        }
        qb.push(")");
    }

    qb.push(" ORDER BY l.seq ASC LIMIT ");
    qb.push_bind(limit + 1);

    let rows: Vec<LabelRow> = qb
        .build_query_as::<LabelRow>()
        .fetch_all(&state.pool)
        .await
        .map_err(|e| XrpcError::Internal(e.to_string()))?;

    // 4. Pagination: we requested limit+1 to detect overflow. If we got
    // limit+1 rows, trim the peek row and emit the last-returned seq as
    // the cursor. The next page's `seq > cursor` will pick up whatever
    // comes after, including any new labels written since this request.
    let (returned, next_cursor) = if rows.len() as i64 > limit {
        let mut trimmed = rows;
        trimmed.truncate(limit as usize);
        let last_seq = trimmed
            .last()
            .expect("trimmed non-empty since we had >limit rows")
            .seq;
        (trimmed, Some(encode_cursor(last_seq)))
    } else {
        (rows, None)
    };

    // 5. Convert rows → Labels → JSON.
    let mut labels = Vec::with_capacity(returned.len());
    for row in returned {
        labels.push(LabelJson::from(row.into_label()?));
    }

    Ok(QueryResponse {
        cursor: next_cursor,
        labels,
    })
}

fn format_now_rfc3339() -> Result<String, String> {
    let dt = OffsetDateTime::now_utc();
    let formatted = dt
        .format(&CTS_FORMAT)
        .map_err(|e| format!("format now: {e}"))?;
    Ok(format!("{formatted}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_empty_is_invalid() {
        assert!(matches!(
            parse_patterns(vec![]),
            Err(XrpcError::InvalidRequest(_))
        ));
    }

    #[test]
    fn patterns_overflow_cap_is_invalid() {
        let too_many: Vec<String> = (0..MAX_URI_PATTERNS + 1)
            .map(|i| format!("at://did:plc:x/a/{i}"))
            .collect();
        assert!(matches!(
            parse_patterns(too_many),
            Err(XrpcError::InvalidRequest(_))
        ));
    }

    #[test]
    fn patterns_exact_requires_protocol_prefix() {
        let err = parse_patterns(vec!["notanat.uri".into()]).unwrap_err();
        assert!(matches!(err, XrpcError::InvalidRequest(_)));
    }

    #[test]
    fn patterns_exact_accepts_at_uri_and_did() {
        let ok = parse_patterns(vec!["at://did:plc:x/a/b".into(), "did:plc:account".into()])
            .expect("both should parse");
        assert_eq!(ok.len(), 2);
        assert!(matches!(ok[0], UriPattern::Exact(_)));
        assert!(matches!(ok[1], UriPattern::Exact(_)));
    }

    #[test]
    fn patterns_trailing_star_is_prefix() {
        let ok =
            parse_patterns(vec!["at://did:plc:x/app.bsky.feed.post/*".into()]).expect("prefix ok");
        match &ok[0] {
            UriPattern::Prefix(p) => assert_eq!(p, "at://did:plc:x/app.bsky.feed.post/"),
            _ => panic!("expected prefix"),
        }
    }

    #[test]
    fn cursor_roundtrips() {
        for seq in [1_i64, 42, 1_000_000, i64::MAX] {
            let encoded = encode_cursor(seq);
            let decoded = decode_cursor(&encoded).expect("decode");
            assert_eq!(decoded, seq);
        }
    }

    #[test]
    fn cursor_rejects_non_base64() {
        assert!(decode_cursor("!!!not_base64!!!").is_err());
    }

    #[test]
    fn cursor_rejects_non_integer_payload() {
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("hello");
        assert!(decode_cursor(&bad).is_err());
    }

    #[test]
    fn label_json_sig_uses_typed_bytes_shape() {
        let label = Label {
            ver: 1,
            src: "did:plc:x".into(),
            uri: "at://did:plc:x/a/b".into(),
            cid: None,
            val: "spam".into(),
            neg: false,
            cts: "2026-04-22T12:00:00.000Z".into(),
            exp: None,
            sig: Some([0xAA; 64]),
        };
        let json = serde_json::to_value(LabelJson::from(label)).unwrap();
        let sig_obj = json.get("sig").expect("sig present");
        assert!(
            sig_obj.get("$bytes").is_some(),
            "sig must use ATProto typed-bytes shape {{\"$bytes\": \"...\"}}"
        );
        // Default neg=false must be omitted.
        assert!(
            json.get("neg").is_none(),
            "neg=false should be omitted per omitFalse convention"
        );
    }

    #[test]
    fn label_json_serializes_neg_true_and_optional_fields() {
        let label = Label {
            ver: 1,
            src: "did:plc:x".into(),
            uri: "at://did:plc:x/a/b".into(),
            cid: Some("bafy...".into()),
            val: "spam".into(),
            neg: true,
            cts: "2026-04-22T12:00:00.000Z".into(),
            exp: Some("2027-04-22T12:00:00.000Z".into()),
            sig: Some([0xCD; 64]),
        };
        let json = serde_json::to_value(LabelJson::from(label)).unwrap();
        assert_eq!(json["neg"], true);
        assert_eq!(json["cid"], "bafy...");
        assert_eq!(json["exp"], "2027-04-22T12:00:00.000Z");
    }
}
