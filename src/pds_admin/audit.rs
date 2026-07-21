//! `pds_admin_audit` table + insertion API (#85, v1.7).
//!
//! Persistence layer for the §F23 outbound bridge. Every PDS-side
//! enforcement attempt the `OzoneBackend` (#86 onward) makes —
//! successful or failed — is recorded as a row in `pds_admin_audit`
//! with a foreign-key tether to the precipitating `subject_actions`
//! row.
//!
//! # Hash-chain integration (§A13)
//!
//! Rows hash-chain into the **same chain as `audit_log`** (§F10). The
//! crate-internal `read_latest_chain_hash` helper in
//! [`crate::audit::append`] computes the unified-chain tip across both
//! tables; this module's writes participate identically to `audit_log`
//! writes — same SHA-256 wrap (via the shared `compute_chain_hash`
//! primitive in [`crate::audit::hash`]), same `BEGIN IMMEDIATE`
//! serialization for cross-process atomicity. The two tables share one
//! continuous chain a forensic walker can reconstruct in insertion-
//! time order.
//!
//! # Why insertion is in its own transaction (per §A13)
//!
//! The recordAction transaction commits **first**. The actual backend
//! HTTP call happens **after** that commit. The `pds_admin_audit` row
//! is inserted in a **separate** transaction. Holding a SQLite write
//! transaction across an HTTP call would deadlock the writer task and
//! starve every other appender — the chain-tip read + INSERT pair only
//! needs to be atomic against other appenders, not against the network
//! call.
//!
//! Failure mode: if the backend call returns an error (or times out),
//! cairn-mod's view of the action stays committed; the audit row
//! records the divergence. Operators reconcile manually in v1.7;
//! automatic retry is a v1.8 concern (per §A13).
//!
//! # v1.7 scope
//!
//! v1.7 ships only the persistence + hash-chain layer. The call sites
//! that drive [`record_pds_admin_call`] land in #87 as part of the
//! recordAction → `OzoneBackend` bridge. Read APIs
//! ([`get_pds_admin_audit`], [`list_pds_admin_audit_for_action`])
//! support #87's "did we already attempt this call?" lookup; the
//! eventual operator-facing `cairn moderator pds-audit` CLI surface
//! lands in #99.

use std::collections::BTreeMap;

use proto_blue_lex_cbor::encode;
use proto_blue_lex_data::LexValue;
use sqlx::sqlite::SqliteConnection;
use sqlx::{Pool, Sqlite};

use crate::audit::append::read_latest_chain_hash;
use crate::audit::hash::{compute_chain_hash, parse_stored_hash};
use crate::error::{Error, Result};
use crate::pds_admin::{BackendActionId, BackendError, BackendMethod};

/// Outcome category for a `pds_admin_audit` row.
///
/// Maps from [`BackendError`] variants and the success case to a
/// stable enumeration suitable for indexing and forensic queries
/// (`SELECT * FROM pds_admin_audit WHERE outcome = 'auth'`). The
/// SQL-level CHECK constraint pins the value-set; adding a value
/// is a coordinated code-and-migration change.
///
/// # v1.7 vs v1.8.1 value-set
///
/// v1.7 shipped eight values: `success` / `unsupported` /
/// `network` / `auth` / `rate_limited` / `conflict` /
/// `remote_error` / `validation`. v1.8.1 adds [`Self::Terminal`]
/// (`'terminal'`) for upstream-state failures (HTTP 404 / 410)
/// distinct from request-shape failures and from the
/// previously-named state-conflict cases. The CHECK constraint
/// in `migrations/0006_pds_admin_audit.sql` does NOT yet include
/// `'terminal'`; relaxing it is a coordinated migration step
/// (see chainlink #104).
///
/// Until that migration lands, the [`Self::from_backend_result`]
/// projection writes only v1.7 values — the new
/// [`outcome_for_backend_error`] mapping (which can produce
/// `Terminal`) is defined here for unit testing and is wired in
/// at the writer call site as a single line change in the same
/// migration step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Backend acknowledged the call and the request semantically
    /// succeeded. `backend_action_id` is populated for methods that
    /// return one (`takedown_account`, `suspend_account`).
    Success,
    /// Backend doesn't implement this method on this PDS, or
    /// cairn-mod's design forbids the call architecturally (label
    /// methods per the §F4 invariant). The `error_category` column
    /// distinguishes the two semantically — see
    /// [`outcome_for_backend_error`].
    Unsupported,
    /// Network-layer failure (DNS, TCP, TLS, timeout). Transient.
    Network,
    /// Authentication or authorization failure. Non-transient.
    Auth,
    /// Backend signaled rate limiting. `retry_after_seconds` may
    /// carry the backend's hint.
    RateLimited,
    /// Backend acknowledged the call but disagreed with the
    /// requested state transition (e.g., `restore_account` on an
    /// account that isn't taken down). Distinct from
    /// [`Self::Terminal`] in v1.8.1+: `Conflict` is reserved for
    /// state-transition disagreements with a recognized shape
    /// (preserving v1.7 dashboards); `Terminal` is the catch-all
    /// for upstream-state rejections without a recognized shape.
    Conflict,
    /// Backend returned an error envelope cairn-mod doesn't have a
    /// dedicated variant for. `error_code` and `error_message`
    /// preserve the wire-level fields verbatim.
    RemoteError,
    /// Pre-call validation failed, or the upstream rejected the
    /// request shape. Distinct from [`Self::Terminal`]: `Validation`
    /// is request-shape; `Terminal` is upstream-state.
    Validation,
    /// **New in v1.8.1.** Upstream-state failure that is not
    /// retryable and not a request-shape problem (HTTP 404 / 410,
    /// or any `BackendError::Terminal` without a recognized
    /// `[sub_classification=...]` marker). The SQL CHECK
    /// constraint does not yet include `'terminal'`; activated by
    /// the migration tracked in chainlink #104.
    Terminal,
}

impl AuditOutcome {
    /// Project a backend call result onto an audit outcome.
    ///
    /// **v1.7-compat projection.** Used by the audit-writer until
    /// the Step 7 schema migration relaxes the outcome CHECK
    /// constraint and adds the `error_category` column. Once the
    /// migration lands, callers switch to
    /// [`outcome_for_backend_error`] (which can produce
    /// [`Self::Terminal`]).
    ///
    /// Generic over the success type so callers with both
    /// `Result<BackendActionId, BackendError>` (takedown / suspend)
    /// and `Result<(), BackendError>` (restore / apply_label /
    /// negate_label) shapes can use the same projection — the unit-
    /// vs ID-bearing trait surface stays a caller concern;
    /// audit-row construction unifies on
    /// `Result<Option<BackendActionId>, BackendError>` (see
    /// [`record_pds_admin_call`]).
    pub fn from_backend_result<T>(result: &std::result::Result<T, BackendError>) -> Self {
        match result {
            Ok(_) => Self::Success,
            Err(e) => Self::from_backend_error_v17_compat(e),
        }
    }

    /// v1.7-compat: maps a [`BackendError`] to an outcome value
    /// that's guaranteed to satisfy the v1.7 CHECK constraint
    /// (eight values; no `terminal`). Internal helper for
    /// [`Self::from_backend_result`].
    fn from_backend_error_v17_compat(e: &BackendError) -> Self {
        match e {
            // Unsupported and ArchitecturallyForbidden share the
            // 'unsupported' outcome; error_category will distinguish
            // them once the column lands (chainlink #104).
            BackendError::Unsupported | BackendError::ArchitecturallyForbidden(_) => {
                Self::Unsupported
            }
            // Transient with the rate-limited marker preserves v1.7's
            // 'rate_limited' outcome; otherwise 'network'.
            BackendError::Transient(msg) => {
                if msg.starts_with("[sub_classification=RateLimited") {
                    Self::RateLimited
                } else {
                    Self::Network
                }
            }
            BackendError::Auth(_) => Self::Auth,
            // Terminal with the conflict marker preserves v1.7's
            // 'conflict' outcome; with the remote-error marker
            // preserves 'remote_error'; otherwise the new
            // 'terminal' value — which the v1.7 CHECK rejects, so
            // we coalesce to 'remote_error' until the Step 7
            // migration relaxes the CHECK (chainlink #104).
            BackendError::Terminal(msg) => {
                if msg.starts_with("[sub_classification=Conflict") {
                    Self::Conflict
                } else if msg.starts_with("[sub_classification=RemoteError") {
                    Self::RemoteError
                } else {
                    // v1.7-compat coalescence: the 'terminal' value
                    // doesn't pass the CHECK constraint yet. Step 7
                    // relaxes the CHECK and switches the writer to
                    // outcome_for_backend_error so this case becomes
                    // 'terminal' atomically.
                    Self::RemoteError
                }
            }
            // CapabilityNotAdvertised is reserved for the v1.8+ Rust
            // PDS backend; under v1.7 it doesn't fire from
            // OzoneBackend. Project to 'validation' to preserve
            // v1.7's "is a validation issue at the call site"
            // semantic per the v1.8.1 mapping table.
            BackendError::CapabilityNotAdvertised(_) => Self::Validation,
            BackendError::Validation(_) => Self::Validation,
        }
    }

    /// DB wire-string form. Inverse of [`Self::from_db_str`].
    /// Pinned against the SQL CHECK constraint values in
    /// `migrations/0006_pds_admin_audit.sql` (eight v1.7 values
    /// plus the v1.8.1 addition `'terminal'` — the latter is
    /// rejected by the current CHECK and only fires once the
    /// chainlink-#104 migration relaxes it).
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Unsupported => "unsupported",
            Self::Network => "network",
            Self::Auth => "auth",
            Self::RateLimited => "rate_limited",
            Self::Conflict => "conflict",
            Self::RemoteError => "remote_error",
            Self::Validation => "validation",
            Self::Terminal => "terminal",
        }
    }

    /// Parse the DB wire-string form. `None` for unrecognized
    /// strings — should never happen in practice (SQL CHECK rejects
    /// unknown values at INSERT), so reaching `None` is a DB
    /// corruption signal.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "success" => Some(Self::Success),
            "unsupported" => Some(Self::Unsupported),
            "network" => Some(Self::Network),
            "auth" => Some(Self::Auth),
            "rate_limited" => Some(Self::RateLimited),
            "conflict" => Some(Self::Conflict),
            "remote_error" => Some(Self::RemoteError),
            "validation" => Some(Self::Validation),
            "terminal" => Some(Self::Terminal),
            _ => None,
        }
    }
}

/// Variant→outcome mapping per the v1.8.1 taxonomy. **Activated
/// by chainlink #104's Step 7 migration**; until then the
/// audit-writer uses [`AuditOutcome::from_backend_result`]
/// (which never produces [`AuditOutcome::Terminal`] because the
/// SQL CHECK constraint rejects it).
///
/// Mapping table:
///
/// | `BackendError` variant            | inner-string marker                      | outcome      |
/// |-----------------------------------|------------------------------------------|--------------|
/// | `Auth`                            | (any)                                    | `auth`       |
/// | `Transient`                       | `[sub_classification=RateLimited ...]`   | `rate_limited` |
/// | `Transient`                       | `[sub_classification=RemoteError ...]`   | `network`    |
/// | `Transient`                       | (no marker)                              | `network`    |
/// | `Validation`                      | (any, including `RemoteError` marker)    | `validation` |
/// | `Terminal`                        | `[sub_classification=Conflict]`          | `conflict`   |
/// | `Terminal`                        | `[sub_classification=RemoteError ...]`   | `remote_error` |
/// | `Terminal`                        | (no marker, or other markers)            | `terminal`   |
/// | `CapabilityNotAdvertised`         | n/a                                      | `validation` |
/// | `Unsupported`                     | n/a                                      | `unsupported`|
/// | `ArchitecturallyForbidden`        | n/a                                      | `unsupported`|
///
/// Sub-classification distinctions inside `outcome` exist for
/// dashboard continuity (v1.7 operators querying
/// `WHERE outcome = 'rate_limited'` continue to get rate-limited
/// rows). Variant-level identity lives in the `error_category`
/// column added by the same chainlink-#104 migration.
pub fn outcome_for_backend_error(e: &BackendError) -> AuditOutcome {
    match e {
        BackendError::Auth(_) => AuditOutcome::Auth,
        BackendError::Transient(msg) => {
            if msg.starts_with("[sub_classification=RateLimited") {
                AuditOutcome::RateLimited
            } else {
                // Both no-marker Transient and the RemoteError-marker
                // Transient land at 'network' (the latter preserves
                // v1.7's outcome=network for unrecognized 5xx-style
                // errors that v1.7 wrote as RemoteError under network
                // semantics — see ozone.rs's other-5xx branch).
                AuditOutcome::Network
            }
        }
        BackendError::Validation(_) => AuditOutcome::Validation,
        BackendError::Terminal(msg) => {
            if msg.starts_with("[sub_classification=Conflict") {
                AuditOutcome::Conflict
            } else if msg.starts_with("[sub_classification=RemoteError") {
                AuditOutcome::RemoteError
            } else {
                AuditOutcome::Terminal
            }
        }
        BackendError::CapabilityNotAdvertised(_) => AuditOutcome::Validation,
        BackendError::Unsupported | BackendError::ArchitecturallyForbidden(_) => {
            AuditOutcome::Unsupported
        }
    }
}

/// A row from `pds_admin_audit`.
///
/// Returned by [`record_pds_admin_call`] (after insertion) and the
/// read APIs. All fields are owned; the type is `Clone` so it can
/// travel across async boundaries without re-fetching.
#[derive(Debug, Clone)]
pub struct PdsAdminAuditRecord {
    /// Primary key.
    pub id: i64,
    /// `subject_actions(id)` of the cairn-mod-side action that
    /// triggered this call. Foreign-key tethered.
    pub precipitating_action_id: i64,
    /// Which trait method was attempted.
    pub backend_method: BackendMethod,
    /// Backend-assigned identifier from the response, when one was
    /// returned. `None` for unit-result methods (`restore_account`,
    /// `apply_label`, `negate_label`) and for any failure that
    /// prevented remote acknowledgment.
    pub backend_action_id: Option<BackendActionId>,
    /// Outcome category.
    pub outcome: AuditOutcome,
    /// Backend-supplied error code, populated from any
    /// `[sub_classification=RemoteError code=X]` marker on the
    /// failing [`BackendError`] (see
    /// [`BackendError::error_code`]). `None` on success and for
    /// variants without the marker.
    pub error_code: Option<String>,
    /// Human-readable error context. `None` on success.
    pub error_message: Option<String>,
    /// Retry-After hint in seconds. Only meaningful for
    /// [`AuditOutcome::RateLimited`] and only when the backend
    /// supplied one.
    pub retry_after_seconds: Option<u32>,
    /// Predecessor link in the unified hash chain.
    pub prev_hash: Vec<u8>,
    /// This row's link in the unified hash chain.
    pub row_hash: Vec<u8>,
    /// Wall-clock epoch-ms when cairn-mod began the call (after
    /// the precipitating recordAction transaction committed).
    pub call_started_at: i64,
    /// Wall-clock epoch-ms when the backend responded or the call
    /// failed at the transport layer.
    pub call_completed_at: i64,
}

/// Borrowed view of a `pds_admin_audit` row's hash-relevant content.
///
/// Field set is the table's columns minus the SQL-level / chain-link
/// plumbing (`id`, `prev_hash`, `row_hash`). Optional columns are
/// `Option<...>`; absence is encoded as field-omission in the
/// canonical CBOR (matching audit_log's `AuditRowForHashing`
/// convention — "absent != null").
///
/// `pub(crate)` so #88's `cairn audit-verify` extension can
/// rehydrate stored rows into this shape and recompute their
/// hashes against the unified chain. The hashing surface is
/// internal to cairn-mod; external callers use the typed
/// [`record_pds_admin_call`] API which constructs this struct
/// internally.
pub(crate) struct PdsAdminAuditRowForHashing<'a> {
    pub(crate) precipitating_action_id: i64,
    pub(crate) backend_method: &'a str,
    pub(crate) backend_action_id: Option<&'a str>,
    pub(crate) outcome: &'a str,
    pub(crate) error_code: Option<&'a str>,
    pub(crate) error_message: Option<&'a str>,
    /// Carried as `i64` (rather than `u32`) so the canonical CBOR
    /// encoding matches `audit_log`'s integer convention. u32 →
    /// i64 is lossless.
    pub(crate) retry_after_seconds: Option<i64>,
    pub(crate) call_started_at: i64,
    pub(crate) call_completed_at: i64,
    // v1.8.6 additions (12-field form, v2 §5.1): Aurora response
    // details persisted since migration 0010, folded into the
    // preimage from the 0011 format boundary forward. Key-omitted
    // when None — an all-None row hashes identically under the
    // 9-field and 12-field forms.
    pub(crate) upstream_audit_entry_id: Option<&'a str>,
    pub(crate) cascading_actions_json: Option<&'a str>,
    pub(crate) snapshots_json: Option<&'a str>,
}

/// Build the `LexValue::Map` representation of a `pds_admin_audit`
/// row's hash-relevant content. proto-blue's canonical encoder
/// applies the §6.2 sort over the map keys; callers don't pre-sort.
///
/// Optional fields are conditionally inserted so absence canonicalizes
/// as "key omitted" rather than "key with null value." Same load-
/// bearing distinction the audit_log builder makes.
fn row_to_lex_value(row: &PdsAdminAuditRowForHashing<'_>) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert(
        "precipitating_action_id".to_string(),
        LexValue::Integer(row.precipitating_action_id),
    );
    m.insert(
        "backend_method".to_string(),
        LexValue::String(row.backend_method.to_string()),
    );
    if let Some(id) = row.backend_action_id {
        m.insert(
            "backend_action_id".to_string(),
            LexValue::String(id.to_string()),
        );
    }
    m.insert(
        "outcome".to_string(),
        LexValue::String(row.outcome.to_string()),
    );
    if let Some(code) = row.error_code {
        m.insert("error_code".to_string(), LexValue::String(code.to_string()));
    }
    if let Some(msg) = row.error_message {
        m.insert(
            "error_message".to_string(),
            LexValue::String(msg.to_string()),
        );
    }
    if let Some(s) = row.retry_after_seconds {
        m.insert("retry_after_seconds".to_string(), LexValue::Integer(s));
    }
    m.insert(
        "call_started_at".to_string(),
        LexValue::Integer(row.call_started_at),
    );
    m.insert(
        "call_completed_at".to_string(),
        LexValue::Integer(row.call_completed_at),
    );
    // v1.8.6 (12-field form): conditionally inserted so absence
    // canonicalizes as "key omitted" — the load-bearing convention
    // that makes an all-None row hash identically under the v1.7
    // 9-field form (see the format boundary in migration 0011).
    if let Some(v) = row.upstream_audit_entry_id {
        m.insert(
            "upstream_audit_entry_id".to_string(),
            LexValue::String(v.to_string()),
        );
    }
    if let Some(v) = row.cascading_actions_json {
        m.insert(
            "cascading_actions_json".to_string(),
            LexValue::String(v.to_string()),
        );
    }
    if let Some(v) = row.snapshots_json {
        m.insert(
            "snapshots_json".to_string(),
            LexValue::String(v.to_string()),
        );
    }
    LexValue::Map(m)
}

/// Compute the SHA-256 row hash for a `pds_admin_audit` row chained
/// from `prev_hash`. Mirrors
/// [`crate::audit::hash::compute_audit_row_hash`] but for the
/// `pds_admin_audit` table's row shape. `pub(crate)` for #88's
/// audit-verify extension.
pub(crate) fn compute_pds_admin_audit_row_hash(
    prev_hash: &[u8; 32],
    row: &PdsAdminAuditRowForHashing<'_>,
) -> Result<[u8; 32]> {
    let canonical = encode(&row_to_lex_value(row))?;
    Ok(compute_chain_hash(prev_hash, &canonical))
}

/// Project a backend-call result into the `(error_code,
/// error_message, retry_after_seconds)` audit-row triple.
///
/// Under the v1.8.1 taxonomy, structured side-channel data lives
/// in `[sub_classification=...]` markers prepended to the inner
/// message. The [`BackendError::error_code`] and
/// [`BackendError::retry_after_seconds`] accessors parse those
/// markers back out; this helper preserves the existing audit-row
/// columns so v1.7 dashboards keep working.
fn project_error_columns<T>(
    result: &std::result::Result<T, BackendError>,
) -> (Option<String>, Option<String>, Option<u32>) {
    match result {
        Ok(_) => (None, None, None),
        Err(e) => {
            let error_code = e.error_code().map(str::to_string);
            // Empty error_message for Unsupported (variant carries no
            // payload) is encoded as None so the audit-row column
            // stays NULL rather than empty-string.
            let message = e.message();
            let error_message = if message.is_empty() {
                None
            } else {
                Some(message.to_string())
            };
            let retry_after = e.retry_after_seconds();
            (error_code, error_message, retry_after)
        }
    }
}

/// Record a `pds_admin_audit` row for a backend-call attempt.
///
/// Acquires a connection, issues `BEGIN IMMEDIATE` to serialize
/// against other audit-chain appenders (the same primitive
/// [`crate::audit::append::append_via_pool`] uses), reads the
/// chain tip across both `audit_log` and `pds_admin_audit` (via
/// the crate-internal `read_latest_chain_hash` helper), computes
/// this row's `row_hash`, INSERTs, and commits.
///
/// The `result` parameter accepts `Option<BackendActionId>` on the
/// success side so the caller unifies the trait's two return
/// shapes (`Result<BackendActionId, BackendError>` for `takedown_account`
/// / `suspend_account`; `Result<(), BackendError>` for
/// `restore_account` / `apply_label` / `negate_label`) into one
/// audit-insertion API. Callers with `Result<BackendActionId, ...>`
/// pass `result.map(Some)`; callers with `Result<(), ...>` pass
/// `result.map(|_| None)`. Single function is cleaner than two
/// near-identical entry points.
///
/// On insertion failure (FK violation, transport error during
/// commit, etc.) the transaction is rolled back and the error
/// surfaces. The cairn-mod-side action stays committed regardless —
/// the recordAction transaction has already committed by the time
/// this is called (per §A13).
///
/// Returns the persisted record so the caller can log structured
/// outcome data without re-querying.
pub async fn record_pds_admin_call(
    pool: &Pool<Sqlite>,
    precipitating_action_id: i64,
    backend_method: BackendMethod,
    result: std::result::Result<Option<BackendActionId>, BackendError>,
    response_details: Option<&crate::pds_admin::rust::action_types::ActionResponse>,
    call_started_at: i64,
    call_completed_at: i64,
) -> Result<PdsAdminAuditRecord> {
    let outcome = AuditOutcome::from_backend_result(&result);
    // Plumbed through perform_insert; the column itself is not yet
    // bound in the INSERT (the migration that adds it lands in
    // chainlink #104's Step 7).
    let error_category: Option<&'static str> = match &result {
        Ok(_) => None,
        Err(e) => Some(e.variant_name()),
    };
    let backend_action_id = match &result {
        Ok(Some(id)) => Some(id.clone()),
        Ok(None) | Err(_) => None,
    };
    let (error_code, error_message, retry_after_seconds) = project_error_columns(&result);

    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| Error::Signing(format!("pds_admin_audit acquire: {e}")))?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .map_err(|e| Error::Signing(format!("pds_admin_audit begin: {e}")))?;

    let inserted = match perform_insert(
        &mut conn,
        precipitating_action_id,
        backend_method,
        backend_action_id.as_ref(),
        outcome,
        error_category,
        error_code.as_deref(),
        error_message.as_deref(),
        retry_after_seconds,
        response_details,
        call_started_at,
        call_completed_at,
    )
    .await
    {
        Ok(record) => record,
        Err(e) => {
            // Best-effort rollback. If the rollback itself fails
            // the connection ends up in a degraded state but the
            // original error is what the caller cares about.
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e);
        }
    };

    sqlx::query("COMMIT")
        .execute(&mut *conn)
        .await
        .map_err(|e| Error::Signing(format!("pds_admin_audit commit: {e}")))?;

    Ok(inserted)
}

#[allow(clippy::too_many_arguments)]
async fn perform_insert(
    conn: &mut SqliteConnection,
    precipitating_action_id: i64,
    backend_method: BackendMethod,
    backend_action_id: Option<&BackendActionId>,
    outcome: AuditOutcome,
    // TODO(#104): activate error_category column write once the
    // pds_admin_audit migration adds the column. Until then the
    // value is plumbed through the call signature but not bound
    // in the INSERT below; the row-hashing input also omits it
    // so chain-walk verification stays compatible with v1.7-era
    // rows.
    _error_category: Option<&'static str>,
    error_code: Option<&str>,
    error_message: Option<&str>,
    retry_after_seconds: Option<u32>,
    // v1.8.5: Aurora's full EmitEventOutput for successful
    // dispatches of the new action methods. Persisted on the
    // migration-0010 columns (upstream_audit_entry_id,
    // cascading_actions_json, snapshots_json). Deliberately NOT
    // part of the row-hash preimage — the v1.7 hash contract
    // covers the original column set; folding these in is a
    // v1.8.6 cross-chain-verify decision.
    response_details: Option<&crate::pds_admin::rust::action_types::ActionResponse>,
    call_started_at: i64,
    call_completed_at: i64,
) -> Result<PdsAdminAuditRecord> {
    let prev_hash = read_latest_chain_hash(&mut *conn).await?;
    let backend_method_str = backend_method.as_wire_str();
    let backend_action_id_str = backend_action_id.map(BackendActionId::as_str);
    let outcome_str = outcome.as_db_str();
    let retry_after_i64 = retry_after_seconds.map(i64::from);

    let upstream_audit_entry_id = response_details.map(|r| r.audit_entry_id.as_str());
    let cascading_actions_json = response_details
        .map(|r| serde_json::to_string(&r.cascading_actions))
        .transpose()
        .map_err(|e| Error::Signing(format!("cascading_actions serialize: {e}")))?;
    let snapshots_json = response_details
        .map(|r| serde_json::to_string(&r.snapshots))
        .transpose()
        .map_err(|e| Error::Signing(format!("snapshots serialize: {e}")))?;

    let row_hash = compute_pds_admin_audit_row_hash(
        &prev_hash,
        &PdsAdminAuditRowForHashing {
            precipitating_action_id,
            backend_method: backend_method_str,
            backend_action_id: backend_action_id_str,
            outcome: outcome_str,
            error_code,
            error_message,
            retry_after_seconds: retry_after_i64,
            call_started_at,
            call_completed_at,
            upstream_audit_entry_id,
            cascading_actions_json: cascading_actions_json.as_deref(),
            snapshots_json: snapshots_json.as_deref(),
        },
    )?;

    let prev_hash_slice: &[u8] = &prev_hash;
    let row_hash_slice: &[u8] = &row_hash;

    let id = sqlx::query_scalar!(
        r#"INSERT INTO pds_admin_audit
             (precipitating_action_id, backend_method, backend_action_id,
              outcome, error_code, error_message, retry_after_seconds,
              prev_hash, row_hash, call_started_at, call_completed_at,
              upstream_audit_entry_id, cascading_actions_json, snapshots_json)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
           RETURNING id AS "id!""#,
        precipitating_action_id,
        backend_method_str,
        backend_action_id_str,
        outcome_str,
        error_code,
        error_message,
        retry_after_i64,
        prev_hash_slice,
        row_hash_slice,
        call_started_at,
        call_completed_at,
        upstream_audit_entry_id,
        cascading_actions_json,
        snapshots_json,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| Error::Signing(format!("pds_admin_audit insert: {e}")))?;

    Ok(PdsAdminAuditRecord {
        id,
        precipitating_action_id,
        backend_method,
        backend_action_id: backend_action_id.cloned(),
        outcome,
        error_code: error_code.map(str::to_string),
        error_message: error_message.map(str::to_string),
        retry_after_seconds,
        prev_hash: prev_hash.to_vec(),
        row_hash: row_hash.to_vec(),
        call_started_at,
        call_completed_at,
    })
}

/// Fetch a `pds_admin_audit` row by id.
pub async fn get_pds_admin_audit(
    pool: &Pool<Sqlite>,
    id: i64,
) -> Result<Option<PdsAdminAuditRecord>> {
    let row = sqlx::query!(
        r#"SELECT id AS "id!", precipitating_action_id, backend_method,
                  backend_action_id, outcome, error_code, error_message,
                  retry_after_seconds, prev_hash, row_hash,
                  call_started_at, call_completed_at
           FROM pds_admin_audit
           WHERE id = ?1"#,
        id
    )
    .fetch_optional(pool)
    .await?;

    row.map(|r| {
        let backend_method = BackendMethod::from_wire_str(&r.backend_method).ok_or_else(|| {
            Error::Signing(format!(
                "pds_admin_audit row {} has unknown backend_method {:?}",
                r.id, r.backend_method
            ))
        })?;
        let outcome = AuditOutcome::from_db_str(&r.outcome).ok_or_else(|| {
            Error::Signing(format!(
                "pds_admin_audit row {} has unknown outcome {:?}",
                r.id, r.outcome
            ))
        })?;
        let retry_after_seconds = match r.retry_after_seconds {
            None => None,
            Some(v) => Some(u32::try_from(v).map_err(|_| {
                Error::Signing(format!(
                    "pds_admin_audit row {} has retry_after_seconds {} out of u32 range",
                    r.id, v
                ))
            })?),
        };
        // Validate hash blob lengths even though we don't unpack
        // them into [u8; 32] here — surfaces DB corruption to
        // callers reading historical rows.
        let _ = parse_stored_hash(&r.prev_hash)?;
        let _ = parse_stored_hash(&r.row_hash)?;
        Ok(PdsAdminAuditRecord {
            id: r.id,
            precipitating_action_id: r.precipitating_action_id,
            backend_method,
            backend_action_id: r.backend_action_id.map(BackendActionId::new),
            outcome,
            error_code: r.error_code,
            error_message: r.error_message,
            retry_after_seconds,
            prev_hash: r.prev_hash,
            row_hash: r.row_hash,
            call_started_at: r.call_started_at,
            call_completed_at: r.call_completed_at,
        })
    })
    .transpose()
}

/// List all `pds_admin_audit` rows for a precipitating action, in
/// chain order (`call_completed_at` ascending, ties broken by `id`).
///
/// "Chain order" because v1.7's "show me everything cairn-mod tried
/// to do on the PDS for this action" forensic query wants the
/// attempts in the order they happened. Pagination is out of scope
/// for this issue (per the prompt's "What NOT to implement"); v1.7
/// row volume per action is bounded (typically 1, occasionally 2-3
/// for retries that v1.8 might add) so an unbounded `Vec` is fine.
pub async fn list_pds_admin_audit_for_action(
    pool: &Pool<Sqlite>,
    precipitating_action_id: i64,
) -> Result<Vec<PdsAdminAuditRecord>> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", precipitating_action_id, backend_method,
                  backend_action_id, outcome, error_code, error_message,
                  retry_after_seconds, prev_hash, row_hash,
                  call_started_at, call_completed_at
           FROM pds_admin_audit
           WHERE precipitating_action_id = ?1
           ORDER BY call_completed_at ASC, id ASC"#,
        precipitating_action_id
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|r| {
            let backend_method =
                BackendMethod::from_wire_str(&r.backend_method).ok_or_else(|| {
                    Error::Signing(format!(
                        "pds_admin_audit row {} has unknown backend_method {:?}",
                        r.id, r.backend_method
                    ))
                })?;
            let outcome = AuditOutcome::from_db_str(&r.outcome).ok_or_else(|| {
                Error::Signing(format!(
                    "pds_admin_audit row {} has unknown outcome {:?}",
                    r.id, r.outcome
                ))
            })?;
            let retry_after_seconds = match r.retry_after_seconds {
                None => None,
                Some(v) => Some(u32::try_from(v).map_err(|_| {
                    Error::Signing(format!(
                        "pds_admin_audit row {} has retry_after_seconds {} out of u32 range",
                        r.id, v
                    ))
                })?),
            };
            let _ = parse_stored_hash(&r.prev_hash)?;
            let _ = parse_stored_hash(&r.row_hash)?;
            Ok(PdsAdminAuditRecord {
                id: r.id,
                precipitating_action_id: r.precipitating_action_id,
                backend_method,
                backend_action_id: r.backend_action_id.map(BackendActionId::new),
                outcome,
                error_code: r.error_code,
                error_message: r.error_message,
                retry_after_seconds,
                prev_hash: r.prev_hash,
                row_hash: r.row_hash,
                call_started_at: r.call_started_at,
                call_completed_at: r.call_completed_at,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::append::{AuditRowForAppend, append_via_pool};
    use crate::storage;
    use tempfile::tempdir;

    /// Open a fresh DB pool against a tempdir-backed file. Leaks the
    /// tempdir so the pool's connections see stable storage for the
    /// test's lifetime — same pattern audit::append's tests use.
    async fn fresh_pool() -> Pool<Sqlite> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pds-admin-audit-test.db");
        let pool = storage::open(&path).await.unwrap();
        Box::leak(Box::new(dir));
        pool
    }

    /// Insert a minimal `subject_actions` row so FKs from
    /// `pds_admin_audit.precipitating_action_id` resolve. Returns the
    /// inserted row's `id`.
    async fn fixture_subject_action(pool: &Pool<Sqlite>) -> i64 {
        sqlx::query_scalar!(
            "INSERT INTO subject_actions (
                subject_did, subject_uri, actor_did, action_type, reason_codes,
                duration, effective_at, expires_at, notes, report_ids,
                strike_value_base, strike_value_applied, was_dampened,
                strikes_at_time_of_action, audit_log_id, created_at,
                actor_kind, triggered_by_policy_rule
             ) VALUES (?1, NULL, ?2, ?3, ?4, NULL, ?5, NULL, NULL, NULL,
                       0, 0, 0, 0, NULL, ?5, 'moderator', NULL)
             RETURNING id",
            "did:plc:subject",
            "did:plc:moderator",
            "warning",
            r#"["test-reason"]"#,
            1_700_000_000_000_i64,
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[test]
    fn audit_outcome_round_trip() {
        let all = [
            AuditOutcome::Success,
            AuditOutcome::Unsupported,
            AuditOutcome::Network,
            AuditOutcome::Auth,
            AuditOutcome::RateLimited,
            AuditOutcome::Conflict,
            AuditOutcome::RemoteError,
            AuditOutcome::Validation,
            AuditOutcome::Terminal,
        ];
        for o in all {
            assert_eq!(AuditOutcome::from_db_str(o.as_db_str()), Some(o));
        }
    }

    #[test]
    fn audit_outcome_from_db_str_rejects_unknown() {
        assert_eq!(AuditOutcome::from_db_str("bogus"), None);
        assert_eq!(AuditOutcome::from_db_str(""), None);
    }

    #[test]
    fn from_backend_result_maps_each_variant_v17_compat() {
        // v1.7-compat projection: never produces Terminal (the SQL
        // CHECK constraint rejects 'terminal'). The new mapping —
        // outcome_for_backend_error — is exercised separately and
        // activates when chainlink #104's migration relaxes the
        // CHECK.
        let success: std::result::Result<i32, BackendError> = Ok(0);
        assert_eq!(
            AuditOutcome::from_backend_result(&success),
            AuditOutcome::Success
        );

        // Unsupported and ArchitecturallyForbidden share 'unsupported'.
        let unsupp: std::result::Result<i32, _> = Err(BackendError::Unsupported);
        assert_eq!(
            AuditOutcome::from_backend_result(&unsupp),
            AuditOutcome::Unsupported
        );
        let forbid: std::result::Result<i32, _> =
            Err(BackendError::ArchitecturallyForbidden("nope".into()));
        assert_eq!(
            AuditOutcome::from_backend_result(&forbid),
            AuditOutcome::Unsupported
        );

        // Plain Transient → 'network'; with rate-limited marker → 'rate_limited'.
        let network: std::result::Result<i32, _> =
            Err(BackendError::Transient("dns failure".into()));
        assert_eq!(
            AuditOutcome::from_backend_result(&network),
            AuditOutcome::Network
        );
        let rate: std::result::Result<i32, _> = Err(BackendError::Transient(
            "[sub_classification=RateLimited retry_after_seconds=30] slow".into(),
        ));
        assert_eq!(
            AuditOutcome::from_backend_result(&rate),
            AuditOutcome::RateLimited
        );

        let auth: std::result::Result<i32, _> = Err(BackendError::Auth("401".into()));
        assert_eq!(AuditOutcome::from_backend_result(&auth), AuditOutcome::Auth);

        // Terminal with conflict marker → 'conflict' (preserves v1.7 dashboard).
        let conflict: std::result::Result<i32, _> = Err(BackendError::Terminal(
            "[sub_classification=Conflict] already taken down".into(),
        ));
        assert_eq!(
            AuditOutcome::from_backend_result(&conflict),
            AuditOutcome::Conflict
        );

        // Terminal with remote-error marker → 'remote_error'.
        let remote: std::result::Result<i32, _> = Err(BackendError::Terminal(
            "[sub_classification=RemoteError code=NotFound] x".into(),
        ));
        assert_eq!(
            AuditOutcome::from_backend_result(&remote),
            AuditOutcome::RemoteError
        );

        // Bare Terminal coalesces to 'remote_error' under v1.7-compat
        // until chainlink #104's migration relaxes the CHECK.
        let bare_terminal: std::result::Result<i32, _> =
            Err(BackendError::Terminal("subject not found".into()));
        assert_eq!(
            AuditOutcome::from_backend_result(&bare_terminal),
            AuditOutcome::RemoteError
        );

        let validation: std::result::Result<i32, _> = Err(BackendError::Validation("oops".into()));
        assert_eq!(
            AuditOutcome::from_backend_result(&validation),
            AuditOutcome::Validation
        );

        let cap: std::result::Result<i32, _> =
            Err(BackendError::CapabilityNotAdvertised("foo".into()));
        assert_eq!(
            AuditOutcome::from_backend_result(&cap),
            AuditOutcome::Validation
        );
    }

    #[test]
    fn outcome_for_backend_error_full_mapping_table() {
        // Activated by chainlink #104's Step 7. Every row of the
        // mapping table is asserted here so the function is ready to
        // fire atomically with the migration.
        assert_eq!(
            outcome_for_backend_error(&BackendError::Auth("401".into())),
            AuditOutcome::Auth
        );

        // Transient: rate-limited marker → rate_limited; remote-error
        // marker → network; no marker → network.
        assert_eq!(
            outcome_for_backend_error(&BackendError::Transient(
                "[sub_classification=RateLimited retry_after_seconds=10] slow".into()
            )),
            AuditOutcome::RateLimited
        );
        assert_eq!(
            outcome_for_backend_error(&BackendError::Transient(
                "[sub_classification=RemoteError code=599] oops".into()
            )),
            AuditOutcome::Network
        );
        assert_eq!(
            outcome_for_backend_error(&BackendError::Transient("dns timeout".into())),
            AuditOutcome::Network
        );

        // Validation: any marker still maps to validation.
        assert_eq!(
            outcome_for_backend_error(&BackendError::Validation("missing".into())),
            AuditOutcome::Validation
        );
        assert_eq!(
            outcome_for_backend_error(&BackendError::Validation(
                "[sub_classification=RemoteError code=InvalidRequest] x".into()
            )),
            AuditOutcome::Validation
        );

        // Terminal: conflict marker → conflict; remote-error marker →
        // remote_error; otherwise terminal.
        assert_eq!(
            outcome_for_backend_error(&BackendError::Terminal(
                "[sub_classification=Conflict] already taken down".into()
            )),
            AuditOutcome::Conflict
        );
        assert_eq!(
            outcome_for_backend_error(&BackendError::Terminal(
                "[sub_classification=RemoteError code=NotFound] x".into()
            )),
            AuditOutcome::RemoteError
        );
        assert_eq!(
            outcome_for_backend_error(&BackendError::Terminal("subject not found".into())),
            AuditOutcome::Terminal
        );

        // CapabilityNotAdvertised stays under validation.
        assert_eq!(
            outcome_for_backend_error(&BackendError::CapabilityNotAdvertised("foo".into())),
            AuditOutcome::Validation
        );

        // Unsupported and ArchitecturallyForbidden share 'unsupported';
        // error_category distinguishes them post-chainlink-#104.
        assert_eq!(
            outcome_for_backend_error(&BackendError::Unsupported),
            AuditOutcome::Unsupported
        );
        assert_eq!(
            outcome_for_backend_error(&BackendError::ArchitecturallyForbidden("§F4".into())),
            AuditOutcome::Unsupported
        );
    }

    #[tokio::test]
    async fn record_success_round_trips() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("ozone-evt-1"))),
            None,
            1_000,
            1_500,
        )
        .await
        .unwrap();

        assert_eq!(stored.precipitating_action_id, action_id);
        assert_eq!(stored.backend_method, BackendMethod::TakedownAccount);
        assert_eq!(stored.outcome, AuditOutcome::Success);
        assert_eq!(
            stored.backend_action_id.as_ref().unwrap().as_str(),
            "ozone-evt-1"
        );
        assert!(stored.error_code.is_none());
        assert!(stored.error_message.is_none());
        assert!(stored.retry_after_seconds.is_none());

        let fetched = get_pds_admin_audit(&pool, stored.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.id, stored.id);
        assert_eq!(fetched.backend_method, stored.backend_method);
        assert_eq!(fetched.outcome, stored.outcome);
        assert_eq!(fetched.backend_action_id, stored.backend_action_id);
        assert_eq!(fetched.row_hash, stored.row_hash);
        assert_eq!(fetched.prev_hash, stored.prev_hash);
        assert_eq!(fetched.call_started_at, stored.call_started_at);
        assert_eq!(fetched.call_completed_at, stored.call_completed_at);
    }

    #[tokio::test]
    async fn record_unit_success_has_null_action_id() {
        // restore_account / apply_label / negate_label return
        // Result<(), _>; the caller maps Ok(()) → Ok(None).
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::RestoreAccount,
            Ok(None),
            None,
            10,
            20,
        )
        .await
        .unwrap();

        assert_eq!(stored.outcome, AuditOutcome::Success);
        assert!(stored.backend_action_id.is_none());
    }

    #[tokio::test]
    async fn record_rate_limited_preserves_retry_hint() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Transient(
                "[sub_classification=RateLimited retry_after_seconds=120] slow down".into(),
            )),
            None,
            10,
            20,
        )
        .await
        .unwrap();

        assert_eq!(stored.outcome, AuditOutcome::RateLimited);
        assert_eq!(stored.retry_after_seconds, Some(120));
        assert!(
            stored
                .error_message
                .as_deref()
                .unwrap()
                .contains("slow down"),
            "error_message preserves the inner text"
        );
        assert!(stored.error_code.is_none());
        assert!(stored.backend_action_id.is_none());
    }

    #[tokio::test]
    async fn record_remote_error_preserves_code_and_message() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Validation(
                "[sub_classification=RemoteError code=InvalidRequest] bad shape".into(),
            )),
            None,
            10,
            20,
        )
        .await
        .unwrap();

        // V1.7-compat: a Validation with the RemoteError marker maps
        // to outcome='validation' (request-shape semantic). Step 7's
        // outcome_for_backend_error keeps the same mapping.
        assert_eq!(stored.outcome, AuditOutcome::Validation);
        assert_eq!(stored.error_code.as_deref(), Some("InvalidRequest"));
        assert!(
            stored
                .error_message
                .as_deref()
                .unwrap()
                .contains("bad shape"),
            "error_message preserves the inner text"
        );
        assert!(stored.retry_after_seconds.is_none());
    }

    #[tokio::test]
    async fn record_terminal_with_remote_error_marker_writes_remote_error_outcome() {
        // Demonstrates the v1.7-compat coalescence: Terminal with the
        // RemoteError marker preserves outcome='remote_error' so v1.7
        // dashboards keep working until chainlink #104's migration.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Terminal(
                "[sub_classification=RemoteError code=NotFound] subject not found".into(),
            )),
            None,
            10,
            20,
        )
        .await
        .unwrap();

        assert_eq!(stored.outcome, AuditOutcome::RemoteError);
        assert_eq!(stored.error_code.as_deref(), Some("NotFound"));
    }

    #[tokio::test]
    async fn record_network_error_has_message_only() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Transient("dns timeout".into())),
            None,
            10,
            20,
        )
        .await
        .unwrap();

        assert_eq!(stored.outcome, AuditOutcome::Network);
        assert!(stored.error_code.is_none());
        assert_eq!(stored.error_message.as_deref(), Some("dns timeout"));
        assert!(stored.retry_after_seconds.is_none());
    }

    #[tokio::test]
    async fn unified_chain_links_audit_log_to_pds_admin_audit() {
        // Insert audit_log row → insert pds_admin_audit row → insert
        // audit_log row again. The middle row's prev_hash must equal
        // the first row's row_hash; the third row's prev_hash must
        // equal the second row's row_hash. This proves the chain is
        // unified across both tables.
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let audit_log_id_1 = append_via_pool(
            &pool,
            &AuditRowForAppend {
                created_at: 1_000,
                action: "label_applied".into(),
                actor_did: "did:plc:m1".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
        )
        .await
        .unwrap();

        let pds_row = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("ozone-1"))),
            None,
            1_500,
            2_000,
        )
        .await
        .unwrap();

        let audit_log_id_2 = append_via_pool(
            &pool,
            &AuditRowForAppend {
                created_at: 3_000,
                action: "label_applied".into(),
                actor_did: "did:plc:m1".into(),
                target: None,
                target_cid: None,
                outcome: "success".into(),
                reason: None,
            },
        )
        .await
        .unwrap();

        let row1_hash: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT row_hash AS "row_hash!" FROM audit_log WHERE id = ?1"#,
            audit_log_id_1
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let row3_prev: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT prev_hash AS "prev_hash!" FROM audit_log WHERE id = ?1"#,
            audit_log_id_2
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            pds_row.prev_hash, row1_hash,
            "pds_admin_audit row must chain after the most recent audit_log row"
        );
        assert_eq!(
            row3_prev, pds_row.row_hash,
            "the next audit_log row must chain after the pds_admin_audit row"
        );
    }

    #[tokio::test]
    async fn first_pds_admin_audit_uses_genesis_when_audit_log_empty() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("evt"))),
            None,
            1,
            2,
        )
        .await
        .unwrap();

        assert_eq!(
            stored.prev_hash.as_slice(),
            crate::audit::hash::GENESIS_PREV_HASH
        );
    }

    #[tokio::test]
    async fn fk_violation_rejects_unknown_action() {
        let pool = fresh_pool().await;
        // No fixture_subject_action — id 999 doesn't exist.
        let res = record_pds_admin_call(
            &pool,
            999,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("x"))),
            None,
            10,
            20,
        )
        .await;
        assert!(res.is_err(), "FK violation must propagate");
    }

    #[tokio::test]
    async fn list_for_action_returns_in_chain_order() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;

        // Three calls with strictly-increasing call_completed_at;
        // list should return them in that order.
        record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Transient("first".into())),
            None,
            10,
            20,
        )
        .await
        .unwrap();
        record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Err(BackendError::Transient("second".into())),
            None,
            30,
            40,
        )
        .await
        .unwrap();
        record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("third"))),
            None,
            50,
            60,
        )
        .await
        .unwrap();

        let listed = list_pds_admin_audit_for_action(&pool, action_id)
            .await
            .unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].error_message.as_deref(), Some("first"));
        assert_eq!(listed[1].error_message.as_deref(), Some("second"));
        assert_eq!(
            listed[2].backend_action_id.as_ref().unwrap().as_str(),
            "third"
        );
    }

    #[tokio::test]
    async fn list_for_action_with_no_rows_is_empty() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let listed = list_pds_admin_audit_for_action(&pool, action_id)
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn get_for_missing_id_returns_none() {
        let pool = fresh_pool().await;
        let res = get_pds_admin_audit(&pool, 9999).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn append_only_trigger_blocks_update() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("evt"))),
            None,
            1,
            2,
        )
        .await
        .unwrap();

        let res = sqlx::query("UPDATE pds_admin_audit SET error_code = 'tampered' WHERE id = ?1")
            .bind(stored.id)
            .execute(&pool)
            .await;
        assert!(
            res.is_err(),
            "BEFORE UPDATE trigger must block all UPDATEs against pds_admin_audit"
        );
    }

    #[tokio::test]
    async fn append_only_trigger_blocks_delete() {
        let pool = fresh_pool().await;
        let action_id = fixture_subject_action(&pool).await;
        let stored = record_pds_admin_call(
            &pool,
            action_id,
            BackendMethod::TakedownAccount,
            Ok(Some(BackendActionId::new("evt"))),
            None,
            1,
            2,
        )
        .await
        .unwrap();

        let res = sqlx::query("DELETE FROM pds_admin_audit WHERE id = ?1")
            .bind(stored.id)
            .execute(&pool)
            .await;
        assert!(
            res.is_err(),
            "BEFORE DELETE trigger must block all DELETEs against pds_admin_audit"
        );
    }
}
