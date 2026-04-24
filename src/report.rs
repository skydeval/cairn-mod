//! Report domain type — flat projection of the `reports` table
//! (§F11 intake schema in migrations/0001_init.sql).
//!
//! Kept flat (string columns for `subject_type` / `status` rather
//! than enums) so callers can map directly from `sqlx` rows without
//! a conversion step, and so the writer's `ResolvedReport` response
//! and the admin `listReports` / `getReport` handlers share one
//! type instead of reserializing across three layers.

/// A row from the `reports` table. Field names / types match the
/// schema 1:1; see `lexicons/tools/cairn/admin/defs.json#reportView`
/// for the wire projection that admin handlers build from this.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Report {
    /// Report row primary key. Stable across a deployment; used
    /// as the opaque handle by `getReport` / `resolveReport`.
    pub id: i64,
    /// RFC-3339 Z with ms precision (§6.1 wire format).
    pub created_at: String,
    /// DID of the caller whose service-auth JWT verified at
    /// `createReport` intake.
    pub reported_by: String,
    /// `com.atproto.moderation.defs#reason*` value — see §F11 for
    /// the accepted set.
    pub reason_type: String,
    /// Report body. §F11: never returned by public endpoints,
    /// never written to logs. Admin handlers enforce via
    /// `project_for_list` vs `project_for_fetch` in
    /// `src/server/admin/report_view.rs`.
    pub reason: Option<String>,
    /// One of `"account"` / `"record"` per the schema CHECK.
    pub subject_type: String,
    /// Subject identifier: for `"account"` this is the DID of the
    /// account being reported; for `"record"` this is the DID
    /// portion of the `at://` URI.
    pub subject_did: String,
    /// For record subjects, the full `at://` URI. `None` when
    /// `subject_type == "account"`.
    pub subject_uri: Option<String>,
    /// For record subjects, the content-addressed ID pinning the
    /// reported record version. `None` when `subject_type ==
    /// "account"`.
    pub subject_cid: Option<String>,
    /// One of `"pending"` / `"resolved"` per the schema CHECK.
    pub status: String,
    /// When `status == "resolved"`, the RFC-3339 Z timestamp of
    /// the resolution. `None` while pending.
    pub resolved_at: Option<String>,
    /// When resolved, the moderator DID that issued the
    /// resolution. `None` while pending.
    pub resolved_by: Option<String>,
    /// If the resolution emitted a label, its value (the `val`
    /// field on the emitted label). `None` if resolved without
    /// labeling.
    pub resolution_label: Option<String>,
    /// Free-text resolution rationale (not the same as the
    /// `reason` — this is the MODERATOR's rationale, recorded at
    /// resolve time).
    pub resolution_reason: Option<String>,
}
