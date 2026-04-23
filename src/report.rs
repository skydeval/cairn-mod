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
    pub id: i64,
    /// RFC-3339 Z with ms precision (§6.1 wire format).
    pub created_at: String,
    pub reported_by: String,
    pub reason_type: String,
    /// Report body. §F11: never returned by public endpoints,
    /// never written to logs. Admin handlers enforce via
    /// `project_for_list` vs `project_for_fetch` in
    /// `src/server/admin/report_view.rs`.
    pub reason: Option<String>,
    /// One of `"account"` / `"record"` per the schema CHECK.
    pub subject_type: String,
    pub subject_did: String,
    pub subject_uri: Option<String>,
    pub subject_cid: Option<String>,
    /// One of `"pending"` / `"resolved"` per the schema CHECK.
    pub status: String,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
    pub resolution_label: Option<String>,
    pub resolution_reason: Option<String>,
}
