//! Report domain type — flat projection of the `reports` table
//! (§F11 intake schema in migrations/0001_init.sql).
//!
//! Kept flat (string columns for `subject_type` rather than enums)
//! so callers can map directly from `sqlx` rows without a conversion
//! step, and so the writer's `ResolvedReport` response and the admin
//! `listReports` / `getReport` handlers share one type instead of
//! reserializing across three layers.
//!
//! Status is the one column that *is* typed: [`ReportStatus`]
//! mirrors the `status IN ('pending', 'resolved')` CHECK constraint
//! at the type level (#27, parallel to [`crate::moderators::Role`]).
//! sqlx [`Type`](sqlx::Type) / [`Decode`](sqlx::Decode) /
//! [`Encode`](sqlx::Encode) impls let `query_as!(Report, ...)`
//! consume the column directly — no separate row struct is needed.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::Sqlite;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;

/// Status values persisted in `reports.status` (§F11). The schema
/// CHECK constrains the column to exactly these two strings, so any
/// other value in a read means corrupt data, not an unknown status.
///
/// Wire shape mirrors the lexicon's
/// `tools.cairn.admin.defs#reportView.status` `knownValues`
/// (`"pending"` / `"resolved"`); serde uses `rename_all = "lowercase"`
/// so on-the-wire bytes are identical to the pre-#27 string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportStatus {
    /// Open report awaiting moderator action.
    Pending,
    /// Closed report; `resolved_*` columns populated.
    Resolved,
}

impl ReportStatus {
    /// DB-side string representation. Must match the CHECK
    /// constraint in migrations and the lexicon `knownValues`.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportStatus::Pending => "pending",
            ReportStatus::Resolved => "resolved",
        }
    }

    /// Parse the string stored in `reports.status` (or supplied via
    /// the `listReports` `status=` query param). Returns `None`
    /// if the value doesn't match the CHECK constraint.
    pub fn from_db_str(s: &str) -> Option<ReportStatus> {
        match s {
            "pending" => Some(ReportStatus::Pending),
            "resolved" => Some(ReportStatus::Resolved),
            _ => None,
        }
    }
}

impl std::fmt::Display for ReportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReportStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ReportStatus::from_db_str(s).ok_or(())
    }
}

// sqlx integration: TEXT-backed enum. Manual impls (rather than
// the `sqlx::Type` derive) keep the trait surface explicit and
// avoid pulling macro internals into the public type.
impl sqlx::Type<Sqlite> for ReportStatus {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <str as sqlx::Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &<Sqlite as sqlx::Database>::TypeInfo) -> bool {
        <str as sqlx::Type<Sqlite>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for ReportStatus {
    fn decode(value: <Sqlite as sqlx::Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        let s = <&str as sqlx::Decode<Sqlite>>::decode(value)?;
        ReportStatus::from_db_str(s)
            .ok_or_else(|| format!("reports.status value {s:?} violates CHECK constraint").into())
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for ReportStatus {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<IsNull, BoxDynError> {
        <&str as sqlx::Encode<Sqlite>>::encode_by_ref(&self.as_str(), buf)
    }
}

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
    /// `pending` or `resolved`. Typed via [`ReportStatus`] (#27);
    /// schema CHECK enforces the same set at the DB layer.
    pub status: ReportStatus,
    /// When `status == Resolved`, the RFC-3339 Z timestamp of
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_db_str_round_trips_known_values() {
        for s in ["pending", "resolved"] {
            let st = ReportStatus::from_db_str(s).expect("known value");
            assert_eq!(st.as_str(), s);
        }
    }

    #[test]
    fn from_db_str_rejects_unknown() {
        assert!(ReportStatus::from_db_str("Pending").is_none());
        assert!(ReportStatus::from_db_str("").is_none());
        assert!(ReportStatus::from_db_str("dismissed").is_none());
    }

    #[test]
    fn serializes_as_lowercase_string() {
        let v = serde_json::to_value(ReportStatus::Pending).unwrap();
        assert_eq!(v, serde_json::Value::String("pending".into()));
        let v = serde_json::to_value(ReportStatus::Resolved).unwrap();
        assert_eq!(v, serde_json::Value::String("resolved".into()));
    }

    #[test]
    fn deserializes_from_lexicon_known_values() {
        let p: ReportStatus = serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(p, ReportStatus::Pending);
        let r: ReportStatus = serde_json::from_str("\"resolved\"").unwrap();
        assert_eq!(r, ReportStatus::Resolved);
    }
}
