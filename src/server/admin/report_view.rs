//! Projections of [`crate::report::Report`] into the wire shapes
//! referenced by the `tools.cairn.admin.defs#reportView` lexicon.
//!
//! **Two distinct types** — `ReportListEntry` and `ReportDetail` —
//! enforce the §F11 rule "report body never returned by public
//! endpoints" at the type system level. A callsite that holds a
//! `ReportListEntry` literally cannot leak `reason` text; the field
//! does not exist on that type. `ReportDetail` carries the full
//! text and is produced only by `getReport` / `resolveReport`
//! handlers, which are admin-authenticated.
//!
//! Both types share the subject-union serialization and status
//! mapping; the only difference is the presence (or not) of the
//! `reason` field.

use serde::Serialize;

use crate::report::Report;

/// `reportView` minus `reason` — used by `listReports`.
///
/// Maps to the lexicon's `#reportView` shape with the `reason`
/// property absent (lexicon marks it optional, and §F11 forbids
/// its return from list-style endpoints). A future refactor that
/// adds `reason` here re-introduces the leak bug.
#[derive(Debug, Serialize)]
pub(super) struct ReportListEntry {
    pub id: i64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    pub subject: SubjectView,
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolvedAt")]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolvedBy")]
    pub resolved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolutionLabel")]
    pub resolution_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolutionReason")]
    pub resolution_reason: Option<String>,
}

/// `reportView` including `reason` — used by `getReport` and
/// `resolveReport`'s response.
#[derive(Debug, Serialize)]
pub(super) struct ReportDetail {
    pub id: i64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub subject: SubjectView,
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolvedAt")]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolvedBy")]
    pub resolved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolutionLabel")]
    pub resolution_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "resolutionReason")]
    pub resolution_reason: Option<String>,
}

/// Union shape matching the lexicon's
/// `{ com.atproto.admin.defs#repoRef | com.atproto.repo.strongRef }`.
#[derive(Debug, Serialize)]
#[serde(tag = "$type")]
pub(super) enum SubjectView {
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    Repo { did: String },
    #[serde(rename = "com.atproto.repo.strongRef")]
    Strong { uri: String, cid: String },
}

fn build_subject(report: &Report) -> SubjectView {
    match report.subject_type.as_str() {
        "record" => SubjectView::Strong {
            uri: report.subject_uri.clone().unwrap_or_default(),
            cid: report.subject_cid.clone().unwrap_or_default(),
        },
        // "account" (or any schema-surprise fallback) maps to repoRef.
        _ => SubjectView::Repo {
            did: report.subject_did.clone(),
        },
    }
}

/// Project a stored report for a LIST response. Deliberately drops
/// `reason` regardless of its storage value. §F11 enforcement via
/// type — the returned struct has no reason field.
pub(super) fn project_for_list(report: Report) -> ReportListEntry {
    let subject = build_subject(&report);
    ReportListEntry {
        id: report.id,
        created_at: report.created_at,
        reason_type: report.reason_type,
        subject,
        reported_by: report.reported_by,
        status: report.status,
        resolved_at: report.resolved_at,
        resolved_by: report.resolved_by,
        resolution_label: report.resolution_label,
        resolution_reason: report.resolution_reason,
    }
}

/// Project a stored report for a FETCH response. Carries `reason`
/// text. Callers: `getReport`, `resolveReport` response.
pub(super) fn project_for_fetch(report: Report) -> ReportDetail {
    let subject = build_subject(&report);
    ReportDetail {
        id: report.id,
        created_at: report.created_at,
        reason_type: report.reason_type,
        reason: report.reason,
        subject,
        reported_by: report.reported_by,
        status: report.status,
        resolved_at: report.resolved_at,
        resolved_by: report.resolved_by,
        resolution_label: report.resolution_label,
        resolution_reason: report.resolution_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(reason: Option<&str>, subject_type: &str) -> Report {
        Report {
            id: 1,
            created_at: "2026-04-23T00:00:00.000Z".into(),
            reported_by: "did:plc:reporter".into(),
            reason_type: "com.atproto.moderation.defs#reasonSpam".into(),
            reason: reason.map(str::to_string),
            subject_type: subject_type.into(),
            subject_did: "did:plc:target".into(),
            subject_uri: Some("at://did:plc:target/col/r".into()),
            subject_cid: Some("bafy".into()),
            status: "pending".into(),
            resolved_at: None,
            resolved_by: None,
            resolution_label: None,
            resolution_reason: None,
        }
    }

    #[test]
    fn list_projection_drops_reason_even_when_stored() {
        // The anti-leak property: if a list endpoint somehow got a
        // row whose stored `reason` is non-empty, the projection
        // produces a JSON object with no `reason` field at all.
        let r = sample(Some("sensitive report body"), "account");
        let entry = project_for_list(r);
        let json = serde_json::to_value(&entry).unwrap();
        assert!(
            json.get("reason").is_none(),
            "list projection must never serialize a reason field: {json}"
        );
    }

    #[test]
    fn fetch_projection_includes_reason() {
        let r = sample(Some("sensitive report body"), "record");
        let detail = project_for_fetch(r);
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["reason"], "sensitive report body");
    }

    #[test]
    fn record_subject_type_serializes_as_strong_ref() {
        let r = sample(None, "record");
        let detail = project_for_fetch(r);
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["subject"]["$type"], "com.atproto.repo.strongRef");
        assert_eq!(json["subject"]["uri"], "at://did:plc:target/col/r");
        assert_eq!(json["subject"]["cid"], "bafy");
    }

    #[test]
    fn account_subject_type_serializes_as_repo_ref() {
        let r = sample(None, "account");
        let detail = project_for_fetch(r);
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["subject"]["$type"], "com.atproto.admin.defs#repoRef");
        assert_eq!(json["subject"]["did"], "did:plc:target");
    }
}
