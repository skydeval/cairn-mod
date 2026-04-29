//! Projection: cairn-mod `audit_log` → Ozone `modEventView` (#98).
//!
//! Phase D's final projection. Different design challenge from
//! #97: cairn-mod's `audit_log.action` vocabulary doesn't fully
//! map to Ozone's `modEvent*` types. Many cairn-mod-internal
//! audit entries have no Ozone analog and are **filtered out** —
//! see [`is_ozone_eligible`] for the policy.
//!
//! # Filter-out policy (the cairn-mod-internal subset)
//!
//! Per the prompt's option 1 ("filter them out — Ozone read
//! endpoint's audience is moderators, who don't need to see the
//! full operator audit surface"), the following actions are
//! invisible to `queryEvents`:
//!
//! - `label_applied` / `label_negated` (admin-direct label
//!   emission, not an action-driven event)
//! - `pending_policy_action_confirmed` / `_dismissed` (policy-
//!   automation, cairn-mod-specific)
//! - `report_resolved`, `reporter_flagged`, `reporter_unflagged`
//!   (report-resolution surface; the original report's
//!   recorded action surfaces via `subject_action_recorded`)
//! - `retention_sweep` (operational, no subject)
//! - `service_record_published` / `_unpublished` (deployment
//!   lifecycle)
//! - `pds_admin_audit` rows (live in a sibling table; never
//!   surface here)
//!
//! Operators retain full visibility via the CLI (§F18) and
//! `cairn audit verify`, which walk the unified hash chain
//! across all rows in `audit_log` (and `pds_admin_audit` per #88).
//!
//! # Surfaced (Ozone-eligible) mapping
//!
//! | cairn-mod row                                              | Ozone event $type             | Notes                                                                                  |
//! |------------------------------------------------------------|-------------------------------|----------------------------------------------------------------------------------------|
//! | `subject_action_recorded` (action_type=warning)            | `modEventLabel`               | `createLabelVals` = the action's `reason_codes` (mirrors #95's emitEvent reverse map). |
//! | `subject_action_recorded` (action_type=note)               | `modEventComment`             | `comment` = the action's `notes`.                                                      |
//! | `subject_action_recorded` (action_type=takedown)           | `modEventTakedown`            | No `durationInHours`.                                                                  |
//! | `subject_action_recorded` (action_type=temp_suspension)    | `modEventTakedown`            | `durationInHours` parsed from the action's `duration` (ISO-8601, typically `PT{h}H`).  |
//! | `subject_action_recorded` (action_type=indef_suspension)   | `modEventTakedown`            | No `durationInHours` (Ozone has no separate "indefinite suspension" wire shape).       |
//! | `subject_action_revoked` (revoked action_type=takedown/temp_suspension/indef_suspension) | `modEventReverseTakedown` | `comment` = the revocation audit's `revoked_reason`.                                   |
//! | `subject_action_revoked` (revoked action_type=warning/note)| (filter out)                  | Ozone has no "reverse comment" / "reverse label" event type in the v1.7 surface.       |
//!
//! All projections are pure functions over already-loaded rows.
//! The handler does the SQL JOIN; the projection does the shape
//! translation.

use serde_json::{Value, json};

/// Ozone event $type discriminators used by the projection.
mod ev_type {
    pub const LABEL: &str = "tools.ozone.moderation.defs#modEventLabel";
    pub const TAKEDOWN: &str = "tools.ozone.moderation.defs#modEventTakedown";
    pub const REVERSE_TAKEDOWN: &str = "tools.ozone.moderation.defs#modEventReverseTakedown";
    pub const COMMENT: &str = "tools.ozone.moderation.defs#modEventComment";
}

/// Subject discriminators reused from #97's projection convention.
const SUBJECT_TYPE_REPO_REF: &str = "com.atproto.admin.defs#repoRef";
const SUBJECT_TYPE_STRONG_REF: &str = "com.atproto.repo.strongRef";

/// Ozone-eligible `audit_log.action` values. Anything outside
/// this set is filtered out at the SQL boundary in the handler;
/// kept here as the canonical source so a future audit-action
/// addition forces a deliberate surface decision.
pub const OZONE_ELIGIBLE_ACTIONS: &[&str] = &["subject_action_recorded", "subject_action_revoked"];

/// Whether an `audit_log.action` value has any Ozone analog. Used
/// by the SQL `WHERE` clause and by tests pinning the filter-out
/// policy.
pub fn is_ozone_eligible(audit_action: &str) -> bool {
    OZONE_ELIGIBLE_ACTIONS.contains(&audit_action)
}

/// One row from `audit_log` joined with the matching
/// `subject_actions` row (where applicable). Both `subject_*`
/// fields are `None` when the join fails — the projection
/// returns `None` (filter out) in that case rather than emitting
/// a partial event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventRow {
    /// `audit_log.id` — used as `modEventView.id`.
    pub audit_id: i64,
    /// `audit_log.action`.
    pub audit_action: String,
    /// `audit_log.actor_did` — surfaces as `modEventView.createdBy`.
    pub actor_did: String,
    /// `audit_log.created_at` (epoch-ms).
    pub created_at: i64,
    /// `subject_actions.action_type`. `None` when the join
    /// failed; the projection filters these out.
    pub subject_action_type: Option<String>,
    /// `subject_actions.subject_did`.
    pub subject_did: Option<String>,
    /// `subject_actions.subject_uri` (NULL for account-level).
    pub subject_uri: Option<String>,
    /// `subject_actions.notes` — surfaces as `comment` for
    /// `modEventComment`.
    pub subject_notes: Option<String>,
    /// `subject_actions.duration` (ISO-8601 string e.g. `PT168H`,
    /// `P7D`). Parsed into `durationInHours` for
    /// `modEventTakedown`.
    pub subject_duration: Option<String>,
    /// `subject_actions.reason_codes` (JSON array string).
    /// Decoded into `createLabelVals` for `modEventLabel`.
    pub subject_reason_codes_json: Option<String>,
    /// `audit_log.reason` — JSON string. For
    /// `subject_action_revoked`, contains `revoked_reason` which
    /// surfaces as `modEventReverseTakedown.comment`.
    pub audit_reason_json: Option<String>,
}

/// Result of projecting one audit row. Field names mirror Ozone's
/// `modEventView`; the handler maps these into the outer wire
/// struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedModEvent {
    /// Stable event identifier (`audit_log.id`).
    pub id: i64,
    /// Discriminated event body.
    pub event: Value,
    /// Discriminated subject ref.
    pub subject: Value,
    /// `audit_log.actor_did`.
    pub created_by: String,
    /// `audit_log.created_at` (epoch-ms — handler converts to
    /// RFC-3339).
    pub created_at: i64,
}

/// Project one audit row into a `modEventView`. Returns `None`
/// when:
///
/// - the audit action isn't Ozone-eligible (defense-in-depth —
///   the SQL filter shouldn't return non-eligible rows, but the
///   projection re-checks),
/// - the `subject_actions` join failed (no row to derive the
///   event payload from),
/// - the underlying action_type has no Ozone analog (e.g.,
///   revoked-warning, since Ozone has no "reverse comment").
pub fn project_audit_event(row: &AuditEventRow) -> Option<ProjectedModEvent> {
    if !is_ozone_eligible(&row.audit_action) {
        return None;
    }
    let action_type = row.subject_action_type.as_deref()?;
    let subject_did = row.subject_did.as_deref()?;
    let event = match (row.audit_action.as_str(), action_type) {
        ("subject_action_recorded", "warning") => Some(project_label_event(row)),
        ("subject_action_recorded", "note") => Some(project_comment_event(row)),
        ("subject_action_recorded", "takedown") => Some(project_takedown_event(row, false)),
        ("subject_action_recorded", "temp_suspension") => Some(project_takedown_event(row, true)),
        ("subject_action_recorded", "indef_suspension") => Some(project_takedown_event(row, false)),
        ("subject_action_revoked", "takedown")
        | ("subject_action_revoked", "temp_suspension")
        | ("subject_action_revoked", "indef_suspension") => {
            Some(project_reverse_takedown_event(row))
        }
        // subject_action_revoked of warning/note has no Ozone
        // analog; filter out.
        ("subject_action_revoked", _) => None,
        // Defensive: any other (audit_action, action_type) tuple
        // we didn't enumerate above. Filter out so the projection
        // is total over the union, but never silently surfaces an
        // un-mapped event.
        _ => None,
    }?;

    Some(ProjectedModEvent {
        id: row.audit_id,
        event,
        subject: project_subject(subject_did, row.subject_uri.as_deref()),
        created_by: row.actor_did.clone(),
        created_at: row.created_at,
    })
}

// ==========================================================================
// Per-event-type projections
// ==========================================================================

fn project_label_event(row: &AuditEventRow) -> Value {
    // createLabelVals = the action's reason_codes (1:1 with
    // #95's emitEvent reverse mapping).
    let create_label_vals: Vec<String> = row
        .subject_reason_codes_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default();
    let mut event = json!({
        "$type": ev_type::LABEL,
        "createLabelVals": create_label_vals,
        "negateLabelVals": [],
    });
    if let Some(notes) = row.subject_notes.as_deref() {
        event["comment"] = json!(notes);
    }
    event
}

fn project_comment_event(row: &AuditEventRow) -> Value {
    let comment = row.subject_notes.clone().unwrap_or_default();
    json!({
        "$type": ev_type::COMMENT,
        "comment": comment,
    })
}

fn project_takedown_event(row: &AuditEventRow, with_duration: bool) -> Value {
    let mut event = json!({
        "$type": ev_type::TAKEDOWN,
    });
    if let Some(notes) = row.subject_notes.as_deref() {
        event["comment"] = json!(notes);
    }
    if with_duration
        && let Some(d) = row.subject_duration.as_deref()
        && let Some(hours) = parse_iso_duration_hours(d)
    {
        event["durationInHours"] = json!(hours);
    }
    event
}

fn project_reverse_takedown_event(row: &AuditEventRow) -> Value {
    let mut event = json!({
        "$type": ev_type::REVERSE_TAKEDOWN,
    });
    if let Some(reason) = revoked_reason_from_audit_reason(row.audit_reason_json.as_deref()) {
        event["comment"] = json!(reason);
    }
    event
}

fn project_subject(subject_did: &str, subject_uri: Option<&str>) -> Value {
    match subject_uri {
        None => json!({
            "$type": SUBJECT_TYPE_REPO_REF,
            "did": subject_did,
        }),
        Some(uri) => json!({
            "$type": SUBJECT_TYPE_STRONG_REF,
            "uri": uri,
        }),
    }
}

// ==========================================================================
// Helpers
// ==========================================================================

/// Parse the `revoked_reason` field out of a
/// `subject_action_revoked` audit reason JSON. Returns `None` if
/// the JSON is malformed or the field is missing/null. Per
/// `AUDIT_REASON_REVOKE_ACTION` (writer.rs), the schema is
/// `{action_id, revoked_reason}`.
pub fn revoked_reason_from_audit_reason(reason: Option<&str>) -> Option<String> {
    let s = reason?;
    let v: Value = serde_json::from_str(s).ok()?;
    v.get("revoked_reason")?.as_str().map(String::from)
}

/// Parse an ISO-8601 duration string into whole hours. Supports
/// the two shapes cairn-mod actually emits: `PT{h}H` (used by the
/// gateway emitEvent handler in #95) and `P{d}D` (used by some CLI
/// paths). Other shapes (mixed days+hours, weeks, etc.) return
/// `None` — the caller falls back to omitting `durationInHours`.
pub fn parse_iso_duration_hours(s: &str) -> Option<i64> {
    let stripped = s.strip_prefix('P')?;
    if let Some(rest) = stripped.strip_prefix('T') {
        // PT<h>H
        let h = rest.strip_suffix('H')?;
        h.parse::<i64>().ok()
    } else if let Some(rest) = stripped.strip_suffix('D') {
        // P<d>D
        rest.parse::<i64>().ok().map(|d| d * 24)
    } else if let Some(rest) = stripped.strip_suffix('H') {
        // P<h>H (less canonical but seen in the wild)
        rest.parse::<i64>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn row(
        audit_id: i64,
        audit_action: &str,
        action_type: Option<&str>,
        subject_did: Option<&str>,
        subject_uri: Option<&str>,
        notes: Option<&str>,
        duration: Option<&str>,
        reason_codes_json: Option<&str>,
        audit_reason_json: Option<&str>,
    ) -> AuditEventRow {
        AuditEventRow {
            audit_id,
            audit_action: audit_action.into(),
            actor_did: "did:plc:moderator".into(),
            created_at: 1_000,
            subject_action_type: action_type.map(String::from),
            subject_did: subject_did.map(String::from),
            subject_uri: subject_uri.map(String::from),
            subject_notes: notes.map(String::from),
            subject_duration: duration.map(String::from),
            subject_reason_codes_json: reason_codes_json.map(String::from),
            audit_reason_json: audit_reason_json.map(String::from),
        }
    }

    // ===== is_ozone_eligible =====

    #[test]
    fn ozone_eligible_pins_to_two_actions() {
        // Pinned at 2: subject_action_recorded + subject_action_revoked.
        // Adding a new audit action requires a deliberate decision
        // about whether it surfaces here.
        assert_eq!(OZONE_ELIGIBLE_ACTIONS.len(), 2);
        assert!(is_ozone_eligible("subject_action_recorded"));
        assert!(is_ozone_eligible("subject_action_revoked"));
    }

    #[test]
    fn cairn_internal_actions_filtered_out() {
        for a in &[
            "label_applied",
            "label_negated",
            "pending_policy_action_confirmed",
            "pending_policy_action_dismissed",
            "report_resolved",
            "reporter_flagged",
            "reporter_unflagged",
            "retention_sweep",
            "service_record_published",
            "service_record_unpublished",
        ] {
            assert!(!is_ozone_eligible(a), "{a} should be filtered out");
        }
    }

    // ===== project_audit_event — surfaced cases =====

    #[test]
    fn warning_recorded_projects_to_label_event() {
        let r = row(
            1,
            "subject_action_recorded",
            Some("warning"),
            Some("did:plc:target"),
            None,
            Some("looks like spam"),
            None,
            Some(r#"["spam","harassment"]"#),
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.id, 1);
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::LABEL));
        assert_eq!(
            p.event["createLabelVals"],
            serde_json::json!(["spam", "harassment"])
        );
        assert_eq!(p.event["comment"].as_str(), Some("looks like spam"));
        assert_eq!(p.subject["$type"].as_str(), Some(SUBJECT_TYPE_REPO_REF));
        assert_eq!(p.subject["did"].as_str(), Some("did:plc:target"));
    }

    #[test]
    fn note_recorded_projects_to_comment_event() {
        let r = row(
            2,
            "subject_action_recorded",
            Some("note"),
            Some("did:plc:target"),
            None,
            Some("needs second review"),
            None,
            None,
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::COMMENT));
        assert_eq!(p.event["comment"].as_str(), Some("needs second review"));
    }

    #[test]
    fn takedown_recorded_projects_to_takedown_event() {
        let r = row(
            3,
            "subject_action_recorded",
            Some("takedown"),
            Some("did:plc:target"),
            None,
            Some("banned"),
            None,
            None,
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::TAKEDOWN));
        assert_eq!(p.event["comment"].as_str(), Some("banned"));
        assert!(p.event.get("durationInHours").is_none());
    }

    #[test]
    fn temp_suspension_projects_to_takedown_with_duration_in_hours() {
        let r = row(
            4,
            "subject_action_recorded",
            Some("temp_suspension"),
            Some("did:plc:target"),
            None,
            Some("7-day cooldown"),
            Some("PT168H"),
            None,
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::TAKEDOWN));
        assert_eq!(p.event["durationInHours"].as_i64(), Some(168));
    }

    #[test]
    fn temp_suspension_with_p7d_duration_resolves_to_168_hours() {
        let r = row(
            5,
            "subject_action_recorded",
            Some("temp_suspension"),
            Some("did:plc:target"),
            None,
            None,
            Some("P7D"),
            None,
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["durationInHours"].as_i64(), Some(168));
    }

    #[test]
    fn indef_suspension_projects_to_takedown_without_duration() {
        let r = row(
            6,
            "subject_action_recorded",
            Some("indef_suspension"),
            Some("did:plc:target"),
            None,
            None,
            None,
            None,
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::TAKEDOWN));
        assert!(p.event.get("durationInHours").is_none());
    }

    #[test]
    fn revoked_takedown_projects_to_reverse_takedown_event() {
        let r = row(
            7,
            "subject_action_revoked",
            Some("takedown"),
            Some("did:plc:target"),
            None,
            None,
            None,
            None,
            Some(r#"{"action_id": 3, "revoked_reason": "appeal granted"}"#),
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::REVERSE_TAKEDOWN));
        assert_eq!(p.event["comment"].as_str(), Some("appeal granted"));
    }

    #[test]
    fn revoked_temp_suspension_projects_to_reverse_takedown() {
        let r = row(
            8,
            "subject_action_revoked",
            Some("temp_suspension"),
            Some("did:plc:target"),
            None,
            None,
            None,
            None,
            Some(r#"{"action_id": 4, "revoked_reason": null}"#),
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.event["$type"].as_str(), Some(ev_type::REVERSE_TAKEDOWN));
        assert!(p.event.get("comment").is_none());
    }

    // ===== project_audit_event — record-level subject =====

    #[test]
    fn record_level_subject_yields_strong_ref() {
        let r = row(
            9,
            "subject_action_recorded",
            Some("warning"),
            Some("did:plc:author"),
            Some("at://did:plc:author/app.bsky.feed.post/abc"),
            None,
            None,
            Some(r#"["spam"]"#),
            None,
        );
        let p = project_audit_event(&r).unwrap();
        assert_eq!(p.subject["$type"].as_str(), Some(SUBJECT_TYPE_STRONG_REF));
        assert_eq!(
            p.subject["uri"].as_str(),
            Some("at://did:plc:author/app.bsky.feed.post/abc")
        );
    }

    // ===== project_audit_event — filter-out cases =====

    #[test]
    fn revoked_warning_filters_out() {
        let r = row(
            10,
            "subject_action_revoked",
            Some("warning"),
            Some("did:plc:target"),
            None,
            None,
            None,
            None,
            Some(r#"{"action_id": 1, "revoked_reason": "mistake"}"#),
        );
        assert!(project_audit_event(&r).is_none());
    }

    #[test]
    fn revoked_note_filters_out() {
        let r = row(
            11,
            "subject_action_revoked",
            Some("note"),
            Some("did:plc:target"),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(project_audit_event(&r).is_none());
    }

    #[test]
    fn ineligible_audit_action_filters_out() {
        // Defense-in-depth: even if a non-eligible action sneaks
        // past the SQL filter, the projection rejects it.
        let r = row(
            12,
            "report_resolved",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(project_audit_event(&r).is_none());
    }

    #[test]
    fn missing_subject_join_filters_out() {
        // The LEFT JOIN failed (audit row exists but no
        // subject_actions row matches) — should not emit a
        // partial event.
        let r = row(
            13,
            "subject_action_recorded",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(project_audit_event(&r).is_none());
    }

    // ===== Helpers =====

    #[test]
    fn parse_iso_duration_pt_hours() {
        assert_eq!(parse_iso_duration_hours("PT168H"), Some(168));
        assert_eq!(parse_iso_duration_hours("PT1H"), Some(1));
        assert_eq!(parse_iso_duration_hours("PT72H"), Some(72));
    }

    #[test]
    fn parse_iso_duration_p_days() {
        assert_eq!(parse_iso_duration_hours("P7D"), Some(168));
        assert_eq!(parse_iso_duration_hours("P1D"), Some(24));
    }

    #[test]
    fn parse_iso_duration_p_hours_loose() {
        // Less-canonical `P{h}H` (no T separator) — accept
        // because seen in the wild from older CLIs.
        assert_eq!(parse_iso_duration_hours("P24H"), Some(24));
    }

    #[test]
    fn parse_iso_duration_unsupported_shapes_return_none() {
        assert_eq!(parse_iso_duration_hours("P1Y"), None);
        assert_eq!(parse_iso_duration_hours("P1W"), None);
        assert_eq!(parse_iso_duration_hours("PT1H30M"), None);
        assert_eq!(parse_iso_duration_hours("not-iso"), None);
        assert_eq!(parse_iso_duration_hours(""), None);
    }

    #[test]
    fn revoked_reason_extraction_handles_string_value() {
        let r = revoked_reason_from_audit_reason(Some(
            r#"{"action_id": 5, "revoked_reason": "appeal granted"}"#,
        ));
        assert_eq!(r.as_deref(), Some("appeal granted"));
    }

    #[test]
    fn revoked_reason_extraction_handles_null_value() {
        let r =
            revoked_reason_from_audit_reason(Some(r#"{"action_id": 5, "revoked_reason": null}"#));
        assert_eq!(r, None);
    }

    #[test]
    fn revoked_reason_extraction_handles_missing_field() {
        let r = revoked_reason_from_audit_reason(Some(r#"{"action_id": 5}"#));
        assert_eq!(r, None);
    }

    #[test]
    fn revoked_reason_extraction_handles_malformed_json() {
        assert_eq!(revoked_reason_from_audit_reason(Some("not json")), None);
        assert_eq!(revoked_reason_from_audit_reason(None), None);
    }
}
