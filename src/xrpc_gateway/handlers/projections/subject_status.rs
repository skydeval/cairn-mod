//! Projection: cairn-mod state → Ozone `subjectStatusView` (#97).
//!
//! Folds the action history (subject_actions log) for a single
//! subject into a *current state* view matching Ozone's
//! `tools.ozone.moderation.defs#subjectStatusView` shape.
//!
//! # Field-by-field projection (v1.7)
//!
//! | Ozone field        | cairn-mod source                                  | Notes                                                                                                                                          |
//! |--------------------|---------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
//! | `id`               | `subject_actions.id` of the most-recent action    | cairn-mod has no "status row" concept; the most-recent action's id is a stable per-subject identifier within a single deployment.              |
//! | `subject`          | `subject_did` + optional `subject_uri`            | `repoRef` for account-level (subject_uri NULL); `strongRef` for record-level (subject_uri populated, cid omitted — cairn-mod doesn't store CIDs on actions). |
//! | `subjectBlobCids`  | not tracked                                       | Always empty `[]` (omitted via `skip_serializing_if`).                                                                                         |
//! | `updatedAt`        | most-recent action's `created_at`                 | Epoch-ms → RFC-3339 Z.                                                                                                                         |
//! | `createdAt`        | earliest action's `created_at`                    | Epoch-ms → RFC-3339 Z.                                                                                                                         |
//! | `reviewState`      | constant `#reviewClosed`                          | cairn-mod has no review-state lifecycle; emitting `#reviewClosed` matches Ozone's "the moderator has acted" semantic for any subject_actions row that exists. |
//! | `comment`          | most-recent action's `notes`                      | `None` if no notes; the lexicon allows omitting.                                                                                               |
//! | `lastReviewedBy`   | most-recent action's `actor_did`                  | DID (always present — `subject_actions.actor_did NOT NULL`).                                                                                   |
//! | `lastReviewedAt`   | most-recent action's `created_at`                 | Same value as `updatedAt` for v1.7.                                                                                                            |
//! | `lastReportedAt`   | `MAX(reports.created_at)` for this subject        | RFC-3339 already (the reports table stores it as TEXT). `None` if no reports.                                                                  |
//! | `takendown`        | `EXISTS unrevoked takedown action_type`           | True iff any `action_type='takedown'` row has `revoked_at IS NULL`. Note: cairn-mod does NOT have a `reverse_takedown` action_type — revocation sets `revoked_at` on the original row. |
//! | `appealed`         | constant `false`                                  | cairn-mod has no appeal flow in v1.7.                                                                                                          |
//! | `tags`             | active label vals from `labels` table             | Distinct `val` strings where `(src=service_did, uri=subject)` and the most-recent row per `(src, uri, val)` has `neg=0`. Same active-label semantic as `crate::server::strike_state::load_active_labels`. |
//!
//! All projections are pure functions. The handler does the IO
//! (subject_actions + labels + reports SELECTs) and hands the rows
//! here for translation.

use serde_json::{Value, json};

/// Lexicon `$type` for the only review-state value v1.7 emits.
/// Matches Ozone's
/// `tools.ozone.moderation.defs#reviewClosed` — "moderator action
/// taken" is the closest analogue cairn-mod has, since every row
/// in `subject_actions` is by definition a moderator (or
/// policy-automation-as-moderator) decision.
pub const REVIEW_STATE_CLOSED: &str = "tools.ozone.moderation.defs#reviewClosed";

/// Lexicon discriminator for an account-level subject reference.
const SUBJECT_TYPE_REPO_REF: &str = "com.atproto.admin.defs#repoRef";

/// Lexicon discriminator for a record-level subject reference.
const SUBJECT_TYPE_STRONG_REF: &str = "com.atproto.repo.strongRef";

/// One row from `subject_actions`, in the projected shape the
/// projection logic needs. The handler-side SQL adapts the table
/// columns into this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectActionRow {
    /// `subject_actions.id`.
    pub id: i64,
    /// `subject_actions.action_type` — one of cairn-mod's five
    /// action types ("warning", "note", "temp_suspension",
    /// "indef_suspension", "takedown").
    pub action_type: String,
    /// `subject_actions.actor_did`.
    pub actor_did: String,
    /// `subject_actions.notes`.
    pub notes: Option<String>,
    /// `subject_actions.revoked_at` (epoch-ms). `None` means the
    /// action is still active.
    pub revoked_at: Option<i64>,
    /// `subject_actions.created_at` (epoch-ms internal wall-clock).
    pub created_at: i64,
}

/// Result of projecting a subject's full state. Field names mirror
/// Ozone's `subjectStatusView`; the handler maps these into the
/// outer wire struct via [`crate::xrpc_gateway::handlers::query_statuses::SubjectStatusView`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedSubjectStatus {
    /// Stable per-subject identifier (most-recent action's id).
    pub id: i64,
    /// Discriminated subject value (`repoRef` or `strongRef`).
    pub subject: Value,
    /// Earliest action's `created_at` (epoch-ms internal wall-clock).
    pub created_at: i64,
    /// Most-recent action's `created_at` (epoch-ms internal wall-clock).
    pub updated_at: i64,
    /// Always [`REVIEW_STATE_CLOSED`] in v1.7.
    pub review_state: String,
    /// Most-recent action's `notes`, if any.
    pub comment: Option<String>,
    /// Most-recent action's `actor_did`.
    pub last_reviewed_by: Option<String>,
    /// Most-recent action's `created_at` (epoch-ms).
    pub last_reviewed_at: Option<i64>,
    /// `MAX(reports.created_at)` for the subject, RFC-3339 (the
    /// `reports` table stores `created_at` as TEXT already).
    pub last_reported_at: Option<String>,
    /// Currently-takendown flag — see [`folded_takedown_state`].
    pub takendown: bool,
    /// Always `false` in v1.7 (no appeal flow).
    pub appealed: bool,
    /// Active label vals for the subject.
    pub tags: Vec<String>,
}

/// Build the discriminated subject value for the wire shape.
/// Account-level subjects get `repoRef`; record-level get
/// `strongRef`. cairn-mod doesn't store CIDs on `subject_actions`,
/// so the `cid` field of `strongRef` is omitted — Ozone's lexicon
/// requires it on `strongRef`, but emitting an empty string would
/// be worse than omission. Document and accept the lexicon
/// non-conformance for record-level subjects until cairn-mod
/// tracks CIDs (deferred to a future cycle).
pub fn project_subject(subject_did: &str, subject_uri: Option<&str>) -> Value {
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

/// Fold an action history into "is this subject currently taken
/// down?" — true iff any action_type='takedown' row has
/// `revoked_at IS NULL`.
///
/// Note that cairn-mod does NOT have a `reverse_takedown`
/// action_type. Revocation sets `revoked_at` on the original row;
/// the no-update trigger blocks all column changes EXCEPT the
/// one-time NULL → non-NULL transition on the revocation columns.
/// So "currently taken down" is a row-level test, not a
/// max-id-comparison fold.
pub fn folded_takedown_state(actions: &[SubjectActionRow]) -> bool {
    actions
        .iter()
        .any(|a| a.action_type == "takedown" && a.revoked_at.is_none())
}

/// The most-recent action by id (largest id wins; subject_actions
/// id is a monotonic AUTOINCREMENT). Returns `None` only when
/// `actions` is empty.
pub fn most_recent_action(actions: &[SubjectActionRow]) -> Option<&SubjectActionRow> {
    actions.iter().max_by_key(|a| a.id)
}

/// The earliest action by id. Returns `None` only when `actions`
/// is empty.
pub fn earliest_action(actions: &[SubjectActionRow]) -> Option<&SubjectActionRow> {
    actions.iter().min_by_key(|a| a.id)
}

/// Pick the comment to surface on the status view. v1.7 chooses
/// the most-recent action's `notes` over reason_codes because
/// notes is operator-authored prose and is closer to what Ozone
/// clients display (Ozone's `comment` field is free-form).
pub fn project_comment(actions: &[SubjectActionRow]) -> Option<String> {
    most_recent_action(actions).and_then(|a| a.notes.clone())
}

/// Build the full [`ProjectedSubjectStatus`] from already-loaded
/// rows.
///
/// Pre-conditions:
/// - `actions` is non-empty (the handler filters empty-history
///   subjects out before calling this — there's no status to
///   surface for a subject with no recorded actions).
/// - `tags` is the result of the active-labels query for this
///   subject (already filtered to `neg=0` most-recent-per-(uri,val)).
/// - `last_reported_at` is the result of the reports lookup for
///   this subject (already RFC-3339 since `reports.created_at`
///   is TEXT).
pub fn project_subject_status(
    subject_did: &str,
    subject_uri: Option<&str>,
    actions: &[SubjectActionRow],
    tags: Vec<String>,
    last_reported_at: Option<String>,
) -> ProjectedSubjectStatus {
    debug_assert!(!actions.is_empty(), "caller filters empty histories");
    let most_recent = most_recent_action(actions).expect("actions non-empty per pre-cond");
    let earliest = earliest_action(actions).expect("actions non-empty per pre-cond");
    ProjectedSubjectStatus {
        id: most_recent.id,
        subject: project_subject(subject_did, subject_uri),
        created_at: earliest.created_at,
        updated_at: most_recent.created_at,
        review_state: REVIEW_STATE_CLOSED.to_string(),
        comment: project_comment(actions),
        last_reviewed_by: Some(most_recent.actor_did.clone()),
        last_reviewed_at: Some(most_recent.created_at),
        last_reported_at,
        takendown: folded_takedown_state(actions),
        appealed: false,
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(
        id: i64,
        action_type: &str,
        revoked_at: Option<i64>,
        created_at: i64,
    ) -> SubjectActionRow {
        SubjectActionRow {
            id,
            action_type: action_type.into(),
            actor_did: "did:plc:moderator".into(),
            notes: None,
            revoked_at,
            created_at,
        }
    }

    fn action_with(
        id: i64,
        action_type: &str,
        revoked_at: Option<i64>,
        created_at: i64,
        notes: Option<&str>,
        actor: &str,
    ) -> SubjectActionRow {
        SubjectActionRow {
            id,
            action_type: action_type.into(),
            actor_did: actor.into(),
            notes: notes.map(String::from),
            revoked_at,
            created_at,
        }
    }

    // ===== folded_takedown_state =====

    #[test]
    fn empty_history_is_not_takendown() {
        assert!(!folded_takedown_state(&[]));
    }

    #[test]
    fn warning_only_history_is_not_takendown() {
        let h = vec![action(1, "warning", None, 100)];
        assert!(!folded_takedown_state(&h));
    }

    #[test]
    fn unrevoked_takedown_is_takendown() {
        let h = vec![action(1, "takedown", None, 100)];
        assert!(folded_takedown_state(&h));
    }

    #[test]
    fn revoked_takedown_is_not_takendown() {
        let h = vec![action(1, "takedown", Some(200), 100)];
        assert!(!folded_takedown_state(&h));
    }

    #[test]
    fn second_takedown_after_revoked_first_is_takendown() {
        // cairn-mod doesn't have reverse_takedown — revocation
        // sets revoked_at. A subsequent fresh takedown is a new
        // row with revoked_at=NULL.
        let h = vec![
            action(1, "takedown", Some(200), 100),
            action(2, "takedown", None, 300),
        ];
        assert!(folded_takedown_state(&h));
    }

    #[test]
    fn takedown_among_other_actions_dominates() {
        let h = vec![
            action(1, "warning", None, 100),
            action(2, "takedown", None, 200),
            action(3, "note", None, 300),
        ];
        assert!(folded_takedown_state(&h));
    }

    #[test]
    fn temp_suspension_is_not_takendown() {
        // takendown is takedown-specific; temp_suspension /
        // indef_suspension don't satisfy it.
        let h = vec![action(1, "temp_suspension", None, 100)];
        assert!(!folded_takedown_state(&h));
    }

    // ===== most_recent / earliest =====

    #[test]
    fn most_recent_picks_largest_id() {
        let h = vec![
            action(5, "warning", None, 100),
            action(2, "note", None, 50),
            action(8, "takedown", None, 200),
        ];
        let r = most_recent_action(&h).unwrap();
        assert_eq!(r.id, 8);
    }

    #[test]
    fn earliest_picks_smallest_id() {
        let h = vec![
            action(5, "warning", None, 100),
            action(2, "note", None, 50),
            action(8, "takedown", None, 200),
        ];
        let r = earliest_action(&h).unwrap();
        assert_eq!(r.id, 2);
    }

    #[test]
    fn most_recent_on_empty_is_none() {
        assert!(most_recent_action(&[]).is_none());
    }

    // ===== project_subject =====

    #[test]
    fn project_subject_account_is_repo_ref() {
        let v = project_subject("did:plc:abc", None);
        assert_eq!(v["$type"].as_str(), Some("com.atproto.admin.defs#repoRef"));
        assert_eq!(v["did"].as_str(), Some("did:plc:abc"));
        assert!(v.get("uri").is_none());
    }

    #[test]
    fn project_subject_record_is_strong_ref() {
        let v = project_subject("did:plc:abc", Some("at://did:plc:abc/app.bsky.feed.post/x"));
        assert_eq!(v["$type"].as_str(), Some("com.atproto.repo.strongRef"));
        assert_eq!(
            v["uri"].as_str(),
            Some("at://did:plc:abc/app.bsky.feed.post/x")
        );
        // CID omitted — cairn-mod doesn't store action-time CIDs.
        assert!(v.get("cid").is_none());
    }

    // ===== project_comment =====

    #[test]
    fn project_comment_picks_most_recent_notes() {
        let h = vec![
            action_with(1, "warning", None, 100, Some("first"), "did:plc:m"),
            action_with(3, "takedown", None, 300, Some("third"), "did:plc:m"),
            action_with(2, "note", None, 200, Some("second"), "did:plc:m"),
        ];
        assert_eq!(project_comment(&h).as_deref(), Some("third"));
    }

    #[test]
    fn project_comment_when_most_recent_has_no_notes_is_none() {
        let h = vec![
            action_with(1, "warning", None, 100, Some("first"), "did:plc:m"),
            action_with(2, "takedown", None, 200, None, "did:plc:m"),
        ];
        assert_eq!(project_comment(&h), None);
    }

    // ===== project_subject_status =====

    #[test]
    fn project_full_status_for_account_with_history() {
        let h = vec![
            action_with(1, "warning", None, 100, Some("warned"), "did:plc:m1"),
            action_with(3, "takedown", None, 300, Some("banned"), "did:plc:m2"),
            action_with(2, "note", None, 200, Some("logged"), "did:plc:m1"),
        ];
        let projected = project_subject_status(
            "did:plc:target",
            None,
            &h,
            vec!["spam".into(), "harassment".into()],
            Some("2026-04-29T12:00:00.000Z".into()),
        );
        assert_eq!(projected.id, 3);
        assert_eq!(
            projected.subject["$type"].as_str(),
            Some("com.atproto.admin.defs#repoRef")
        );
        assert_eq!(projected.subject["did"].as_str(), Some("did:plc:target"));
        assert_eq!(projected.created_at, 100);
        assert_eq!(projected.updated_at, 300);
        assert_eq!(projected.review_state, REVIEW_STATE_CLOSED);
        assert_eq!(projected.comment.as_deref(), Some("banned"));
        assert_eq!(projected.last_reviewed_by.as_deref(), Some("did:plc:m2"));
        assert_eq!(projected.last_reviewed_at, Some(300));
        assert_eq!(
            projected.last_reported_at.as_deref(),
            Some("2026-04-29T12:00:00.000Z")
        );
        assert!(projected.takendown);
        assert!(!projected.appealed);
        assert_eq!(projected.tags, vec!["spam", "harassment"]);
    }

    #[test]
    fn project_full_status_for_revoked_takedown_is_not_takendown() {
        let h = vec![action_with(
            1,
            "takedown",
            Some(200),
            100,
            Some("revoked"),
            "did:plc:m",
        )];
        let projected = project_subject_status("did:plc:target", None, &h, vec![], None);
        assert!(!projected.takendown);
    }

    #[test]
    fn project_full_status_record_level_uses_strong_ref() {
        let h = vec![action_with(1, "note", None, 100, None, "did:plc:m")];
        let uri = "at://did:plc:author/app.bsky.feed.post/x";
        let projected = project_subject_status("did:plc:author", Some(uri), &h, vec![], None);
        assert_eq!(
            projected.subject["$type"].as_str(),
            Some("com.atproto.repo.strongRef")
        );
        assert_eq!(projected.subject["uri"].as_str(), Some(uri));
    }
}
