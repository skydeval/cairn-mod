//! Shared subject-strike-state surface used by both
//! `tools.cairn.admin.getSubjectStrikes` (#52) and
//! `tools.cairn.public.getMyStrikeState` (#54).
//!
//! Both endpoints return the same wire shape — admin/public differ
//! at the auth layer, not the data layer. Centralizing the
//! projection here means the two endpoints can never drift on
//! field shape, and the cache-bypass invariant
//! ("always recomputed from source-of-truth") is enforced once for
//! all callers.
//!
//! The `subject_strike_state` SQLite cache table is intentionally
//! NOT consulted — see [`build_strike_state_view`]. Cache freshness
//! is #55's concern.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::moderation::decay::{ActiveSuspension, calculate_strike_state};
use crate::moderation::policy::StrikePolicy;
use crate::moderation::types::{ActionRecord, ActionType};
use crate::writer::rfc3339_from_epoch_ms;

/// Wire shape declared in
/// `lexicons/tools/cairn/admin/defs.json#subjectStrikeState`.
/// Optional fields use `skip_serializing_if` so absent maps to JSON-
/// key-omit, matching the §F11 anti-leak posture.
#[derive(Debug, Serialize)]
pub(crate) struct SubjectStrikeStateOut {
    /// Active strike total after decay and revocation.
    #[serde(rename = "currentStrikeCount")]
    pub current_strike_count: u32,
    /// Lifetime sum of strike_value_applied (ignores decay + revoke).
    #[serde(rename = "rawTotal")]
    pub raw_total: u32,
    /// Strikes lost to decay across unrevoked actions.
    #[serde(rename = "decayedCount")]
    pub decayed_count: u32,
    /// Strikes from revoked actions.
    #[serde(rename = "revokedCount")]
    pub revoked_count: u32,
    /// `true` iff currentStrikeCount <= policy.good_standing_threshold.
    #[serde(rename = "goodStanding")]
    pub good_standing: bool,
    /// Currently-active suspension if any.
    #[serde(rename = "activeSuspension", skip_serializing_if = "Option::is_none")]
    pub active_suspension: Option<ActiveSuspensionOut>,
    /// Days until the most recent strike-bearing action falls out
    /// of the decay window. Omitted when `currentStrikeCount == 0`.
    #[serde(
        rename = "decayWindowRemainingDays",
        skip_serializing_if = "Option::is_none"
    )]
    pub decay_window_remaining_days: Option<u32>,
    /// RFC-3339 effective_at of the most recent strike-bearing
    /// unrevoked action; absent if none.
    #[serde(rename = "lastActionAt", skip_serializing_if = "Option::is_none")]
    pub last_action_at: Option<String>,
    /// ATProto labels cairn-mod is currently emitting against this
    /// subject. One entry per non-revoked action that emitted
    /// labels and whose action label's most recent record is
    /// non-negated. Empty array when nothing is active.
    #[serde(rename = "activeLabels")]
    pub active_labels: Vec<ActiveLabelOut>,
}

/// Per-action active-label entry. Action-centric grouping: one
/// entry per active action carrying the action label's `val` plus
/// the reason codes that produced its reason labels. See
/// `lexicons/tools/cairn/admin/defs.json#activeLabel` for the
/// wire schema.
#[derive(Debug, Serialize)]
pub(crate) struct ActiveLabelOut {
    /// Action label `val` (e.g., `!takedown`).
    pub val: String,
    /// `subject_actions.id` of the source action.
    #[serde(rename = "actionId")]
    pub action_id: i64,
    /// Reason codes whose reason-labels were emitted alongside the
    /// action label. Always present (may be empty).
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    /// RFC-3339 expiry of the action's emitted labels; absent for
    /// non-temp_suspension actions.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Wire shape declared in
/// `lexicons/tools/cairn/admin/defs.json#activeSuspension`. Surfaced
/// on [`SubjectStrikeStateOut::active_suspension`].
#[derive(Debug, Serialize)]
pub(crate) struct ActiveSuspensionOut {
    /// `temp_suspension` or `indef_suspension`.
    #[serde(rename = "actionType")]
    pub action_type: String,
    /// RFC-3339 wall-clock the suspension took effect.
    #[serde(rename = "effectiveAt")]
    pub effective_at: String,
    /// RFC-3339 wall-clock the suspension ends; absent for indef.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Whether any `subject_actions` row exists for this DID. Used by
/// the read endpoints to surface SubjectNotFound (404) when the
/// subject has never been actioned, distinct from "actioned but
/// filtered to empty" (which returns 200 with an empty array).
///
/// The partial index `subject_actions_subject_idx` makes this
/// O(1) on the typical SELECT.
pub(crate) async fn subject_has_history(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    subject_did: &str,
) -> Result<bool> {
    let row = sqlx::query!(
        r#"SELECT EXISTS(SELECT 1 FROM subject_actions WHERE subject_did = ?1) AS "exists!: i64""#,
        subject_did,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.exists != 0)
}

/// Load the subject's full action history into the v1.4
/// calculators' [`ActionRecord`] projection. Pool-direct query
/// (no transaction) — both read endpoints operate outside the
/// writer task's transaction context.
pub(crate) async fn load_action_history(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    subject_did: &str,
) -> Result<Vec<ActionRecord>> {
    let rows = sqlx::query!(
        "SELECT action_type, strike_value_applied, was_dampened,
                effective_at, expires_at, revoked_at
         FROM subject_actions
         WHERE subject_did = ?1
         ORDER BY id ASC",
        subject_did,
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let action_type = ActionType::from_db_str(&r.action_type).ok_or_else(|| {
            Error::Signing(format!(
                "subject_actions row has invalid action_type {:?}",
                r.action_type
            ))
        })?;
        let strike_value_applied = u32::try_from(r.strike_value_applied).map_err(|_| {
            Error::Signing(format!(
                "subject_actions strike_value_applied {} out of u32 range",
                r.strike_value_applied
            ))
        })?;
        out.push(ActionRecord {
            strike_value_applied,
            effective_at: epoch_ms_to_systemtime(r.effective_at),
            revoked_at: r.revoked_at.map(epoch_ms_to_systemtime),
            action_type,
            expires_at: r.expires_at.map(epoch_ms_to_systemtime),
            was_dampened: r.was_dampened != 0,
        });
    }
    Ok(out)
}

/// Compute and project the subject's currently-active strike state.
/// Caller is responsible for verifying existence first via
/// [`subject_has_history`] — this function returns the projected
/// state for whatever the DB currently says, including an
/// all-zeros result for a subject with no rows.
///
/// **Cache bypass invariant**: this function reads only
/// `subject_actions` and re-runs the decay calculator (#50). The
/// `subject_strike_state` cache table is NOT consulted, so a stale
/// cache row can never produce a misleading read. The `labels`
/// table consulted by [`load_active_labels`] is the authoritative
/// source for emitted-label state — no cache lives in front of it
/// either.
///
/// `service_did` is cairn-mod's labeler DID; used to scope the
/// `labels.src` filter when computing `active_labels` (each
/// labeler may have signed its own records against the same
/// subject).
pub(crate) async fn build_strike_state_view(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    subject_did: &str,
    service_did: &str,
    policy: &StrikePolicy,
    now: SystemTime,
) -> Result<SubjectStrikeStateOut> {
    let history = load_action_history(pool, subject_did).await?;
    let st = calculate_strike_state(&history, policy, now);

    // last_action_at: most recent unrevoked strike-bearing
    // action's effective_at. Drives both the lastActionAt field
    // and the decayWindowRemainingDays computation below.
    let last_action_at = history
        .iter()
        .rev()
        .find(|a| a.action_type.contributes_strikes() && a.revoked_at.is_none())
        .map(|a| a.effective_at);

    let decay_window_remaining_days: Option<u32> = if st.current_count == 0 {
        None
    } else {
        last_action_at.map(|t| {
            let elapsed_days = now.duration_since(t).unwrap_or(Duration::ZERO).as_secs() / 86_400;
            let window = policy.decay_window_days as u64;
            window.saturating_sub(elapsed_days) as u32
        })
    };

    let last_action_at_rfc = last_action_at
        .map(systemtime_to_rfc3339)
        .transpose()
        .unwrap_or(None);

    let active_suspension = st
        .active_suspension
        .as_ref()
        .map(project_active_suspension)
        .transpose()?;

    let active_labels = load_active_labels(pool, subject_did, service_did).await?;

    Ok(SubjectStrikeStateOut {
        current_strike_count: st.current_count,
        raw_total: st.raw_total,
        decayed_count: st.decayed_count,
        revoked_count: st.revoked_count,
        good_standing: st.good_standing,
        active_suspension,
        decay_window_remaining_days,
        last_action_at: last_action_at_rfc,
        active_labels,
    })
}

/// Compute the subject's currently-active labels (#65, v1.5).
/// Walks `subject_actions` for non-revoked rows that emitted an
/// action label, then for each one verifies the most recent
/// `labels` record for `(src=service_did, uri=subject, val=...)`
/// is non-negated. A negation supersedes the original on the
/// wire; cairn-mod's read endpoints reflect that supersession.
///
/// `expiresAt`-passed labels are still INCLUDED in the result —
/// exp-based visibility is the consumer AppView's responsibility,
/// and cairn-mod surfaces what it has emitted regardless. Clients
/// that want a strictly-honored-now view filter on `expiresAt` <
/// `now` themselves.
///
/// Order: most-recent-action first (descending by
/// `subject_actions.id`). Stable for clients that want the
/// "what's affecting me now" UX without their own sort.
pub(crate) async fn load_active_labels(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    subject_did: &str,
    service_did: &str,
) -> Result<Vec<ActiveLabelOut>> {
    // Candidate actions: non-revoked, emitted an action label.
    let actions = sqlx::query!(
        r#"SELECT
             id              AS "id!: i64",
             subject_uri,
             expires_at,
             reason_codes    AS "reason_codes!: String",
             emitted_label_uri AS "emitted_label_uri!: String"
           FROM subject_actions
           WHERE subject_did = ?1
             AND revoked_at IS NULL
             AND emitted_label_uri IS NOT NULL
           ORDER BY id DESC"#,
        subject_did,
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(actions.len());
    for a in actions {
        let label_uri = a
            .subject_uri
            .clone()
            .unwrap_or_else(|| subject_did.to_string());

        // Most recent labels-table record for the (src, uri, val)
        // tuple. If neg=true, the negation supersedes (per ATProto
        // and per #62's revocation flow); skip the action.
        let latest = sqlx::query_scalar!(
            r#"SELECT neg AS "neg!: i64"
               FROM labels
               WHERE src = ?1 AND uri = ?2 AND val = ?3
               ORDER BY seq DESC
               LIMIT 1"#,
            service_did,
            label_uri,
            a.emitted_label_uri,
        )
        .fetch_optional(pool)
        .await?;
        match latest {
            Some(neg) if neg != 0 => continue, // negated → not active
            None => continue, // no label record at all (defensive — shouldn't happen if emitted_label_uri is set)
            _ => {}
        }

        // reason_codes column stores the input JSON array
        // (preserving the moderator's original ordering); reuse
        // it directly so the surface mirrors what was recorded.
        // subject_action_reason_labels is the linkage source of
        // truth for what was *emitted*, but in v1.5 the two are
        // identical when emit_reason_labels = true at recording
        // time. When false, we want the linkage rows (which will
        // be empty) — query that table to be precise.
        let reason_codes: Vec<String> = sqlx::query_scalar!(
            "SELECT reason_code FROM subject_action_reason_labels
             WHERE action_id = ?1
             ORDER BY reason_code ASC",
            a.id,
        )
        .fetch_all(pool)
        .await?;

        // a.reason_codes is also captured for forensic display;
        // unused in this projection (we surface the linkage rows
        // since they reflect actual emission state). Suppress
        // the unused-binding warning explicitly.
        let _ = a.reason_codes;

        let expires_at = match a.expires_at {
            Some(ms) => Some(rfc3339_from_epoch_ms(ms)?),
            None => None,
        };

        out.push(ActiveLabelOut {
            val: a.emitted_label_uri,
            action_id: a.id,
            reason_codes,
            expires_at,
        });
    }
    Ok(out)
}

/// Project an [`ActiveSuspension`] (decay-calculator output) into
/// the wire shape declared in `defs.json#activeSuspension`.
fn project_active_suspension(s: &ActiveSuspension) -> Result<ActiveSuspensionOut> {
    let effective_at = systemtime_to_rfc3339(s.effective_at)?;
    let expires_at = s.expires_at.map(systemtime_to_rfc3339).transpose()?;
    Ok(ActiveSuspensionOut {
        action_type: s.action_type.as_db_str().to_string(),
        effective_at,
        expires_at,
    })
}

fn epoch_ms_to_systemtime(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH
    }
}

fn systemtime_to_rfc3339(t: SystemTime) -> Result<String> {
    let ms: i64 = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(0);
    rfc3339_from_epoch_ms(ms)
}
