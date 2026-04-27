//! `tools.cairn.admin.getSubjectStrikes` handler (#52 / read-half
//! of #53).
//!
//! Loads the subject's full `subject_actions` history and runs the
//! v1.4 decay calculator (#50) over it, returning the resolved
//! [`SubjectStrikeStateOut`] envelope. Mod or Admin role.
//!
//! The cache table (`subject_strike_state`) is intentionally
//! bypassed: the response is always recomputed from source-of-
//! truth so a stale cache row can never produce a misleading read.
//! Cache invalidation / freshness check is #55's concern; for this
//! endpoint the only way to be wrong is to be wrong about the
//! actions.
//!
//! `decayWindowRemainingDays` is the operator-friendly "returns to
//! good standing in N days at current trajectory" surface. Computed
//! as `max(0, decay_window_days - days_since_last_strike_action)`.
//! Omitted when `currentStrikeCount == 0` (nothing to decay).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Extension;
use axum::Json;
use axum::extract::RawQuery;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::moderation::decay::{ActiveSuspension, calculate_strike_state};
use crate::moderation::types::{ActionRecord, ActionType};
use crate::writer::rfc3339_from_epoch_ms;

use super::common::{AdminError, AdminState, verify_and_authorize};
use super::subject_action_view::subject_has_history;

const LXM: &str = "tools.cairn.admin.getSubjectStrikes";

#[derive(Debug, Serialize)]
struct ActiveSuspensionOut {
    #[serde(rename = "actionType")]
    action_type: String,
    #[serde(rename = "effectiveAt")]
    effective_at: String,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubjectStrikeStateOut {
    #[serde(rename = "currentStrikeCount")]
    current_strike_count: u32,
    #[serde(rename = "rawTotal")]
    raw_total: u32,
    #[serde(rename = "decayedCount")]
    decayed_count: u32,
    #[serde(rename = "revokedCount")]
    revoked_count: u32,
    #[serde(rename = "goodStanding")]
    good_standing: bool,
    #[serde(rename = "activeSuspension", skip_serializing_if = "Option::is_none")]
    active_suspension: Option<ActiveSuspensionOut>,
    #[serde(
        rename = "decayWindowRemainingDays",
        skip_serializing_if = "Option::is_none"
    )]
    decay_window_remaining_days: Option<u32>,
    #[serde(rename = "lastActionAt", skip_serializing_if = "Option::is_none")]
    last_action_at: Option<String>,
}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(e) = verify_and_authorize(&state, &headers, LXM).await {
        return e.into_response();
    }

    let subject = match parse_subject(query.as_deref().unwrap_or("")) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    match subject_has_history(&state.pool, &subject).await {
        Ok(true) => {}
        Ok(false) => return AdminError::SubjectNotFound.into_response(),
        Err(_) => return AdminError::Internal.into_response(),
    }

    let history = match load_history(&state.pool, &subject).await {
        Ok(h) => h,
        Err(_) => return AdminError::Internal.into_response(),
    };

    // Always recompute from source-of-truth — see module docs.
    let now = SystemTime::now();
    let st = calculate_strike_state(&history, &state.strike_policy, now);

    // decay_window_remaining_days: only meaningful when there's
    // anything left to decay. Compute from the most recent
    // unrevoked strike-bearing action's effective_at.
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
            let window = state.strike_policy.decay_window_days as u64;
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
        .transpose();
    let active_suspension = match active_suspension {
        Ok(o) => o,
        Err(_) => return AdminError::Internal.into_response(),
    };

    Json(SubjectStrikeStateOut {
        current_strike_count: st.current_count,
        raw_total: st.raw_total,
        decayed_count: st.decayed_count,
        revoked_count: st.revoked_count,
        good_standing: st.good_standing,
        active_suspension,
        decay_window_remaining_days,
        last_action_at: last_action_at_rfc,
    })
    .into_response()
}

fn parse_subject(raw: &str) -> Result<String, AdminError> {
    let mut subject: Option<String> = None;
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        if k == "subject" && !v.is_empty() {
            subject = Some(v.into_owned());
        }
    }
    let subject = subject.ok_or(AdminError::InvalidRequest("subject is required"))?;
    if !subject.starts_with("did:") {
        return Err(AdminError::InvalidRequest("subject must be a DID"));
    }
    Ok(subject)
}

/// Project an [`ActiveSuspension`] (decay-calculator output) into
/// the wire shape declared in defs.json#activeSuspension. action_type
/// goes through the ActionType DB-string form so the wire matches
/// the `subject_actions.action_type` SQL CHECK enum.
fn project_active_suspension(s: &ActiveSuspension) -> Result<ActiveSuspensionOut, ()> {
    let effective_at = systemtime_to_rfc3339(s.effective_at).map_err(|_| ())?;
    let expires_at = match s.expires_at {
        None => None,
        Some(t) => Some(systemtime_to_rfc3339(t).map_err(|_| ())?),
    };
    Ok(ActiveSuspensionOut {
        action_type: s.action_type.as_db_str().to_string(),
        effective_at,
        expires_at,
    })
}

/// Load the subject's full action history into the v1.4
/// calculators' [`ActionRecord`] projection. Same shape as the
/// recorder's `load_subject_actions_for_calc` helper, but as a
/// pool-direct query (no transaction).
async fn load_history(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    subject_did: &str,
) -> crate::error::Result<Vec<ActionRecord>> {
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
            crate::error::Error::Signing(format!(
                "subject_actions row has invalid action_type {:?}",
                r.action_type
            ))
        })?;
        let strike_value_applied = u32::try_from(r.strike_value_applied).map_err(|_| {
            crate::error::Error::Signing(format!(
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

fn epoch_ms_to_systemtime(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH
    }
}

fn systemtime_to_rfc3339(t: SystemTime) -> crate::error::Result<String> {
    let ms: i64 = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(0);
    rfc3339_from_epoch_ms(ms)
}
