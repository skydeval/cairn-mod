//! Subject-strike-state cache management (#55).
//!
//! The cache (`subject_strike_state` SQLite table) is populated by
//! the recorder (#51) on every `recordAction` / `revokeAction`. It
//! holds `(subject_did → current_strike_count, last_action_at,
//! last_recompute_at)`.
//!
//! Two roles in v1.4:
//!
//! - **Write-through** (already shipped in #51): every action
//!   recorder + revoker writes the cache in the same transaction
//!   as the underlying `subject_actions` mutation, so the cache
//!   stays in sync with the action stream up to whatever decay has
//!   accumulated since the last touch.
//! - **Lazy recompute-on-read** (this module): a v1.5+ consumer
//!   that wants O(1) "is this user past threshold right now?"
//!   without a full history walk can call
//!   [`get_or_recompute_strike_count`] — fresh cache returns
//!   immediately; stale cache triggers a recompute via the decay
//!   calculator (#50) and a write-back.
//!
//! v1.4 has zero in-tree consumers of [`get_or_recompute_strike_count`].
//! The function ships ahead of v1.5's auto-action-threshold-check
//! consumer; landing it now keeps cache invariants paired with
//! their write path (#51) instead of split across releases.
//!
//! # Cache-bypass invariant on read endpoints
//!
//! `tools.cairn.admin.getSubjectStrikes` (#52) and
//! `tools.cairn.public.getMyStrikeState` (#54) intentionally DO
//! NOT consult the cache. They always recompute from
//! `subject_actions` via `crate::server::strike_state::build_strike_state_view`
//! (private to the server module). That invariant is preserved
//! through this module — adding cache management does not change
//! the read-side correctness story.
//!
//! # Freshness semantics
//!
//! The cache is fresh when `now - last_recompute_at <
//! policy.cache_freshness_window_seconds`. Strict less-than:
//! exact-boundary equality counts as stale. Clock-skew
//! (`last_recompute_at` in the future relative to `now`) is also
//! treated as stale — that state is either bug-induced or the
//! result of an out-of-band clock jump, and the safe answer in
//! both cases is "recompute."
//!
//! # Missing-cache stance
//!
//! [`get_or_recompute_strike_count`] returns
//! [`Error::StrikeCacheMissing`] when the subject_did has no cache
//! row. Same semantic as the read endpoints' `SubjectNotFound`:
//! "no actions have ever been recorded against this subject." v1.5
//! consumers that want optimistic "never-actioned == 0 strikes"
//! semantics can wrap with `unwrap_or(0)` or branch on the typed
//! error; the typed branching is friendlier than a magic-zero
//! return.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::{Pool, Sqlite};

use crate::error::{Error, Result};
use crate::moderation::decay::calculate_strike_state;
use crate::moderation::policy::StrikePolicy;
use crate::server::strike_state::load_action_history;

/// Read-side projection of one `subject_strike_state` row. Stored
/// timestamps are epoch-ms `i64`; this struct holds the
/// [`SystemTime`] equivalents so the freshness check works in
/// `Duration` arithmetic without callers re-doing the conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectStrikeStateCache {
    /// Account DID this row attributes to (PK).
    pub subject_did: String,
    /// Cached active strike count. Authoritative-as-of
    /// `last_recompute_at`; drifts with time as decay accumulates.
    pub current_strike_count: u32,
    /// Effective_at of the most recent action recorded against
    /// this DID. `None` when no actions exist (which shouldn't
    /// happen in practice — the recorder writes a row on every
    /// action — but the schema column is nullable for forward
    /// compatibility with future write paths).
    pub last_action_at: Option<SystemTime>,
    /// Wall-clock the `current_strike_count` was last derived. Drives
    /// the freshness check.
    pub last_recompute_at: SystemTime,
}

/// Whether the cache row is fresh enough to read without a
/// recompute. Pure function: same input always yields the same
/// output.
///
/// Returns `false` for:
/// - `now - last_recompute_at >= freshness_window` (stale).
/// - `last_recompute_at > now` (clock skew or corruption — safe
///   default is "recompute").
pub fn cache_is_fresh(
    cache: &SubjectStrikeStateCache,
    freshness_window: Duration,
    now: SystemTime,
) -> bool {
    match now.duration_since(cache.last_recompute_at) {
        Ok(elapsed) => elapsed < freshness_window,
        // last_recompute_at is in the future relative to now —
        // either clock skew or a corrupted row. Treat as stale.
        Err(_) => false,
    }
}

/// Load the cache row for a DID. Returns `Ok(None)` if no row
/// exists.
pub async fn load_cache(
    pool: &Pool<Sqlite>,
    subject_did: &str,
) -> Result<Option<SubjectStrikeStateCache>> {
    let row = sqlx::query!(
        "SELECT subject_did, current_strike_count, last_action_at, last_recompute_at
         FROM subject_strike_state WHERE subject_did = ?1",
        subject_did,
    )
    .fetch_optional(pool)
    .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    let current_strike_count = u32::try_from(r.current_strike_count).map_err(|_| {
        Error::Signing(format!(
            "subject_strike_state.current_strike_count {} out of u32 range",
            r.current_strike_count
        ))
    })?;
    Ok(Some(SubjectStrikeStateCache {
        subject_did: r.subject_did,
        current_strike_count,
        last_action_at: r.last_action_at.map(epoch_ms_to_systemtime),
        last_recompute_at: epoch_ms_to_systemtime(r.last_recompute_at),
    }))
}

/// UPSERT a recompute result into the cache. Bumps
/// `current_strike_count` and `last_recompute_at`; leaves
/// `last_action_at` untouched on the conflict-update path (this is
/// a recompute, not a new action). On the insert path
/// `last_action_at` is `NULL` — the conflict-update branch should
/// be the only realistic path since the recorder writes the row on
/// every action; a fresh-INSERT here would only happen if the
/// caller invokes this on a never-actioned subject (which the
/// public surface forbids via [`get_or_recompute_strike_count`]'s
/// missing-cache check).
pub async fn update_cache(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    current_count: u32,
    now: SystemTime,
) -> Result<()> {
    let now_ms = systemtime_to_epoch_ms(now);
    let count_i64 = current_count as i64;
    sqlx::query!(
        "INSERT INTO subject_strike_state (subject_did, current_strike_count, last_action_at, last_recompute_at)
         VALUES (?1, ?2, NULL, ?3)
         ON CONFLICT(subject_did) DO UPDATE SET
             current_strike_count = excluded.current_strike_count,
             last_recompute_at = excluded.last_recompute_at",
        subject_did,
        count_i64,
        now_ms,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Return the subject's currently-active strike count, recomputing
/// from `subject_actions` history if the cache is stale.
///
/// Currently UNUSED by any in-tree code. Ships ahead of v1.5's
/// auto-action-threshold-check consumer (per the brief that
/// settled this seam); landing the cache management alongside the
/// cache write path it pairs with — instead of split across
/// releases — keeps the invariants reviewable in one place.
///
/// Errors:
/// - [`Error::StrikeCacheMissing`] when no cache row exists for
///   `subject_did`. The recorder writes the row on every action,
///   so this means the subject has never been actioned.
/// - DB / arithmetic / decay-calculator errors propagate.
///
/// Cache-write best-effort: when a recompute fires, the new count
/// is written back via [`update_cache`]. If that write fails
/// (e.g., a transient DB error), the recomputed count is still
/// returned to the caller — the cache update is an optimization,
/// not a correctness gate. The failure is logged via `tracing::warn`.
pub async fn get_or_recompute_strike_count(
    pool: &Pool<Sqlite>,
    subject_did: &str,
    policy: &StrikePolicy,
    now: SystemTime,
) -> Result<u32> {
    let Some(cache) = load_cache(pool, subject_did).await? else {
        return Err(Error::StrikeCacheMissing(subject_did.to_string()));
    };

    let freshness_window = Duration::from_secs(policy.cache_freshness_window_seconds as u64);
    if cache_is_fresh(&cache, freshness_window, now) {
        return Ok(cache.current_strike_count);
    }

    // Stale: recompute from source-of-truth via the shared loader
    // + decay calculator.
    let history = load_action_history(pool, subject_did).await?;
    let state = calculate_strike_state(&history, policy, now);
    let new_count = state.current_count;

    // Best-effort cache update. A failure here doesn't lose the
    // recomputed count — the caller gets correct data even if the
    // cache stays stale for another freshness_window.
    if let Err(e) = update_cache(pool, subject_did, new_count, now).await {
        tracing::warn!(
            subject = %subject_did,
            error = %e,
            "strike-state cache update failed; returning recomputed count anyway",
        );
    }

    Ok(new_count)
}

fn epoch_ms_to_systemtime(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH
    }
}

fn systemtime_to_epoch_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(2_000_000_000)
    }

    fn cache_at(last_recompute: SystemTime) -> SubjectStrikeStateCache {
        SubjectStrikeStateCache {
            subject_did: "did:plc:test".to_string(),
            current_strike_count: 0,
            last_action_at: None,
            last_recompute_at: last_recompute,
        }
    }

    // ---------- cache_is_fresh ----------

    #[test]
    fn fresh_within_window() {
        let now = t0();
        let c = cache_at(now - Duration::from_secs(1800));
        assert!(cache_is_fresh(&c, Duration::from_secs(3600), now));
    }

    #[test]
    fn stale_past_window() {
        let now = t0();
        let c = cache_at(now - Duration::from_secs(7200));
        assert!(!cache_is_fresh(&c, Duration::from_secs(3600), now));
    }

    #[test]
    fn exact_boundary_is_stale_strict_less_than() {
        // freshness_window = 3600s, last_recompute exactly 3600s
        // ago → elapsed == window → NOT fresh (the check is strict
        // less-than).
        let now = t0();
        let c = cache_at(now - Duration::from_secs(3600));
        assert!(!cache_is_fresh(&c, Duration::from_secs(3600), now));
    }

    #[test]
    fn last_recompute_in_future_is_stale() {
        // Clock skew: last_recompute_at is AFTER now. Treat as stale
        // — the safe answer in either bug-induced or clock-jump
        // scenarios is to recompute.
        let now = t0();
        let c = cache_at(now + Duration::from_secs(60));
        assert!(!cache_is_fresh(&c, Duration::from_secs(3600), now));
    }

    #[test]
    fn zero_freshness_window_makes_everything_stale() {
        // Defensive: a zero-window policy (which validation
        // forbids, but defense-in-depth) makes nothing fresh.
        let now = t0();
        let c = cache_at(now);
        assert!(!cache_is_fresh(&c, Duration::ZERO, now));
    }

    #[test]
    fn epoch_ms_systemtime_round_trip() {
        // Pin the conversion contract used by load_cache /
        // update_cache. Pick a value that doesn't sit on a second
        // boundary so the ms precision matters.
        let original_ms: i64 = 1_776_902_400_123;
        let st = epoch_ms_to_systemtime(original_ms);
        let back = systemtime_to_epoch_ms(st);
        assert_eq!(back, original_ms);
    }

    // The DB-touching paths (load_cache / update_cache /
    // get_or_recompute_strike_count) are exercised in
    // tests/strike_cache.rs against a real SQLite database — the
    // unit tests stay pure to avoid sqlx-prepare churn for what
    // are otherwise straightforward UPSERT statements.
}
