-- Label emission linkage (#57, v1.5, §F21).
--
-- v1.5 closes v1.4's loop: when an action is recorded against a
-- subject, cairn-mod now also emits ATProto labels per the
-- operator's [label_emission] policy (#58). This migration adds
-- the persistence surface that ties subject_actions rows back to
-- the labels they emitted, so revocation (#62) can negate them
-- and read endpoints (#65) can surface the currently-active set.
--
-- Two changes:
--
-- 1. subject_actions gains `emitted_label_uri` — the AT-URI of
--    the action label emitted at record time. Populated by the
--    recorder (#60) IN THE SAME TRANSACTION as the row INSERT,
--    via an UPDATE immediately after the INSERT. The trigger
--    below is rewritten to permit this NULL→non-NULL transition
--    (once only; further changes abort, mirroring the existing
--    revocation exception from #46).
--
-- 2. New table `subject_action_reason_labels` — one row per
--    (action_id, reason_code) pair, holding the AT-URI of the
--    reason label emitted alongside the action. Walked by
--    revocation to negate each reason label individually, and by
--    getSubjectStrikes (#65) to surface the active reason set.
--    Write-once-on-emit; no triggers — rows preserved as forensic
--    record after revocation per §F21.3 (revocation emits
--    negation labels; the linkage rows themselves stay).
--
-- Same correctness-not-security trigger posture as #46 §F20.6:
-- defends against bugs in cairn-mod's own write paths, not
-- against direct DB tampering. The audit_log hash chain (#39) is
-- the only cryptographic defense against direct-DB tampering.
--
-- This migration is JUST the schema. Rust integration of the
-- emission flow lands in #58-#65; this migration unblocks all of
-- them.

PRAGMA foreign_keys = ON;

-- Add the action-label linkage column. Nullable: existing rows
-- (created pre-v1.5) get NULL, and the recorder (#60) populates it
-- on every new RecordAction. Once non-NULL, the trigger below
-- forbids further changes.
ALTER TABLE subject_actions ADD COLUMN emitted_label_uri TEXT;

-- Trigger update: drop the v1.4 trigger and recreate with an
-- additional clause that permits the emitted_label_uri NULL →
-- non-NULL transition exactly like revoked_at's. The condition
-- "OLD.emitted_label_uri IS NOT NULL AND OLD.emitted_label_uri
-- IS NOT NEW.emitted_label_uri" aborts:
--   - Any UPDATE that changes a NON-NULL emitted_label_uri to a
--     different value (no re-emission swap).
-- It permits:
--   - INSERT (NEW.emitted_label_uri NULL or non-NULL — INSERT
--     doesn't go through this BEFORE UPDATE trigger).
--   - UPDATE NULL → non-NULL (the recorder's emission step).
-- Recap: the column moves NULL→non-NULL exactly once over the
-- row's lifetime, then is frozen.
DROP TRIGGER subject_actions_no_update_except_revoke;

CREATE TRIGGER subject_actions_no_update_except_revoke BEFORE UPDATE ON subject_actions
WHEN OLD.id != NEW.id
  OR OLD.subject_did != NEW.subject_did
  OR (OLD.subject_uri IS NOT NEW.subject_uri)
  OR OLD.actor_did != NEW.actor_did
  OR OLD.action_type != NEW.action_type
  OR OLD.reason_codes != NEW.reason_codes
  OR (OLD.duration IS NOT NEW.duration)
  OR OLD.effective_at != NEW.effective_at
  OR (OLD.expires_at IS NOT NEW.expires_at)
  OR (OLD.notes IS NOT NEW.notes)
  OR (OLD.report_ids IS NOT NEW.report_ids)
  OR OLD.strike_value_base != NEW.strike_value_base
  OR OLD.strike_value_applied != NEW.strike_value_applied
  OR OLD.was_dampened != NEW.was_dampened
  OR OLD.strikes_at_time_of_action != NEW.strikes_at_time_of_action
  OR (OLD.audit_log_id IS NOT NEW.audit_log_id)
  OR OLD.created_at != NEW.created_at
  OR (OLD.revoked_at IS NOT NULL AND OLD.revoked_at IS NOT NEW.revoked_at)
  OR (OLD.revoked_by_did IS NOT NULL AND OLD.revoked_by_did IS NOT NEW.revoked_by_did)
  OR (OLD.revoked_reason IS NOT NULL AND OLD.revoked_reason IS NOT NEW.revoked_reason)
  OR (OLD.emitted_label_uri IS NOT NULL AND OLD.emitted_label_uri IS NOT NEW.emitted_label_uri)
BEGIN
    SELECT RAISE(ABORT, 'subject_actions is append-only except for one-time revocation and one-time label-emission linkage');
END;

-- Per-(action, reason) label linkage (#57, v1.5, §F21.7).
-- Written once on emission (#60); read by revocation (#62) to
-- negate per-reason labels; read by getSubjectStrikes (#65) to
-- surface active reason labels.
CREATE TABLE subject_action_reason_labels (
    -- Owning subject_actions row. NO ACTION FK semantics
    -- (SQLite default) — combined with subject_actions's
    -- no-delete trigger, this means the linkage row outlives any
    -- attempt to remove its action.
    action_id INTEGER NOT NULL REFERENCES subject_actions(id),
    -- Reason identifier from the operator's [moderation_reasons]
    -- vocabulary (#47). Encoded into the label_uri's val as
    -- policy.reason_label_prefix + reason_code (default
    -- 'reason-<code>'); see §F21.2.
    reason_code TEXT NOT NULL,
    -- AT-URI of the emitted label record. The labels table holds
    -- the signed record itself; this column is the join key
    -- revocation (#62) uses to find which label to negate.
    emitted_label_uri TEXT NOT NULL,
    -- Epoch-ms wall-clock at emission. Equal to the action's
    -- created_at in practice (emission happens in the same tx as
    -- recording), but stored explicitly for audit clarity.
    emitted_at INTEGER NOT NULL,
    -- Composite PK ensures one linkage row per (action, reason)
    -- pair. Leftmost-fast scans by action_id (the revocation
    -- query) come for free without an extra index.
    PRIMARY KEY (action_id, reason_code)
) STRICT;
