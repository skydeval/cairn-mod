-- Add subject_cid to subject_actions + rebuild the append-only trigger
-- (v1.8.3, §4.5 / Workstream B).
--
-- Record-subject moderation dispatch (v1.8.2's takedown_record routing)
-- requires the record CID; subject_actions had no CID column, so every
-- record-targeted row rejected at dispatch with a validation outcome.
-- This migration adds the column; the v1.8.3 code change populates it
-- from RecordActionRequest.subject_cid or the report-join fallback
-- (reports.subject_cid).
--
-- SQLite permits ALTER TABLE ADD COLUMN of a nullable typed column on
-- STRICT tables, so no table rebuild is needed. But the append-only
-- guard trigger `subject_actions_no_update_except_revoke` enforces
-- immutability by ENUMERATING columns — a plainly-added subject_cid
-- would be silently mutable while every sibling identity column is
-- guarded. So the trigger is dropped and recreated with subject_cid in
-- the enumeration.
--
-- NOTE ON PROVENANCE: the trigger has been rebuilt at every column
-- addition — 0003 created it, 0004 rebuilt it (emitted_label_uri
-- one-time linkage), 0005 rebuilt it again (actor_kind /
-- triggered_by_policy_rule write-once pins). The body below is the
-- CURRENT body from 0005:148-172 copied verbatim with ONE added clause
-- (marked). The one-time revocation carve-out and the 0004/0005
-- clauses are all preserved unchanged. subject_actions_no_delete is
-- untouched.
--
-- Legacy rows keep subject_cid = NULL (no backfill; see the v1.8.3
-- design §5.7 — record-targeted legacy rows continue to reject at
-- dispatch until re-issued through the new plumbing).

PRAGMA foreign_keys = ON;

ALTER TABLE subject_actions ADD COLUMN subject_cid TEXT;

DROP TRIGGER subject_actions_no_update_except_revoke;

CREATE TRIGGER subject_actions_no_update_except_revoke BEFORE UPDATE ON subject_actions
WHEN OLD.id != NEW.id
  OR OLD.subject_did != NEW.subject_did
  OR (OLD.subject_uri IS NOT NEW.subject_uri)
  OR (OLD.subject_cid IS NOT NEW.subject_cid)   -- v1.8.3: new column, immutable like subject_uri
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
  OR OLD.actor_kind != NEW.actor_kind
  OR (OLD.triggered_by_policy_rule IS NOT NEW.triggered_by_policy_rule)
BEGIN
    SELECT RAISE(ABORT, 'subject_actions is append-only except for one-time revocation and one-time label-emission linkage; actor_kind and triggered_by_policy_rule are write-once at INSERT');
END;
