-- Policy automation substrate (#70, v1.6, §F22).
--
-- v1.6's "policy automation" theme adds an engine that evaluates
-- operator-declared rules against subject strike state on every
-- recordAction and either auto-records consequent actions or queues
-- them as pending for moderator review. This migration adds the
-- schema substrate the engine requires; Rust integration of the
-- evaluation flow lands across #71-#82.
--
-- Two changes:
--
-- 1. subject_actions gains two columns:
--    - `actor_kind` discriminates between moderator-recorded actions
--      (the v1.4 / v1.5 baseline) and policy-recorded actions (new
--      in v1.6). Existing rows backfill to 'moderator' via the
--      DEFAULT clause; new rows from the moderator path set the
--      same value explicitly; new rows the policy engine inserts
--      set 'policy'.
--    - `triggered_by_policy_rule` records which `[policy_automation]`
--      rule fired for this action, NULL for moderator-recorded rows
--      (and for actions that the engine did not produce).
--    Both columns are write-once at INSERT; the no-update trigger
--    from #46/#57 is rewritten to abort changes to either.
--
-- 2. New table `pending_policy_actions` — flag-mode rule firings
--    queue here for moderator review. Each row holds the proposed
--    action's shape (action_type, duration, reasons), the rule that
--    fired, the triggering subject_actions row, and resolution
--    state (NULL while pending; 'confirmed' or 'dismissed' once a
--    moderator acts). Confirmation creates a real subject_actions
--    row and links it via `confirmed_action_id`; dismissal leaves
--    the linkage NULL but marks the row resolved. Resolution
--    transitions are NULL → non-NULL exactly once (mirroring the
--    revocation columns from #46 and the emitted_label_uri column
--    from #57); subsequent changes abort.
--
-- Same correctness-not-security trigger posture as #46 / #57:
-- defends against bugs in cairn-mod's own write paths, not direct
-- DB tampering. The audit_log hash chain (#39) remains the only
-- cryptographic defense against direct-DB tampering.
--
-- This migration is JUST the schema. Rust integration (config
-- loader, evaluator, recorder integration, read endpoints, CLI,
-- end-to-end tests) lands across #71-#82.
--
-- ----------------------------------------------------------------
-- Inline smoke-test contracts (Python + sqlite3, mirrors #57 style):
-- ----------------------------------------------------------------
--
-- Setup:
--   import sqlite3
--   con = sqlite3.connect(":memory:")
--   # apply 0001_init.sql, 0002_audit_hash_chain.sql,
--   # 0003_account_moderation_state.sql, 0004_label_emission.sql,
--   # then this file
--
-- 1. actor_kind backfills to 'moderator' for existing v1.4-era rows:
--   con.execute("INSERT INTO subject_actions (subject_did, actor_did, "
--               "action_type, reason_codes, effective_at, "
--               "strike_value_base, strike_value_applied, "
--               "strikes_at_time_of_action, created_at) "
--               "VALUES ('did:plc:s', 'did:plc:m', 'warning', '[]', "
--               "0, 0, 0, 0, 0)")
--   row = con.execute("SELECT actor_kind, triggered_by_policy_rule "
--                     "FROM subject_actions").fetchone()
--   assert row == ('moderator', None), row  # default backfill
--
-- 2. actor_kind CHECK constraint rejects bad values:
--   try:
--       con.execute("INSERT INTO subject_actions (subject_did, "
--                   "actor_did, action_type, reason_codes, "
--                   "effective_at, strike_value_base, "
--                   "strike_value_applied, strikes_at_time_of_action, "
--                   "created_at, actor_kind) VALUES (...., 'bogus')")
--       assert False, "CHECK should have aborted"
--   except sqlite3.IntegrityError as e:
--       assert "CHECK constraint failed" in str(e)
--
-- 3. Pending-row resolution NULL → 'confirmed' allowed once:
--   con.execute("INSERT INTO pending_policy_actions (subject_did, "
--               "action_type, reason_codes, "
--               "triggered_by_policy_rule, triggered_at, "
--               "triggering_action_id) VALUES "
--               "('did:plc:s', 'warning', '[]', 'rule_a', 0, 1)")
--   con.execute("UPDATE pending_policy_actions SET "
--               "resolution = 'confirmed', resolved_at = 1, "
--               "resolved_by_did = 'did:plc:m', "
--               "confirmed_action_id = 1 WHERE id = 1")
--   row = con.execute("SELECT resolution FROM "
--                     "pending_policy_actions WHERE id = 1").fetchone()
--   assert row[0] == 'confirmed'
--
-- 4. Re-transitioning resolution aborts:
--   try:
--       con.execute("UPDATE pending_policy_actions SET "
--                   "resolution = 'dismissed' WHERE id = 1")
--       assert False, "trigger should have aborted"
--   except sqlite3.IntegrityError as e:
--       assert "pending_policy_actions" in str(e)
--
-- 5. DELETE on pending_policy_actions aborts unconditionally:
--   try:
--       con.execute("DELETE FROM pending_policy_actions WHERE id = 1")
--       assert False, "trigger should have aborted"
--   except sqlite3.IntegrityError:
--       pass
--
-- 6. Changing immutable columns post-INSERT aborts:
--   try:
--       con.execute("UPDATE pending_policy_actions SET "
--                   "subject_did = 'did:plc:other' WHERE id = 1")
--       assert False, "trigger should have aborted"
--   except sqlite3.IntegrityError:
--       pass

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------
-- 1. Extend subject_actions
-- ----------------------------------------------------------------

-- actor_kind: 'moderator' for moderator-recorded actions (the v1.4 /
-- v1.5 baseline), 'policy' for actions the engine inserts directly
-- (mode=auto rule firings). Pending → confirmed flow's resulting
-- subject_actions row uses 'moderator' (the moderator takes
-- responsibility by confirming); the rule's name is preserved on
-- triggered_by_policy_rule for provenance. Existing rows backfill
-- via DEFAULT.
ALTER TABLE subject_actions
    ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'moderator'
    CHECK (actor_kind IN ('moderator', 'policy'));

-- triggered_by_policy_rule: the [policy_automation.<rule>] name
-- that produced this action. NULL for moderator-recorded actions
-- the engine had no hand in. Preserved through pending →
-- confirmed flow as forensic provenance.
ALTER TABLE subject_actions
    ADD COLUMN triggered_by_policy_rule TEXT;

-- Trigger update: drop the v1.5 trigger (which permitted the
-- emitted_label_uri NULL → non-NULL transition) and recreate
-- with additional clauses pinning the new columns as
-- write-once-at-INSERT. INSERT is unaffected — BEFORE UPDATE
-- triggers don't fire on INSERT — so the columns are set at
-- INSERT and frozen thereafter.
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
  OR OLD.actor_kind != NEW.actor_kind
  OR (OLD.triggered_by_policy_rule IS NOT NEW.triggered_by_policy_rule)
BEGIN
    SELECT RAISE(ABORT, 'subject_actions is append-only except for one-time revocation and one-time label-emission linkage; actor_kind and triggered_by_policy_rule are write-once at INSERT');
END;

-- ----------------------------------------------------------------
-- 2. pending_policy_actions table
-- ----------------------------------------------------------------

-- Flag-mode rule firings queue here. Write-once on every column at
-- INSERT except the four resolution columns, which transition
-- NULL → non-NULL exactly once when a moderator confirms or
-- dismisses. confirmed_action_id is non-NULL only when
-- resolution = 'confirmed' (the linkage to the real subject_actions
-- row created on confirm); dismissed rows leave it NULL.
CREATE TABLE pending_policy_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Account DID the proposed action would target. Strike
    -- accounting rolls up here regardless of subject_uri presence.
    subject_did TEXT NOT NULL,
    -- AT-URI for record-level proposed actions; NULL for
    -- account-level. Mirrors subject_actions.subject_uri.
    subject_uri TEXT,
    -- Proposed action_type. Same enum as subject_actions; CHECK
    -- enforced.
    action_type TEXT NOT NULL CHECK (action_type IN (
        'warning', 'note', 'temp_suspension', 'indef_suspension', 'takedown'
    )),
    -- Proposed duration in milliseconds. Required for
    -- temp_suspension; NULL otherwise. Application layer enforces
    -- the action_type ↔ duration_ms relationship at INSERT
    -- (the schema can't express "non-NULL iff action_type =
    -- temp_suspension" without a more elaborate trigger).
    duration_ms INTEGER,
    -- JSON array of reason-code strings (same shape as
    -- subject_actions.reason_codes). Validation against the
    -- [moderation_reasons] vocabulary is application-level (#71).
    reason_codes TEXT NOT NULL,
    -- The [policy_automation.<rule>] sub-block name that fired.
    triggered_by_policy_rule TEXT NOT NULL,
    -- Epoch-ms wall-clock at which the rule fired (== the
    -- triggering recordAction's effective_at).
    triggered_at INTEGER NOT NULL,
    -- The subject_actions row whose strike contribution caused
    -- the rule's threshold to be crossed.
    triggering_action_id INTEGER NOT NULL REFERENCES subject_actions(id),
    -- Resolution state. NULL while pending; 'confirmed' if a
    -- moderator promoted to a real subject_actions row; 'dismissed'
    -- if a moderator declined. Write-once on the NULL → non-NULL
    -- transition per the trigger below.
    resolution TEXT CHECK (resolution IS NULL OR resolution IN ('confirmed', 'dismissed')),
    resolved_at INTEGER,
    -- DID of the moderator (or the synthetic policy DID for
    -- takedown-triggered auto-dismissals per #76) that resolved
    -- the row.
    resolved_by_did TEXT,
    -- The subject_actions row created when the pending was
    -- confirmed. NULL while pending OR if the pending was
    -- dismissed. Write-once on NULL → non-NULL.
    confirmed_action_id INTEGER REFERENCES subject_actions(id)
) STRICT;

-- ----------------------------------------------------------------
-- Indexes for the read patterns the v1.6 surfaces use:
-- ----------------------------------------------------------------

-- Fast "pending actions for this subject" lookup. Partial index
-- on the active-only subset stays small under heavy resolution
-- churn.
CREATE INDEX pending_policy_actions_subject_pending_idx
    ON pending_policy_actions(subject_did)
    WHERE resolution IS NULL;

-- Moderator review queue scan: "all pending across subjects."
-- Partial index again — only pending rows are interesting for
-- the queue surface.
CREATE INDEX pending_policy_actions_pending_idx
    ON pending_policy_actions(triggered_at DESC)
    WHERE resolution IS NULL;

-- Operator reporting: "how often did rule X fire?" Composite
-- index supports both rule-name lookups and time-range scans.
CREATE INDEX pending_policy_actions_rule_idx
    ON pending_policy_actions(triggered_by_policy_rule, triggered_at DESC);

-- ----------------------------------------------------------------
-- Triggers on pending_policy_actions
-- ----------------------------------------------------------------

-- BEFORE UPDATE: only the four resolution columns may transition
-- NULL → non-NULL. Any other change, or a re-transition of an
-- already-set resolution column, aborts. Same write-once-on-NULL-
-- to-non-NULL pattern as subject_actions.revoked_* (#46) and
-- subject_actions.emitted_label_uri (#57).
CREATE TRIGGER pending_policy_actions_no_update_except_resolution BEFORE UPDATE ON pending_policy_actions
WHEN OLD.id != NEW.id
  OR OLD.subject_did != NEW.subject_did
  OR (OLD.subject_uri IS NOT NEW.subject_uri)
  OR OLD.action_type != NEW.action_type
  OR (OLD.duration_ms IS NOT NEW.duration_ms)
  OR OLD.reason_codes != NEW.reason_codes
  OR OLD.triggered_by_policy_rule != NEW.triggered_by_policy_rule
  OR OLD.triggered_at != NEW.triggered_at
  OR OLD.triggering_action_id != NEW.triggering_action_id
  OR (OLD.resolution IS NOT NULL AND OLD.resolution IS NOT NEW.resolution)
  OR (OLD.resolved_at IS NOT NULL AND OLD.resolved_at IS NOT NEW.resolved_at)
  OR (OLD.resolved_by_did IS NOT NULL AND OLD.resolved_by_did IS NOT NEW.resolved_by_did)
  OR (OLD.confirmed_action_id IS NOT NULL AND OLD.confirmed_action_id IS NOT NEW.confirmed_action_id)
BEGIN
    SELECT RAISE(ABORT, 'pending_policy_actions is append-only except for one-time resolution (NULL → confirmed | dismissed)');
END;

-- BEFORE DELETE: unconditionally aborts. Pending rows are
-- forensic record; resolution moves them out of the active set
-- but they stay in the table.
CREATE TRIGGER pending_policy_actions_no_delete BEFORE DELETE ON pending_policy_actions
BEGIN
    SELECT RAISE(ABORT, 'pending_policy_actions is append-only');
END;
