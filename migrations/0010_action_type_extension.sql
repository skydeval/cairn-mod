-- v1.8.5 action-surface enrichment (§4.6.1, chainlink #134): extend
-- both CHECK-constrained action vocabularies for the 10 new dispatched
-- emitEvent variants, and add the response-persistence columns to the
-- outcome ledger.
--
-- Two-table scope (R2 NEW-2 + R3 NEW-R3-4):
--
-- 1. `subject_actions.action_type` gains 10 values (the intent
--    ledger — CLI/recordAction rows for the new pds-admin verbs).
--    The rebuild also adds `action_detail` (nullable JSON TEXT):
--    variant-specific intent data (report id, appeal id + decision,
--    email template/subject/body, status value, prior backend action
--    id for blob restores). This column deviates from v4 §4.6.1
--    item 5 ("ride reason_codes JSON") because the shipped writer
--    validates every reason_codes entry against the
--    [moderation_reasons] vocabulary — smuggled JSON is rejected at
--    runtime (source-wins deviation logged on chainlink #134).
--    reason_codes stays what it is: validated reason identifiers.
--
-- 2. `pds_admin_audit.backend_method` gains the same 10 method
--    names, and the table gains `upstream_audit_entry_id`,
--    `cascading_actions_json`, `snapshots_json` (all nullable) —
--    Aurora's EmitEventOutput details persisted on the OUTCOME
--    ledger per v4's storage-home decision (option a). The
--    pre-existing `backend_action_id` column keeps holding the root
--    event id; no duplicate column is added.
--
-- Rebuild technique: SQLite cannot alter a CHECK in place, and
-- subject_actions is an FK PARENT (children: 0004's
-- subject_action_reason_labels, 0005's pending_policy_actions,
-- 0006/0008's pds_admin_audit with ON DELETE RESTRICT). sqlx runs
-- migrations inside a transaction where `PRAGMA foreign_keys = OFF`
-- is a silent no-op, `defer_foreign_keys` explicitly does not defer
-- RESTRICT, and ALTER TABLE RENAME rewrites child FK clauses
-- regardless of legacy_alter_table (verified empirically on SQLite
-- 3.45). The only rebuild that works with FK enforcement live for
-- every statement is the full-family choreography:
--
--   1. stage each child's rows into a bare temp table and DROP the
--      child (dropping a child is always FK-clean);
--   2. rebuild subject_actions 0008-style (now genuinely childless);
--   3. recreate each child with its live DDL (pds_admin_audit gets
--      the new CHECK + columns; the other two are byte-identical to
--      their originating migrations — forward-trace verified: no
--      later migration rebuilds either), copy the staged rows back
--      (FK-validated per row against the new parent — ids are
--      copied verbatim so every reference resolves), drop the
--      staging tables, recreate indexes and triggers.
--
-- Trigger forward-trace per memory #28 (verified at R3, re-verified
-- here): subject_actions' live UPDATE-trigger body is 0009's
-- (rebuilt 0003 -> 0004 -> 0005 -> 0009); its DELETE trigger is
-- 0003's original; pds_admin_audit's triggers are 0008's
-- (byte-identical to 0006's). Hash chains are unaffected —
-- prev_hash/row_hash are plain column copies.
--
-- NOT extended: `pending_policy_actions.action_type` (0005). Policy
-- automation proposes only the classic graduated actions; the new
-- operator verbs are not policy-proposable in v1.8.5 (config-load
-- rejection in policy/automation.rs).
--
-- New action_type / backend_method values are snake_case DB/audit
-- strings; the emitEvent wire discriminator remains PascalCase
-- ({"kind": "DeleteAccount"}) — the writer maps enum -> string via
-- ActionType::as_db_str / BackendMethod::as_wire_str as before.

-- ---------------------------------------------------------------
-- 0. Stage and drop the three FK children of subject_actions.
--    (DROP TABLE also drops each child's triggers; indexes die
--    with their tables. Staging tables are plain column copies —
--    constraints don't matter, they exist only inside this
--    migration.)
-- ---------------------------------------------------------------

CREATE TABLE _mig0010_pds_admin_audit AS SELECT * FROM pds_admin_audit;
DROP TABLE pds_admin_audit;

CREATE TABLE _mig0010_reason_labels AS SELECT * FROM subject_action_reason_labels;
DROP TABLE subject_action_reason_labels;

CREATE TABLE _mig0010_pending AS SELECT * FROM pending_policy_actions;
DROP TABLE pending_policy_actions;

-- ---------------------------------------------------------------
-- 1. subject_actions rebuild: extended action_type CHECK +
--    action_detail column.
-- ---------------------------------------------------------------
-- Column set = 0003 base + 0004 emitted_label_uri + 0005 actor_kind /
-- triggered_by_policy_rule + 0009 subject_cid + (new) action_detail.
-- Column rationale comments live in the originating migrations.

CREATE TABLE subject_actions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_did TEXT NOT NULL,
    subject_uri TEXT,
    actor_did TEXT NOT NULL,
    -- v1.8.5: the 10 new dispatched-action values join the v1.4 five.
    action_type TEXT NOT NULL CHECK (action_type IN (
        'warning', 'note', 'temp_suspension', 'indef_suspension', 'takedown',
        'delete_account', 'quarantine_blob', 'restore_blob', 'delete_blob',
        'resolve_report', 'dismiss_report', 'resolve_appeal', 'escalate_appeal',
        'send_email', 'update_subject_status'
    )),
    reason_codes TEXT NOT NULL,
    duration TEXT,
    effective_at INTEGER NOT NULL,
    expires_at INTEGER,
    notes TEXT,
    report_ids TEXT,
    strike_value_base INTEGER NOT NULL,
    strike_value_applied INTEGER NOT NULL,
    was_dampened INTEGER NOT NULL DEFAULT 0 CHECK (was_dampened IN (0, 1)),
    strikes_at_time_of_action INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_by_did TEXT,
    revoked_reason TEXT,
    audit_log_id INTEGER REFERENCES audit_log(id),
    created_at INTEGER NOT NULL,
    emitted_label_uri TEXT,
    actor_kind TEXT NOT NULL DEFAULT 'moderator'
        CHECK (actor_kind IN ('moderator', 'policy')),
    triggered_by_policy_rule TEXT,
    subject_cid TEXT,
    -- v1.8.5: variant-specific intent payload for the new action
    -- types, JSON object (e.g. {"reportId": 5, "resolution":
    -- "resolved"}). NULL for the classic five action types.
    -- Write-once at INSERT (trigger clause below).
    action_detail TEXT
) STRICT;

INSERT INTO subject_actions_new (
    id, subject_did, subject_uri, actor_did, action_type, reason_codes,
    duration, effective_at, expires_at, notes, report_ids,
    strike_value_base, strike_value_applied, was_dampened,
    strikes_at_time_of_action, revoked_at, revoked_by_did, revoked_reason,
    audit_log_id, created_at, emitted_label_uri, actor_kind,
    triggered_by_policy_rule, subject_cid
)
SELECT
    id, subject_did, subject_uri, actor_did, action_type, reason_codes,
    duration, effective_at, expires_at, notes, report_ids,
    strike_value_base, strike_value_applied, was_dampened,
    strikes_at_time_of_action, revoked_at, revoked_by_did, revoked_reason,
    audit_log_id, created_at, emitted_label_uri, actor_kind,
    triggered_by_policy_rule, subject_cid
FROM subject_actions;

DROP TABLE subject_actions;

ALTER TABLE subject_actions_new RENAME TO subject_actions;

-- Recreate the 0003 indexes.
CREATE INDEX subject_actions_subject_idx ON subject_actions(subject_did, created_at);
CREATE INDEX subject_actions_audit_idx ON subject_actions(audit_log_id) WHERE audit_log_id IS NOT NULL;
CREATE INDEX subject_actions_active_idx ON subject_actions(subject_did) WHERE revoked_at IS NULL;

-- Recreate the UPDATE trigger from the 0009 live body (forward-trace
-- verified) + one new clause: action_detail is write-once at INSERT,
-- immutable like the other intent columns.
CREATE TRIGGER subject_actions_no_update_except_revoke BEFORE UPDATE ON subject_actions
WHEN OLD.id != NEW.id
  OR OLD.subject_did != NEW.subject_did
  OR (OLD.subject_uri IS NOT NEW.subject_uri)
  OR (OLD.subject_cid IS NOT NEW.subject_cid)   -- v1.8.3: new column, immutable like subject_uri
  OR (OLD.action_detail IS NOT NEW.action_detail)  -- v1.8.5: write-once at INSERT
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

-- Recreate the DELETE trigger from the 0003 live body.
CREATE TRIGGER subject_actions_no_delete BEFORE DELETE ON subject_actions
BEGIN
    SELECT RAISE(ABORT, 'subject_actions is append-only');
END;

-- ---------------------------------------------------------------
-- 2. pds_admin_audit shadow-swap: extended backend_method CHECK +
--    ActionResponse persistence columns.
-- ---------------------------------------------------------------
-- Column set = 0008 rebuild + three new nullable columns. See 0006
-- for the original column rationale comments.

CREATE TABLE pds_admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    precipitating_action_id INTEGER NOT NULL REFERENCES subject_actions(id) ON DELETE RESTRICT,
    -- v1.8.5: the 10 new dispatched methods join the v1.8.2 six.
    backend_method TEXT NOT NULL CHECK (backend_method IN (
        'takedown_account', 'suspend_account', 'restore_account',
        'apply_label', 'negate_label', 'takedown_record',
        'delete_account', 'quarantine_blob', 'restore_blob', 'delete_blob',
        'resolve_report', 'dismiss_report', 'resolve_appeal', 'escalate_appeal',
        'send_email', 'update_subject_status'
    )),
    -- Root Aurora event id (pre-existing column; v1.8.5's
    -- ActionResponse.event_id lands here — no duplicate column).
    backend_action_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN (
        'success', 'unsupported', 'network', 'auth', 'rate_limited',
        'conflict', 'remote_error', 'validation'
    )),
    error_code TEXT,
    error_message TEXT,
    retry_after_seconds INTEGER,
    prev_hash BLOB NOT NULL,
    row_hash BLOB NOT NULL,
    call_started_at INTEGER NOT NULL,
    call_completed_at INTEGER NOT NULL,
    -- v1.8.5 ActionResponse persistence (all nullable; populated on
    -- successful v1.8.5 dispatches, NULL for v1.7/v1.8.2 methods
    -- and failures). NOTE: appended AFTER the hash columns and NOT
    -- part of the row-hash preimage — the v1.7 hash contract (#39)
    -- covers the original column set; the cross-chain verify
    -- surface (v1.8.6) decides whether to fold them in.
    upstream_audit_entry_id TEXT,
    cascading_actions_json TEXT,
    snapshots_json TEXT
) STRICT;

INSERT INTO pds_admin_audit (
    id, precipitating_action_id, backend_method, backend_action_id,
    outcome, error_code, error_message, retry_after_seconds,
    prev_hash, row_hash, call_started_at, call_completed_at
)
SELECT
    id, precipitating_action_id, backend_method, backend_action_id,
    outcome, error_code, error_message, retry_after_seconds,
    prev_hash, row_hash, call_started_at, call_completed_at
FROM _mig0010_pds_admin_audit;

DROP TABLE _mig0010_pds_admin_audit;

-- Recreate the 0008 indexes.
CREATE INDEX pds_admin_audit_action_idx ON pds_admin_audit(precipitating_action_id);
CREATE INDEX pds_admin_audit_outcome_idx ON pds_admin_audit(outcome);
CREATE INDEX pds_admin_audit_completed_idx ON pds_admin_audit(call_completed_at);

-- Recreate the 0008 append-only triggers.
CREATE TRIGGER pds_admin_audit_no_update BEFORE UPDATE ON pds_admin_audit
BEGIN
    SELECT RAISE(ABORT, 'pds_admin_audit is append-only');
END;

CREATE TRIGGER pds_admin_audit_no_delete BEFORE DELETE ON pds_admin_audit
BEGIN
    SELECT RAISE(ABORT, 'pds_admin_audit is append-only');
END;

-- ---------------------------------------------------------------
-- 3. subject_action_reason_labels: recreate byte-identical to 0004
--    (no later migration touches it) and restore rows.
-- ---------------------------------------------------------------

CREATE TABLE subject_action_reason_labels (
    action_id INTEGER NOT NULL REFERENCES subject_actions(id),
    reason_code TEXT NOT NULL,
    emitted_label_uri TEXT NOT NULL,
    emitted_at INTEGER NOT NULL,
    PRIMARY KEY (action_id, reason_code)
) STRICT;

INSERT INTO subject_action_reason_labels (action_id, reason_code, emitted_label_uri, emitted_at)
SELECT action_id, reason_code, emitted_label_uri, emitted_at FROM _mig0010_reason_labels;

DROP TABLE _mig0010_reason_labels;

-- ---------------------------------------------------------------
-- 4. pending_policy_actions: recreate byte-identical to 0005 (no
--    later migration touches it; its action_type CHECK stays at
--    the five graduated values — policy automation cannot propose
--    the v1.8.5 verbs) and restore rows, indexes, triggers.
-- ---------------------------------------------------------------

CREATE TABLE pending_policy_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_did TEXT NOT NULL,
    subject_uri TEXT,
    action_type TEXT NOT NULL CHECK (action_type IN (
        'warning', 'note', 'temp_suspension', 'indef_suspension', 'takedown'
    )),
    duration_ms INTEGER,
    reason_codes TEXT NOT NULL,
    triggered_by_policy_rule TEXT NOT NULL,
    triggered_at INTEGER NOT NULL,
    triggering_action_id INTEGER NOT NULL REFERENCES subject_actions(id),
    resolution TEXT CHECK (resolution IS NULL OR resolution IN ('confirmed', 'dismissed')),
    resolved_at INTEGER,
    resolved_by_did TEXT,
    confirmed_action_id INTEGER REFERENCES subject_actions(id)
) STRICT;

INSERT INTO pending_policy_actions (
    id, subject_did, subject_uri, action_type, duration_ms, reason_codes,
    triggered_by_policy_rule, triggered_at, triggering_action_id,
    resolution, resolved_at, resolved_by_did, confirmed_action_id
)
SELECT
    id, subject_did, subject_uri, action_type, duration_ms, reason_codes,
    triggered_by_policy_rule, triggered_at, triggering_action_id,
    resolution, resolved_at, resolved_by_did, confirmed_action_id
FROM _mig0010_pending;

DROP TABLE _mig0010_pending;

CREATE INDEX pending_policy_actions_subject_pending_idx
    ON pending_policy_actions(subject_did)
    WHERE resolution IS NULL;

CREATE INDEX pending_policy_actions_pending_idx
    ON pending_policy_actions(triggered_at DESC)
    WHERE resolution IS NULL;

CREATE INDEX pending_policy_actions_rule_idx
    ON pending_policy_actions(triggered_by_policy_rule, triggered_at DESC);

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

CREATE TRIGGER pending_policy_actions_no_delete BEFORE DELETE ON pending_policy_actions
BEGIN
    SELECT RAISE(ABORT, 'pending_policy_actions is append-only');
END;
