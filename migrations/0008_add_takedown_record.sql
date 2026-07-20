-- Extend pds_admin_audit's backend_method CHECK with 'takedown_record'
-- (v1.8.2, §4.7).
--
-- v1.8.2 adds the takedown_record trait method (record-level takedown:
-- RustBackend via emitEvent {"kind": "TakedownRecord"}; OzoneBackend via
-- updateSubjectStatus with a strongRef subject). The audit row's
-- backend_method column must accept the new wire string.
--
-- SQLite cannot alter a CHECK constraint in place, so this is the
-- standard table-rebuild: create the replacement with the extended
-- CHECK, copy rows, drop the old table, rename, then recreate the
-- indexes and append-only triggers. Everything else about the schema —
-- STRICT, column set, FK, the eight-value outcome CHECK — is
-- byte-identical to migration 0006 (see 0006 for the full column
-- rationale comments). The hash chain is unaffected: row content is
-- copied verbatim and row_hash/prev_hash are plain column copies.
--
-- The append-only triggers are dropped for the duration of the copy
-- (they fire on UPDATE/DELETE only, so INSERT..SELECT and DROP TABLE
-- are unaffected; recreating them on the new table restores the
-- contract).

PRAGMA foreign_keys = ON;

CREATE TABLE pds_admin_audit_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    precipitating_action_id INTEGER NOT NULL REFERENCES subject_actions(id) ON DELETE RESTRICT,
    -- v1.8.2: 'takedown_record' joins the v1.7 five.
    backend_method TEXT NOT NULL CHECK (backend_method IN (
        'takedown_account', 'suspend_account', 'restore_account',
        'apply_label', 'negate_label', 'takedown_record'
    )),
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
    call_completed_at INTEGER NOT NULL
) STRICT;

INSERT INTO pds_admin_audit_new (
    id, precipitating_action_id, backend_method, backend_action_id,
    outcome, error_code, error_message, retry_after_seconds,
    prev_hash, row_hash, call_started_at, call_completed_at
)
SELECT
    id, precipitating_action_id, backend_method, backend_action_id,
    outcome, error_code, error_message, retry_after_seconds,
    prev_hash, row_hash, call_started_at, call_completed_at
FROM pds_admin_audit;

DROP TABLE pds_admin_audit;

ALTER TABLE pds_admin_audit_new RENAME TO pds_admin_audit;

-- Recreate the 0006 indexes on the rebuilt table.
CREATE INDEX pds_admin_audit_action_idx ON pds_admin_audit(precipitating_action_id);
CREATE INDEX pds_admin_audit_outcome_idx ON pds_admin_audit(outcome);
CREATE INDEX pds_admin_audit_completed_idx ON pds_admin_audit(call_completed_at);

-- Recreate the 0006 append-only triggers (correctness-not-security
-- posture; the row_hash chain is the cryptographic defense).
CREATE TRIGGER pds_admin_audit_no_update BEFORE UPDATE ON pds_admin_audit
BEGIN
    SELECT RAISE(ABORT, 'pds_admin_audit is append-only');
END;

CREATE TRIGGER pds_admin_audit_no_delete BEFORE DELETE ON pds_admin_audit
BEGIN
    SELECT RAISE(ABORT, 'pds_admin_audit is append-only');
END;
