-- pds_admin_audit table (#85, v1.7).
--
-- Records every PDS-side enforcement attempt the OzoneBackend (#86 onward)
-- makes — successful or failed — with a foreign-key tether to the
-- precipitating subject_actions row that triggered the call.
--
-- Hash-chain integration per §A13: this table participates in the SAME
-- hash chain as audit_log (#39, v1.3). New rows reference whichever of
-- the two tables holds the most recent chain entry as their prev_hash;
-- the next audit_log or pds_admin_audit insertion will reference this
-- row's row_hash in turn. The chain is unified so a forensic walker
-- visiting both tables in insertion-time order sees one continuous
-- SHA-256 thread. Walking is by-timestamp (audit_log.created_at vs.
-- pds_admin_audit.call_completed_at) since ids are per-table.
--
-- Trade-off: cairn audit-verify (#41) walks audit_log only and treats a
-- prev_hash that doesn't match the previous audit_log row's row_hash as
-- a divergence. Once a v1.7+ deployment writes pds_admin_audit rows,
-- audit-verify will report false-positive divergences for any audit_log
-- row whose actual chain-predecessor is a pds_admin_audit row. Extending
-- audit-verify to walk the unified chain is deferred to v1.8 (the prompt
-- documents this explicitly under "What NOT to implement"); meanwhile,
-- operators wanting integrity verification on a v1.7 deployment use the
-- cairn-mod-side action commit + pds_admin_audit row as a tracking pair
-- and re-run audit-verify against pre-v1.7 segments.
--
-- The recordAction transaction commits FIRST; the actual backend HTTP
-- call happens AFTER; the resulting pds_admin_audit row is inserted in
-- a SEPARATE transaction (per §A13 — holding a SQLite write transaction
-- across an HTTP call would deadlock the writer task).
--
-- Why outcome is text-coded rather than enum-validated at the SQL level:
-- the CHECK constraint enumerates the eight v1.7 outcomes. Future
-- variants (retry-pending, etc.) would require a follow-up migration —
-- intentional, so adding an outcome category is a deliberate schema
-- decision, not an accidental code-side enum bump.
--
-- Append-only by contract: BEFORE UPDATE / BEFORE DELETE triggers
-- abort, matching audit_log_no_update / audit_log_no_delete from
-- migration 0001.

PRAGMA foreign_keys = ON;

CREATE TABLE pds_admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- FK to subject_actions(id) — the cairn-mod-side action whose
    -- effective_at triggered this PDS call. ON DELETE RESTRICT is
    -- belt-and-braces: subject_actions has its own no-delete trigger
    -- (see migration 0003), so deletion is blocked at that layer
    -- already; RESTRICT documents the intent at the schema level.
    precipitating_action_id INTEGER NOT NULL REFERENCES subject_actions(id) ON DELETE RESTRICT,
    -- The backend method that was attempted, as the wire-string form
    -- of crate::pds_admin::BackendMethod. Stored as TEXT because the
    -- enum variant set is a Rust-side concern; SQLite's CHECK pins
    -- the v1.7 set, but adding methods is a code-side decision (and
    -- requires a migration to relax the CHECK if it expands).
    backend_method TEXT NOT NULL CHECK (backend_method IN (
        'takedown_account', 'suspend_account', 'restore_account',
        'apply_label', 'negate_label'
    )),
    -- Backend-assigned identifier for the call, when the remote
    -- responded with one. NULL when the call failed before remote
    -- acknowledgment (Network, Auth, Validation outcomes) and for
    -- unit-result methods (restore_account, apply_label, negate_label
    -- per §A2's trait shape) which never carry a backend ID even on
    -- success.
    backend_action_id TEXT,
    -- Outcome category. Maps from BackendError variants + the
    -- success case. Indexed for "show me all auth failures" /
    -- "all rate-limits" operator queries.
    outcome TEXT NOT NULL CHECK (outcome IN (
        'success', 'unsupported', 'network', 'auth', 'rate_limited',
        'conflict', 'remote_error', 'validation'
    )),
    -- Backend-supplied error code, when applicable. Populated for
    -- outcome='remote_error' (BackendError::RemoteError.code) and may
    -- be populated for 'auth' / 'rate_limited' if the backend
    -- supplied one. NULL for 'success' and for variants without a
    -- code field.
    error_code TEXT,
    -- Human-readable error message from the backend's response or
    -- cairn-mod's transport-layer error wrapper. NULL for 'success'.
    error_message TEXT,
    -- Retry-After hint from the backend, in seconds. Only meaningful
    -- for outcome='rate_limited' and only when the backend supplied
    -- a Retry-After header (or equivalent JSON field). NULL otherwise.
    retry_after_seconds INTEGER,
    -- Hash chain. Both columns are NOT NULL: pds_admin_audit only
    -- holds v1.7+ rows, so there is no pre-attestation horizon
    -- (unlike audit_log, where pre-v1.3 rows have NULL hashes
    -- pending cairn audit-rebuild). Column type matches §F10's
    -- BLOB convention (migration 0002).
    prev_hash BLOB NOT NULL,
    row_hash BLOB NOT NULL,
    -- Wall-clock epoch-ms at which cairn-mod began the backend call,
    -- captured AFTER the precipitating recordAction transaction
    -- committed (per §A13).
    call_started_at INTEGER NOT NULL,
    -- Wall-clock epoch-ms at which the backend responded, or the
    -- call timed out / failed at the transport layer. Latency
    -- between the two timestamps is the operator-visible signal
    -- for "how long is the PDS taking to acknowledge."
    call_completed_at INTEGER NOT NULL
) STRICT;

-- "Show me everything cairn-mod tried to do on the PDS for action N."
-- Primary join target for the §F20 history surfaces (#99 will plug
-- this into the `cairn moderator history` CLI; #87 reads it for the
-- recordAction → backend bridge to detect already-recorded calls).
CREATE INDEX pds_admin_audit_action_idx ON pds_admin_audit(precipitating_action_id);

-- "Show me all rate-limit / auth failures since timestamp T."
-- Operator-facing health surface; the partial-or-full split isn't
-- worth the complexity at v1.7 row volumes.
CREATE INDEX pds_admin_audit_outcome_idx ON pds_admin_audit(outcome);

-- Chain-walk ordering. Used by the future v1.8 audit-verify
-- extension that walks the unified chain in time order; harmless
-- in v1.7 (small table, low cardinality on first-deploy).
CREATE INDEX pds_admin_audit_completed_idx ON pds_admin_audit(call_completed_at);

-- Append-only triggers. Same correctness-not-security posture as
-- audit_log_no_update / audit_log_no_delete (migration 0001) and
-- subject_actions_no_delete (migration 0003): defends cairn-mod's
-- own write paths against bug-driven UPDATE/DELETE; the row_hash
-- chain is the cryptographic defense against direct-DB tampering.
CREATE TRIGGER pds_admin_audit_no_update BEFORE UPDATE ON pds_admin_audit
BEGIN
    SELECT RAISE(ABORT, 'pds_admin_audit is append-only');
END;

CREATE TRIGGER pds_admin_audit_no_delete BEFORE DELETE ON pds_admin_audit
BEGIN
    SELECT RAISE(ABORT, 'pds_admin_audit is append-only');
END;
