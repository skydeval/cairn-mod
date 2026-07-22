-- v1.8.9 ops-and-runtime (v2 §5/§7, chainlink #151): local ledger
-- of cairn-mod-initiated runtime-setting writes.
--
-- **Additive-only** — one table + one index; no rebuilds, no CHECK
-- extensions on existing tables, no trigger changes. Per corollary
-- #28 the trigger forward-trace is unaffected: live bodies remain
-- 0010's (subject_actions, pds_admin_audit) and 0001's (audit_log).
--
-- Unchained + advisory (the cross_verify_outcomes posture): a
-- setting write has no subject (subject_actions.subject_did is NOT
-- NULL) and no representable verb in pds_admin_audit's 16-verb
-- CHECK, and its hash-chained rows require a subject_actions FK —
-- so the authoritative audit record is Aurora's own chain entry
-- (action 'SetRuntimeSetting'), reachable via v1.8.6 cross-verify
-- and mirrored by v1.8.8 when chain co-delivery is on. This table
-- is the local operator convenience: what did THIS cairn-mod
-- change, when, and under which upstream chain entry.
--
-- Cross-verify does NOT auto-join these rows (no
-- backend_action_id exists). Manual reconciliation joins
-- aurora_audit_entry_id against upstream_audit_mirror.entry_id;
-- automated coverage is a v1.8.11 evaluation item. Operators MAY
-- prune.
--
-- source = 'local' for cairn-mod-initiated writes; 'upstream' is
-- reserved (stream-side mirroring is an explicit v1.8.9 non-goal,
-- also v1.8.11 evaluation).

CREATE TABLE runtime_settings_writes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    -- JSON-encoded value as dispatched.
    value TEXT NOT NULL,
    rationale TEXT NOT NULL,
    -- Aurora's audit-chain entry id (String on the wire).
    aurora_audit_entry_id TEXT NOT NULL UNIQUE,
    dispatched_at TEXT NOT NULL DEFAULT (datetime('now')),
    source TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'upstream'))
) STRICT;

CREATE INDEX runtime_settings_writes_key_idx
    ON runtime_settings_writes (key, dispatched_at DESC);
