-- v1.8.8 realtime infrastructure (v2 §7, chainlink #147).
--
-- **Additive-only** — no table rebuilds, no CHECK extensions on
-- existing constraints, no trigger changes (contrast 0010's family
-- choreography). Per corollary #28 the trigger forward-trace is
-- unaffected: live bodies remain 0010's (subject_actions,
-- pds_admin_audit) and 0001's (audit_log); `reports` has no
-- triggers.
--
-- 1. `stream_cursors` — client-owned resume positions for the
--    subscribeModEvents consumer. TWO independent cursors (Aurora's
--    event seq and audit-chain seq are separate monotonic
--    counters). The persist-BEFORE-process discipline on this
--    table is what realizes F10's at-most-once contract —
--    cairn-mod-side, not Aurora-imposed. `last_created_at` is the
--    reconciliation window's lower bound (queryEvents filters by
--    RFC3339 time, not by seq). Two-row bookkeeping; no growth.
--
-- 2. `upstream_events` — unchained observational mirror of
--    genuinely-upstream events (echo-suppressed frames are NOT
--    mirrored; cairn-mod's own actions are first-class in
--    subject_actions + pds_admin_audit). Upstream observations
--    cannot ride pds_admin_audit: precipitating_action_id is a
--    NOT NULL FK to subject_actions, backend_method's CHECK covers
--    only cairn-mod's 16 dispatch verbs, and rows are
--    hash-chained (R1 A2). Advisory posture: operators MAY prune
--    (recommended retention 30 days); the event_id UNIQUE is the
--    reconciliation-dedup key and assumes a single Aurora
--    upstream per cairn-mod instance (v2 §11 non-goal).
--
-- 3. `reports.upstream_resolution` — write-once annotation from
--    upstream report_review events, matched by subject
--    coordinates (report ids do not ride the stream — R1 A3).
--    Only the two wire-derivable states; local `status` remains
--    operator-owned.
--
-- 4. `upstream_audit_mirror` — unchained mirror of streamed
--    audit-chain entries, each independently re-verified through
--    v1.8.6's Path A pipeline. `verified_upstream` is Aurora's own
--    per-row recompute (wire field); `verified_local` is
--    cairn-mod's verdict — disagreement is itself signal.
--    Operators MAY prune; `cairn audit cross-verify` remains the
--    authoritative whole-chain surface.
--
-- 5. Partial index on `pds_admin_audit.backend_action_id` — the
--    echo-suppression join key (unindexed at HEAD; index-only
--    change on the hash-chained table, preimage untouched).

CREATE TABLE stream_cursors (
    kind TEXT NOT NULL PRIMARY KEY CHECK (kind IN ('mod_events', 'audit_chain')),
    position INTEGER NOT NULL,
    -- RFC3339 createdAt of the last ingested event (mod_events row
    -- only; NULL for audit_chain).
    last_created_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE TABLE upstream_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Aurora's moderation_event.id (the payload `id`).
    event_id INTEGER NOT NULL UNIQUE,
    -- Envelope sequence when delivered live; NULL for
    -- reconciliation-sourced rows (queryEvents carries no seq).
    stream_seq INTEGER,
    event_type TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    subject_did TEXT,
    subject_uri TEXT,
    subject_cid TEXT,
    -- Raw details JSON, verbatim (the verb disambiguator and the
    -- cascade markers ride here).
    details TEXT,
    created_at TEXT NOT NULL,
    -- Provenance for operator reads.
    source TEXT NOT NULL CHECK (source IN ('stream', 'reconciliation')),
    ingested_at INTEGER NOT NULL
) STRICT;

CREATE INDEX upstream_events_subject_idx ON upstream_events(subject_did, created_at);
CREATE INDEX upstream_events_type_idx ON upstream_events(event_type);

ALTER TABLE reports ADD COLUMN upstream_resolution TEXT
    CHECK (upstream_resolution IN ('resolved', 'dismissed') OR upstream_resolution IS NULL);

CREATE TABLE upstream_audit_mirror (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Aurora chain coordinates.
    entry_id TEXT NOT NULL,
    sequence INTEGER NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    action TEXT NOT NULL,
    subject_did TEXT,
    subject_uri TEXT,
    subject_cid TEXT,
    rationale TEXT NOT NULL,
    snapshot_id TEXT,
    event_id TEXT,
    current_hash TEXT NOT NULL,
    previous_hash TEXT,
    cascade_subjects TEXT,
    cascade_snapshot_ids TEXT,
    source TEXT NOT NULL,
    payload TEXT,
    -- Aurora's own per-row recompute (wire `verified`).
    verified_upstream INTEGER NOT NULL CHECK (verified_upstream IN (0, 1)),
    -- cairn-mod's independent Path A verdict
    -- (v1.8.6 verify_upstream_entry): 1 = V09/Legacy/Sentinel,
    -- 0 = Tampered.
    verified_local INTEGER NOT NULL CHECK (verified_local IN (0, 1)),
    ingested_at INTEGER NOT NULL
) STRICT;

CREATE INDEX upstream_audit_mirror_event_idx ON upstream_audit_mirror(event_id)
    WHERE event_id IS NOT NULL;

CREATE INDEX pds_admin_audit_backend_action_idx
    ON pds_admin_audit(backend_action_id) WHERE backend_action_id IS NOT NULL;
