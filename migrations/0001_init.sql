-- Initial schema for Cairn storage (§10 architecture).
--
-- All user tables are STRICT for SQLite-enforced type safety.
-- Wire-facing timestamps (RFC 3339 `Z`-suffixed, ms precision per §6.1) are
-- TEXT; internal timestamps are INTEGER epoch-ms. Signatures are BLOB in raw
-- 64-byte compact `(r, s)` form per §6.2.
--
-- Tables: label_sequence, signing_keys, labels, reports, moderators,
-- audit_log, labeler_config, server_instance_lease, suppressed_reporters.

PRAGMA foreign_keys = ON;

-- Frame-sequence counter (§F5). Writer uses
-- `INSERT INTO label_sequence DEFAULT VALUES RETURNING seq` to claim the next
-- strictly-monotonic frame seq before constructing the label record.
CREATE TABLE label_sequence (
    seq INTEGER PRIMARY KEY AUTOINCREMENT
) STRICT;

-- Signing-key registry (§F8). Schema-only in v1 — exactly one active row
-- expected; rotation is a v1.1 feature. `public_key_multibase` is the
-- publicKeyMultibase form published at verification method `#atproto_label`.
-- `valid_from`/`valid_to` are RFC-3339 `Z`-suffixed strings, lexicographically
-- comparable against `labels.cts` so key lookup at a label's `cts` is an
-- indexed range query without date parsing.
CREATE TABLE signing_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_multibase TEXT NOT NULL UNIQUE,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    created_at INTEGER NOT NULL
) STRICT;

-- Emitted labels (§6.1). `seq` is the frame sequence from `label_sequence`
-- and is the cursor value surfaced on the `#labels` frame in subscribeLabels.
-- `cts` is the wire-format RFC-3339 timestamp (per §6.1 monotonicity clamp);
-- `created_at` is the internal wall-clock at INSERT, kept distinct because
-- `cts` may be clamped forward of wall clock under rapid re-emission.
CREATE TABLE labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL UNIQUE REFERENCES label_sequence(seq),
    ver INTEGER NOT NULL,
    src TEXT NOT NULL,
    uri TEXT NOT NULL,
    cid TEXT,
    val TEXT NOT NULL,
    neg INTEGER NOT NULL DEFAULT 0 CHECK (neg IN (0, 1)),
    cts TEXT NOT NULL,
    exp TEXT,
    sig BLOB NOT NULL,
    signing_key_id INTEGER NOT NULL REFERENCES signing_keys(id),
    created_at INTEGER NOT NULL
) STRICT;

-- queryLabels filters by URI (prefix or exact per F3); uri index serves both.
CREATE INDEX labels_uri_idx ON labels(uri);
-- Monotonicity clamp looks up prior `cts` for a given (src, uri, val) tuple;
-- negation lookup queries the same prefix. Composite index covers both.
CREATE INDEX labels_tuple_idx ON labels(src, uri, val);

-- Reports (§F11). `created_at` is wire-format TEXT because the response shape
-- surfaces it as `createdAt`. The sliding-window rate-limit query compares
-- `reported_by` + `created_at`, so the composite index below covers it.
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    reported_by TEXT NOT NULL,
    reason_type TEXT NOT NULL,
    reason TEXT,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('account', 'record')),
    subject_did TEXT NOT NULL,
    subject_uri TEXT,
    subject_cid TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved')),
    resolved_at TEXT,
    resolved_by TEXT,
    resolution_label TEXT,
    resolution_reason TEXT
) STRICT;

CREATE INDEX reports_status_idx ON reports(status);
CREATE INDEX reports_reporter_created_idx ON reports(reported_by, created_at);

-- Moderators (§5.2, §F9). Role grants are authorization rows; revocation is a
-- hard delete — the audit_log preserves the grant/revoke history.
CREATE TABLE moderators (
    did TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('mod', 'admin')),
    added_by TEXT,
    added_at INTEGER NOT NULL
) STRICT;

-- Audit log (§F10). `created_at` is internal wall-clock epoch-ms; `id` is the
-- monotonic audit-log seq referenced by §F10 "timestamps (seq + wall clock)".
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    target TEXT,
    target_cid TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    reason TEXT
) STRICT;

CREATE INDEX audit_log_actor_idx ON audit_log(actor_did);
CREATE INDEX audit_log_action_idx ON audit_log(action);
CREATE INDEX audit_log_created_at_idx ON audit_log(created_at);

-- §F10 / §12: append-only enforcement. This is a correctness defense against
-- bugs in Cairn's own write paths, NOT a security boundary — anyone with
-- direct SQLite file access can DROP TRIGGER or replace the file. Hash-chain
-- integrity is v1.1.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

-- Labeler config (consolidated: §F1 service-record state + future knobs).
-- Keyed kv store; `value` is opaque TEXT (callers parse as JSON/bytes/scalar
-- per key semantics). Known keys used by F1:
--   `service_record_cid`           — current published record CID (for swapRecord)
--   `service_record_content_hash`  — SHA-256 of the rendered record body,
--                                     excluding `createdAt`, for idempotency
--   `service_record_created_at`    — RFC-3339 `createdAt` of the current record,
--                                     preserved across content-identical republishes
CREATE TABLE labeler_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Single-instance lease (§F5). Singleton row (id=1). Startup refuses if a
-- live lease (last_heartbeat within 60s) exists. Heartbeat every 10s; clean
-- shutdown releases.
CREATE TABLE server_instance_lease (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id TEXT NOT NULL,
    acquired_at INTEGER NOT NULL,
    last_heartbeat INTEGER NOT NULL
) STRICT;

-- Suppressed reporters (§F11). DIDs listed here get `RateLimitExceeded` from
-- createReport with no indication of suppression (non-enumeration § 4.5).
CREATE TABLE suppressed_reporters (
    did TEXT PRIMARY KEY,
    suppressed_by TEXT NOT NULL,
    suppressed_at INTEGER NOT NULL,
    reason TEXT
) STRICT;
