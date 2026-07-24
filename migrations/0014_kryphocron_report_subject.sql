-- v1.8.13 report-flow private-record retrieval (§4.B.2, chainlink #167):
-- extend the `reports.subject_type` CHECK with 'kryphocron_record'
-- and add two columns for the decode path.
--
-- Rebuild technique: SQLite cannot alter a CHECK in place, so the
-- `subject_type` CHECK extension requires a table rebuild
-- (CREATE _new + INSERT..SELECT + DROP + RENAME), mirroring 0010's
-- idiom. Unlike 0010's `subject_actions` (an FK parent needing the
-- full-family choreography), `reports` is childless: it has no
-- triggers, no views, and no foreign keys in either direction
-- (DDL forward-trace verified across 0001-0013). So this is the
-- simple rebuild — no child staging, no PRAGMA gymnastics.
--
-- No explicit BEGIN/COMMIT: sqlx's Migrator wraps each migration in
-- a transaction (see 0010's note); an explicit transaction here
-- would double-wrap.
--
-- id preservation is LOAD-BEARING: `subject_actions.report_ids`
-- (0003) stores report ids BY VALUE as a JSON array (e.g. '[42,47]'),
-- not a foreign key, so the INSERT..SELECT copies `id` verbatim and
-- SQLite's AUTOINCREMENT sequence re-derives from MAX(id) — every
-- existing reference resolves unchanged.
--
-- Data-sensitivity note: `decoded_plaintext` holds decoded private-
-- tier content at rest. This is deliberate — laquna is a friction
-- encoding, not confidentiality (v1.8 kryphocron threat model), so
-- decoded plaintext crosses no threat boundary the encoded form
-- didn't already. Same retention and moderator-only ACLs as `reason`.

CREATE TABLE reports_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    reported_by TEXT NOT NULL,
    reason_type TEXT NOT NULL,
    reason TEXT,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('account', 'record', 'kryphocron_record')),
    subject_did TEXT NOT NULL,
    subject_uri TEXT,
    subject_cid TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved')),
    resolved_at TEXT,
    resolved_by TEXT,
    resolution_label TEXT,
    resolution_reason TEXT,
    -- 0012 realtime infrastructure: upstream resolution mirror.
    upstream_resolution TEXT
        CHECK (upstream_resolution IN ('resolved', 'dismissed') OR upstream_resolution IS NULL),
    -- v1.8.13: which decode path produced `decoded_plaintext`.
    -- NULL for non-kryphocron subjects; 'aurora_server' when the PDS
    -- returned server-side-decoded `text` (authorized read);
    -- 'cairn_client' when cairn-mod client-side-decoded `encodedContent`.
    decode_source TEXT
        CHECK (decode_source IN ('aurora_server', 'cairn_client') OR decode_source IS NULL),
    -- v1.8.13: decoded private-tier plaintext for kryphocron_record
    -- subjects (see data-sensitivity note above). NULL otherwise.
    decoded_plaintext TEXT
) STRICT;

INSERT INTO reports_new (
    id, created_at, reported_by, reason_type, reason, subject_type,
    subject_did, subject_uri, subject_cid, status, resolved_at, resolved_by,
    resolution_label, resolution_reason, upstream_resolution,
    decode_source, decoded_plaintext
)
SELECT
    id, created_at, reported_by, reason_type, reason, subject_type,
    subject_did, subject_uri, subject_cid, status, resolved_at, resolved_by,
    resolution_label, resolution_reason, upstream_resolution,
    NULL, NULL
FROM reports;

DROP TABLE reports;

ALTER TABLE reports_new RENAME TO reports;

-- Recreate the 0001 indexes.
CREATE INDEX reports_status_idx ON reports(status);
CREATE INDEX reports_reporter_created_idx ON reports(reported_by, created_at);
