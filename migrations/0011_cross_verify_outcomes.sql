-- v1.8.6 audit verification (v2 §6.1/§9, chainlink #139): the
-- cross-verify persistence surface and the own-chain preimage
-- format boundary.
--
-- **Additive-only** — no table rebuilds, no CHECK extensions, no
-- trigger changes (contrast 0010's family choreography). Per
-- corollary #28 the trigger forward-trace is unaffected: live
-- bodies remain 0010's (subject_actions, pds_admin_audit) and
-- 0001's (audit_log).
--
-- 1. `cross_verify_outcomes` — operational records of
--    `cairn audit cross-verify` runs. Deliberately UNCHAINED and
--    trigger-free: verify outcomes are meta-audit data; chaining
--    them into the structure being verified is recursive and adds
--    no evidence value. Advisory records, not audit evidence —
--    operators MAY prune.
--
-- 2. `pds_admin_audit_format_boundary` — one-row bookkeeping for
--    the v1.8.6 hash-preimage format bump (v2 §5.2). Rows with
--    id at or below the boundary hash under the v1.7 9-field
--    preimage; rows above it under the v1.8.6 12-field preimage
--    (which adds upstream_audit_entry_id / cascading_actions_json
--    / snapshots_json — key-omitted when NULL, so an all-NULL row
--    hashes identically under both forms). The boundary is
--    per-deployment data captured at apply time; verify walks
--    fall back to the 9-field form for post-boundary rows
--    (counted, not failed) as a mid-upgrade defense.

CREATE TABLE cross_verify_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Epoch-ms wall-clock bounds of the run.
    run_started_at INTEGER NOT NULL,
    run_completed_at INTEGER NOT NULL,
    -- Local pass: cairn-mod's own 4-table chain verify.
    local_verified INTEGER NOT NULL CHECK (local_verified IN (0, 1)),
    -- Rows attested locally before any divergence (NULL when the
    -- local pass was clean end-to-end and the count equals the
    -- attested total in the notes).
    local_verified_through INTEGER,
    -- Upstream pass: Aurora's chainVerified AND cairn-mod's
    -- independent Path A walk agreeing.
    upstream_verified INTEGER NOT NULL CHECK (upstream_verified IN (0, 1)),
    upstream_verified_through INTEGER,
    -- Aurora-reported legacy-form count for the verified window.
    upstream_legacy_count INTEGER,
    -- Join pass: local dispatch rows vs upstream chain entries.
    cross_verified INTEGER NOT NULL CHECK (cross_verified IN (0, 1)),
    -- Structured JSON: unjoinable rows (NULL join keys), join
    -- mismatches, independent-walk detail, sentinel counts,
    -- pagination extent.
    cross_verify_notes TEXT
) STRICT;

-- History reads (`cairn audit cross-verify --history`) list
-- newest-first.
CREATE INDEX cross_verify_outcomes_started_idx
    ON cross_verify_outcomes(run_started_at DESC);

CREATE TABLE pds_admin_audit_format_boundary (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- Max pds_admin_audit.id at 0011 apply time; 0 on fresh
    -- deployments (every row then hashes under the 12-field
    -- form).
    boundary_id INTEGER NOT NULL
) STRICT;

INSERT INTO pds_admin_audit_format_boundary (id, boundary_id)
SELECT 1, COALESCE(MAX(id), 0) FROM pds_admin_audit;
