-- xrpc_gateway membership tables (#94, v1.7).
--
-- Two append-only-except-revoke tables that gate per-NSID
-- authorization for the inbound XRPC gateway. Per §A9 / §A10
-- they answer cryptographically distinct authorization questions:
--
--   xrpc_known_callers — moderator DIDs whose proxied
--     `tools.ozone.moderation.*` calls cairn-mod accepts (the
--     issuer of the JWT is a user attesting to themselves).
--
--   xrpc_trusted_pdses — PDS DIDs whose forwarded
--     `com.atproto.moderation.createReport` calls cairn-mod
--     accepts (the issuer of the JWT is the PDS attesting to who
--     reportedBy is).
--
-- Conflating these into a single table would create a confused
-- trust model: a row meaning "user X is a moderator" must NOT
-- imply "PDS X is trusted to forward reports". Two tables, two
-- middlewares (per A8.1 layering), two CLI surfaces.
--
-- # Hash-chain integration
--
-- Both tables participate in the unified audit chain (§F23 /
-- #85). ADD is a chained INSERT — the row carries
-- prev_hash + row_hash linking into the chain alongside
-- audit_log + pds_admin_audit. REVOKE is the only permitted
-- UPDATE: it sets revoked_at + revoked_by_moderator on the
-- existing row (which keeps the original chain link intact)
-- AND writes a sibling audit_log row recording the revocation
-- event so revocations are also visible in chain order.
--
-- # Append-only triggers
--
-- BEFORE UPDATE allows ONLY revoked_at + revoked_by_moderator
-- transitions (and only when revoked_at was previously NULL —
-- no re-revocation, no un-revocation). Every other column is
-- frozen at INSERT.
--
-- BEFORE DELETE blocks all hard deletes — revocation is the
-- only path to "this DID is no longer authorized."

PRAGMA foreign_keys = ON;

CREATE TABLE xrpc_known_callers (
    -- Subject DID. Primary key for current-state lookups; the
    -- common query is `SELECT 1 FROM xrpc_known_callers WHERE
    -- did = ?1 AND revoked_at IS NULL`.
    did TEXT PRIMARY KEY,
    -- Operator-supplied label for forensics
    -- (e.g. "alice@bsky.example.com"). Optional but strongly
    -- encouraged so a future operator inspecting the table can
    -- correlate DIDs to humans.
    note TEXT,
    -- DID of the moderator who added this row. Required —
    -- attribution is mandatory for the gateway's audit
    -- forensics. CLI surface enforces via `--by <did>`.
    added_by_moderator TEXT NOT NULL,
    -- Wall-clock epoch-ms at INSERT time. Becomes the row's
    -- chain-ordering timestamp.
    added_at INTEGER NOT NULL,
    -- Revocation columns. NULL until revoked; once set, the
    -- BEFORE UPDATE trigger forbids further mutation. The pair
    -- is updated atomically by `revoke_known_caller`.
    revoked_at INTEGER,
    revoked_by_moderator TEXT,
    -- Hash chain. Computed at INSERT from (did, note,
    -- added_by_moderator, added_at) — the immutable fields. The
    -- revocation columns are NOT part of the hash so revoke can
    -- mutate the row without breaking the chain.
    prev_hash BLOB NOT NULL,
    row_hash BLOB NOT NULL
) STRICT;

CREATE INDEX idx_xrpc_known_callers_active
    ON xrpc_known_callers(did) WHERE revoked_at IS NULL;

-- Append-only-except-revoke. UPDATE is permitted ONLY when:
--   - all immutable columns are unchanged
--   - revoked_at transitions from NULL to non-NULL (set, not change)
--   - revoked_by_moderator transitions from NULL to non-NULL
-- Any other UPDATE shape aborts.
CREATE TRIGGER xrpc_known_callers_only_revoke
BEFORE UPDATE ON xrpc_known_callers
WHEN
    OLD.did IS NOT NEW.did
    OR (OLD.note IS NOT NEW.note)
    OR OLD.added_by_moderator IS NOT NEW.added_by_moderator
    OR OLD.added_at IS NOT NEW.added_at
    OR OLD.prev_hash IS NOT NEW.prev_hash
    OR OLD.row_hash IS NOT NEW.row_hash
    OR (OLD.revoked_at IS NOT NULL AND OLD.revoked_at IS NOT NEW.revoked_at)
    OR (OLD.revoked_by_moderator IS NOT NULL AND OLD.revoked_by_moderator IS NOT NEW.revoked_by_moderator)
BEGIN
    SELECT RAISE(ABORT, 'xrpc_known_callers: only revoked_at + revoked_by_moderator may be set, and only once');
END;

CREATE TRIGGER xrpc_known_callers_no_delete
BEFORE DELETE ON xrpc_known_callers
BEGIN
    SELECT RAISE(ABORT, 'xrpc_known_callers is append-only; use revocation');
END;

CREATE TABLE xrpc_trusted_pdses (
    -- PDS service DID (typically `did:web:<pds-host>`).
    did TEXT PRIMARY KEY,
    note TEXT,
    added_by_moderator TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_by_moderator TEXT,
    prev_hash BLOB NOT NULL,
    row_hash BLOB NOT NULL
) STRICT;

CREATE INDEX idx_xrpc_trusted_pdses_active
    ON xrpc_trusted_pdses(did) WHERE revoked_at IS NULL;

CREATE TRIGGER xrpc_trusted_pdses_only_revoke
BEFORE UPDATE ON xrpc_trusted_pdses
WHEN
    OLD.did IS NOT NEW.did
    OR (OLD.note IS NOT NEW.note)
    OR OLD.added_by_moderator IS NOT NEW.added_by_moderator
    OR OLD.added_at IS NOT NEW.added_at
    OR OLD.prev_hash IS NOT NEW.prev_hash
    OR OLD.row_hash IS NOT NEW.row_hash
    OR (OLD.revoked_at IS NOT NULL AND OLD.revoked_at IS NOT NEW.revoked_at)
    OR (OLD.revoked_by_moderator IS NOT NULL AND OLD.revoked_by_moderator IS NOT NEW.revoked_by_moderator)
BEGIN
    SELECT RAISE(ABORT, 'xrpc_trusted_pdses: only revoked_at + revoked_by_moderator may be set, and only once');
END;

CREATE TRIGGER xrpc_trusted_pdses_no_delete
BEFORE DELETE ON xrpc_trusted_pdses
BEGIN
    SELECT RAISE(ABORT, 'xrpc_trusted_pdses is append-only; use revocation');
END;
