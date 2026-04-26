-- Account moderation state model (#46, v1.4, §F20).
--
-- Two tables introduced for the graduated-action moderation surface
-- (warning / note / temp_suspension / indef_suspension / takedown):
--
-- 1. subject_actions — append-only log of moderation actions. Each
--    row captures the action's intent, the strike weight applied at
--    action time (frozen for forensic history), and revocation
--    metadata. Same correctness-not-security posture as audit_log
--    (#39 §F10): the no-update trigger blocks all column changes
--    EXCEPT the one-time revocation transition (NULL → non-NULL on
--    revoked_at + revoked_by_did + revoked_reason). DELETE is
--    unconditionally blocked.
--
-- 2. subject_strike_state — cache keyed by account DID. Recomputed
--    by the strike calculator (#49) on every recordAction /
--    revokeAction (#51, #53) within the same transaction as the
--    subject_actions write, and lazily on read when last_recompute_at
--    is older than the configured threshold (#55). Background refresh
--    deferred to v1.5.
--
-- Strike accounting is unified at the account level: subject_actions
-- can target either a DID (account-level action) or an at:// URI
-- (record-level action), but subject_strike_state is keyed by the
-- parent account DID only.
--
-- This migration is JUST the schema. Rust structs + queries that
-- consume these tables come in subsequent issues (#47-#55); the
-- writer-task RecordAction / RevokeAction variants and the strike
-- calculators are also in those issues.

PRAGMA foreign_keys = ON;

-- Append-only log of moderation actions (§F20). action_type is the
-- operator-facing graduated-action enum; revocation is tracked via
-- the revoked_at columns on the original row, NOT as a separate
-- action_type, so this enum has five values.
CREATE TABLE subject_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Account DID this action is attributed to. For record-level
    -- actions, the parent account; for account-level, the account
    -- itself. Strike accounting always rolls up to this DID.
    subject_did TEXT NOT NULL,
    -- Optional record URI for record-level actions (taking down a
    -- single post, e.g.). NULL for account-level actions.
    subject_uri TEXT,
    -- DID of the moderator/admin who recorded this action. JWT iss
    -- when from XRPC; CLI's caller DID when from `cairn moderator`.
    actor_did TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type IN (
        'warning', 'note', 'temp_suspension', 'indef_suspension', 'takedown'
    )),
    -- JSON array of reason-code strings (e.g. '["hate-speech",
    -- "harassment"]'). Validation against the [moderation_reasons]
    -- vocabulary is application-level (#47); the column itself
    -- just stores the JSON.
    reason_codes TEXT NOT NULL,
    -- Original ISO-8601 duration string (e.g. 'P7D'), preserved for
    -- display. expires_at is the canonical "when does this end"
    -- surface for queries.
    duration TEXT,
    -- Epoch-ms wall-clock at which the action takes effect. Equal
    -- to created_at for immediate actions; may be in the future
    -- for scheduled ones.
    effective_at INTEGER NOT NULL,
    -- Epoch-ms wall-clock at which the action expires. NULL for
    -- warning, note, indef_suspension, takedown. Computed from
    -- effective_at + duration for temp_suspension.
    expires_at INTEGER,
    -- Optional moderator note / rationale.
    notes TEXT,
    -- JSON array of report IDs that motivated this action (e.g.
    -- '[42, 47]'). NULL when no reports were involved (proactive
    -- moderation).
    report_ids TEXT,
    -- Strike weight from the reason vocabulary (#47) BEFORE
    -- dampening. For multi-reason actions, the highest base_weight
    -- among the declared reasons (severe reasons always win — they
    -- bypass dampening even when paired with non-severe).
    strike_value_base INTEGER NOT NULL,
    -- Strike weight ACTUALLY APPLIED to the subject's strike count
    -- after dampening was computed and frozen at action time per
    -- the strike calculator (#49). For a user in good standing
    -- this may be lower than the base; for severe reasons or
    -- out-of-good-standing users, equals base.
    strike_value_applied INTEGER NOT NULL,
    -- Whether dampening reduced the applied weight. Stored
    -- explicitly so a forensic reader doesn't have to derive it
    -- from base vs. applied (which can be ambiguous when base
    -- happens to equal applied for an undampened user — e.g.,
    -- base = 1 with no dampening curve drop applies).
    was_dampened INTEGER NOT NULL DEFAULT 0 CHECK (was_dampened IN (0, 1)),
    -- The subject's strike count at the moment the action was
    -- recorded. Frozen for forensic history — three years later, an
    -- operator can see exactly what state the user was in when
    -- this decision was made.
    strikes_at_time_of_action INTEGER NOT NULL,
    -- Revocation metadata. NULL until the action is revoked via
    -- `cairn moderator revoke` (#51) or
    -- tools.cairn.admin.revokeAction (#53); once set, the
    -- no-update trigger prevents further changes (no
    -- re-revocation, no un-revocation).
    revoked_at INTEGER,
    revoked_by_did TEXT,
    revoked_reason TEXT,
    -- FK to the audit_log row that captured this action's intent.
    -- Always populated by the writer; the rare NULL case would be
    -- a future migration backfill scenario, kept nullable for
    -- safety.
    audit_log_id INTEGER REFERENCES audit_log(id),
    -- Internal wall-clock at INSERT, kept distinct from
    -- effective_at because effective_at may be in the future for
    -- scheduled actions.
    created_at INTEGER NOT NULL
) STRICT;

-- History queries (`cairn moderator history <subject>` #52,
-- getSubjectHistory #53) want id-ordered scans by subject_did with
-- fast filtering on created_at; the composite index serves both.
CREATE INDEX subject_actions_subject_idx ON subject_actions(subject_did, created_at);
-- Audit-log cross-reference: given an audit_log row, find the
-- subject_actions row it created. Partial index keeps it small.
CREATE INDEX subject_actions_audit_idx ON subject_actions(audit_log_id) WHERE audit_log_id IS NOT NULL;
-- Active-action queries (suspension currently in effect, takedown
-- not yet revoked) filter on revoked_at IS NULL frequently. Partial
-- index on the active-only subset stays small under heavy
-- revocation churn.
CREATE INDEX subject_actions_active_idx ON subject_actions(subject_did) WHERE revoked_at IS NULL;

-- §F20 trigger: subject_actions is append-only EXCEPT for the
-- one-time revocation transition. The trigger blocks any UPDATE
-- that changes the immutable core columns, AND blocks UPDATE that
-- would change a non-NULL revocation column (no re-revocation, no
-- un-revocation). Same correctness-not-security posture as
-- audit_log_no_update (#39 §F10): defends against bugs in
-- cairn-mod's own write paths, not against direct DB tampering.
-- The whole-row hash-chain attestation that audit_log gains in #39
-- is the only cryptographic defense against direct-DB tampering;
-- this trigger is the application-layer guardrail.
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
BEGIN
    SELECT RAISE(ABORT, 'subject_actions is append-only except for one-time revocation');
END;

CREATE TRIGGER subject_actions_no_delete BEFORE DELETE ON subject_actions
BEGIN
    SELECT RAISE(ABORT, 'subject_actions is append-only');
END;

-- Strike-state cache (§F20 / #55). Holds a single row per account
-- DID with the cached strike total + recompute timestamp. No
-- triggers — the cache is meant to be updateable on every action
-- write and on every stale-cache read. Recompute logic uses the
-- decay calculator (#50); the lifecycle is governed by #55.
CREATE TABLE subject_strike_state (
    subject_did TEXT PRIMARY KEY,
    -- Currently-active strike count (excluding revoked actions and
    -- already-decayed contributions) per the strike calculator
    -- (#49) and decay calculator (#50).
    current_strike_count INTEGER NOT NULL DEFAULT 0,
    -- Most recent action's effective_at; used by the dampening
    -- calculator (#49) to compute "position within dampening
    -- window" without re-scanning subject_actions.
    last_action_at INTEGER,
    -- When was current_strike_count last recomputed. Reads decide
    -- if a fresh recompute is needed by comparing this against
    -- now() and the configured threshold (#55, default 1 hour).
    last_recompute_at INTEGER NOT NULL
) STRICT;
