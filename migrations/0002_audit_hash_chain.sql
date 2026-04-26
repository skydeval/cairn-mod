-- Audit log hash-chaining (#39, v1.3).
--
-- Adds prev_hash and row_hash columns to audit_log so audit-log tampering is
-- cryptographically detectable, not just trigger-defended (§F10's existing
-- BEFORE UPDATE/DELETE trigger is a correctness defense, not a security
-- defense — anyone with direct SQLite file access can drop the trigger).
--
-- Both columns are NULLable. Pre-v1.3 rows have NULL hashes; new v1.3+ rows
-- always populate both at INSERT time. cairn audit-rebuild (#40) backfills
-- pre-v1.3 rows with hashes computed from their stored content.
--
-- Hash construction (defined in src/audit/hash.rs):
--   row_hash = SHA-256(prev_hash || dag_cbor_canonical(row_content))
-- where row_content excludes id, prev_hash, row_hash and is encoded via
-- proto-blue's lex_cbor::encode (the same canonical profile used for label
-- signing in §6.2). The genesis sentinel for prev_hash is 32 zero bytes —
-- documented as crate::audit::hash::GENESIS_PREV_HASH.
--
-- Trust horizon: the v1.3 append path uses GENESIS_PREV_HASH whenever the
-- latest audit_log row has NULL row_hash. The v1.3 chain is rooted at GENESIS
-- regardless of whether cairn audit-rebuild has run. After rebuild, pre-v1.3
-- rows have hashes too — a separate chain also rooted at GENESIS — but those
-- hashes are unattested. Only post-migration rows carry the integrity claim.
--
-- The hash deliberately excludes the row's id: id is a SQL-level primary key,
-- not part of the audit semantic. Chain integrity locks ordering via prev_hash,
-- not via id. Reordering rows would break each affected row's prev_hash link.

ALTER TABLE audit_log ADD COLUMN prev_hash BLOB;
ALTER TABLE audit_log ADD COLUMN row_hash  BLOB;
