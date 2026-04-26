//! Unified error taxonomy for the CLI handlers + the exit-code
//! contract (criterion G / §F9's "specific exit codes per error
//! class").
//!
//! Exit codes are a durable part of the CLI contract — scripts that
//! branch on them will depend on the numbers below. Add new classes
//! by appending new codes; renumbering is breaking.

use std::net::SocketAddr;

use thiserror::Error;

use super::pds::PdsError;
use super::session::SessionError;
use crate::signing_key::KeyLoadError;

/// Exit code taxonomy. Matches criterion G from the #16 plan.
pub mod code {
    /// Clean exit.
    pub const SUCCESS: i32 = 0;
    /// Usage / argument parsing. clap exits with 2 directly — this
    /// constant exists so hand-written handlers agree.
    pub const USAGE: i32 = 2;
    /// Session file absent, permissions wrong, version mismatch.
    pub const SESSION: i32 = 3;
    /// Transport-level failure: unreachable host, TLS error, timeout.
    pub const NETWORK: i32 = 4;
    /// PDS rejected credentials OR Cairn returned 401.
    pub const AUTH: i32 = 5;
    /// Cairn returned 403.
    pub const FORBIDDEN: i32 = 6;
    /// Cairn returned some other 4xx.
    pub const SERVER_4XX: i32 = 7;
    /// Cairn returned 5xx.
    pub const SERVER_5XX: i32 = 8;
    /// Internal error (malformed response body, unexpected state).
    pub const INTERNAL: i32 = 10;
    /// `cairn serve` could not acquire the single-instance lease —
    /// another Cairn process holds it with a fresh heartbeat (§F5).
    /// Distinct from INTERNAL so systemd-restart-loop logic can
    /// branch ("another instance is running, don't restart") vs.
    /// genuine internal failure.
    pub const LEASE_CONFLICT: i32 = 11;
    /// Service record verify (§F1, #8): local `[labeler]` config
    /// differs from the published `app.bsky.labeler.service` record
    /// on the PDS. Operator action required: reconcile via
    /// `cairn publish-service-record`.
    pub const SERVICE_RECORD_DRIFT: i32 = 12;
    /// Service record verify (§F1, #8): no record published yet.
    /// Operator action required: run
    /// `cairn publish-service-record` for the first time.
    pub const SERVICE_RECORD_ABSENT: i32 = 13;
    /// Service record verify (§F1, #8): PDS unreachable during
    /// the verify fetch. Transient infra issue; orchestrators
    /// should retry rather than treating as a config drift.
    pub const SERVICE_RECORD_UNREACHABLE: i32 = 14;
    /// `cairn audit verify` (#41) detected a hash-chain divergence:
    /// the chain walked successfully up to row N-1, then row N's
    /// recomputed hash did not match its stored row_hash. Distinct
    /// exit code so monitoring/CI can branch on integrity-failure
    /// (chain broken — operational alert) vs. generic CLI error.
    pub const AUDIT_DIVERGENCE: i32 = 15;
}

/// Error sources the CLI dispatcher knows about. The human-readable
/// `Display` output is what lands on stderr; [`CliError::exit_code`]
/// maps variants onto the [`code`] table.
#[derive(Debug, Error)]
pub enum CliError {
    /// Session-file failure (absent, permissions, ownership,
    /// version mismatch, malformed JSON).
    #[error("{0}")]
    Session(#[from] SessionError),
    /// PDS interaction failure (network, unauthorized, swap-race,
    /// unexpected status, malformed response).
    #[error("{0}")]
    Pds(#[from] PdsError),
    /// Authed command ran with no session file present.
    #[error("not logged in; run `cairn login --cairn-server ... --pds ... --handle ...`")]
    NotLoggedIn,
    /// Transport-level failure contacting a Cairn server URL
    /// (timeout, DNS, TLS, connection refused).
    #[error("network error contacting {url}: {source}")]
    Http {
        /// URL that failed.
        url: String,
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },
    /// Cairn returned a non-2xx HTTP status.
    #[error("Cairn at {url} returned {status}: {body}")]
    CairnStatus {
        /// URL that returned the error.
        url: String,
        /// HTTP status code.
        status: u16,
        /// Response body for operator-side diagnostics.
        body: String,
    },
    /// Cairn returned a 2xx response but the body didn't parse as
    /// the expected shape.
    #[error("could not parse Cairn response from {url}: {source}")]
    MalformedResponse {
        /// URL whose response failed to parse.
        url: String,
        /// Underlying serde_json error.
        #[source]
        source: serde_json::Error,
    },
    /// Argument-shape failure — malformed CLI inputs, config
    /// validation failures.
    #[error("{0}")]
    Config(String),
    /// Signing key file couldn't be loaded (§5.1 invariant failure,
    /// bad hex, wrong length, env-override attempt). Full cause lives
    /// on the nested `KeyLoadError`; `Display` never includes the key
    /// material because the key bytes are never decoded when an error
    /// path runs, and `KeyLoadError::Display` only formats paths +
    /// metadata.
    #[error("signing key load failed: {0}")]
    KeyLoad(#[from] KeyLoadError),
    /// SQLite migrations failed at startup. String-only rather than
    /// wrapping sqlx's error type to avoid leaking schema internals
    /// into the error taxonomy.
    #[error("migrations failed: {0}")]
    MigrationFailed(String),
    /// Another Cairn instance holds the single-instance lease (§F5).
    /// Distinct variant so operators + systemd can branch on the
    /// dedicated [`code::LEASE_CONFLICT`] exit code.
    #[error("another Cairn instance holds the lease (instance_id={instance_id}, age={age_secs}s)")]
    LeaseConflict {
        /// Instance identifier held by the rival process.
        instance_id: String,
        /// Seconds since the rival last heartbeated.
        age_secs: u64,
    },
    /// `TcpListener::bind` failed — port in use, permission denied,
    /// malformed addr, etc.
    #[error("could not bind {addr}: {source}")]
    BindFailed {
        /// Address we attempted to bind.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Anything in the startup sequence that doesn't fit the buckets
    /// above (writer spawn, auth-context init). Rare at runtime;
    /// surfaces as INTERNAL.
    #[error("startup failure: {0}")]
    Startup(String),
    /// `cairn serve` startup verify (§F1, #8): the published
    /// `app.bsky.labeler.service` record on the operator's PDS
    /// differs from what the local `[labeler]` config block would
    /// render. Reconcile via `cairn publish-service-record`.
    #[error(
        "service record verification failed: local [labeler] config differs from the published record at {pds_url}/{service_did}.\n\nDifferences:\n{summary}\n\nThe local config and the published record must agree before `cairn serve` will start. To reconcile, review the differences above, then on the operator's host run:\n\n    cairn publish-service-record --config <path>\n\nto update the PDS record."
    )]
    ServiceRecordDrift {
        /// PDS URL the verify check fetched from.
        pds_url: String,
        /// Labeler service DID whose record was fetched.
        service_did: String,
        /// Per-field drift summary built by `serve::verify`. Not
        /// raw JSON — a human-readable enumeration of the fields
        /// that differ.
        summary: String,
    },
    /// `cairn serve` startup verify (§F1, #8): no
    /// `app.bsky.labeler.service` record exists on the operator's
    /// PDS for the labeler's DID. The labeler hasn't published
    /// its declaration yet.
    #[error(
        "service record verification failed: app.bsky.labeler.service record not found at {pds_url} for repo {service_did}.\n\nThis labeler has not yet published its declaration to the PDS. On the operator's host (where operator credentials are configured), run:\n\n    cairn publish-service-record --config <path>\n\nthen restart `cairn serve`."
    )]
    ServiceRecordAbsent {
        /// PDS URL the verify check fetched from.
        pds_url: String,
        /// Labeler service DID whose record was searched.
        service_did: String,
    },
    /// `cairn serve` startup verify (§F1, #8): could not reach
    /// the PDS to perform the verify fetch. Transient infra
    /// issue, distinct from drift / absent — orchestrators should
    /// retry.
    #[error(
        "service record verification failed: could not reach PDS at {pds_url} to fetch app.bsky.labeler.service.\n\nUnderlying error: {cause}\n\nThis is likely a transient infrastructure issue (PDS down, network flaky, rate limit). Verify the PDS is reachable then retry. If the issue persists, check `operator.pds_url` in your config and confirm the labeler DID's home PDS."
    )]
    ServiceRecordUnreachable {
        /// PDS URL the verify check tried to fetch from.
        pds_url: String,
        /// Underlying error message (transport, status, etc.).
        cause: String,
    },
    /// `cairn audit verify` (#41) detected a hash-chain divergence.
    /// The walk recomputed `row_id`'s row_hash from its content +
    /// the running prev_hash and got `expected_hash`; the row's
    /// stored `actual_hash` did not match. Distinct exit code
    /// ([`code::AUDIT_DIVERGENCE`]) so monitoring/CI can branch on
    /// integrity-failure vs. generic CLI error.
    ///
    /// The dispatcher prints the verify outcome (human or JSON) to
    /// stdout *before* returning this error, so operators see the
    /// structured report on stdout and the same message on stderr
    /// alongside the non-zero exit. Stdout-only consumers
    /// (`cairn audit verify --json`) get the JSON line; the stderr
    /// echo is redundant for them but harmless.
    #[error(
        "audit chain divergence at row {row_id}: expected {expected_hash}, found {actual_hash} ({attested_rows_before_divergence} row(s) verified before divergence)"
    )]
    AuditDivergence {
        /// `audit_log.id` of the row whose recomputed hash did not
        /// match the stored row_hash.
        row_id: i64,
        /// Hex-encoded SHA-256 the chain says this row's row_hash
        /// should be (recomputed from the running prev_hash + the
        /// row's stored content).
        expected_hash: String,
        /// Hex-encoded SHA-256 actually stored in the row's
        /// row_hash column.
        actual_hash: String,
        /// Number of rows whose hashes verified before this one —
        /// the truncation point operators reconcile from.
        attested_rows_before_divergence: i64,
    },
}

impl CliError {
    /// Exit code per criterion G. Kept close to the Display output
    /// so script authors can correlate message prefix with code.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Session(SessionError::Io(_)) => code::SESSION,
            CliError::Session(_) => code::SESSION,
            CliError::NotLoggedIn => code::SESSION,
            CliError::Pds(PdsError::Network { .. }) => code::NETWORK,
            CliError::Pds(PdsError::Unauthorized { .. }) => code::AUTH,
            CliError::Pds(PdsError::InvalidUrl { .. }) => code::USAGE,
            CliError::Pds(PdsError::MalformedResponse { .. }) => code::INTERNAL,
            CliError::Pds(PdsError::SwapRace { .. }) => code::INTERNAL,
            CliError::Pds(PdsError::UnexpectedStatus { status, .. }) => match *status {
                401 => code::AUTH,
                403 => code::FORBIDDEN,
                400..=499 => code::SERVER_4XX,
                500..=599 => code::SERVER_5XX,
                _ => code::INTERNAL,
            },
            CliError::Http { .. } => code::NETWORK,
            CliError::CairnStatus { status, .. } => match *status {
                401 => code::AUTH,
                403 => code::FORBIDDEN,
                400..=499 => code::SERVER_4XX,
                500..=599 => code::SERVER_5XX,
                _ => code::INTERNAL,
            },
            CliError::MalformedResponse { .. } => code::INTERNAL,
            CliError::Config(_) => code::USAGE,
            CliError::KeyLoad(_) => code::INTERNAL,
            CliError::MigrationFailed(_) => code::INTERNAL,
            CliError::LeaseConflict { .. } => code::LEASE_CONFLICT,
            CliError::BindFailed { .. } => code::NETWORK,
            CliError::Startup(_) => code::INTERNAL,
            CliError::ServiceRecordDrift { .. } => code::SERVICE_RECORD_DRIFT,
            CliError::ServiceRecordAbsent { .. } => code::SERVICE_RECORD_ABSENT,
            CliError::ServiceRecordUnreachable { .. } => code::SERVICE_RECORD_UNREACHABLE,
            CliError::AuditDivergence { .. } => code::AUDIT_DIVERGENCE,
        }
    }
}
