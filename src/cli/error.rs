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
        }
    }
}
