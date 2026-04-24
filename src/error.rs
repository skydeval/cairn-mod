//! Crate-wide error type.

use thiserror::Error;

/// Top-level error type for the `cairn-mod` library.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Configuration loading or validation failed.
    #[error("config error: {0}")]
    Config(String),

    /// I/O failure (filesystem, stdio, etc.).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Figment config-source failure (TOML parse, env-var extraction).
    #[error(transparent)]
    Figment(Box<figment::Error>),

    /// SQLx query or connection failure.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    /// Embedded migration runner failed.
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// DAG-CBOR encode / decode failure from `proto-blue-lex-cbor`.
    #[error(transparent)]
    Cbor(#[from] proto_blue_lex_cbor::CborError),

    /// Cryptographic primitive failure (signing, hashing, key parse).
    #[error(transparent)]
    Crypto(#[from] proto_blue_crypto::CryptoError),

    /// Invariant violation specific to label signing (e.g. missing `sig`,
    /// wrong algorithm in the multibase key, sig-length mismatch).
    #[error("signing: {0}")]
    Signing(String),

    /// Another Cairn instance holds a fresh lease on the same SQLite file
    /// (§F5 single-instance invariant). Refusing to start — the other
    /// instance must shut down or its lease must age past 60s.
    #[error(
        "server_instance_lease held by another instance (instance_id={instance_id}, last heartbeat {age_secs}s ago)"
    )]
    LeaseHeld {
        /// Instance identifier of the rival process holding the lease.
        instance_id: String,
        /// Seconds since that instance last heartbeated.
        age_secs: u64,
    },

    /// Negating a label that does not currently apply. Either the tuple
    /// `(src, uri, val)` has no apply events, or the most recent event for
    /// the tuple is already a negation (§F6).
    #[error("no applied label for ({src}, {uri}, {val}) — nothing to negate")]
    LabelNotFound {
        /// Labeler DID (Cairn's own service DID for emissions).
        src: String,
        /// Subject AT-URI or DID.
        uri: String,
        /// Label value.
        val: String,
    },

    /// `resolveReport` (§F12) targeted a report id that doesn't exist.
    /// Surface via the handler as `ReportNotFound` (declared lexicon error).
    #[error("report not found: id={id}")]
    ReportNotFound {
        /// Report primary key that didn't resolve.
        id: i64,
    },

    /// `resolveReport` (§F12) targeted a report that is already resolved.
    /// Surface via the handler as `InvalidRequest` with a generic message
    /// (no timestamps or resolver DID per the anti-leak principle).
    #[error("report already resolved: id={id}")]
    ReportAlreadyResolved {
        /// Report primary key that was already resolved.
        id: i64,
    },
}

impl From<figment::Error> for Error {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

/// Crate-wide `Result` alias using [`enum@Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;
