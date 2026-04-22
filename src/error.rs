//! Crate-wide error type.

use thiserror::Error;

/// Top-level error type for the `cairn-mod` library.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("config error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Figment(Box<figment::Error>),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error(transparent)]
    Cbor(#[from] proto_blue_lex_cbor::CborError),

    #[error(transparent)]
    Crypto(#[from] proto_blue_crypto::CryptoError),

    /// Invariant violation specific to label signing (e.g. missing `sig`,
    /// wrong algorithm in the multibase key, sig-length mismatch).
    #[error("signing: {0}")]
    Signing(String),
}

impl From<figment::Error> for Error {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
