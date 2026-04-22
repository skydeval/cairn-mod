//! Layered config loading.
//!
//! Precedence (lowest → highest): compiled-in defaults, then TOML file,
//! then environment variables prefixed `CAIRN_`. CLI-flag overrides land
//! once the clap surface grows subcommands.
//!
//! Per §5.1, signing-key private material is NEVER sourced through this
//! path. The signing-key *path* may be configured here in a later issue,
//! but the bytes are read only by the signing module with explicit
//! permission and ownership checks.

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::path::PathBuf;

use crate::error::Result;

/// Top-level Cairn configuration.
///
/// Fields grow with features; the struct is `non_exhaustive` so additions
/// are not a breaking change for downstream crates.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Config {
    /// The service DID Cairn runs as (§5.1).
    pub service_did: String,
}

impl Config {
    /// Load configuration. Sources, low to high precedence:
    /// 1. Compiled-in defaults (none yet).
    /// 2. TOML at the path in `CAIRN_CONFIG`, or `/etc/cairn/cairn.toml` if that file exists.
    /// 3. Environment variables prefixed `CAIRN_` (e.g. `CAIRN_SERVICE_DID`).
    pub fn load() -> Result<Self> {
        let toml_path: PathBuf = std::env::var_os("CAIRN_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/cairn/cairn.toml"));

        let mut fig = Figment::new();
        if toml_path.is_file() {
            fig = fig.merge(Toml::file(&toml_path));
        }
        fig = fig.merge(Env::prefixed("CAIRN_"));

        Ok(fig.extract()?)
    }
}
