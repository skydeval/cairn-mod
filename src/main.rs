//! `cairn` — ATProto labeler binary entry point.

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

/// Cairn — lightweight Rust-native ATProto labeler.
#[derive(Debug, Parser)]
#[command(name = "cairn", version, about)]
struct Cli {}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let _cli = Cli::parse();

    let config = cairn_mod::Config::load().context("loading configuration")?;
    tracing::info!(service_did = %config.service_did, "cairn started");

    Ok(())
}
