//! SQLite storage layer (§10 architecture).
//!
//! Owns the connection pool, migration runner, and the small surface of
//! cross-cutting queries (currently just a health probe). Domain-specific
//! query modules (labels, reports, audit, etc.) will land alongside the
//! writer task in subsequent issues.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use sqlx::{
    Pool, Sqlite,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use crate::error::Result;

/// Embedded migration bundle. Sources from `./migrations/` relative to the
/// crate root at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Open a SQLite connection pool at `path`, creating the file if it doesn't
/// exist, and run all pending migrations.
///
/// WAL mode and a 5s busy timeout are set per §F5 "Writer architecture."
/// Foreign keys are enabled (off by default in SQLite).
pub async fn open<P: AsRef<Path>>(path: P) -> Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::new()
        .filename(path.as_ref())
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5000))
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;

    MIGRATOR.run(&pool).await?;

    Ok(pool)
}

/// Point-in-time storage health snapshot.
#[derive(Debug, Serialize)]
pub struct Health {
    /// Total rows in the `labels` table (emitted labels, including negations).
    pub labels: i64,
    /// The current single-instance lease row, if one is held.
    pub lease: Option<Lease>,
}

/// The singleton row from `server_instance_lease`.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Lease {
    pub instance_id: String,
    pub acquired_at: i64,
    pub last_heartbeat: i64,
}

/// Query the current storage health: label count and live instance lease.
///
/// Intentionally cheap — exists both as an operator-facing sanity check and
/// as the smoke query that exercises the compile-time-checked `sqlx` offline
/// cache in CI.
pub async fn health(pool: &Pool<Sqlite>) -> Result<Health> {
    let labels: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM labels")
        .fetch_one(pool)
        .await?;

    let lease = sqlx::query_as!(
        Lease,
        "SELECT instance_id, acquired_at, last_heartbeat \
         FROM server_instance_lease WHERE id = 1"
    )
    .fetch_optional(pool)
    .await?;

    Ok(Health { labels, lease })
}

#[cfg(test)]
mod tests {
    use super::*;

    // `:memory:` + a pooled connection is unsound — each pool connection gets
    // its own independent in-memory DB, so migrations applied on one wouldn't
    // be visible to the next. Use a tempfile so the pool shares real storage.
    #[tokio::test]
    async fn migrations_apply_to_fresh_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pool = open(dir.path().join("cairn.db")).await.expect("open pool");
        let h = health(&pool).await.expect("health query");
        assert_eq!(h.labels, 0);
        assert!(h.lease.is_none());
    }
}
