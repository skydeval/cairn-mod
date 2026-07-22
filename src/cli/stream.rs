//! `cairn stream` operator surface (v1.8.8, v2 §8, chainlink
//! #147).
//!
//! DB-backed only: the CLI runs in a separate process from
//! `cairn serve`, so the consumer task's in-process counters are
//! not reachable here — `status` reports the durable state
//! (cursor rows + observational-table statistics), which is also
//! exactly what survives restarts. Cursor overrides are the
//! documented at-most-once escape hatches: `reset mod_events`
//! makes the next connect cursor-less (live-only from tail, with
//! reconciliation available for the gap); `set` enables
//! deliberate replay into idempotent ingestion
//! (`upstream_events.event_id UNIQUE` absorbs duplicates).
//!
//! `start` / `stop` subcommands are deferred (flagged on #147):
//! they need an authenticated server-side control endpoint, which
//! is its own small design against the xrpc_gateway auth surface.
//! The v1.8.8 operator mechanism is the
//! `[pds_admin.rust.stream].enabled` toggle + process restart
//! (which also clears a HardStop).

use serde_json::json;
use sqlx::{Pool, Sqlite};

use crate::cli::error::CliError;
use crate::pds_admin::rust::stream::read_cursor;

/// Valid `stream_cursors.kind` values (mirrors the 0012 CHECK).
pub const CURSOR_KINDS: [&str; 2] = ["mod_events", "audit_chain"];

fn validate_kind(kind: &str) -> Result<(), CliError> {
    if CURSOR_KINDS.contains(&kind) {
        Ok(())
    } else {
        Err(CliError::Config(format!(
            "cursor kind must be one of mod_events/audit_chain; got {kind:?}"
        )))
    }
}

/// `cairn stream status` — durable stream state.
pub async fn status(pool: &Pool<Sqlite>) -> Result<String, CliError> {
    let mut cursors = serde_json::Map::new();
    for kind in CURSOR_KINDS {
        let row = read_cursor(pool, kind).await;
        cursors.insert(
            kind.to_string(),
            match row {
                Some((position, last_created_at)) => json!({
                    "position": position,
                    "lastCreatedAt": last_created_at,
                }),
                None => serde_json::Value::Null,
            },
        );
    }

    let scalar = |sql: &str| {
        let sql = sql.to_string();
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&sql)
                .fetch_one(&pool)
                .await
                .map_err(|e| CliError::Startup(format!("stream status query: {e}")))
        }
    };
    let upstream_events = scalar("SELECT COUNT(*) FROM upstream_events").await?;
    let reconciled =
        scalar("SELECT COUNT(*) FROM upstream_events WHERE source = 'reconciliation'").await?;
    let mirror_rows = scalar("SELECT COUNT(*) FROM upstream_audit_mirror").await?;
    let tampered =
        scalar("SELECT COUNT(*) FROM upstream_audit_mirror WHERE verified_local = 0").await?;
    let disagreements = scalar(
        "SELECT COUNT(*) FROM upstream_audit_mirror WHERE verified_local != verified_upstream",
    )
    .await?;
    let annotated =
        scalar("SELECT COUNT(*) FROM reports WHERE upstream_resolution IS NOT NULL").await?;

    Ok(serde_json::to_string_pretty(&json!({
        "cursors": cursors,
        "upstreamEvents": {
            "total": upstream_events,
            "viaReconciliation": reconciled,
        },
        "auditMirror": {
            "total": mirror_rows,
            "tamperedLocal": tampered,
            "verdictDisagreements": disagreements,
        },
        "reportsAnnotated": annotated,
        "note": "durable state only; live task counters are in the serve process logs",
    }))
    .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")))
}

/// `cairn stream cursor get` — both rows, raw.
pub async fn cursor_get(pool: &Pool<Sqlite>) -> Result<String, CliError> {
    let mut out = serde_json::Map::new();
    for kind in CURSOR_KINDS {
        out.insert(
            kind.to_string(),
            match read_cursor(pool, kind).await {
                Some((position, last_created_at)) => json!({
                    "position": position,
                    "lastCreatedAt": last_created_at,
                }),
                None => serde_json::Value::Null,
            },
        );
    }
    Ok(
        serde_json::to_string_pretty(&serde_json::Value::Object(out))
            .unwrap_or_else(|e| format!("{{\"error\": \"render: {e}\"}}")),
    )
}

/// `cairn stream cursor set <kind> <position>` — deliberate
/// replay override. Replayed frames re-ingest idempotently.
pub async fn cursor_set(pool: &Pool<Sqlite>, kind: &str, position: i64) -> Result<(), CliError> {
    validate_kind(kind)?;
    sqlx::query(
        "INSERT INTO stream_cursors (kind, position)
         VALUES (?1, ?2)
         ON CONFLICT (kind) DO UPDATE SET
             position = excluded.position,
             updated_at = datetime('now')",
    )
    .bind(kind)
    .bind(position)
    .execute(pool)
    .await
    .map_err(|e| CliError::Startup(format!("cursor set: {e}")))?;
    Ok(())
}

/// `cairn stream cursor reset <kind>` — delete the row. Next
/// connect is cursor-less (mod_events: live-only from tail;
/// audit_chain: re-verifies from position 0 into the deduping
/// mirror).
pub async fn cursor_reset(pool: &Pool<Sqlite>, kind: &str) -> Result<u64, CliError> {
    validate_kind(kind)?;
    let result = sqlx::query("DELETE FROM stream_cursors WHERE kind = ?1")
        .bind(kind)
        .execute(pool)
        .await
        .map_err(|e| CliError::Startup(format!("cursor reset: {e}")))?;
    Ok(result.rows_affected())
}
