//! Single-writer task (§F5 / §10 architecture).
//!
//! All mutations to `labels`, `label_sequence`, `audit_log`, and
//! `server_instance_lease` flow through one task that owns the write pool.
//! Other components obtain a cheaply-cloneable [`WriterHandle`] and submit
//! [`ApplyLabelRequest`] / [`NegateLabelRequest`] over an mpsc channel;
//! replies travel on per-request oneshot channels so the caller may cancel
//! (drop the future) without corrupting writer state — the transaction
//! still commits, the reply is discarded.
//!
//! Invariants this module enforces, any of which is load-bearing:
//!
//! - **Single instance.** On startup [`spawn`] either acquires the lease
//!   row in `server_instance_lease` (id = 1) or returns
//!   [`Error::LeaseHeld`]. A background heartbeat updates `last_heartbeat`
//!   every 10s; a second Cairn started against the same file sees a
//!   <60s-old heartbeat and refuses. The 60s threshold is 6× the heartbeat
//!   interval — tolerant of a single missed tick, strict enough that a
//!   legitimately-orphaned lease (hard crash, unclean shutdown) ages out
//!   before the operator manually restarts.
//!
//! - **Monotonic seq.** Sequence values come from
//!   `label_sequence.seq` (AUTOINCREMENT) reserved inside the same
//!   transaction as the `labels` INSERT. Under AUTOINCREMENT, SQLite
//!   never reuses a seq value even across rollbacks.
//!
//! - **Monotonic cts.** For each `(src, uri, val)` tuple the writer
//!   clamps to `max(wall_now, prev_cts + 1ms)` (§6.1) using the
//!   `labels_tuple_idx` composite index for the prev-cts lookup.
//!
//! - **Audit-per-write.** Every successful label INSERT produces exactly
//!   one `audit_log` row **in the same transaction**. The audit row's
//!   `reason` column carries a JSON object documenting the event
//!   ({"val", "neg", "moderator_reason"}). See [`AUDIT_REASON_SCHEMA`].
//!
//! - **Sign-then-insert.** `sign_label` runs between sequence reservation
//!   and the labels INSERT. The signed bytes include `ver` but not `seq`
//!   or `signing_key_id` (§6.2 step 1, §6.1: seq lives on the frame, not
//!   the label).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proto_blue_crypto::{K256Keypair, Keypair as _, format_multikey};
use sqlx::{Pool, Sqlite};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::label::Label;
use crate::signing::sign_label;
use crate::signing_key::SigningKey;

/// Lease freshness threshold (§F5). A lease younger than this is held by
/// a live peer; younger than 10s would be flaky under a single missed
/// heartbeat, older than ~2× the value risks a genuine zombie blocking a
/// legitimate restart for too long.
const LEASE_STALE_MS: i64 = 60_000;

/// Heartbeat interval. 10s × 6 = 60s staleness budget per the threshold.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Upper bound on queued write commands. Moderators rarely drive more
/// than single-digit req/s even on busy operators; 64 is a comfortable
/// overshoot that still makes backpressure visible quickly under a bug.
const COMMAND_BUFFER: usize = 64;

/// Broadcast buffer for [`LabelEvent`] fan-out. Slow subscribers hit
/// `RecvError::Lagged` past this; the subscribeLabels endpoint (#7) turns
/// that into a client-connection close.
const BROADCAST_BUFFER: usize = 1024;

/// Audit-log `reason` JSON schema for `label_applied` / `label_negated`.
/// Centralized as a doc constant so future actions (signing_key_added,
/// report_resolved, etc.) have an obvious place to register their shape.
///
/// ```json
/// {
///   "val": "<label value>",
///   "neg": true | false,
///   "moderator_reason": "<free text>" | null
/// }
/// ```
#[doc(alias = "audit_log.reason")]
pub const AUDIT_REASON_SCHEMA: &str =
    "label_applied / label_negated: { val, neg, moderator_reason }";

/// RFC-3339 with millisecond precision. `Z` is appended by
/// [`rfc3339_from_epoch_ms`] and stripped by [`parse_rfc3339_ms`] — kept
/// out of the format description because `time::OffsetDateTime::parse`
/// can't infer a UTC offset from the literal character `Z`, and
/// symmetric Z-handling at the string boundary is simpler than switching
/// parsing-only to `well_known::Rfc3339`.
const CTS_FORMAT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");

/// Moderator request to apply a label (positive event).
#[derive(Debug, Clone)]
pub struct ApplyLabelRequest {
    /// The DID of the moderator issuing the request. Becomes
    /// `audit_log.actor_did`. `src` on the label itself is the writer's
    /// service DID, not this.
    pub actor_did: String,
    /// AT-URI or DID of the subject being labeled.
    pub uri: String,
    /// Optional record-version pin. Present means "this specific version";
    /// absent means "all versions / the account" per §6.1.
    pub cid: Option<String>,
    /// Label value, ≤128 bytes (validated on insert by schema CHECK and
    /// by caller-side input validation on the XRPC boundary).
    pub val: String,
    /// Optional expiration timestamp (RFC-3339 Z). Stored only; expiry
    /// enforcement is v1.1 (§F7).
    pub exp: Option<String>,
    /// Free-text reason recorded to `audit_log` only. Not signed, not
    /// included in the label record.
    pub moderator_reason: Option<String>,
}

/// Moderator request to negate (withdraw) a previously-applied label.
///
/// Uniqueness is at the `(src, uri, val)` tuple. The negation copies the
/// most-recent applied event's `cid` so the negation pins the same record
/// version — callers don't supply it.
#[derive(Debug, Clone)]
pub struct NegateLabelRequest {
    pub actor_did: String,
    pub uri: String,
    pub val: String,
    pub moderator_reason: Option<String>,
}

/// A committed label event. Returned by `apply_label` / `negate_label` and
/// broadcast to subscribers (subscribeLabels consumers in #7). Wire
/// serialization is that consumer's concern — the LabelEvent itself
/// carries no serde derive because the canonical encoding for the wire is
/// the DAG-CBOR path in `crate::signing`, not serde JSON.
#[derive(Debug, Clone)]
pub struct LabelEvent {
    /// Frame sequence number from `label_sequence`. Strictly monotonic.
    pub seq: i64,
    /// The full signed label (`sig` populated).
    pub label: Label,
}

/// Internal write command. One variant per public method.
enum WriteCommand {
    Apply(ApplyLabelRequest, oneshot::Sender<Result<LabelEvent>>),
    Negate(NegateLabelRequest, oneshot::Sender<Result<LabelEvent>>),
    Shutdown(oneshot::Sender<Result<()>>),
}

/// Cheap handle to the writer task. Clones share the same underlying
/// mpsc channel; a drop of the last clone is a silent shutdown signal
/// to the writer task (receiver closes). For a clean shutdown that
/// releases the lease row, call [`WriterHandle::shutdown`].
#[derive(Debug, Clone)]
pub struct WriterHandle {
    tx: mpsc::Sender<WriteCommand>,
    broadcast_tx: broadcast::Sender<LabelEvent>,
}

impl WriterHandle {
    /// Submit an apply-label request. Resolves when the writer has
    /// committed the transaction and broadcast the event, or returns an
    /// `Err` describing why the write was rejected.
    pub async fn apply_label(&self, req: ApplyLabelRequest) -> Result<LabelEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::Apply(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Submit a negate-label request. Returns [`Error::LabelNotFound`] if
    /// no applied label currently exists for `(service_did, uri, val)`.
    pub async fn negate_label(&self, req: NegateLabelRequest) -> Result<LabelEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::Negate(req, reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }

    /// Subscribe to committed events. The returned receiver lags past
    /// [`BROADCAST_BUFFER`] events; the consumer (subscribeLabels, #7)
    /// turns `RecvError::Lagged` into a connection close.
    pub fn subscribe(&self) -> broadcast::Receiver<LabelEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Explicit shutdown. Drains in-flight writes, releases the lease
    /// row, stops the heartbeat, and returns. Idempotent-ish: calling on
    /// an already-shut-down writer returns a channel-closed error, not a
    /// panic.
    pub async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::Shutdown(reply_tx))
            .await
            .map_err(|_| Error::Signing("writer task is already shut down".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Signing("writer dropped reply channel".into()))?
    }
}

/// Start the writer task. Acquires the instance lease, bootstraps the
/// `signing_keys` row if empty, and spawns the event loop + heartbeat.
///
/// `service_did` stamps `labels.src` on every emitted event. `key` must
/// be the private key whose public form is recorded (or will be recorded)
/// in `signing_keys`.
pub async fn spawn(
    pool: Pool<Sqlite>,
    key: SigningKey,
    service_did: String,
) -> Result<WriterHandle> {
    let instance_id = acquire_lease(&pool).await?;
    let signing_key_id = ensure_signing_key_row(&pool, &key).await?;

    let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
    let (broadcast_tx, _first_rx) = broadcast::channel(BROADCAST_BUFFER);

    let writer = Writer {
        pool,
        key,
        service_did,
        signing_key_id,
        instance_id,
        rx,
        broadcast_tx: broadcast_tx.clone(),
    };

    tokio::spawn(writer.run());

    Ok(WriterHandle { tx, broadcast_tx })
}

// ---------- Writer task ----------

struct Writer {
    pool: Pool<Sqlite>,
    key: SigningKey,
    service_did: String,
    signing_key_id: i64,
    instance_id: String,
    rx: mpsc::Receiver<WriteCommand>,
    broadcast_tx: broadcast::Sender<LabelEvent>,
}

impl Writer {
    async fn run(mut self) {
        let mut heartbeat_timer = interval(HEARTBEAT_INTERVAL);
        heartbeat_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // First tick fires immediately; skip it — we just acquired the lease
        // with a fresh timestamp, so touching it again is redundant.
        heartbeat_timer.tick().await;

        loop {
            tokio::select! {
                biased;
                // Prefer draining write commands over heartbeats so a
                // steady-state of inbound work does not starve itself
                // behind a background housekeeping task.
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(WriteCommand::Apply(req, reply)) => {
                            let res = self.handle_apply(req).await;
                            // Caller may have cancelled; dropping the reply is fine.
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::Negate(req, reply)) => {
                            let res = self.handle_negate(req).await;
                            let _ = reply.send(res);
                        }
                        Some(WriteCommand::Shutdown(reply)) => {
                            let res = self.release_lease().await;
                            let _ = reply.send(res);
                            return;
                        }
                        None => {
                            // All handles dropped without explicit shutdown.
                            // Best-effort lease release so a same-process
                            // restart doesn't trip the 60s wait.
                            if let Err(e) = self.release_lease().await {
                                tracing::error!("lease release on handle drop: {e}");
                            }
                            return;
                        }
                    }
                }
                _ = heartbeat_timer.tick() => {
                    if let Err(e) = self.heartbeat().await {
                        // Transient DB errors are logged, not fatal. A
                        // sustained failure is caught at the next-instance
                        // startup check — not at this writer's expense.
                        tracing::error!("lease heartbeat failed: {e}");
                    }
                }
            }
        }
    }

    async fn handle_apply(&self, req: ApplyLabelRequest) -> Result<LabelEvent> {
        let mut tx = self.pool.begin().await?;

        let seq = reserve_seq(&mut tx).await?;
        let prev_cts: Option<String> = sqlx::query_scalar!(
            // sqlx type override — MAX() strips column origin metadata so
            // sqlx can't infer the TEXT+nullable shape on its own. `?:`
            // forces the nullable wrapper (Option<String>).
            r#"SELECT MAX(cts) AS "max_cts?: String" FROM labels
               WHERE src = ?1 AND uri = ?2 AND val = ?3"#,
            self.service_did,
            req.uri,
            req.val,
        )
        .fetch_one(&mut *tx)
        .await?;

        let wall_now_ms = epoch_ms_now();
        let cts = clamp_cts(wall_now_ms, prev_cts.as_deref())?;

        let mut label = Label {
            ver: 1,
            src: self.service_did.clone(),
            uri: req.uri.clone(),
            cid: req.cid.clone(),
            val: req.val.clone(),
            neg: false,
            cts: cts.clone(),
            exp: req.exp.clone(),
            sig: None,
        };
        label.sig = Some(sign_label(&self.key, &label)?);
        let sig_bytes = label.sig.expect("just set").to_vec();

        let created_at = wall_now_ms;
        let neg_int: i64 = 0;
        sqlx::query!(
            "INSERT INTO labels (seq, ver, src, uri, cid, val, neg, cts, exp, sig, signing_key_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            seq,
            label.ver,
            label.src,
            label.uri,
            label.cid,
            label.val,
            neg_int,
            label.cts,
            label.exp,
            sig_bytes,
            self.signing_key_id,
            created_at,
        )
        .execute(&mut *tx)
        .await?;

        let audit_reason = build_audit_reason(&req.val, false, req.moderator_reason.as_deref());
        let action = "label_applied";
        let outcome = "success";
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, target, target_cid, outcome, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            created_at,
            action,
            req.actor_did,
            req.uri,
            req.cid,
            outcome,
            audit_reason,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let event = LabelEvent { seq, label };
        // No-receivers is not a write failure (§plan point G).
        let _ = self.broadcast_tx.send(event.clone());
        Ok(event)
    }

    async fn handle_negate(&self, req: NegateLabelRequest) -> Result<LabelEvent> {
        let mut tx = self.pool.begin().await?;

        // Most-recent event for the tuple. Not-found OR latest-is-already-
        // a-negation both surface as LabelNotFound (§F6).
        let latest = sqlx::query!(
            "SELECT neg, cid FROM labels
             WHERE src = ?1 AND uri = ?2 AND val = ?3
             ORDER BY seq DESC LIMIT 1",
            self.service_did,
            req.uri,
            req.val,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let cid = match latest {
            Some(row) if row.neg == 0 => row.cid,
            _ => {
                return Err(Error::LabelNotFound {
                    src: self.service_did.clone(),
                    uri: req.uri,
                    val: req.val,
                });
            }
        };

        let seq = reserve_seq(&mut tx).await?;
        // Prev cts lookup is the same query as apply; tuple uniqueness is
        // on (src, uri, val) regardless of neg.
        let prev_cts: Option<String> = sqlx::query_scalar!(
            // sqlx type override — MAX() strips column origin metadata so
            // sqlx can't infer the TEXT+nullable shape on its own. `?:`
            // forces the nullable wrapper (Option<String>).
            r#"SELECT MAX(cts) AS "max_cts?: String" FROM labels
               WHERE src = ?1 AND uri = ?2 AND val = ?3"#,
            self.service_did,
            req.uri,
            req.val,
        )
        .fetch_one(&mut *tx)
        .await?;

        let wall_now_ms = epoch_ms_now();
        let cts = clamp_cts(wall_now_ms, prev_cts.as_deref())?;

        let mut label = Label {
            ver: 1,
            src: self.service_did.clone(),
            uri: req.uri.clone(),
            cid: cid.clone(),
            val: req.val.clone(),
            neg: true,
            cts: cts.clone(),
            exp: None, // Negations never carry an expiry.
            sig: None,
        };
        label.sig = Some(sign_label(&self.key, &label)?);
        let sig_bytes = label.sig.expect("just set").to_vec();

        let created_at = wall_now_ms;
        let neg_int: i64 = 1;
        sqlx::query!(
            "INSERT INTO labels (seq, ver, src, uri, cid, val, neg, cts, exp, sig, signing_key_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            seq,
            label.ver,
            label.src,
            label.uri,
            label.cid,
            label.val,
            neg_int,
            label.cts,
            label.exp,
            sig_bytes,
            self.signing_key_id,
            created_at,
        )
        .execute(&mut *tx)
        .await?;

        let audit_reason = build_audit_reason(&req.val, true, req.moderator_reason.as_deref());
        let action = "label_negated";
        let outcome = "success";
        sqlx::query!(
            "INSERT INTO audit_log (created_at, action, actor_did, target, target_cid, outcome, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            created_at,
            action,
            req.actor_did,
            req.uri,
            cid,
            outcome,
            audit_reason,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let event = LabelEvent { seq, label };
        let _ = self.broadcast_tx.send(event.clone());
        Ok(event)
    }

    async fn heartbeat(&self) -> Result<()> {
        let now_ms = epoch_ms_now();
        sqlx::query!(
            "UPDATE server_instance_lease SET last_heartbeat = ?1
             WHERE id = 1 AND instance_id = ?2",
            now_ms,
            self.instance_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn release_lease(&self) -> Result<()> {
        sqlx::query!(
            "DELETE FROM server_instance_lease WHERE id = 1 AND instance_id = ?1",
            self.instance_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ---------- Lease + key bootstrap ----------

async fn acquire_lease(pool: &Pool<Sqlite>) -> Result<String> {
    let now_ms = epoch_ms_now();

    let existing =
        sqlx::query!("SELECT instance_id, last_heartbeat FROM server_instance_lease WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    if let Some(row) = existing {
        let age_ms = (now_ms - row.last_heartbeat).max(0);
        if age_ms < LEASE_STALE_MS {
            return Err(Error::LeaseHeld {
                instance_id: row.instance_id,
                age_secs: (age_ms / 1000) as u64,
            });
        }
    }

    let new_id = Uuid::new_v4().to_string();
    // INSERT OR REPLACE on id=1: takes over a stale lease row if present,
    // or creates the row on first startup. Legal because the staleness
    // check above confirms no live peer.
    sqlx::query!(
        "INSERT INTO server_instance_lease (id, instance_id, acquired_at, last_heartbeat)
         VALUES (1, ?1, ?2, ?2)
         ON CONFLICT(id) DO UPDATE SET
             instance_id = excluded.instance_id,
             acquired_at = excluded.acquired_at,
             last_heartbeat = excluded.last_heartbeat",
        new_id,
        now_ms,
    )
    .execute(pool)
    .await?;

    Ok(new_id)
}

async fn ensure_signing_key_row(pool: &Pool<Sqlite>, key: &SigningKey) -> Result<i64> {
    let kp = K256Keypair::from_private_key(key.expose_secret())?;
    let my_multibase = format_multikey("ES256K", &kp.public_key_compressed());

    let existing =
        sqlx::query!("SELECT id, public_key_multibase FROM signing_keys ORDER BY id LIMIT 1")
            .fetch_optional(pool)
            .await?;

    if let Some(row) = existing {
        if row.public_key_multibase != my_multibase {
            return Err(Error::Signing(format!(
                "signing_keys.public_key_multibase ({}) does not match the loaded signing key's derived public key ({}) — key rotation is v1.1 scope",
                row.public_key_multibase, my_multibase
            )));
        }
        return Ok(row.id);
    }

    let now_ms = epoch_ms_now();
    let valid_from = rfc3339_from_epoch_ms(now_ms)?;
    let id = sqlx::query_scalar!(
        "INSERT INTO signing_keys (public_key_multibase, valid_from, valid_to, created_at)
         VALUES (?1, ?2, NULL, ?3)
         RETURNING id",
        my_multibase,
        valid_from,
        now_ms,
    )
    .fetch_one(pool)
    .await?;

    Ok(id)
}

// ---------- Pure helpers (unit-testable without a DB) ----------

async fn reserve_seq(tx: &mut sqlx::SqliteConnection) -> Result<i64> {
    // label_sequence has a single auto-increment column; `DEFAULT VALUES`
    // triggers a fresh allocation. Under AUTOINCREMENT the assigned seq
    // is never reused even across rolled-back transactions — this is what
    // gives us "strictly monotonic, no gaps from writer's perspective."
    let seq = sqlx::query_scalar!("INSERT INTO label_sequence DEFAULT VALUES RETURNING seq")
        .fetch_one(tx)
        .await?;
    Ok(seq)
}

/// §6.1 monotonicity clamp. `prev_cts_str`, when present, is expected to
/// be in the writer's canonical `CTS_FORMAT`.
fn clamp_cts(wall_now_ms: i64, prev_cts_str: Option<&str>) -> Result<String> {
    let effective_ms = match prev_cts_str {
        Some(s) => {
            let prev_ms = parse_rfc3339_ms(s)?;
            wall_now_ms.max(prev_ms + 1)
        }
        None => wall_now_ms,
    };
    rfc3339_from_epoch_ms(effective_ms)
}

fn rfc3339_from_epoch_ms(ms: i64) -> Result<String> {
    let nanos: i128 = (ms as i128) * 1_000_000;
    let dt = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|e| Error::Signing(format!("epoch ms {ms} out of range: {e}")))?;
    let formatted = dt
        .format(&CTS_FORMAT)
        .map_err(|e| Error::Signing(format!("format cts: {e}")))?;
    Ok(format!("{formatted}Z"))
}

fn parse_rfc3339_ms(s: &str) -> Result<i64> {
    let stripped = s
        .strip_suffix('Z')
        .ok_or_else(|| Error::Signing(format!("cts {s:?} missing trailing Z")))?;
    let pdt = PrimitiveDateTime::parse(stripped, &CTS_FORMAT)
        .map_err(|e| Error::Signing(format!("parse cts {s:?}: {e}")))?;
    let nanos = pdt.assume_utc().unix_timestamp_nanos();
    Ok((nanos / 1_000_000) as i64)
}

fn epoch_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}

fn build_audit_reason(val: &str, neg: bool, moderator_reason: Option<&str>) -> String {
    let body = serde_json::json!({
        "val": val,
        "neg": neg,
        "moderator_reason": moderator_reason,
    });
    body.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1_715_000_000_000 ms since epoch = 2024-05-06T12:53:20.000Z UTC.
    // The four tests below pin every branch of the clamp: no prior,
    // wall-ahead, wall-behind (use prev+1ms), wall-equal (advance anyway).

    #[test]
    fn clamp_cts_uses_wall_clock_when_no_prior() {
        let out = clamp_cts(1_715_000_000_000, None).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:20.000Z");
    }

    #[test]
    fn clamp_cts_advances_one_ms_past_prior_when_wall_clock_lags() {
        // wall_clock one second behind prev: result is prev + 1ms, not wall.
        let prev = "2024-05-06T12:53:20.500Z";
        let out = clamp_cts(1_715_000_000_000 - 1000, Some(prev)).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:20.501Z");
    }

    #[test]
    fn clamp_cts_uses_wall_clock_when_ahead_of_prior() {
        let prev = "2024-05-06T12:53:20.500Z";
        let out = clamp_cts(1_715_000_000_000 + 2000, Some(prev)).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:22.000Z");
    }

    #[test]
    fn clamp_cts_handles_equal_wall_and_prior_by_advancing() {
        // wall_clock == prev exactly: must advance by 1ms (strictly greater).
        let prev = "2024-05-06T12:53:20.500Z";
        let out = clamp_cts(1_715_000_000_500, Some(prev)).expect("clamp");
        assert_eq!(out, "2024-05-06T12:53:20.501Z");
    }

    #[test]
    fn build_audit_reason_shape_matches_documented_schema() {
        let json = build_audit_reason("spam", false, Some("user reported"));
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["val"], "spam");
        assert_eq!(v["neg"], false);
        assert_eq!(v["moderator_reason"], "user reported");
    }

    #[test]
    fn build_audit_reason_null_when_moderator_reason_absent() {
        let json = build_audit_reason("spam", true, None);
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(v["moderator_reason"].is_null());
    }

    #[test]
    fn rfc3339_roundtrip() {
        let s = "2026-04-22T12:00:00.938Z";
        let ms = parse_rfc3339_ms(s).expect("parse");
        let back = rfc3339_from_epoch_ms(ms).expect("format");
        assert_eq!(back, s);
    }
}
