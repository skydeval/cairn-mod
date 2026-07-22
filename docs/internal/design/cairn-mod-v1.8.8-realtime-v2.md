# cairn-mod v1.8.8 realtime — design v1

**Status:** Draft v2. R1 folded (chainlink #146); locked pending implementation kickoff.

- cairn-mod HEAD: `3b1af7d` (`skydeval/v1.8.7-batch`, unpushed)
- Aurora-Locus HEAD: `2ffeb1a` (`skydeval/v0.11-cycle`)
- Recon: `docs/internal/recon/v1.8.8-realtime-recon.md` (chainlink #144)
- Design chainlink: #145

## §1 — Process context + memory locks

Umbrella §4.A.8 scope with the four recon-time corrections (§2.3). Straight to CC-adversarial after drafting (memory #16). Sourcing per memory #6 + corollaries #27/#28/#29/#30/#31 — every wire block below is copied byte-verbatim from Aurora `2ffeb1a` or cairn-mod `3b1af7d`; drafting-time verification greps are cited inline. Firewall applies.

## §2 — What v1.8.8 is

cairn-mod consumes Aurora's `tools.aurora.admin.subscribeModEvents` WebSocket: a long-lived consumer task with a reconnect state machine, client-owned dual-cursor persistence realizing F10's at-most-once contract, echo suppression against cairn-mod's own dispatch ledger, ingestion of genuinely-upstream events into new unchained observational tables, optional audit-chain co-delivery re-verified through v1.8.6's Path A pipeline, and `queryEvents` reconciliation for outdated-cursor recovery.

### §2.1 Locked decisions (kickoff LB-1..6 + subsidiary), with source-wins amendments

Kickoff decisions hold except where shipped source contradicts them. **Seven amendments (A1–A7), each flagged on chainlink #145** — per the standing source-wins rule, none is a scope change; each is the shipped codebase refusing the kickoff's sketch-level phrasing:

- **A1 (LB-3)**: the six `$type` discriminators are **bare lowerCamel strings** (`"hello"`, `"event"`, `"auditEntry"`, `"heartbeat"`, `"outdatedCursor"`, `"error"`), NOT NSID-qualified `tools.aurora.admin.subscribeModEvents#hello` forms. Source: `#[serde(tag = "$type")]` + `#[serde(rename = "hello")]` etc. on Aurora's `SubscribeMessage` (recon §2a verbatim). §4.2 uses the source strings.
- **A2 (LB-5, load-bearing)**: upstream events **cannot** ride `pds_admin_audit`. Live DDL (migration 0010, verbatim): `precipitating_action_id INTEGER NOT NULL REFERENCES subject_actions(id) ON DELETE RESTRICT`, `backend_method TEXT NOT NULL CHECK (backend_method IN (…16 cairn dispatch verbs…))`, hash-chained rows whose 12-field preimage includes both. An upstream observation has no local intent row (FK unsatisfiable), frequently no representable verb (`label_create`, `report_submit` are not in the CHECK), and folding observations into the dispatch-outcome chain would contradict the v1.8.6 posture that cairn-mod's chain records cairn-mod-initiated calls only. The kickoff's `pds_admin_audit.origin` column + `record_pds_admin_call`-with-`origin:'upstream'` is dropped; action events ingest into a **new unchained `upstream_events` table** (§7.2). Echo suppression (LB-4) is unaffected — it joins against `backend_action_id`, no schema change to `pds_admin_audit` beyond the missing index (A5).
- **A3 (LB-5)**: report ids do NOT ride the stream. Aurora's `build_event_details` (verbatim, §4.3) writes only `rationale` + `action` (+ optional `metadata`) — `ResolveReport`'s `report_id` lives inside the action enum and never reaches `moderation_event.details`. `reports.upstream_resolution` therefore updates by **subject-coordinate match** (§6.4), documented as a heuristic. Appeal events do not touch `reports` (they are not reports); they ingest to `upstream_events` only.
- **A4 (LB-2)**: reconciliation windows by **RFC3339 time**, not sequence — v1.8.3's shipped `QueryEventsFilter` has `after`/`before` (inclusive, RFC3339) and no id bound. `stream_cursors` gains a `last_created_at TEXT` column so the reconciliation window's lower bound survives restarts.
- **A5**: live `pds_admin_audit` DDL + append-only triggers are at **migration 0010** (the kickoff said 0008; 0010's shadow-swap rebuilt table, indexes, and triggers). `backend_action_id` is **unindexed** at HEAD (full-migration grep: only `precipitating_action_id` / `outcome` / `call_completed_at` indexes exist) — 0012 adds the partial index LB-4 requires.
- **A6 (LB-1)**: registry entries are **suffix-less family names** — the 8th entry is `("mod-events-stream", CapabilityClassification::OperatorOptIn)`, not `"mod-events-stream-v1"`. And it is the **second** OperatorOptIn family, not the third: `audit-trail` (v1.8.6) is AutoAdvance; `batch-takedown` (v1.8.7) is the first OperatorOptIn.
- **A7 (LB-1, subsidiary)**: cairn-mod has no `AuroraNsid` enum — NSIDs are `const &str` items in `rust/mod.rs` (house pattern since v1.8.1). v1.8.8 adds `SUBSCRIBE_MOD_EVENTS_NSID`, `MOD_EVENTS_STREAM_FAMILY`, `MOD_EVENTS_STREAM_CAPABILITY` consts. (Same phrasing was ignored the same way in v1.8.7.)

Also refined: `subscribe_mod_events` cannot return `impl Stream` — `PdsAdminBackend` is consumed as `Arc<dyn PdsAdminBackend>`, so the return is a boxed stream (§5.1).

Everything else holds as locked: NSID + OperatorOptIn gate (LB-1, dual-posture per v1.8.7 §8.1 precedent), two cursors + persist-before-process (LB-2), `UpstreamEvent` mirror + disambiguation (LB-3), echo suppression via `backend_action_id` join (LB-4), `StreamIngestor` trait + Path A on audit frames + `queryEvents` reconciliation (LB-5), consumer task + state machine (LB-6), 1 trait method (36→37, S-1: reconciliation reuses shipped `query_events`), `cairn stream` CLI, `[pds_admin.rust.stream]` config block, tokio-tungstenite promotion, no new exit codes, no new `BackendError` variants.

### §2.2 Non-goals

- No kryphocron event consumption (variants enumerated in recon §2a for v1.8.14; ingestion **stores** any frame's `eventType` verbatim but drives no behavior from kryphocron values).
- No `actionFilter` consumption (recon §7a item 6: repeated-key Vec through axum `Query`/serde_urlencoded is doubtful; cairn-mod wants the unfiltered stream regardless).
- No server-side filter params at all in v1: connect with `cursor` (+ `auditChainCursor` when chain-enabled) only.
- No at-least-once / client dedup machinery: F10 at-most-once is the contract; the `upstream_events` UNIQUE key gives idempotency for the reconciliation overlap, not a delivery guarantee.
- No local hash-chaining of upstream observations (`upstream_events` and `upstream_audit_mirror` are unchained, prunable, advisory — the v1.8.6 `cross_verify_outcomes` posture).
- No notification/webhook surface; observability is `tracing` + CLI status/reads.
- No LISTEN/NOTIFY push assumptions — the wire contract is the polling-driven one; a future Aurora push swap is transparent.
- No changes to local report lifecycle: `reports.status` stays operator-owned; `upstream_resolution` is an annotation.
- No push (skydeval owns pushes).

### §2.3 Umbrella-vs-source corrections (landed at recon)

1. NSID is `tools.aurora.admin.subscribeModEvents` (admin namespace, single-route `mod-events-stream-v1` attribution).
2. JSON text frames, `$type`-tagged envelopes; no CBOR, no sub-protocol.
3. Heartbeat is an application frame (30s, suppressed while data flows); no server read timeout / keepalive expectation / connection limits / reconnect rate limit. Dead-connection detection is client-side.
4. F10 at-most-once is realized cairn-mod-side via persist-before-process; Aurora replays from any in-retention presented cursor.

Umbrella reconciliation deferred to the v1.8.11 series wrap (§12).

## §3 — Aurora surfaces consumed

### §3.1 Endpoint + auth + role

Route (Aurora `admin.rs:675-684`, verbatim in recon §1a): GET upgrade, `CapsBuilder::new(Family::Admin).extensions(["mod-events-stream-v1"])`. Auth: standard `Authorization: Bearer` on the upgrade request through `AdminAuthContext` — token form 4 is `verify_service_jwt`, so cairn-mod's existing ES256K per-call mint works unchanged with `lxm = tools.aurora.admin.subscribeModEvents`, 3600s expiry, validated once at upgrade; every reconnect mints fresh. Role floor Moderator+ — under-role is a plain HTTP **403** with body `subscribeModEvents requires Moderator+ role` **before** upgrade (drafting-time re-verified against `subscribe_mod_events`). Since the connect floor equals the chain-visibility floor (`can_see_audit_chain` = Moderator+), an accepted connection's `includeAuditChain` opt-in is never silently role-dropped in practice.

### §3.2 Connect params (subset consumed)

Aurora's `SubscribeModEventsParams` (recon §1c verbatim). cairn-mod sends only:
- `cursor=<i64>` — omitted entirely on a fresh deployment (live-only from tail; Aurora `hello.sequence` tells us where we joined) and after outdated-cursor reconciliation.
- `auditChainCursor=<i64>` + `includeAuditChain=true` — only when `[pds_admin.rust.stream].include_audit_chain = true`.

### §3.3 Cursor + resumption contract

Recon §3 pinned: cursor = `mod_event_seq.seq` (independent monotonic counter; NOT `moderation_event.id`, NOT the chain sequence), semantics = last-delivered (`seq > cursor` fetch), retention default 7 days (`PDS_MOD_EVENT_RETENTION_DAYS`, daily cleanup), outdated boundary exactly `client_cursor < oldest - 1`, then one `outdatedCursor` frame + clean close 1000/`"outdated cursor"`. Chain cursor never goes outdated (`audit_chain_entry` unpruned). Aurora holds no per-subscriber state; **the client-presented cursor is the only resume authority — which is why F10 is cairn-mod's to realize (§6.2)**.

### §3.4 Heartbeat + lifecycle rules

`POLL_INTERVAL_SECS = 5`, `HEARTBEAT_INTERVAL_SECS = 30`, `MAX_EVENTS_PER_POLL: i64 = 50` (verbatim, recon §4a). Heartbeat is `{"$type":"heartbeat","sequence":N}` — an echo, not a delivery: **it must not advance the persisted cursor** (its `sequence` repeats the server-side event cursor; persisting it would be harmless today but couples us to an undocumented invariant — rule stays). Delivery latency ≤ ~5s; backlog drain ≤ 50 rows/table/tick. Close inventory: 1000 (`outdated cursor`) is the only explicit close; `error` frame then socket-drop; no 4xxx codes; no server idle timeout — silence detection is ours (§5.3).

### §3.5 `includeAuditChain` variance

Separate interleaved `auditEntry` frames (event frames unchanged), timestamp-merged with event-wins ties, ≤50/tick own cap; `entry` is **byte-identical** to `getAuditTrail` items (pinned upstream by `audit_entry_wire_shape_matches_get_audit_trail_items`) → v1.8.6's `AuroraAuditEntry` mirror deserializes it unchanged. Envelope `sequence` duplicates `entry.sequence`. Correlation: `entry.event_id` (stringified) ↔ event payload `id`. No cross-tick pairing guarantee (independent caps).

## §4 — Wire mirror types

New module `src/pds_admin/rust/stream_types.rs`.

### §4.1 `UpstreamEvent` — the flat v0.2 payload

Aurora builds the payload in `fetch_new_events` (recon §2a verbatim; keys: `id`, `eventType`, `actorDid`, `subjectDid`, `subjectUri`, `subjectCid`, `details`, `createdAt`). Mirror:

```rust
/// Mirror of the `event` frame payload — Aurora's v0.2-stable flat
/// shape built in `aurora_subscribe.rs::fetch_new_events` (recon
/// §2a). NOT `EventWithContext` (v1.8.3): no handle enrichment, no
/// `$type` subject union — flat nullable subject columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamEvent {
    /// `moderation_event.id` — the SAME id space `queryEvents`
    /// items use, and the payload cairn-mod's own dispatches store
    /// as `BackendActionId::PerEvent`/`PerBatch` (stringified).
    /// The echo-suppression and reconciliation-dedup join key.
    pub id: i64,
    /// Snake_case `ModerationEventType::as_str` value. LOSSY for
    /// emitEvent-originated events (§4.3).
    pub event_type: String,
    pub actor_did: String,
    pub subject_did: Option<String>,
    pub subject_uri: Option<String>,
    pub subject_cid: Option<String>,
    /// Parsed detail JSON or `null` (Aurora substitutes null on
    /// parse failure). Carries the disambiguator (§4.3).
    pub details: serde_json::Value,
    /// RFC3339 (also the reconciliation window bound, A4).
    pub created_at: String,
}
```

### §4.2 `StreamFrame` — six `$type` envelopes (A1: bare discriminators)

```rust
/// One server frame. Aurora serializes `SubscribeMessage` with
/// `#[serde(tag = "$type")]` and bare lowerCamel rename values
/// (recon §2a verbatim) — NOT NSID-qualified strings.
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub enum StreamFrame {
    #[serde(rename = "hello")]
    Hello {
        #[serde(rename = "instanceVersion")]
        instance_version: String,
        sequence: i64,
    },
    #[serde(rename = "event")]
    Event {
        event: UpstreamEvent,
        sequence: i64,
    },
    #[serde(rename = "auditEntry", rename_all = "camelCase")]
    AuditEntry {
        /// v1.8.6-shipped mirror, reused byte-identical (§3.5).
        entry: Box<AuroraAuditEntry>,
        sequence: i64,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat { sequence: i64 },
    #[serde(rename = "outdatedCursor", rename_all = "camelCase")]
    OutdatedCursor {
        oldest_available_seq: i64,
        message: String,
    },
    #[serde(rename = "error")]
    Error { code: String, message: String },
}
```

Unknown `$type` values deserialize to an error; the consumer logs-and-skips the frame (forward-compat: a future Aurora frame type must not kill the stream) — implemented via a two-stage parse (raw `serde_json::Value`, inspect `$type`, then typed parse) so unknown types are distinguishable from malformed knowns. Malformed known frames are `Terminal`-logged and skipped; **the cursor does NOT advance for skipped frames the client failed to parse** (we never extracted a sequence we trust — the next reconnect re-delivers; this is the one deliberate at-least-once edge and it re-delivers into idempotent ingestion, §6.4).

### §4.3 Discriminator disambiguation (lossy `event_type_for`)

Aurora's `event_type_for` collapses verbs (recon §2a verbatim: `DeleteAccount`/`TakedownRecord`/`UpdateSubjectStatus` → `account_takedown`; `DeleteBlob` → `blob_quarantine`; `SendEmail` → `account_warn`). The disambiguator lives in `details` — `build_event_details` verbatim (Aurora `aurora_admin.rs:947-958`):

```rust
fn build_event_details(input: &EmitEventInput, metadata: &Option<serde_json::Value>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("rationale".to_string(), serde_json::Value::String(input.rationale.clone()));
    obj.insert(
        "action".to_string(),
        serde_json::to_value(action_kind_str(&input.action)).unwrap_or(serde_json::Value::Null),
    );
    if let Some(m) = metadata {
        obj.insert("metadata".to_string(), m.clone());
    }
    serde_json::Value::Object(obj)
}
```

`action_kind_str` returns the **PascalCase `kind` discriminator** (`"TakedownAccount"` … `"UpdateSubjectStatus"`, 16 values, full-file enumerated) — so every emitEvent-originated event (including v1.8.7 `_many` multi-subject) is exactly disambiguable via `details.action`. Dedicated-batch events differ: `insert_batch_account_moderations_in_tx` writes `details = {"rationale", "action": event_type.as_str(), "batch": true, "subjects": [dids]}` — `action` is the **snake_case lossy** string there, with `batch: true` + `subjects` as the batch markers. Non-emitEvent events (`report_submit`, `appeal_submit`, kryphocron, ops variants) have their own detail shapes and pass through opaque.

```rust
/// Best-effort verb classification for an incoming event.
pub enum EventVerb {
    /// `details.action` carried a PascalCase emitEvent kind.
    EmitEvent(String),
    /// `details.batch == true` — dedicated-batch origin; verb is
    /// the (lossy) eventType + subjects shape.
    DedicatedBatch,
    /// Everything else — classify by `event_type` alone.
    Other,
}

pub fn disambiguate_event_verb(event: &UpstreamEvent) -> EventVerb {
    if event.details.get("batch").and_then(serde_json::Value::as_bool) == Some(true) {
        return EventVerb::DedicatedBatch;
    }
    match event.details.get("action").and_then(serde_json::Value::as_str) {
        // PascalCase = emitEvent kind vocabulary; snake_case or
        // absent = not an emitEvent detail payload.
        Some(a) if a.chars().next().is_some_and(char::is_uppercase) => {
            EventVerb::EmitEvent(a.to_string())
        }
        _ => EventVerb::Other,
    }
}
```

Stored verbatim either way (§7.2 keeps raw `details`); the classification only drives the `reports` annotation arm (§6.4).

### §4.4 Frame-payload notes

`Hello`/`Heartbeat`/`OutdatedCursor`/`Error` need no standalone structs (inline enum fields above mirror Aurora's serializer exactly). `hello.sequence` = starting event cursor (join point); the consumer logs it and — on a cursor-less connect — seeds `stream_cursors.mod_events` from it (so the first persisted position exists even before the first event frame).

## §5 — cairn-mod-side consumer

### §5.1 Trait additions (36 → 38) + task lifecycle

```rust
/// Open the realtime moderation-event stream (v1.8.8) —
/// `tools.aurora.admin.subscribeModEvents` WebSocket. Gated on the
/// `mod-events-stream` family (OperatorOptIn: advertised AND
/// pinned, second consumer of the v1.8.7 gate semantics). Returns
/// a boxed frame stream — `Pin<Box<dyn Stream ...>>` rather than
/// `impl Stream` because the trait is consumed as
/// `Arc<dyn PdsAdminBackend>` (first stream-returning method in
/// the trait; every prior method is request/response).
async fn subscribe_mod_events(
    &self,
    cursor: Option<i64>,
    audit_chain_cursor: Option<i64>,
    include_audit_chain: bool,
) -> Result<
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<StreamFrame, BackendError>> + Send>>,
    BackendError,
>;

Ozone: `Unsupported` (exit 17 posture unchanged). (S-1: the v1 `reconcile_query_events` companion method is dropped — reconciliation reuses v1.8.3's shipped `query_events`; trait grows 36 → 37.) RustBackend `subscribe_mod_events`: capability gate (advertised AND pinned, same `dispatch_batch`-shaped check against `MOD_EVENTS_STREAM_FAMILY`) → fresh JWT → `tokio_tungstenite::connect_async` with `Authorization: Bearer` header on the upgrade request (ws:// or wss:// derived from the configured `pds_url` scheme) → adapt the socket into a `StreamFrame` stream (text frames parsed per §4.2; binary/ping/pong ignored; Close/error terminates the stream with a final `Err(Transient)` item unless close was clean).

The **consumer task** (`src/pds_admin/rust/stream.rs`) is spawned at backend startup when `stream.enabled && caps advertised && pinned` (checked at spawn AND re-checked per connection attempt — the background capability refresh can change the advertised set). Task holds `Weak<RustBackend>` (the `spawn_capability_refresh` pattern verbatim: upgrade-fails → task exits; returns `None` outside a runtime). Uncaught internal panics crash the process (writer-task discipline).

### §5.2 State machine + backoff

```
Disconnected --spawn/backoff--> Connecting --hello--> Connected
Connecting --401/403--> HardStop
Connecting --network err--> Disconnected (backoff++)
Connected --outdatedCursor frame--> Reconciling --done--> Connecting (cursor-less)
Connected --silence timer / send err / abnormal close--> Disconnected (backoff++)
Connected --clean close 1000--> Draining --> Disconnected (reconnect only if
                                             reconnect_on_normal_close)
Connected --frame flow--> Connected (backoff resets to floor on first
                                     post-hello frame)
```

Backoff: exponential, floor 1s, factor 2, cap `reconnect_max_backoff` (default 60s), ±25% jitter (`fastrand`-free: derive jitter from `epoch_ms_now() % …` — no new RNG dependency). Backoff resets only after a connection proves healthy (first frame after `hello`), not on mere connect success — a server that accepts-then-drops must not hot-loop.

**Timer bounds (M-4)**: `Connecting` and `Draining` share `silence_timeout` — no hello within it → `Disconnected` with backoff (post-upgrade Aurora silence can't hang the task); drain not complete within it → buffered frames dropped (at-most-once; next connect resumes from the persisted cursor) and `Disconnected`.

**HardStop**: HTTP 401/403 at upgrade (auth/role — operator-actionable; recon §7d rule: do NOT hot-loop on `Auth`). Task parks; log at ERROR with the remediation hint; `cairn stream status` shows `hard-stop`; restart via process restart or `cairn stream start`. `CapabilityNotAdvertised` (unadvertised or unpinned at attempt time) also parks — but as `dormant`, re-evaluated on each capability refresh tick rather than requiring operator action, because advertisement can legitimately come and go.

### §5.3 Silence timer

Client-side dead-connection detection: no frame of any kind for `silence_timeout` (default 35s = Aurora's 30s heartbeat + slack) → treat as `Transient`, drop socket, `Disconnected` with backoff. Any frame (including heartbeat/error) feeds the timer. Implemented as `tokio::time::timeout` around each stream read.

### §5.4 Draining

On clean close (1000): finish parsing/ingesting frames already buffered by the WS library, persist cursors, then stop (or reconnect when `reconnect_on_normal_close = true`). Aurora's only clean-close-with-prior-frame is outdatedCursor, which transitions to `Reconciling` before the close is even read — a bare 1000 without outdatedCursor is treated as operator/server-intent shutdown, hence default no-reconnect.

### §5.5 Reconciliation (outdatedCursor + cold-gap) — consumer-side page loop (S-1)

Reconciliation is consumer-side orchestration, not a dedicated trait method. On `outdatedCursor` receipt or reconnect after silence-timeout exceeding retention, the state machine transitions to `Reconciling` and drives v1.8.3's shipped `query_events` in a page loop:

```
loop:
  page = query_events(
      filter: QueryEventsFilter { after: last_created_at, before: current_time },
      cursor: page_cursor,
      limit: DEFAULT_PAGE_LIMIT,
  ).await?
  
  for event in page.events:
      ingest_via_stream_ingestor(event).await
      // upstream_events.event_id UNIQUE absorbs any overlap with prior partial runs
      // and any overlap with the resubscribed stream post-Reconciling.
  
  if page.cursor.is_none() { break }
  page_cursor = page.cursor
end

// Only after full page-loop exhaustion, advance the watermark.
stream_cursors.last_created_at = current_time
```

**Aurora's window ordering** is `ORDER BY created_at DESC, id DESC` (verified at `aurora_admin.rs:<line>`). The consumer-side loop drains all pages before advancing `last_created_at` because any truncation would silently hole the middle of the window in a way a single watermark can't recover from. Aurora's shipped cursor pagination handles resume-from-hole for free within a single reconciliation pass; the outer loop bounds memory by processing one page at a time.

**Pre-exhaustion crash handling.** If the consumer task crashes mid-reconciliation, `last_created_at` has not advanced. Next task start re-runs the full page loop from the same `last_created_at`. Every event previously ingested hits `upstream_events.event_id UNIQUE ON CONFLICT DO NOTHING` — dedup is the invariant that makes retry safe.

**Post-reconciliation resubscribe** is cursor-less (`subscribe_mod_events(cursor: None, ...)`). Aurora responds by resuming from current stream head; the overlap with the reconciled tail is absorbed by the same `UNIQUE` constraint.

## §6 — Ingestion

### §6.1 `StreamIngestor` trait

```rust
/// Ingestion sink for stream/reconciliation frames (v1.8.8).
/// Trait-shaped so tests inject recording sinks and so a future
/// release can layer policy-driven consumers without touching the
/// consumer task. NOT a `PdsAdminBackend` extension — ingestion is
/// local persistence, not backend dispatch.
#[async_trait]
pub trait StreamIngestor: Send + Sync {
    async fn ingest_event(&self, event: &UpstreamEvent, origin: Origin) -> Result<(), IngestError>;
    async fn ingest_audit_entry(&self, entry: &AuroraAuditEntry) -> Result<(), IngestError>;
}
```

`IngestError` is a thin local error (DB failure vs verification-tamper), NOT `BackendError` — ingestion errors never leave the consumer task except as logs + `stream status` counters.

### §6.2 Cursor persistence discipline — F10 realized here

Per-frame order in the consumer loop, non-negotiable:
1. Frame parsed → extract its envelope `sequence`.
2. **UPDATE `stream_cursors` FIRST** (`mod_events` row for `event` frames — also refreshing `last_created_at` from the payload; `audit_chain` row for `auditEntry` frames; heartbeats/hellos/others touch nothing).
3. Then classify (§6.3) and ingest (§6.4).
4. Ingestion failure → frame lost, logged at ERROR with full frame JSON, `stream status` failure counter bumps. The persisted cursor already points past it.

**Why persist-BEFORE-process:** persisting after would make a crash between ingest and persist re-deliver the frame on reconnect — at-least-once semantics leaking in, duplicate ingestion possible (the `upstream_events` UNIQUE key would mask events but NOT the reports-annotation side effects, which are not idempotent under re-observation ordering). F10's at-most-once is exactly this ordering choice; Aurora imposes nothing (§3.3). The single deliberate exception is unparseable frames (§4.2), which never yielded a trusted sequence.

Writes go through the writer task? **No** — deliberately not. `stream_cursors`/`upstream_events`/`upstream_audit_mirror` are unchained advisory tables outside the hash-chain and outside `subject_actions`; the consumer task owns them with its own pool handle, exactly as `cross_verify_outcomes` writes bypass the writer (v1.8.6 precedent). The `reports.upstream_resolution` UPDATE is the one touch on a chained-adjacent table — `reports` has no append-only trigger (drafting-time grep: zero `CREATE TRIGGER` on reports) and the column is annotation-only.

### §6.3 Echo suppression

```rust
pub enum Origin {
    /// This event's id matches a cairn-mod-dispatched
    /// backend_action_id — our own action echoing back.
    Local,
    /// Genuinely upstream.
    Upstream,
}
```

Classification: `SELECT id FROM pds_admin_audit WHERE backend_action_id = ?1 AND call_completed_at >= ?2 LIMIT 1` with `?1 = event.id.to_string()` (the stored column is the bare `PerEvent`/`PerBatch` payload — v1.8.7 LB-5's variant-agnostic `as_str`, which is precisely what makes batch echoes joinable) and `?2 = now - LOOKBACK_MS`.

- `const LOOKBACK_MS: i64 = 86_400_000;` (24h) — module-top const, not config. Rationale: the join key is time-independent but the scan shouldn't be; 24h comfortably covers dispatch→echo latency (≤5s poll + reconciliation windows) with 5 orders of magnitude margin.
- Index (0012, §7.5): `CREATE INDEX pds_admin_audit_backend_action_idx ON pds_admin_audit(backend_action_id) WHERE backend_action_id IS NOT NULL;` — absent at HEAD (A5). Adding an index to the hash-chained table is trigger-safe and preimage-irrelevant.
- `Origin::Local` → cursor already advanced (§6.2 step 2 happens first); ingestion **skipped entirely** — no `upstream_events` row (the action is already first-class in `subject_actions` + `pds_admin_audit`; mirroring the echo would double-count in operator queries). A `stream status` counter tracks suppressed echoes.
- Check errors → log WARN, **treat as `Origin::Upstream`** and ingest: the failure mode of a broken echo check must be a duplicate observational row (harmless, dedup-able), never a silently dropped upstream event.
**Cascade-event echoes are ingested by design.** When a cairn-mod-dispatched action produces cascaded reversals (per v1.8.7 R1 LB-5: appeal-approval cascades into an account/blob restore), Aurora emits two events on the stream: the original action (echo-suppressed via `backend_action_id` match) and the cascaded reversal. The cascaded reversal's `event.id` lands in `EmitEventOutput.cascading_actions` on cairn-mod's own dispatch response, persisted to `pds_admin_audit.cascading_actions_json` — NOT to `backend_action_id`. The §6.3 join classifies the cascade `Origin::Upstream`.

Rather than adding per-frame JSON-array containment joins (`cascading_actions_json` contains `event.id`), cairn-mod treats cascade events as ingested-by-design. Cascade rows in `upstream_events` are queryable via `details.cascadeOf IS NOT NULL AND details.actor_did = <cairn-mod's service DID>` — operators auditing cascade lineage use that pattern rather than trying to reconstruct from `pds_admin_audit`'s JSON column.

Testing (§10.3): pinning test verifies a cascade event's `details.cascadeOf` matches the parent `event_id` from cairn-mod's dispatched action, both are queryable together, and no false-positive suppression rejects legitimate upstream events with a coincidentally-matching `cascadeOf`.

**Audit-insert-failure self-echo edge.** cairn-mod's dispatch path (v1.8.5–v1.8.7) commits to fail-open: if the local `pds_admin_audit` INSERT fails after a successful Aurora dispatch, the dispatch is not rolled back (Aurora's state has already changed). The Terminal error is logged; the operator can reconcile via v1.8.6's cross-verify.

When this happens, the subsequent stream echo has no matching `backend_action_id` entry, so §6.3's join classifies it `Origin::Upstream`. cairn-mod records the action twice from its read-side: the failed audit attempt is logged (out-of-band), and the stream echo lands in `upstream_events`. This is accepted as the cost of fail-open — a local audit-insert failure is already an operator-alert condition, and having the action visible in `upstream_events` is preferable to silently dropping it entirely.

Operators encountering audit-insert failures use cross-verify (v1.8.6) to reconcile: matching an `upstream_events` row against a missing `pds_admin_audit` row (both referring to the same Aurora `event_id`) surfaces as a `divergence-join-mismatch` outcome that operators investigate.

- Audit-entry frames are NOT origin-checked: the mirror table wants the complete chain including entries for cairn-mod's own actions (it mirrors Aurora's ledger, not cairn-mod's).

### §6.4 Per-verb ingestion

**All `Origin::Upstream` action events** → one `upstream_events` row (§7.2): verbatim payload columns + envelope seq + received/reconciled provenance + ingest timestamp. `INSERT OR IGNORE` on `event_id` UNIQUE (reconciliation dedup).

**Report-resolution annotation** (the one write-side coupling): when `event_type == "report_review"` AND `disambiguate_event_verb` yields `EmitEvent("ResolveReport")` or `EmitEvent("DismissReport")` — subject-match rule (A3: no report id on the wire):

```sql
UPDATE reports SET upstream_resolution = ?1
 WHERE status = 'pending'
   AND subject_did = ?2
   AND (subject_uri IS ?3)
   AND upstream_resolution IS NULL
```

`?1` = `'resolved'` for ResolveReport (the resolution enum value is also absent from the wire — `details` carries only rationale/action; recorded as the coarse `'resolved'`), `'dismissed'` for DismissReport. Multiple matching pending rows all annotate (honest: Aurora resolved *a* report about this subject; cairn-mod can't tell which). Local `status` untouched — operator-owned lifecycle. `upstream_resolution` CHECK: `('resolved', 'dismissed')` — only values actually derivable from the wire (A3 narrows the kickoff's speculative list). Appeal events (`appeal_review`) get NO reports coupling; `upstream_events` row only.

**Audit-entry frames** → §6.5, then `upstream_audit_mirror` row.

`ingest_via_stream_ingestor` is a single entry point shared by both stream-frame ingestion (LB-5) and reconciliation-fetched events (S-1). Idempotency is guaranteed by `upstream_events.event_id UNIQUE`; downstream side effects (report annotation, audit-mirror insertion) either operate on rows created by the same INSERT (join by fresh `upstream_events.id`) or are guarded by the same UNIQUE-driven skip.

### §6.5 Path A verification on audit-entry frames

Every `auditEntry` frame runs v1.8.6's `verify_upstream_entry` (`rust/upstream_verify.rs`) — the same both-canonical-forms check cross-verify uses, no new verification code. Outcomes:
- `V09` / `Legacy` → mirror row with `verified = 1`.
- `Sentinel` → mirror row, `verified = 1`, sentinel-noted (pre-chain rows per v1.8.6 rules).
- `Tampered` → **log at ERROR with the AuditDivergence framing**, mirror row with `verified = 0`, cursor advances (at-most-once holds even for tampered frames — the evidence is the mirror row, and `cairn audit cross-verify` remains the authoritative whole-chain verdict / exit-15 surface; the stream consumer never exits the process). A `stream status` tamper counter surfaces it operationally.

Aurora's own per-row `verified` field is stored alongside cairn-mod's independent verdict (`verified_upstream` vs `verified_local` columns) — disagreement is itself signal (recon: Aurora computes the same primitive, so mismatch means transport or logic drift).

## §7 — Migration 0012 (additive-only)

Forward-trace (corollary #28, drafting-time verified): live `pds_admin_audit` DDL/indexes/triggers at **0010** (A5); live `subject_actions` at 0010; `reports` live at 0001, **zero triggers**; no table this migration touches is rebuilt — everything below is `CREATE TABLE` / `CREATE INDEX` / `ALTER TABLE ADD COLUMN`, trigger bodies unchanged, hash preimages unchanged.

### §7.1 `stream_cursors`

```sql
CREATE TABLE stream_cursors (
    kind TEXT NOT NULL PRIMARY KEY CHECK (kind IN ('mod_events', 'audit_chain')),
    position INTEGER NOT NULL,
    -- RFC3339 createdAt of the last ingested event (mod_events row
    -- only; NULL for audit_chain). Reconciliation's time-window
    -- lower bound (A4: QueryEventsFilter has after/before, no id
    -- bound).
    last_created_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**Pruning posture**: `stream_cursors` is a two-row bookkeeping table; no growth over time. Operators MAY reset either row via `cairn stream cursor reset <kind>` — resetting `mod_events` triggers full reconciliation on next task start; resetting `audit_chain` triggers full re-verification from position 0.

No seed rows — absence of the `mod_events` row means "never connected" (fresh deployments subscribe cursor-less). Note `updated_at` uses a non-deterministic default: acceptable, table is unchained (contrast the 0011 boundary-capture discipline, not needed here).

### §7.2 `upstream_events`

```sql
CREATE TABLE upstream_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Aurora's moderation_event.id (the payload `id`). UNIQUE is
    -- the reconciliation-dedup key.
    event_id INTEGER NOT NULL UNIQUE,
    -- Envelope sequence when delivered live; NULL for
    -- reconciliation-sourced rows (queryEvents carries no seq).
    stream_seq INTEGER,
    event_type TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    subject_did TEXT,
    subject_uri TEXT,
    subject_cid TEXT,
    -- Raw details JSON, verbatim (disambiguator preserved).
    details TEXT,
    created_at TEXT NOT NULL,
    -- 'stream' | 'reconciliation' — provenance for operator reads.
    source TEXT NOT NULL CHECK (source IN ('stream', 'reconciliation')),
    ingested_at INTEGER NOT NULL
) STRICT;

CREATE INDEX upstream_events_subject_idx ON upstream_events(subject_did, created_at);
CREATE INDEX upstream_events_type_idx ON upstream_events(event_type);
```

Unchained, prunable, advisory (the `cross_verify_outcomes` posture). A2's home for what the kickoff wanted in `pds_admin_audit`.

**Pruning posture**: operators MAY prune old rows for storage management without breaking any invariant — the `event_id` UNIQUE prevents reconciliation-time re-ingestion, and cascade-lineage queries (§6.3) operate on recently-ingested rows. Recommended: retain 30 days. `pds_admin_audit` is NOT prunable and retains all local dispatch history.

### §7.3 `reports.upstream_resolution`

```sql
ALTER TABLE reports ADD COLUMN upstream_resolution TEXT
    CHECK (upstream_resolution IN ('resolved', 'dismissed') OR upstream_resolution IS NULL);
```

Nullable, CHECK passes for all existing rows (NULL). Values narrowed per A3 (only wire-derivable states). No trigger interaction (reports has none). The one UPDATE site is §6.4's annotation (write-once by the `upstream_resolution IS NULL` guard in the UPDATE's WHERE).

### §7.4 `upstream_audit_mirror`

```sql
CREATE TABLE upstream_audit_mirror (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Aurora chain coordinates.
    entry_id TEXT NOT NULL,
    sequence INTEGER NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    action TEXT NOT NULL,
    subject_did TEXT,
    subject_uri TEXT,
    subject_cid TEXT,
    rationale TEXT NOT NULL,
    snapshot_id TEXT,
    event_id TEXT,
    current_hash TEXT NOT NULL,
    previous_hash TEXT,
    cascade_subjects TEXT,
    cascade_snapshot_ids TEXT,
    source TEXT NOT NULL,
    payload TEXT,
    -- Aurora's own per-row recompute (wire `verified`).
    verified_upstream INTEGER NOT NULL CHECK (verified_upstream IN (0, 1)),
    -- cairn-mod's independent Path A verdict (v1.8.6
    -- verify_upstream_entry): 1 = V09/Legacy/Sentinel, 0 = Tampered.
    verified_local INTEGER NOT NULL CHECK (verified_local IN (0, 1)),
    ingested_at INTEGER NOT NULL
) STRICT;

CREATE INDEX upstream_audit_mirror_event_idx ON upstream_audit_mirror(event_id)
    WHERE event_id IS NOT NULL;
```

`sequence UNIQUE` = dedup across reconnects. Unchained (mirroring Aurora's ledger, never entering cairn-mod's own chain — §2.2). Columns mirror the v1.8.6 `AuroraAuditEntry` field set flat.

### §7.5 `pds_admin_audit` index (echo suppression)

```sql
CREATE INDEX pds_admin_audit_backend_action_idx
    ON pds_admin_audit(backend_action_id) WHERE backend_action_id IS NOT NULL;
```

Index-only change on the hash-chained table: no rebuild, triggers untouched, preimage untouched (A5).

## §8 — CLI extensions

New top-level group `cairn stream` (module `src/cli/stream.rs`):

- `cairn stream status` — reads `stream_cursors` + the consumer task's shared status cell (state, connected-since, frames/echoes/failures/tamper counters, current backoff). Works whether or not the server process runs (DB-only fields degrade gracefully).
- `cairn stream start` / `cairn stream stop` — operator control via the admin XRPC surface (moderator-tier WriteCommand convention, memory #10): the server-side consumer task parks/unparks. `start` clears a HardStop.
- `cairn stream cursor get` — print both rows of `stream_cursors`.
- `cairn stream cursor set <kind> <position>` / `cairn stream cursor reset <kind>` — operator overrides (reset deletes the row → next connect is cursor-less/live-only; set enables deliberate replay into idempotent ingestion). Guarded by a `--yes` confirm; documented as at-most-once escape hatches.
- `cairn stream reconcile` — manual reconciliation run (§5.5 procedure) for closing known gaps on demand.

## §9 — Config + dependencies

### §9.1 `[pds_admin.rust.stream]`

```toml
[pds_admin.rust.stream]
enabled = false                     # default: stream dormant
include_audit_chain = false         # opt-in audit co-delivery
reconnect_max_backoff_seconds = 60  # backoff cap (floor 1s fixed)
silence_timeout_seconds = 35        # dead-connection detection
reconnect_on_normal_close = false   # bare 1000 = intended shutdown
```

Parsed into `RustStreamConfig` on `RustBackendConfig` (defaults above when the block is absent — zero-config deployments unchanged). Validation: `silence_timeout_seconds >= 31` (must exceed Aurora's heartbeat interval or every healthy-idle connection flaps — reject with an operator-facing message naming the 30s heartbeat); `reconnect_max_backoff_seconds >= 1`. `enabled = true` additionally requires the OperatorOptIn pin at dispatch time (the gate, not config validation — posture A/B semantics identical to v1.8.7 §8.1, with `mod-events-stream = "v1"` as the pin line and `mod-events-stream-v1` in `required_capabilities` for posture B).

### §9.2 Cargo.toml

- `tokio-tungstenite = { version = "0.29", features = ["rustls-tls-webpki-roots"] }` promoted to `[dependencies]` (already pinned at 0.29 in dev-deps; TLS feature matches reqwest's `rustls-tls` webpki posture — no native-tls anywhere in the tree). Dev-dep entry collapses into the prod entry.
- `futures-util` already a production dependency (`sink`,`std`) — add the `Stream` re-export use only; no feature change expected (verify `std` covers `Stream` at implementation).

## §10 — Test coverage plan

1. **Unit (frames)**: all six `$type` variants parse from recon-verbatim JSON; unknown `$type` → skip path; malformed known frame → skip-without-cursor-advance; bare (non-NSID) discriminator pinned (A1).
2. **Unit (cursor discipline)**: persist-before-process order pinned with an injected failing ingestor — cursor advanced, failure counted; heartbeat/hello advance nothing; `last_created_at` tracks event frames only.
3. **Unit (echo suppression)**: `PerEvent` echo suppressed; `PerBatch` echo suppressed (v1.8.7 join-key reuse); unknown id ingests; check-error ingests (fail-open); lookback bound respected; cascade event (`details.cascadeOf` = parent event id, self actor DID) classifies `Origin::Upstream` and ingests, queryable alongside the parent (S-2 pin); no false-positive suppression for a coincidental `cascadeOf`.
4. **Unit (disambiguation)**: `EmitEvent("DeleteAccount")` from PascalCase details on an `account_takedown` event; `DedicatedBatch` from `batch:true`; `Other` for `report_submit`/kryphocron shapes.
5. **Unit (state machine)**: transition table §5.2 — auth→HardStop, unpinned→dormant, outdatedCursor→Reconciling→cursor-less connect, clean-close default no-reconnect, backoff reset only after first post-hello frame.
6. **Integration (mock WS Aurora)**: axum ws test server (dev tokio-tungstenite client infra exists) — hello/event/heartbeat flow; silence-timeout reconnect; outdatedCursor → queryEvents reconciliation → dedup via `upstream_events` UNIQUE; includeAuditChain interleave with dual-cursor persistence.
7. **Integration (Path A)**: streamed auditEntry through `verify_upstream_entry` — verified mirror row; tampered frame → `verified_local = 0` row + cursor advance; `verified_upstream` vs `verified_local` disagreement representable.
8. **Integration (reports)**: report_review + ResolveReport details annotates matching pending report (`'resolved'`); DismissReport → `'dismissed'`; non-matching subject leaves rows untouched; second annotation blocked by `IS NULL` guard.
9. **Migration 0012**: fresh + upgrade paths; index exists; reports CHECK accepts NULL/values, rejects others; 0010 triggers still fire (append-only preserved).
10. **Posture fixtures**: enabled+advertised+pinned → task connects; advertised+unpinned → dormant with the WARN; posture B validation per v1.8.7 precedent. Canonical capability fixtures add `mod-events-stream-v1` (probe assertion 4 → 5 strings); registry-shape pinned test at `src/pds_admin/types.rs` (NOT `tests/rust_backend.rs:70`) updates 7 → 8 (M-1).
11. **Regression**: full `cargo test` (memory #24).

## §11 — Non-goals

See §2.2. Restated headline items: no kryphocron consumption, no actionFilter, no chaining of upstream observations, no report-lifecycle mutation beyond the write-once annotation, no notification surface, no multi-Aurora upstream consumption (single upstream per cairn-mod instance — `upstream_events.event_id UNIQUE` and the cursor semantics rely on it; multi-upstream would need a compound `(upstream_did, event_id)` key and a cursor discriminator, a post-v1.8 concern per umbrella §6), no push.

## §12 — Umbrella §4.A.8 reconciliation for v1.8.11

Carry to series wrap: the four §2.3 corrections; A2 (upstream observations live beside, not inside, the dispatch audit chain); A3 (report ids absent from the stream — umbrella's implied report-level reconciliation is subject-level in practice); the two-cursor reality; `mod-events-stream` as the second OperatorOptIn consumer.

## §13 — Ready-for-implementation checklist

- [ ] Branch off `3b1af7d`; implementation chainlink open.
- [ ] Aurora cites re-verified at `2ffeb1a`: route + caps (`admin.rs:675-684`), `SubscribeModEventsParams` (`aurora_subscribe.rs:83-128`), `SubscribeMessage` + renames (`:130-179`), consts (`:181-184`), cursor-advance-before-send loop, outdatedCursor boundary (`< oldest - 1`), payload `json!` block (`:704-720`), `build_event_details` (`aurora_admin.rs:947-958`) + `action_kind_str` 16-arm enumeration, batch details block (`:1580-1585`), `event_type_for` (`:406-424`), `mod_event_seq` DDL (Aurora migration 0006), retention (`jobs/tasks.rs:155-205`).
- [ ] cairn-mod re-verified at HEAD: trait = 36; registry = 7 + pinned test; `pds_admin_audit` DDL/triggers live at 0010 with NO `backend_action_id` index; `reports` trigger-free with `('pending','resolved')` status CHECK; `QueryEventsFilter.after/before`; `AuroraAuditEntry` field set; tokio-tungstenite 0.29 dev-dep; `futures-util` prod features.
- [ ] Highest migration is 0011 (0012 free).
- [ ] Firewall grep on this doc: clean.

## §14 — Post-implementation checklist

- [ ] All six frame types round-trip against recon-verbatim JSON.
- [ ] F10 pinned by test §10.2 (the at-most-once ordering).
- [ ] Echo counters visible in `cairn stream status`.
- [ ] Full `cargo test` green; fmt/clippy/rustdoc/release gates; sqlx cache refreshed for 0012 queries.
- [ ] CHANGELOG hand-written; chainlink closed `--no-changelog`.
- [ ] Umbrella reconciliation notes filed for v1.8.11 (§12).

## §15 — Revision log

**v2 (this draft).** Post-CC-adversarial R1 fold (chainlink #146). R1 verdict: 30+ verifications with 0 LB, 2 S, 6 M. All seven drafting-time amendments A1–A7 HELD against source. Ship signal per memory #12: 0 LB → fold-and-lock. Both S findings + all M findings folded; recommendation → straight to implementation kickoff, no R2.

**R1 S-1 fold**: dropped the `reconcile_via_query_events` trait method. Reconciliation is consumer-side page loop over v1.8.3-shipped `query_events`. Trait grows 36 → 37 (not 38). Aurora's `ORDER BY created_at DESC, id DESC` window ordering made the accumulator return structurally unable to bound memory without silent middle-of-window hole; consumer-side pagination with per-page ingestion + `last_created_at` advancing only after exhaustion + `UNIQUE`-driven dedup makes reconciliation resumable and bounded. §2.1, §5.5, §6.4 updated.

**R1 S-2 fold**: cascade-event echoes documented as ingested-by-design in §6.3. When cairn-mod's dispatched actions cascade into reversal events (appeal-approval → account/blob restore), the reversal's `event_id` lands in `EmitEventOutput.cascading_actions` (persisted to `pds_admin_audit.cascading_actions_json`), NOT `backend_action_id`. §6.3's join classifies the cascade `Origin::Upstream` — accepted, not fixed. Per-frame JSON-array containment joins would be a poor cost/benefit trade; cascade rows are cheaply queryable via `details.cascadeOf` + self actor DID. Pinning test added to §10.3.

**R1 M-1 fold**: Fixture updates in §10. Canonical capability fixtures gain `mod-events-stream-v1`; probe assertion tests expect 5 (was 4); registry-shape pinned tests at `src/pds_admin/types.rs` update 7 → 8.

**R1 M-2 fold**: MAY-prune sentences added to §7.1 (`stream_cursors`, two-row bookkeeping) and §7 upstream_events (30-day recommended retention). `pds_admin_audit` explicitly non-prunable.

**R1 M-3 fold**: Multi-Aurora upstream added to §11 non-goals. `upstream_events.event_id UNIQUE` + cursor-persistence semantics assume single Aurora upstream per cairn-mod instance; future multi-upstream would need compound key. Umbrella §6 already declares multi-PDS backend dispatch a post-v1.8 concern; v1.8.8 respects that scope boundary explicitly.

**R1 M-4 fold**: §5.1 state machine gains `silence_timeout` bounds on `Connecting` (hello-wait) and `Draining` (drain deadline). Reuses existing config knob — no new knob added.

**R1 M-5 fold**: §6.3 gains audit-insert-failure self-echo edge note under existing fail-open posture. When local `pds_admin_audit` INSERT fails after successful Aurora dispatch, subsequent stream echo lands in `upstream_events` (classified `Origin::Upstream`) — recording the action twice from cairn-mod's read-side. Accepted as fail-open cost; operators reconcile via v1.8.6 cross-verify.

**Design decisions locked at v2**:
- All six LB kickoff decisions hold (NSID, dual-cursor persistence, `UpstreamEvent` mirror, echo suppression, `StreamIngestor` trait, consumer task state machine).
- Trait grows 36 → 37 (one method, not two).
- Reconciliation via consumer-side pagination over shipped `query_events`; `last_created_at` advances only after exhaustion; `UNIQUE` absorbs overlap.
- Cascade echoes ingested-by-design; queryable via `details.cascadeOf`.
- Migration 0012 scope unchanged (five items: `stream_cursors` with `last_created_at`, `reports.upstream_resolution`, `pds_admin_audit.origin` NOT ADDED per A2 amendment fold — replaced by `upstream_events` unchained table, `upstream_audit_mirror` unchained table, `pds_admin_audit.backend_action_id` index).
- Single-upstream premise explicit non-goal.
- Fail-open self-echo edge documented.

**v1 (superseded).** Initial draft. See git history if needed.

Pending: implementation kickoff.
