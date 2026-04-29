//! `cairn moderator events` (#99, Phase E) — operator-tier audit-events view.
//!
//! Mirrors `tools.ozone.moderation.queryEvents` (#98) but exposes
//! the **full** cairn-mod audit_log vocabulary, not the Ozone-
//! filtered subset. Operators see what cairn-mod actually did
//! (including pending_*, retention_sweep, xrpc collaboration
//! changes, label_*, etc.); the gateway endpoint exposes only the
//! moderator-facing subset.
//!
//! `--ozone-only` is the bridge flag: when present, applies the
//! same filter-out policy as the gateway endpoint by routing rows
//! through `audit_event::project_audit_event`. Without
//! `--ozone-only`, all eligible audit_log rows surface (with
//! cairn-mod-internal events rendered in a generic shape).
//!
//! Direct-DB (no HTTP, no moderator session). Pool comes from the
//! TOML config — same lease-aware posture as `cairn audit-rebuild`
//! and `cairn audit verify`.

use std::path::Path;

use serde::Serialize;
use sqlx::QueryBuilder;
use sqlx::{Pool, Sqlite};

use crate::xrpc_gateway::handlers::projections::audit_event::{
    AuditEventRow, OZONE_ELIGIBLE_ACTIONS, ProjectedModEvent, project_audit_event,
};

use super::error::CliError;

/// `cairn moderator events` input. Field-by-field mirroring of the
/// CLI args; `from`/`to` are RFC-3339 (parsed to epoch-ms in the
/// orchestrator).
#[derive(Debug, Clone, Default)]
pub struct EventsInput {
    /// Filter to events about a specific subject (DID for
    /// account-level, AT-URI for record-level).
    pub subject: Option<String>,
    /// Filter to events by this moderator/actor DID
    /// (`audit_log.actor_did`).
    pub actor: Option<String>,
    /// Filter to a specific `audit_log.action` value (or, when
    /// `--ozone-only`, an Ozone $type — cf. queryEvents'
    /// `types`). The CLI surface accepts the cairn-mod-side
    /// vocabulary directly since this is operator-tier; rejected
    /// values surface as InvalidRequest.
    pub action_type: Option<String>,
    /// RFC-3339 lower bound on `audit_log.created_at`.
    pub from: Option<String>,
    /// RFC-3339 upper bound.
    pub to: Option<String>,
    /// Page size. Capped at 250 (matches existing `cairn audit list`).
    pub limit: Option<u32>,
    /// Opaque pagination cursor — base64url(JSON `{cursor_id: i64}`),
    /// matching #98's queryEvents cursor format. Operators can
    /// pass cursors freely between the two surfaces because the
    /// underlying audit_log.id is the same monotonic key.
    pub cursor: Option<String>,
    /// When `true`, applies the gateway endpoint's filter-out
    /// policy + projection. The output shape becomes Ozone's
    /// `modEventView`. When `false` (default), surfaces ALL
    /// eligible audit_log rows.
    pub ozone_only: bool,
}

const MAX_LIMIT: u32 = 250;
const DEFAULT_LIMIT: u32 = 50;

/// One row of CLI output. Distinguishes between Ozone-shaped
/// projected events and the generic-shape rows that surface only
/// in `--ozone-only=false` mode.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "shape")]
pub enum EventRow {
    /// An Ozone-shaped event — always emitted with `--ozone-only`,
    /// and emitted alongside `Internal` events without
    /// `--ozone-only`.
    #[serde(rename = "ozone")]
    Ozone(OzoneEventRow),
    /// A cairn-mod-internal audit row that has no Ozone analog.
    /// Surfaced only when `ozone_only=false`.
    #[serde(rename = "internal")]
    Internal(InternalEventRow),
}

/// Wire shape for an Ozone-eligible event in the CLI output.
/// Mirrors the gateway's `ModEventView` minus the empty
/// `subject_blob_cids` field (the CLI omits redundantly empty
/// fields).
#[derive(Debug, Clone, Serialize)]
pub struct OzoneEventRow {
    /// `audit_log.id`.
    pub id: i64,
    /// Discriminated event body (`modEventLabel` / `Takedown` /
    /// `ReverseTakedown` / `Comment`).
    pub event: serde_json::Value,
    /// Discriminated subject ref.
    pub subject: serde_json::Value,
    /// `audit_log.actor_did`.
    pub created_by: String,
    /// RFC-3339 Z.
    pub created_at: String,
}

/// Wire shape for a cairn-mod-internal audit row. Generic shape:
/// the row's raw `action` value plus actor / target / outcome /
/// timestamp.
#[derive(Debug, Clone, Serialize)]
pub struct InternalEventRow {
    /// `audit_log.id`.
    pub id: i64,
    /// `audit_log.action` — the cairn-mod-internal vocabulary.
    pub action: String,
    /// `audit_log.actor_did`.
    pub actor_did: String,
    /// `audit_log.target` (subject DID, AT-URI, action_id, etc. —
    /// shape varies by action; surfaced verbatim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `audit_log.outcome` (`success` or `failure`).
    pub outcome: String,
    /// RFC-3339 Z (converted from `audit_log.created_at` epoch-ms).
    pub created_at: String,
}

/// Response. The CLI prints either tabular (default) or JSON
/// (`--json`) output.
#[derive(Debug, Clone, Serialize)]
pub struct EventsResponse {
    /// Opaque cursor for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Page rows, sort-direction-respecting.
    pub events: Vec<EventRow>,
}

/// `cairn moderator events` orchestrator. Parses input + queries
/// audit_log + projects + serializes.
pub async fn list(pool: &Pool<Sqlite>, input: EventsInput) -> Result<EventsResponse, CliError> {
    let parsed = parse_input(input)?;
    let raw = fetch_page(pool, &parsed).await?;
    let has_more = raw.len() > parsed.limit as usize;
    let surfaced: Vec<RawAuditRow> = raw.into_iter().take(parsed.limit as usize).collect();

    let mut events = Vec::with_capacity(surfaced.len());
    let mut last_id: Option<i64> = None;
    for r in &surfaced {
        last_id = Some(r.audit_id);

        if parsed.ozone_only {
            // Apply the gateway endpoint's filter-out policy by
            // routing the row through project_audit_event. Filtered-
            // out rows skip without further surfacing.
            let aer = r.to_audit_event_row();
            if let Some(projected) = project_audit_event(&aer) {
                events.push(EventRow::Ozone(projected_to_row(projected)));
            }
            continue;
        }

        // ozone_only=false: surface every row, choosing the right
        // shape per action.
        if OZONE_ELIGIBLE_ACTIONS.contains(&r.audit_action.as_str()) {
            let aer = r.to_audit_event_row();
            if let Some(projected) = project_audit_event(&aer) {
                events.push(EventRow::Ozone(projected_to_row(projected)));
                continue;
            }
            // The action is Ozone-eligible at the audit-action
            // level but the per-row projection filtered it out
            // (e.g., revoked-warning has no Ozone analog). Fall
            // through to the Internal-shape so operators still see
            // the event.
        }
        events.push(EventRow::Internal(InternalEventRow {
            id: r.audit_id,
            action: r.audit_action.clone(),
            actor_did: r.actor_did.clone(),
            target: r.target.clone(),
            outcome: r.outcome.clone(),
            created_at: epoch_ms_to_rfc3339(r.created_at),
        }));
    }

    let cursor = if has_more {
        last_id.map(encode_cursor)
    } else {
        None
    };

    Ok(EventsResponse { cursor, events })
}

// ==========================================================================
// Input parsing
// ==========================================================================

#[derive(Debug)]
struct ParsedInput {
    subject_did: Option<String>,
    subject_uri: Option<String>,
    actor: Option<String>,
    action_type: Option<String>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    limit: u32,
    cursor_id: Option<i64>,
    ozone_only: bool,
}

fn parse_input(i: EventsInput) -> Result<ParsedInput, CliError> {
    let limit = match i.limit {
        None => DEFAULT_LIMIT,
        Some(0) => return Err(CliError::Config("limit must be at least 1".into())),
        Some(n) if n > MAX_LIMIT => {
            return Err(CliError::Config(format!(
                "limit {n} exceeds maximum {MAX_LIMIT}"
            )));
        }
        Some(n) => n,
    };

    let cursor_id = match i.cursor.as_deref() {
        None => None,
        Some(s) => Some(decode_cursor(s)?),
    };

    let (subject_did, subject_uri) = match i.subject.as_deref() {
        None => (None, None),
        Some(s) if s.starts_with("at://") => {
            let did = s
                .strip_prefix("at://")
                .and_then(|rest| rest.split('/').next())
                .filter(|d| d.starts_with("did:"))
                .ok_or_else(|| {
                    CliError::Config(format!("subject AT-URI {s:?} missing DID authority"))
                })?
                .to_string();
            (Some(did), Some(s.to_string()))
        }
        Some(s) if s.starts_with("did:") => (Some(s.to_string()), None),
        Some(s) => {
            return Err(CliError::Config(format!(
                "subject {s:?} is neither a DID nor an AT-URI"
            )));
        }
    };

    let from_ms = match i.from.as_deref() {
        None => None,
        Some(s) => Some(parse_rfc3339_to_ms(s)?),
    };
    let to_ms = match i.to.as_deref() {
        None => None,
        Some(s) => Some(parse_rfc3339_to_ms(s)?),
    };

    Ok(ParsedInput {
        subject_did,
        subject_uri,
        actor: i.actor,
        action_type: i.action_type,
        from_ms,
        to_ms,
        limit,
        cursor_id,
        ozone_only: i.ozone_only,
    })
}

fn parse_rfc3339_to_ms(s: &str) -> Result<i64, CliError> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let dt = OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| CliError::Config(format!("malformed RFC-3339 timestamp: {s:?}")))?;
    Ok((dt.unix_timestamp_nanos() / 1_000_000) as i64)
}

// ==========================================================================
// Cursor (matches #98's audit-id-only encoding)
// ==========================================================================

#[derive(serde::Serialize, serde::Deserialize)]
struct CursorBody {
    cursor_id: i64,
}

fn encode_cursor(id: i64) -> String {
    use base64::Engine as _;
    let json = serde_json::to_vec(&CursorBody { cursor_id: id }).expect("cursor serializes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

fn decode_cursor(s: &str) -> Result<i64, CliError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CliError::Config(format!("malformed cursor (base64): {e}")))?;
    let body: CursorBody = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::Config(format!("malformed cursor (json): {e}")))?;
    Ok(body.cursor_id)
}

// ==========================================================================
// Page query
// ==========================================================================

/// Raw row shape from the page query. Holds enough columns to
/// project either as an Ozone event (when joined to subject_actions)
/// or as an Internal row (when there's no join).
#[derive(Debug, Clone)]
struct RawAuditRow {
    audit_id: i64,
    audit_action: String,
    actor_did: String,
    target: Option<String>,
    outcome: String,
    created_at: i64,
    subject_action_type: Option<String>,
    subject_did: Option<String>,
    subject_uri: Option<String>,
    subject_notes: Option<String>,
    subject_duration: Option<String>,
    subject_reason_codes: Option<String>,
    audit_reason: Option<String>,
}

impl RawAuditRow {
    fn to_audit_event_row(&self) -> AuditEventRow {
        AuditEventRow {
            audit_id: self.audit_id,
            audit_action: self.audit_action.clone(),
            actor_did: self.actor_did.clone(),
            created_at: self.created_at,
            subject_action_type: self.subject_action_type.clone(),
            subject_did: self.subject_did.clone(),
            subject_uri: self.subject_uri.clone(),
            subject_notes: self.subject_notes.clone(),
            subject_duration: self.subject_duration.clone(),
            subject_reason_codes_json: self.subject_reason_codes.clone(),
            audit_reason_json: self.audit_reason.clone(),
        }
    }
}

async fn fetch_page(
    pool: &Pool<Sqlite>,
    parsed: &ParsedInput,
) -> Result<Vec<RawAuditRow>, CliError> {
    // Both modes share the same SQL up to the action filter:
    // ozone_only restricts to the OZONE_ELIGIBLE_ACTIONS set; the
    // full mode pulls every action. Subject filter applies through
    // the join in both modes (for non-eligible actions, the join
    // returns NULLs, and a subject_did filter would zero them out
    // — which is the intended behavior, since "events about
    // subject X" only makes sense for rows that have a subject).
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        r#"SELECT
             a.id           AS audit_id,
             a.action       AS audit_action,
             a.actor_did    AS actor_did,
             a.target       AS target,
             a.outcome      AS outcome,
             a.created_at   AS created_at,
             sa.action_type AS subject_action_type,
             sa.subject_did AS subject_did,
             sa.subject_uri AS subject_uri,
             sa.notes       AS subject_notes,
             sa.duration    AS subject_duration,
             sa.reason_codes AS subject_reason_codes,
             a.reason       AS audit_reason
           FROM audit_log a
           LEFT JOIN subject_actions sa ON
             (a.action = 'subject_action_recorded' AND sa.audit_log_id = a.id)
             OR (a.action = 'subject_action_revoked' AND sa.id = CAST(a.target AS INTEGER))
           WHERE 1=1"#,
    );

    if parsed.ozone_only {
        qb.push(" AND a.action IN (");
        let mut sep = qb.separated(", ");
        for action in OZONE_ELIGIBLE_ACTIONS {
            sep.push_bind(*action);
        }
        qb.push(")");
    }

    if let Some(action) = &parsed.action_type {
        qb.push(" AND a.action = ").push_bind(action.clone());
    }
    if let Some(actor) = &parsed.actor {
        qb.push(" AND a.actor_did = ").push_bind(actor.clone());
    }
    if let Some(did) = &parsed.subject_did {
        qb.push(" AND sa.subject_did = ").push_bind(did.clone());
        if parsed.subject_uri.is_none() {
            qb.push(" AND sa.subject_uri IS NULL");
        }
    }
    if let Some(uri) = &parsed.subject_uri {
        qb.push(" AND sa.subject_uri = ").push_bind(uri.clone());
    }
    if let Some(from) = parsed.from_ms {
        qb.push(" AND a.created_at >= ").push_bind(from);
    }
    if let Some(to) = parsed.to_ms {
        qb.push(" AND a.created_at <= ").push_bind(to);
    }
    if let Some(c) = parsed.cursor_id {
        // Default sort is DESC (newest first); cursor selects rows
        // strictly older than the previous-page boundary.
        qb.push(" AND a.id < ").push_bind(c);
    }

    qb.push(" ORDER BY a.id DESC LIMIT ")
        .push_bind((parsed.limit + 1) as i64);

    qb.build_query_as::<(
        i64,
        String,
        String,
        Option<String>,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )>()
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(
                    audit_id,
                    audit_action,
                    actor_did,
                    target,
                    outcome,
                    created_at,
                    subject_action_type,
                    subject_did,
                    subject_uri,
                    subject_notes,
                    subject_duration,
                    subject_reason_codes,
                    audit_reason,
                )| RawAuditRow {
                    audit_id,
                    audit_action,
                    actor_did,
                    target,
                    outcome,
                    created_at,
                    subject_action_type,
                    subject_did,
                    subject_uri,
                    subject_notes,
                    subject_duration,
                    subject_reason_codes,
                    audit_reason,
                },
            )
            .collect()
    })
    .map_err(|e| CliError::Startup(format!("audit_log query: {e}")))
}

// ==========================================================================
// Output helpers
// ==========================================================================

fn projected_to_row(p: ProjectedModEvent) -> OzoneEventRow {
    OzoneEventRow {
        id: p.id,
        event: p.event,
        subject: p.subject,
        created_by: p.created_by,
        created_at: epoch_ms_to_rfc3339(p.created_at),
    }
}

fn epoch_ms_to_rfc3339(ms: i64) -> String {
    crate::writer::rfc3339_from_epoch_ms(ms)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00.000Z"))
}

/// Tabular human renderer. One line per event; fields tab-
/// separated for greppability. Columns differ between Ozone and
/// Internal shapes; the output keeps both shapes in chronological
/// order so an operator's `cairn moderator events | grep <did>`
/// surfaces both moderator-facing events and operator-internal
/// noise.
pub fn format_human(resp: &EventsResponse) -> String {
    use std::fmt::Write;
    if resp.events.is_empty() {
        let mut s = String::from("(no events)");
        if let Some(c) = &resp.cursor {
            let _ = write!(s, "\nnext cursor: {c}");
        }
        return s;
    }

    let mut out = String::new();
    for ev in &resp.events {
        match ev {
            EventRow::Ozone(o) => {
                let ty = o.event["$type"].as_str().unwrap_or("?");
                let subj = o.subject["did"]
                    .as_str()
                    .or_else(|| o.subject["uri"].as_str())
                    .unwrap_or("?");
                let _ = writeln!(
                    out,
                    "ozone\t{}\t{}\t{}\t{}\tby={}",
                    o.id, o.created_at, ty, subj, o.created_by,
                );
            }
            EventRow::Internal(i) => {
                let target = i.target.as_deref().unwrap_or("-");
                let _ = writeln!(
                    out,
                    "internal\t{}\t{}\t{}\t{}\tby={}\toutcome={}",
                    i.id, i.created_at, i.action, target, i.actor_did, i.outcome,
                );
            }
        }
    }
    if let Some(c) = &resp.cursor {
        let _ = write!(out, "next cursor: {c}");
    } else if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// JSON renderer. Single-line JSON for tooling.
pub fn format_json(resp: &EventsResponse) -> String {
    serde_json::to_string(resp).expect("EventsResponse serializes")
}

/// Public type-aware path-aware DB pool helper, matching the
/// existing CLI convention (cf. `audit_verify::verify` taking
/// `&Pool<Sqlite>` directly). main.rs opens the pool from
/// `--config` and passes through.
#[allow(dead_code)]
fn _imports_used(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input() -> EventsInput {
        EventsInput::default()
    }

    // ===== Param parsing =====

    #[test]
    fn default_limit_is_50() {
        let p = parse_input(empty_input()).unwrap();
        assert_eq!(p.limit, 50);
    }

    #[test]
    fn limit_capped_at_250() {
        let mut i = empty_input();
        i.limit = Some(500);
        let err = parse_input(i).unwrap_err();
        assert!(err.to_string().contains("250"));
    }

    #[test]
    fn limit_zero_rejected() {
        let mut i = empty_input();
        i.limit = Some(0);
        let err = parse_input(i).unwrap_err();
        assert!(err.to_string().contains("at least 1"));
    }

    #[test]
    fn account_level_subject_parses_to_did() {
        let mut i = empty_input();
        i.subject = Some("did:plc:abc".into());
        let p = parse_input(i).unwrap();
        assert_eq!(p.subject_did.as_deref(), Some("did:plc:abc"));
        assert!(p.subject_uri.is_none());
    }

    #[test]
    fn record_level_subject_parses_to_did_plus_uri() {
        let mut i = empty_input();
        i.subject = Some("at://did:plc:author/c/r".into());
        let p = parse_input(i).unwrap();
        assert_eq!(p.subject_did.as_deref(), Some("did:plc:author"));
        assert_eq!(p.subject_uri.as_deref(), Some("at://did:plc:author/c/r"));
    }

    #[test]
    fn malformed_subject_rejected() {
        let mut i = empty_input();
        i.subject = Some("not-a-did".into());
        assert!(parse_input(i).is_err());
    }

    #[test]
    fn malformed_rfc3339_rejected() {
        let mut i = empty_input();
        i.from = Some("not-a-date".into());
        assert!(parse_input(i).is_err());
    }

    #[test]
    fn cursor_round_trip() {
        let s = encode_cursor(42);
        let id = decode_cursor(&s).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn malformed_cursor_rejected() {
        assert!(decode_cursor("not-base64-!!!").is_err());
    }

    // ===== Format =====

    #[test]
    fn format_human_empty() {
        let resp = EventsResponse {
            cursor: None,
            events: Vec::new(),
        };
        assert_eq!(format_human(&resp), "(no events)");
    }

    #[test]
    fn format_human_with_cursor_appends_cursor_line() {
        let resp = EventsResponse {
            cursor: Some("c".into()),
            events: Vec::new(),
        };
        let out = format_human(&resp);
        assert!(out.contains("next cursor: c"));
    }

    #[test]
    fn format_human_renders_internal_row() {
        let resp = EventsResponse {
            cursor: None,
            events: vec![EventRow::Internal(InternalEventRow {
                id: 5,
                action: "retention_sweep".into(),
                actor_did: "did:plc:m".into(),
                target: None,
                outcome: "success".into(),
                created_at: "2026-04-29T00:00:00.000Z".into(),
            })],
        };
        let out = format_human(&resp);
        assert!(out.contains("internal"));
        assert!(out.contains("retention_sweep"));
        assert!(out.contains("did:plc:m"));
    }

    #[test]
    fn format_human_renders_ozone_row() {
        let resp = EventsResponse {
            cursor: None,
            events: vec![EventRow::Ozone(OzoneEventRow {
                id: 7,
                event: serde_json::json!({
                    "$type": "tools.ozone.moderation.defs#modEventLabel",
                    "createLabelVals": ["spam"],
                }),
                subject: serde_json::json!({
                    "$type": "com.atproto.admin.defs#repoRef",
                    "did": "did:plc:t",
                }),
                created_by: "did:plc:m".into(),
                created_at: "2026-04-29T00:00:00.000Z".into(),
            })],
        };
        let out = format_human(&resp);
        assert!(out.contains("ozone"));
        assert!(out.contains("modEventLabel"));
        assert!(out.contains("did:plc:t"));
    }

    #[test]
    fn format_json_round_trip() {
        let resp = EventsResponse {
            cursor: Some("c".into()),
            events: vec![EventRow::Internal(InternalEventRow {
                id: 1,
                action: "report_resolved".into(),
                actor_did: "did:plc:m".into(),
                target: Some("42".into()),
                outcome: "success".into(),
                created_at: "2026-04-29T00:00:00.000Z".into(),
            })],
        };
        let s = format_json(&resp);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["cursor"].as_str(), Some("c"));
        assert_eq!(v["events"][0]["shape"].as_str(), Some("internal"));
        assert_eq!(v["events"][0]["action"].as_str(), Some("report_resolved"));
    }
}
