//! `tools.cairn.admin.getTrustChain` handler (#36, §F12 admin-role-only).
//!
//! Read-only. Reads `signing_keys`, `moderators`, and the
//! `labeler_config` KV row for `service_record_content_hash`; assembles
//! the four shared-typed fields the lexicon's response schema declares
//! (signingKeys / maintainers / serviceRecord / instance) plus the
//! top-level `serviceDid` and the wrapping envelope. No DB writes; no
//! `audit_log` row — this is a transparency surface, not a moderation
//! event.
//!
//! On `provenanceAttested`: `moderators.added_by` is NULL for rows that
//! were inserted via the CLI (cairn moderator add) or direct SQL —
//! pre-dating any HTTP-attested moderator-add flow. The trust-chain
//! surface reports `provenanceAttested: false` for those rows so an
//! external auditor can distinguish "added via the writeable admin
//! endpoint with a verified caller DID" from "added by the operator
//! out-of-band." Same provenance reasoning is documented in the
//! README's Moderator-management `added_by` semantics block.
//!
//! On `serviceRecord` nullability: returned as `null` when the
//! deployment runs without a `[labeler]` config block (§F19 labeler-
//! absent path) OR when no service record has been published yet
//! (no `service_record_content_hash` in `labeler_config`). The summary
//! is meaningful only when BOTH the declared taxonomy AND the published
//! hash are present; partial states (one without the other) produce
//! `null` to avoid surfacing half-truths.

use axum::Extension;
use axum::Json;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::writer::{epoch_ms_now, rfc3339_from_epoch_ms};

use super::common::{AdminError, AdminState, verify_and_authorize_admin_only};

const LXM: &str = "tools.cairn.admin.getTrustChain";

#[derive(Debug, Serialize)]
struct Output {
    #[serde(rename = "serviceDid")]
    service_did: String,
    #[serde(rename = "signingKeys")]
    signing_keys: Vec<SigningKeyEntry>,
    maintainers: Vec<MaintainerEntry>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "serviceRecord")]
    service_record: Option<ServiceRecordSummary>,
    instance: InstanceInfo,
}

#[derive(Debug, Serialize)]
struct SigningKeyEntry {
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "validTo")]
    valid_to: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "isActive")]
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct MaintainerEntry {
    did: String,
    role: String,
    #[serde(rename = "addedAt")]
    added_at: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "addedBy")]
    added_by: Option<String>,
    #[serde(rename = "provenanceAttested")]
    provenance_attested: bool,
}

#[derive(Debug, Serialize)]
struct ServiceRecordSummary {
    #[serde(rename = "contentHash")]
    content_hash: String,
    #[serde(rename = "labelValues")]
    label_values: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InstanceInfo {
    version: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: String,
}

pub(super) async fn handler(
    Extension(state): Extension<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = verify_and_authorize_admin_only(&state, &headers, LXM).await {
        return e.into_response();
    }

    let signing_keys = match load_signing_keys(&state).await {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let maintainers = match load_maintainers(&state).await {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let service_record = match load_service_record(&state).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    Json(Output {
        service_did: state.config.service_did.clone(),
        signing_keys,
        maintainers,
        service_record,
        instance: InstanceInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            service_endpoint: state.config.service_endpoint.clone(),
        },
    })
    .into_response()
}

async fn load_signing_keys(state: &AdminState) -> Result<Vec<SigningKeyEntry>, AdminError> {
    let rows = sqlx::query!(
        r#"SELECT public_key_multibase, valid_from, valid_to, created_at AS "created_at!: i64"
           FROM signing_keys
           ORDER BY valid_from ASC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AdminError::Internal)?;

    // Comparison anchor for `isActive`: valid_to is TEXT in
    // RFC-3339 Z form (matches `cts` formatter); lexicographic
    // compare against now-as-RFC-3339 is correct because all values
    // are UTC with the same precision. Equivalent to "valid_to IS
    // NULL OR valid_to > now" without parsing.
    let now_ms = epoch_ms_now();
    let now_rfc = rfc3339_from_epoch_ms(now_ms).map_err(|_| AdminError::Internal)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let created_at = rfc3339_from_epoch_ms(r.created_at).map_err(|_| AdminError::Internal)?;
        let is_active = match r.valid_to.as_deref() {
            None => true,
            Some(v) => v.as_bytes() > now_rfc.as_bytes(),
        };
        out.push(SigningKeyEntry {
            public_key_multibase: r.public_key_multibase,
            valid_from: r.valid_from,
            valid_to: r.valid_to,
            created_at,
            is_active,
        });
    }
    Ok(out)
}

async fn load_maintainers(state: &AdminState) -> Result<Vec<MaintainerEntry>, AdminError> {
    let rows = sqlx::query!(
        r#"SELECT did, role, added_by, added_at AS "added_at!: i64"
           FROM moderators
           ORDER BY added_at ASC, did ASC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AdminError::Internal)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let added_at = rfc3339_from_epoch_ms(r.added_at).map_err(|_| AdminError::Internal)?;
        let provenance_attested = r.added_by.is_some();
        out.push(MaintainerEntry {
            did: r.did,
            role: r.role,
            added_at,
            added_by: r.added_by,
            provenance_attested,
        });
    }
    Ok(out)
}

/// Loads `serviceRecord` only when BOTH the declared taxonomy AND the
/// published content hash are present (see module-level doc). Returns
/// `Ok(None)` for partial states (one without the other) — those are
/// not error conditions, just half-states the trust-chain surface
/// declines to present as if they were complete.
async fn load_service_record(
    state: &AdminState,
) -> Result<Option<ServiceRecordSummary>, AdminError> {
    let Some(label_values) = state.config.declared_label_values.clone() else {
        return Ok(None);
    };

    let row =
        sqlx::query!("SELECT value FROM labeler_config WHERE key = 'service_record_content_hash'",)
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| AdminError::Internal)?;

    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(ServiceRecordSummary {
        content_hash: row.value,
        label_values,
    }))
}
