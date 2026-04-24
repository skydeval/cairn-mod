//! `GET /.well-known/did.json` — did:web DID document for Cairn (L3).
//!
//! Synthesized on every request from [`crate::Config`] + the
//! `signing_keys` table (bootstrapped by the Writer task per #4).
//! No caching, no state beyond the pool + config — per-request
//! SELECT is cheap and consumers do their own TTL caching per §5.4.
//!
//! Scope boundary:
//!
//! - **#8** publishes the `app.bsky.labeler.service` RECORD (labelValues,
//!   locales, severity) to the operator's PDS. Distinct artifact.
//! - **L3 (this module)** serves the DID document that identifies the
//!   labeler + advertises its signing key + HTTP endpoint.
//! - **L4** (cairn serve) wires this router into the live binary and
//!   **must** ensure the Writer task bootstraps `signing_keys` before the
//!   HTTP listener binds — else this endpoint returns 503 on startup.
//!
//! Forward-compat note on signing-key rotation (v1.1): the SELECT
//! filters on `valid_to IS NULL`, so a future multi-row state during
//! rotation naturally emits multiple `verificationMethod` entries with
//! suffixed fragment IDs. v1 always has one row → one unsuffixed entry
//! matching the `#atproto_label` constant used elsewhere in the codebase.

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use serde_json::json;
use sqlx::{Pool, Sqlite};

use crate::config::Config;

/// Fragment used for the single-key case. Matches the constant
/// referenced by [`crate::auth`] and [`crate::signing`].
pub const LABELER_KEY_FRAGMENT: &str = "#atproto_label";

/// `service.id` + `service.type` for the `AtprotoLabeler` entry that
/// tells consumers where Cairn's HTTP / WS endpoints live. `AtprotoLabeler`
/// is a Bluesky-ecosystem convention rather than a W3C-level DID spec,
/// but it's what atproto-api and moderation tooling look up; matching
/// it is the interop contract.
const LABELER_SERVICE_FRAGMENT: &str = "#atproto_labeler";
const LABELER_SERVICE_TYPE: &str = "AtprotoLabeler";

/// Minimal SigningKeyRow projection — the two fields the DID doc
/// builder consumes. Exposed so the unit tests can construct
/// synthetic rows without going through sqlx.
#[derive(Debug, Clone)]
pub struct SigningKeyRow {
    /// `signing_keys.id` primary key. Used for fragment-ID
    /// suffixing when multiple keys are active (v1.1 rotation).
    pub id: i64,
    /// Public key in multibase (z-prefixed base58btc)
    /// encoding. Emitted verbatim on the wire.
    pub public_key_multibase: String,
}

/// Wire shape of `/.well-known/did.json` (L3). Field names match
/// the did:web document the rest of the ATProto ecosystem expects:
/// `@context` + `id` + `verificationMethod[]` + `service[]`.
#[derive(Debug, Serialize)]
pub struct DidDocumentWire {
    /// W3C DID context URIs. Both W3C DID v1 + Multikey v1 are
    /// included for interop.
    #[serde(rename = "@context")]
    pub context: Vec<&'static str>,
    /// The DID this document describes (matches Cairn's
    /// configured `service_did`).
    pub id: String,
    /// One entry per active signing key. Single-key case uses the
    /// unsuffixed `#atproto_label` fragment; multi-key rotation
    /// windows use `#atproto_label_{id}`.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethodWire>,
    /// Typically a single `AtprotoLabeler` entry advertising this
    /// Cairn instance's public endpoint URL.
    pub service: Vec<ServiceWire>,
}

/// One `verificationMethod` entry in the emitted DID document.
/// Always a `Multikey` in v1; see [`crate::signing`] for the
/// signing side of the contract.
#[derive(Debug, Serialize)]
pub struct VerificationMethodWire {
    /// Full verification-method identifier, e.g.
    /// `did:web:labeler.example#atproto_label`.
    pub id: String,
    /// Always `"Multikey"` in v1.
    #[serde(rename = "type")]
    pub r#type: &'static str,
    /// The DID that controls this key (always the service DID
    /// itself for a labeler's own signing key).
    pub controller: String,
    /// Multibase-encoded public key material.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// One `service` entry — for Cairn's DID document this is the
/// `AtprotoLabeler` record that points consumers at the HTTP /
/// WebSocket surface.
#[derive(Debug, Serialize)]
pub struct ServiceWire {
    /// Service fragment id (e.g. `"#atproto_labeler"`).
    pub id: &'static str,
    /// Always `"AtprotoLabeler"` for Cairn (Bluesky-ecosystem
    /// convention; see `LABELER_SERVICE_TYPE`).
    #[serde(rename = "type")]
    pub r#type: &'static str,
    /// Publicly-reachable base URL where consumers call this
    /// labeler — matches `Config::service_endpoint`.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Pure builder — inputs determine output. Used by both the route
/// handler and unit tests.
///
/// Fragment-ID rules:
/// - single key → unsuffixed `#atproto_label` (matches the rest of
///   the codebase's canonical reference).
/// - multiple keys → `#atproto_label_{id}` per row, preserving
///   uniqueness during a v1.1 rotation window.
pub fn build_did_document(
    service_did: &str,
    service_endpoint: &str,
    keys: &[SigningKeyRow],
) -> DidDocumentWire {
    let single = keys.len() == 1;
    let verification_method = keys
        .iter()
        .map(|k| {
            let fragment = if single {
                LABELER_KEY_FRAGMENT.to_string()
            } else {
                format!("{LABELER_KEY_FRAGMENT}_{}", k.id)
            };
            VerificationMethodWire {
                id: format!("{service_did}{fragment}"),
                r#type: "Multikey",
                controller: service_did.to_string(),
                public_key_multibase: k.public_key_multibase.clone(),
            }
        })
        .collect();
    DidDocumentWire {
        context: vec![
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        id: service_did.to_string(),
        verification_method,
        service: vec![ServiceWire {
            id: LABELER_SERVICE_FRAGMENT,
            r#type: LABELER_SERVICE_TYPE,
            service_endpoint: service_endpoint.to_string(),
        }],
    }
}

/// Build a router exposing `GET /.well-known/did.json`.
/// Compose into the live binary via [`axum::Router::merge`].
pub fn did_document_router(pool: Pool<Sqlite>, config: Config) -> Router {
    Router::new()
        .route("/.well-known/did.json", get(serve_did_document))
        .layer(Extension(DidDocumentState { pool, config }))
}

#[derive(Clone)]
struct DidDocumentState {
    pool: Pool<Sqlite>,
    config: Config,
}

async fn serve_did_document(Extension(state): Extension<DidDocumentState>) -> Response {
    let rows = match sqlx::query_as!(
        SigningKeyRow,
        "SELECT id, public_key_multibase FROM signing_keys WHERE valid_to IS NULL ORDER BY id"
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return internal_error(),
    };
    if rows.is_empty() {
        return service_unavailable();
    }
    let doc = build_did_document(
        &state.config.service_did,
        &state.config.service_endpoint,
        &rows,
    );
    let body = serde_json::to_vec(&doc).expect("DidDocumentWire always serializes");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "ServiceUnavailable",
            "message": "signing key not bootstrapped",
        })),
    )
        .into_response()
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "InternalServerError",
            "message": "service temporarily unavailable",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn row(id: i64, mb: &str) -> SigningKeyRow {
        SigningKeyRow {
            id,
            public_key_multibase: mb.into(),
        }
    }

    #[test]
    fn single_key_uses_unsuffixed_fragment() {
        let doc = build_did_document(
            "did:web:labeler.example",
            "https://labeler.example",
            &[row(1, "zXYZ")],
        );
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].id,
            "did:web:labeler.example#atproto_label"
        );
        assert_eq!(doc.verification_method[0].r#type, "Multikey");
        assert_eq!(
            doc.verification_method[0].controller,
            "did:web:labeler.example"
        );
        assert_eq!(doc.verification_method[0].public_key_multibase, "zXYZ");
    }

    #[test]
    fn multi_key_uses_id_suffixed_fragments() {
        // Forward-compat for v1.1 rotation windows.
        let doc = build_did_document(
            "did:web:labeler.example",
            "https://labeler.example",
            &[row(1, "zOLD"), row(2, "zNEW")],
        );
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(
            doc.verification_method[0].id,
            "did:web:labeler.example#atproto_label_1"
        );
        assert_eq!(
            doc.verification_method[1].id,
            "did:web:labeler.example#atproto_label_2"
        );
    }

    #[test]
    fn context_contains_required_entries() {
        let doc = build_did_document(
            "did:web:labeler.example",
            "https://labeler.example",
            &[row(1, "z")],
        );
        assert!(doc.context.contains(&"https://www.w3.org/ns/did/v1"));
        assert!(
            doc.context
                .contains(&"https://w3id.org/security/multikey/v1")
        );
    }

    #[test]
    fn service_entry_is_atproto_labeler() {
        let doc = build_did_document(
            "did:web:labeler.example",
            "https://labeler.example",
            &[row(1, "z")],
        );
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].id, "#atproto_labeler");
        assert_eq!(doc.service[0].r#type, "AtprotoLabeler");
        assert_eq!(doc.service[0].service_endpoint, "https://labeler.example");
    }

    #[test]
    fn serialized_json_has_camelcase_field_names() {
        let doc = build_did_document(
            "did:web:labeler.example",
            "https://labeler.example",
            &[row(1, "z")],
        );
        let v: Value = serde_json::to_value(&doc).unwrap();
        // Spot-check renames
        assert!(v.get("@context").is_some());
        assert!(
            v["verificationMethod"][0]
                .get("publicKeyMultibase")
                .is_some()
        );
        assert!(v["service"][0].get("serviceEndpoint").is_some());
    }
}
