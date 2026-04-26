//! `cairn trust-chain show` — admin-side trust-chain transparency
//! query (#37).
//!
//! Wraps `tools.cairn.admin.getTrustChain`
//! (src/server/admin/get_trust_chain.rs). **Admin role only** —
//! the server's auth check uses `verify_and_authorize_admin_only`,
//! so a moderator-role session file produces a 403 that surfaces
//! as `CliError::CairnStatus { status: 403, .. }` here.
//!
//! No query parameters; the endpoint takes no inputs and returns
//! a single envelope (signingKeys / maintainers / serviceRecord /
//! instance + top-level serviceDid).
//!
//! Pattern matches `cli/audit.rs` exactly: typed `Input` →
//! `show()` orchestrator → typed `TrustChainResponse` → pure
//! `format_*` functions. Same `acquire_service_auth` token-refresh
//! shape (factor pending in #28; not in scope here).

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::error::CliError;
use super::pds::{PdsClient, PdsError};
use super::session::SessionFile;

const GET_TRUST_CHAIN_LXM: &str = "tools.cairn.admin.getTrustChain";

/// Wire shape of the `getTrustChain` envelope. Mirrors the server's
/// `Output` struct in `src/server/admin/get_trust_chain.rs`, which
/// references `tools.cairn.admin.defs#signingKeyEntry` etc.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustChainResponse {
    /// Service DID (the labeler identity).
    #[serde(rename = "serviceDid")]
    pub service_did: String,
    /// Declared signing keys, ordered by `validFrom` ascending.
    #[serde(rename = "signingKeys")]
    pub signing_keys: Vec<SigningKeyEntry>,
    /// Current maintainer roster.
    pub maintainers: Vec<MaintainerEntry>,
    /// Published service record summary. Absent when the
    /// deployment has no `[labeler]` config block, OR when no
    /// publish has happened yet (handler-side detail; both
    /// half-states surface as `None` here).
    #[serde(
        rename = "serviceRecord",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub service_record: Option<ServiceRecordSummary>,
    /// Instance metadata (build version + serving URL).
    pub instance: InstanceInfo,
}

/// One entry in the `signingKeys` array.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SigningKeyEntry {
    /// Multibase-encoded public key (matches `verificationMethod[*].
    /// publicKeyMultibase` in the labeler's DID document).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
    /// RFC-3339 timestamp the key became valid.
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    /// RFC-3339 timestamp the key was rotated out. Absent when
    /// still valid (rotation-shaped schema, §F8; v1.1 has no
    /// rotation flow yet).
    #[serde(rename = "validTo", skip_serializing_if = "Option::is_none", default)]
    pub valid_to: Option<String>,
    /// RFC-3339 timestamp the row was inserted.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// `true` when `validTo` is absent or in the future.
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

/// One entry in the `maintainers` array.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MaintainerEntry {
    /// Maintainer DID.
    pub did: String,
    /// Role discriminator (`"mod"` or `"admin"`).
    pub role: String,
    /// RFC-3339 timestamp the row was inserted.
    #[serde(rename = "addedAt")]
    pub added_at: String,
    /// DID of the moderator who added this entry via the HTTP-
    /// attested admin endpoint. Absent when the row was inserted
    /// via the CLI / direct SQL.
    #[serde(rename = "addedBy", skip_serializing_if = "Option::is_none", default)]
    pub added_by: Option<String>,
    /// `true` iff `addedBy` is present (verified caller DID
    /// recorded). `false` for CLI-initiated inserts pre-dating
    /// HTTP-attested moderator-add flows.
    #[serde(rename = "provenanceAttested")]
    pub provenance_attested: bool,
}

/// `serviceRecord` body when the labeler has both a declared
/// taxonomy and a published record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceRecordSummary {
    /// SHA-256 hex of the published record's canonical encoding.
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    /// Declared label-value short names from the `[labeler]`
    /// config block.
    #[serde(rename = "labelValues")]
    pub label_values: Vec<String>,
}

/// Instance metadata footer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstanceInfo {
    /// Semver of the running cairn-mod binary.
    pub version: String,
    /// Public-facing service endpoint URL.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Input to `cairn trust-chain show`. Endpoint takes no per-call
/// parameters; only the session-related override lives here.
#[derive(Debug, Clone, Default)]
pub struct TrustChainShowInput {
    /// Per-invocation override of the session's stored Cairn URL.
    pub cairn_server_override: Option<String>,
}

/// Fetch the trust-chain envelope via the admin HTTP endpoint.
///
/// Wraps the `tools.cairn.admin.getTrustChain` handler at
/// [src/server/admin/get_trust_chain.rs](..) — GET, no query params;
/// server enforces ADMIN role (`verify_and_authorize_admin_only`),
/// returns the envelope.
pub async fn show(
    session: &mut SessionFile,
    session_path: &Path,
    input: TrustChainShowInput,
) -> Result<TrustChainResponse, CliError> {
    let cairn_server = input
        .cairn_server_override
        .as_deref()
        .unwrap_or(&session.cairn_server_url)
        .trim_end_matches('/')
        .to_string();
    let pds = PdsClient::new(&session.pds_url)?;
    let token = acquire_service_auth(&pds, session, session_path, GET_TRUST_CHAIN_LXM).await?;

    let url = format!("{cairn_server}/xrpc/{GET_TRUST_CHAIN_LXM}");
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest build");
    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::CairnStatus { url, status, body });
    }
    let bytes = resp.bytes().await.map_err(|source| CliError::Http {
        url: url.clone(),
        source,
    })?;
    serde_json::from_slice::<TrustChainResponse>(&bytes)
        .map_err(|source| CliError::MalformedResponse { url, source })
}

/// Tabular human output. Sections: service-DID line, signing-keys
/// table, maintainers table, service-record block (or "(not
/// published)" line), instance footer. Sections separated by
/// blank lines; matches the existing `cli/audit.rs` aesthetic.
pub fn format_show_human(resp: &TrustChainResponse) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "service: {}", resp.service_did);

    // ---- signing keys ----
    let _ = writeln!(s);
    let _ = writeln!(s, "signing keys ({}):", resp.signing_keys.len());
    if resp.signing_keys.is_empty() {
        let _ = writeln!(s, "  (none)");
    } else {
        let key_w = resp
            .signing_keys
            .iter()
            .map(|k| k.public_key_multibase.len().min(48))
            .max()
            .unwrap_or(20)
            .max(20);
        let _ = writeln!(
            s,
            "  {:<key_w$}  {:<24}  {:<6}",
            "PUBLIC_KEY_MULTIBASE",
            "VALID_FROM",
            "ACTIVE",
            key_w = key_w,
        );
        for k in &resp.signing_keys {
            let key = truncate(&k.public_key_multibase, 48);
            let active = if k.is_active { "yes" } else { "no" };
            let _ = writeln!(
                s,
                "  {:<key_w$}  {:<24}  {:<6}",
                key,
                k.valid_from,
                active,
                key_w = key_w,
            );
        }
    }

    // ---- maintainers ----
    let _ = writeln!(s);
    let _ = writeln!(s, "maintainers ({}):", resp.maintainers.len());
    if resp.maintainers.is_empty() {
        let _ = writeln!(s, "  (none)");
    } else {
        let did_w = resp
            .maintainers
            .iter()
            .map(|m| m.did.len().min(40))
            .max()
            .unwrap_or(8)
            .max(8);
        let _ = writeln!(
            s,
            "  {:<did_w$}  {:<5}  {:<24}  {:<10}",
            "DID",
            "ROLE",
            "ADDED_AT",
            "PROVENANCE",
            did_w = did_w,
        );
        for m in &resp.maintainers {
            let did = truncate(&m.did, 40);
            let prov = if m.provenance_attested {
                "attested"
            } else {
                "unattested"
            };
            let _ = writeln!(
                s,
                "  {:<did_w$}  {:<5}  {:<24}  {:<10}",
                did,
                m.role,
                m.added_at,
                prov,
                did_w = did_w,
            );
        }
    }

    // ---- service record ----
    let _ = writeln!(s);
    match &resp.service_record {
        Some(sr) => {
            let _ = writeln!(s, "service record:");
            let _ = writeln!(s, "  content_hash: {}", sr.content_hash);
            let _ = writeln!(s, "  label values: {}", sr.label_values.join(", "));
        }
        None => {
            let _ = writeln!(s, "service record: (not published)");
        }
    }

    // ---- instance footer ----
    let _ = writeln!(s);
    let _ = writeln!(s, "instance:");
    let _ = writeln!(s, "  version:          {}", resp.instance.version);
    let _ = write!(s, "  service endpoint: {}", resp.instance.service_endpoint);
    s
}

/// JSON output. Pretty-printed for shell readability; clients
/// piping through `jq` get the canonical wire shape.
pub fn format_show_json(resp: &TrustChainResponse) -> String {
    serde_json::to_string_pretty(resp).expect("TrustChainResponse serializes")
}

// ============================================================
// Shared helpers (mirror src/cli/audit.rs and src/cli/report.rs)
// ============================================================

/// Char-aware right-truncation with trailing `…`. Local copy of
/// the helper in `cli/audit.rs` — duplication threshold (per
/// session N3) not yet hit; factor when 6+ identical copies exist.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

/// §5.3 auto-refresh helper. Same shape as the one in
/// `cli/audit.rs` — factoring tracked in #28.
async fn acquire_service_auth(
    pds: &PdsClient,
    session: &mut SessionFile,
    session_path: &Path,
    lxm: &str,
) -> Result<String, CliError> {
    match pds
        .get_service_auth(&session.access_jwt, &session.cairn_service_did, lxm)
        .await
    {
        Ok(t) => Ok(t),
        Err(PdsError::Unauthorized {
            context: "getServiceAuth",
            ..
        }) => {
            let refreshed = pds.refresh_session(&session.refresh_jwt).await?;
            session.access_jwt = refreshed.access_jwt;
            session.refresh_jwt = refreshed.refresh_jwt;
            session.save(session_path)?;
            Ok(pds
                .get_service_auth(&session.access_jwt, &session.cairn_service_did, lxm)
                .await?)
        }
        Err(other) => Err(other.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(service_record: Option<ServiceRecordSummary>) -> TrustChainResponse {
        TrustChainResponse {
            service_did: "did:plc:cairn0000000000000000000000".into(),
            signing_keys: vec![SigningKeyEntry {
                public_key_multibase: "zKeyAbc123".into(),
                valid_from: "2026-04-23T00:00:00.000Z".into(),
                valid_to: None,
                created_at: "2026-04-23T00:00:00.000Z".into(),
                is_active: true,
            }],
            maintainers: vec![
                MaintainerEntry {
                    did: "did:plc:admin00000000000000000000".into(),
                    role: "admin".into(),
                    added_at: "2026-04-25T00:00:00.000Z".into(),
                    added_by: None,
                    provenance_attested: false,
                },
                MaintainerEntry {
                    did: "did:plc:byhttp00000000000000000000".into(),
                    role: "mod".into(),
                    added_at: "2026-04-26T00:00:00.000Z".into(),
                    added_by: Some("did:plc:admin00000000000000000000".into()),
                    provenance_attested: true,
                },
            ],
            service_record,
            instance: InstanceInfo {
                version: "1.2.0".into(),
                service_endpoint: "https://labeler.example".into(),
            },
        }
    }

    #[test]
    fn format_human_shows_required_sections() {
        let r = sample(Some(ServiceRecordSummary {
            content_hash: "abcdef0123".into(),
            label_values: vec!["spam".into(), "abuse".into()],
        }));
        let s = format_show_human(&r);
        assert!(s.contains("service: did:plc:cairn0000000000000000000000"));
        assert!(s.contains("signing keys (1)"));
        assert!(s.contains("zKeyAbc123"));
        assert!(s.contains("maintainers (2)"));
        assert!(s.contains("attested"));
        assert!(s.contains("unattested"));
        assert!(s.contains("service record:"));
        assert!(s.contains("content_hash: abcdef0123"));
        assert!(s.contains("spam, abuse"));
        assert!(s.contains("version:          1.2.0"));
        assert!(s.contains("https://labeler.example"));
    }

    #[test]
    fn format_human_marks_service_record_not_published_when_absent() {
        let r = sample(None);
        let s = format_show_human(&r);
        assert!(s.contains("service record: (not published)"));
        assert!(
            !s.contains("content_hash:"),
            "no content_hash line when service_record is None"
        );
    }

    #[test]
    fn format_json_round_trips() {
        let r = sample(Some(ServiceRecordSummary {
            content_hash: "deadbeef".into(),
            label_values: vec!["spam".into()],
        }));
        let json = format_show_json(&r);
        let parsed: TrustChainResponse = serde_json::from_str(&json).expect("round trip");
        assert_eq!(parsed.service_did, r.service_did);
        assert_eq!(parsed.signing_keys.len(), 1);
        assert_eq!(parsed.maintainers.len(), 2);
        assert_eq!(
            parsed
                .service_record
                .as_ref()
                .map(|s| s.content_hash.as_str()),
            Some("deadbeef")
        );
        assert_eq!(parsed.instance.version, "1.2.0");
    }

    #[test]
    fn deserialize_omits_optional_fields() {
        // Wire shape with no validTo, no addedBy, no serviceRecord —
        // exact bytes the server emits via skip_serializing_if.
        let body = r#"{
          "serviceDid": "did:plc:x",
          "signingKeys": [{
            "publicKeyMultibase": "zk",
            "validFrom": "2026-01-01T00:00:00.000Z",
            "createdAt": "2026-01-01T00:00:00.000Z",
            "isActive": true
          }],
          "maintainers": [{
            "did": "did:plc:m",
            "role": "admin",
            "addedAt": "2026-01-01T00:00:00.000Z",
            "provenanceAttested": false
          }],
          "instance": {
            "version": "1.2.0",
            "serviceEndpoint": "https://labeler.example"
          }
        }"#;
        let parsed: TrustChainResponse = serde_json::from_str(body).expect("parse");
        assert!(parsed.signing_keys[0].valid_to.is_none());
        assert!(parsed.maintainers[0].added_by.is_none());
        assert!(parsed.service_record.is_none());
    }
}
