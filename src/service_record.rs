//! `app.bsky.labeler.service` record rendering + idempotency hash (§F1, §6.4).
//!
//! This module is the pure core of #8: given a
//! [`crate::config::LabelerConfigToml`], produce the JSON body that
//! `cairn publish-service-record` PUTs to the operator's PDS, plus
//! the content hash that powers idempotency.
//!
//! **Content-hash excludes `createdAt`.** Every startup generates a
//! fresh `createdAt` candidate; hashing over it would make every
//! publish appear changed, churning the PDS record unnecessarily.
//! The published `createdAt` is preserved across unchanged republishes
//! by rendering from `labeler_config.service_record_created_at` when
//! the hash matches the prior value.
//!
//! The record shape is hand-rolled (§6.4) rather than relying on a
//! lexicon validator. proto-blue-lex-data v0.2 doesn't carry
//! `app.bsky.labeler.service`; adding atrium-api just for validation
//! is deferred. A unit test in this module asserts every required
//! field is present in rendered output — the forcing function.

use serde::Serialize;
use serde_json::Value;

use crate::config::{
    BlursToml, DefaultSettingToml, LabelValueDefinitionToml, LabelerConfigToml, LocaleToml,
    SeverityToml,
};

/// `$type` value — the record's lexicon NSID (§6.4).
pub const RECORD_TYPE: &str = "app.bsky.labeler.service";

/// Collection NSID under which the record is stored in the operator's
/// repo. Identical to `$type` per ATProto repo conventions.
pub const RECORD_COLLECTION: &str = "app.bsky.labeler.service";

/// `rkey` — §6.4 requires exactly `"self"`; any other rkey is a
/// protocol violation.
pub const RECORD_RKEY: &str = "self";

/// Wire shape of the service record (§6.4). Field renames produce
/// camelCase JSON; optional fields are `skip_serializing_if = "...is_none"`
/// or `...is_empty`.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceRecord {
    #[serde(rename = "$type")]
    pub record_type: &'static str,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub policies: Policies,
    #[serde(rename = "reasonTypes", skip_serializing_if = "Vec::is_empty")]
    pub reason_types: Vec<String>,
    #[serde(rename = "subjectTypes", skip_serializing_if = "Vec::is_empty")]
    pub subject_types: Vec<String>,
    #[serde(rename = "subjectCollections", skip_serializing_if = "Vec::is_empty")]
    pub subject_collections: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Policies {
    #[serde(rename = "labelValues")]
    pub label_values: Vec<String>,
    #[serde(
        rename = "labelValueDefinitions",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub label_value_definitions: Vec<LabelValueDefinition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabelValueDefinition {
    pub identifier: String,
    pub severity: &'static str,
    pub blurs: &'static str,
    #[serde(rename = "defaultSetting", skip_serializing_if = "Option::is_none")]
    pub default_setting: Option<&'static str>,
    #[serde(rename = "adultOnly", skip_serializing_if = "Option::is_none")]
    pub adult_only: Option<bool>,
    pub locales: Vec<Locale>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Locale {
    pub lang: String,
    pub name: String,
    pub description: String,
}

/// Validation: every required §6.4 constraint that can't be enforced
/// by serde alone. Called by [`render`] before emission; a failing
/// record never reaches the PDS.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("labeler.label_values is empty; the record must declare at least one label")]
    NoLabelValues,
    #[error("labeler.label_value_definitions[{idx}] has no locales; §6.4 requires at least one")]
    NoLocales { idx: usize },
}

/// Render the record body ready for PDS emission. `created_at` is
/// the RFC-3339 timestamp the caller chose — use the prior record's
/// value when hashes match (idempotency), or `time::OffsetDateTime`
/// now-formatted otherwise.
pub fn render(cfg: &LabelerConfigToml, created_at: &str) -> Result<ServiceRecord, RenderError> {
    if cfg.label_values.is_empty() {
        return Err(RenderError::NoLabelValues);
    }
    for (idx, def) in cfg.label_value_definitions.iter().enumerate() {
        if def.locales.is_empty() {
            return Err(RenderError::NoLocales { idx });
        }
    }
    let definitions = cfg
        .label_value_definitions
        .iter()
        .map(project_definition)
        .collect();
    Ok(ServiceRecord {
        record_type: RECORD_TYPE,
        created_at: created_at.to_string(),
        policies: Policies {
            label_values: cfg.label_values.clone(),
            label_value_definitions: definitions,
        },
        reason_types: cfg.reason_types.clone(),
        subject_types: cfg.subject_types.clone(),
        subject_collections: cfg.subject_collections.clone(),
    })
}

fn project_definition(src: &LabelValueDefinitionToml) -> LabelValueDefinition {
    LabelValueDefinition {
        identifier: src.identifier.clone(),
        severity: severity_str(src.severity),
        blurs: blurs_str(src.blurs),
        default_setting: src.default_setting.map(default_setting_str),
        adult_only: src.adult_only,
        locales: src
            .locales
            .iter()
            .map(|l: &LocaleToml| Locale {
                lang: l.lang.clone(),
                name: l.name.clone(),
                description: l.description.clone(),
            })
            .collect(),
    }
}

fn severity_str(s: SeverityToml) -> &'static str {
    match s {
        SeverityToml::Inform => "inform",
        SeverityToml::Alert => "alert",
        SeverityToml::None => "none",
    }
}

fn blurs_str(b: BlursToml) -> &'static str {
    match b {
        BlursToml::Content => "content",
        BlursToml::Media => "media",
        BlursToml::None => "none",
    }
}

fn default_setting_str(d: DefaultSettingToml) -> &'static str {
    match d {
        DefaultSettingToml::Ignore => "ignore",
        DefaultSettingToml::Warn => "warn",
        DefaultSettingToml::Hide => "hide",
    }
}

/// Content hash (§F1 idempotency). SHA-256 of a serde-canonical JSON
/// rendering **with `createdAt` removed**. Keyed-BTreeMap serialization
/// gives deterministic ordering; reusing the existing `serde_json` path
/// is sufficient because Cairn is both producer and consumer of this
/// hash — we don't need to match any external canonicalization spec.
///
/// Returns 32 raw bytes; callers hex-encode for persistence.
pub fn content_hash(record: &ServiceRecord) -> [u8; 32] {
    let mut v = serde_json::to_value(record).expect("ServiceRecord serializes");
    // Remove createdAt in-place so two renders differing only in
    // that field hash identically.
    if let Value::Object(map) = &mut v {
        map.remove("createdAt");
    }
    // Re-serialize through a BTreeMap-backed path for stable key
    // ordering regardless of serde_json's Value internals.
    let canonical = canonicalize(v);
    let bytes = serde_json::to_vec(&canonical).expect("Value serializes");
    proto_blue_crypto::sha256(&bytes)
}

/// Recursively rebuild `Value` with `BTreeMap`-backed objects so
/// key ordering is deterministic. `serde_json::Value::Object` uses
/// `serde_json::Map` which, depending on feature flags, may or may
/// not preserve insertion order; this walk forces lexicographic.
fn canonicalize(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, Value> =
                std::collections::BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k, canonicalize(v));
            }
            serde_json::to_value(sorted).expect("BTreeMap<String, Value> serializes")
        }
        Value::Array(xs) => Value::Array(xs.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LabelValueDefinitionToml, LocaleToml};

    fn sample_cfg() -> LabelerConfigToml {
        LabelerConfigToml {
            label_values: vec!["spam".into()],
            label_value_definitions: vec![LabelValueDefinitionToml {
                identifier: "spam".into(),
                severity: SeverityToml::Alert,
                blurs: BlursToml::None,
                default_setting: Some(DefaultSettingToml::Warn),
                adult_only: Some(false),
                locales: vec![LocaleToml {
                    lang: "en".into(),
                    name: "Spam".into(),
                    description: "Unsolicited promotional content.".into(),
                }],
            }],
            reason_types: vec!["com.atproto.moderation.defs#reasonSpam".into()],
            subject_types: vec!["account".into(), "record".into()],
            subject_collections: vec!["app.bsky.feed.post".into()],
        }
    }

    #[test]
    fn rendered_record_has_every_required_field() {
        let rec = render(&sample_cfg(), "2026-04-23T00:00:00.000Z").unwrap();
        let v = serde_json::to_value(&rec).unwrap();
        // §6.4 required top-level: $type, createdAt, policies.
        assert_eq!(v["$type"], "app.bsky.labeler.service");
        assert_eq!(v["createdAt"], "2026-04-23T00:00:00.000Z");
        assert!(v["policies"].is_object());
        // policies.labelValues required.
        assert!(v["policies"]["labelValues"].is_array());
        assert_eq!(v["policies"]["labelValues"][0], "spam");
        // labelValueDefinitions required fields.
        let def = &v["policies"]["labelValueDefinitions"][0];
        for field in ["identifier", "severity", "blurs", "locales"] {
            assert!(def.get(field).is_some(), "missing {field} in def: {def}");
        }
        // §6.4: locales must be non-empty.
        assert!(!def["locales"].as_array().unwrap().is_empty());
        let locale = &def["locales"][0];
        for field in ["lang", "name", "description"] {
            assert!(
                locale.get(field).is_some(),
                "missing {field} in locale: {locale}"
            );
        }
    }

    #[test]
    fn empty_label_values_rejected() {
        let mut cfg = sample_cfg();
        cfg.label_values.clear();
        assert!(matches!(
            render(&cfg, "2026-04-23T00:00:00.000Z"),
            Err(RenderError::NoLabelValues)
        ));
    }

    #[test]
    fn empty_locales_rejected() {
        let mut cfg = sample_cfg();
        cfg.label_value_definitions[0].locales.clear();
        assert!(matches!(
            render(&cfg, "2026-04-23T00:00:00.000Z"),
            Err(RenderError::NoLocales { idx: 0 })
        ));
    }

    #[test]
    fn content_hash_excludes_created_at() {
        let a = render(&sample_cfg(), "2026-04-23T00:00:00.000Z").unwrap();
        let b = render(&sample_cfg(), "2030-12-31T23:59:59.999Z").unwrap();
        assert_eq!(
            content_hash(&a),
            content_hash(&b),
            "hashes must match when only createdAt differs"
        );
    }

    #[test]
    fn content_hash_changes_on_label_value_change() {
        let a = render(&sample_cfg(), "2026-04-23T00:00:00.000Z").unwrap();
        let mut cfg = sample_cfg();
        cfg.label_values.push("abuse".into());
        let b = render(&cfg, "2026-04-23T00:00:00.000Z").unwrap();
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn content_hash_changes_on_severity_change() {
        let a = render(&sample_cfg(), "2026-04-23T00:00:00.000Z").unwrap();
        let mut cfg = sample_cfg();
        cfg.label_value_definitions[0].severity = SeverityToml::Inform;
        let b = render(&cfg, "2026-04-23T00:00:00.000Z").unwrap();
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn content_hash_changes_on_locale_change() {
        let a = render(&sample_cfg(), "2026-04-23T00:00:00.000Z").unwrap();
        let mut cfg = sample_cfg();
        cfg.label_value_definitions[0].locales.push(LocaleToml {
            lang: "fr".into(),
            name: "Spam".into(),
            description: "Contenu promotionnel non sollicité.".into(),
        });
        let b = render(&cfg, "2026-04-23T00:00:00.000Z").unwrap();
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn content_hash_is_stable_across_runs() {
        // Two independent calls on the same config must produce the
        // same hash — basic determinism.
        let cfg = sample_cfg();
        let a = render(&cfg, "2026-04-23T00:00:00.000Z").unwrap();
        let b = render(&cfg, "2026-04-23T00:00:00.000Z").unwrap();
        assert_eq!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn optional_fields_omitted_when_empty() {
        let mut cfg = sample_cfg();
        cfg.reason_types.clear();
        cfg.subject_types.clear();
        cfg.subject_collections.clear();
        let rec = render(&cfg, "2026-04-23T00:00:00.000Z").unwrap();
        let v = serde_json::to_value(&rec).unwrap();
        // skip_serializing_if = "Vec::is_empty" should omit empty arrays.
        assert!(v.get("reasonTypes").is_none());
        assert!(v.get("subjectTypes").is_none());
        assert!(v.get("subjectCollections").is_none());
    }
}
