//! Reason vocabulary for the v1.4 graduated-action moderation model
//! (#47, §F20).
//!
//! Each declared reason has a base strike weight, a `severe`
//! (bypass-dampening) flag, and an operator-facing description.
//! The vocabulary is loaded once at config-load time and is
//! read-only thereafter — operators restart `cairn serve` to change
//! the reason set, matching the existing `[labeler]` config posture.
//!
//! Two sources, mutually exclusive at the operator's level:
//!
//! 1. **Shipped defaults** — loaded when the operator's config
//!    contains no `[moderation_reasons.*]` blocks. Eight reasons
//!    cairn-mod ships with sensible weights for the common cases
//!    (hate-speech, harassment, threats-of-violence, csam, spam,
//!    misinformation, nsfw, other). Two of those bypass dampening
//!    (csam, threats-of-violence) regardless of the user's
//!    standing.
//! 2. **Operator-declared vocabulary** — loaded when one or more
//!    `[moderation_reasons.<identifier>]` blocks are present.
//!    Defaults are NOT loaded in this case. This prevents
//!    accidental mixing of operator-declared and shipped-default
//!    reasons that the operator didn't intend; the operator either
//!    accepts the full default set, or declares everything they
//!    want from scratch.
//!
//! An empty `[moderation_reasons]` section (the bare header with no
//! sub-blocks) is invalid — either declare reasons or omit the
//! section entirely.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// One entry in the reason vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonDef {
    /// Lowercase-kebab-case identifier (e.g. `"hate-speech"`).
    /// Stored both as the map key and on the value so callers
    /// iterating the vocabulary don't have to thread the key
    /// alongside.
    pub identifier: String,
    /// Strike weight applied at action time, BEFORE dampening.
    /// Always ≥ 1 — zero-weight reasons would be inert and the
    /// validator rejects them at config-load.
    pub base_weight: u32,
    /// When `true`, applying this reason bypasses dampening (#49)
    /// regardless of the subject's standing — severe categories
    /// always count at full weight.
    pub severe: bool,
    /// Operator-facing label describing what the reason means. Not
    /// a policy statement about how operators should act on it; the
    /// description is for the operator's own UI / picker, not for
    /// users or external consumers.
    pub description: String,
}

/// Resolved reason vocabulary. Use [`ReasonVocabulary::from_config`]
/// at config-load time and pass the resolved vocabulary into the
/// strike calculator (#49) and the action recorder (#51).
///
/// Backed by a [`BTreeMap`] for deterministic iteration order:
/// test fixtures stay stable, and any future
/// `cairn moderator list-reasons` CLI gets sorted-by-identifier
/// output without an extra `collect` + sort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonVocabulary {
    reasons: BTreeMap<String, ReasonDef>,
}

impl ReasonVocabulary {
    /// Build the vocabulary from `cfg.moderation_reasons`. When the
    /// field is `None` (operator declared no blocks), returns
    /// [`Self::defaults`]. When the field is `Some(empty_map)` (the
    /// operator wrote a bare `[moderation_reasons]` section with no
    /// sub-blocks), returns an error — silently treating that as
    /// "load defaults" would mask a probable typo.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self> {
        let Some(declared) = &cfg.moderation_reasons else {
            return Ok(Self::defaults());
        };
        if declared.is_empty() {
            return Err(Error::Signing(
                "config: [moderation_reasons] section is empty — \
                 either declare at least one reason or omit the section entirely"
                    .to_string(),
            ));
        }
        let mut reasons = BTreeMap::new();
        for (identifier, toml) in declared {
            validate_identifier(identifier)?;
            if toml.base_weight < 1 {
                return Err(Error::Signing(format!(
                    "config: [moderation_reasons.{identifier}] base_weight must be >= 1 (got {})",
                    toml.base_weight
                )));
            }
            if toml.description.trim().is_empty() {
                return Err(Error::Signing(format!(
                    "config: [moderation_reasons.{identifier}] description is required and must be non-empty"
                )));
            }
            reasons.insert(
                identifier.clone(),
                ReasonDef {
                    identifier: identifier.clone(),
                    base_weight: toml.base_weight,
                    severe: toml.severe,
                    description: toml.description.clone(),
                },
            );
        }
        Ok(Self { reasons })
    }

    /// The shipped default vocabulary. Loaded when an operator's
    /// config has no `[moderation_reasons.*]` blocks. Eight reasons
    /// covering the common moderation categories; two of them
    /// (`csam`, `threats-of-violence`) bypass dampening.
    ///
    /// Descriptions are deliberately descriptive ("what does this
    /// reason mean?") rather than prescriptive ("what should an
    /// operator do about it?"). Operator policy lives in the
    /// operator's runbook, not in the shipped vocabulary.
    pub fn defaults() -> Self {
        const ENTRIES: &[(&str, u32, bool, &str)] = &[
            (
                "hate-speech",
                4,
                false,
                "Content targeting individuals or groups based on protected characteristics.",
            ),
            (
                "harassment",
                4,
                false,
                "Repeated unwanted contact, intimidation, or coordinated targeting.",
            ),
            (
                "threats-of-violence",
                12,
                true,
                "Statements expressing intent to harm.",
            ),
            ("csam", 999, true, "Child sexual abuse material."),
            (
                "spam",
                2,
                false,
                "Unsolicited promotional content or repeated link-dropping.",
            ),
            (
                "misinformation",
                3,
                false,
                "Demonstrably false factual claims.",
            ),
            (
                "nsfw",
                2,
                false,
                "Adult-oriented or sexually explicit content.",
            ),
            (
                "other",
                2,
                false,
                "Catch-all for situations not covered by other reasons.",
            ),
        ];

        let mut reasons = BTreeMap::new();
        for &(id, base_weight, severe, description) in ENTRIES {
            reasons.insert(
                id.to_string(),
                ReasonDef {
                    identifier: id.to_string(),
                    base_weight,
                    severe,
                    description: description.to_string(),
                },
            );
        }
        Self { reasons }
    }

    /// Look up a reason by identifier. Returns `None` when the
    /// identifier is not in the vocabulary; the action recorder
    /// (#51) surfaces this as `InvalidReason` to the caller.
    pub fn lookup(&self, identifier: &str) -> Option<&ReasonDef> {
        self.reasons.get(identifier)
    }

    /// Iterate over the vocabulary in identifier-ascending order
    /// (BTreeMap iteration order). Stable across runs.
    pub fn iter(&self) -> impl Iterator<Item = &ReasonDef> {
        self.reasons.values()
    }

    /// Number of reasons in the vocabulary. Cheap O(1).
    pub fn len(&self) -> usize {
        self.reasons.len()
    }

    /// Whether the vocabulary is empty. Always `false` for a
    /// successfully-built vocabulary — `from_config` errors out on
    /// an empty operator-declared section, and `defaults()` always
    /// has eight entries — but exposed for completeness and to
    /// satisfy clippy's `len_without_is_empty` lint.
    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// Identifier rules: 1-64 chars, must start with a-z, then any of
/// a-z / 0-9 / `-`. Matches the lowercase-kebab-case constraint
/// declared in the issue body. Doesn't reject double-hyphens or
/// trailing hyphens — those are operator-aesthetic concerns rather
/// than parser concerns, and tightening here would be over-
/// engineering for v1.4.
fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 64 {
        return Err(Error::Signing(format!(
            "config: moderation reason identifier '{s}' must be 1-64 chars (got {} chars)",
            s.len()
        )));
    }
    let mut chars = s.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() {
        return Err(Error::Signing(format!(
            "config: moderation reason identifier '{s}' must start with a lowercase ASCII letter (got '{first}')"
        )));
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(Error::Signing(format!(
                "config: moderation reason identifier '{s}' contains invalid char '{c}' (allowed: a-z, 0-9, hyphen)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_with_reasons(value: serde_json::Value) -> Config {
        let mut v = serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
        });
        if !value.is_null() {
            v["moderation_reasons"] = value;
        }
        serde_json::from_value(v).expect("config deserializes")
    }

    // ---------- defaults() ----------

    #[test]
    fn defaults_has_eight_entries() {
        let v = ReasonVocabulary::defaults();
        assert_eq!(v.len(), 8);
    }

    #[test]
    fn defaults_csam_is_severe_with_high_weight() {
        let v = ReasonVocabulary::defaults();
        let csam = v.lookup("csam").expect("csam in defaults");
        assert!(csam.severe);
        assert_eq!(csam.base_weight, 999);
    }

    #[test]
    fn defaults_threats_of_violence_is_severe() {
        let v = ReasonVocabulary::defaults();
        let tv = v
            .lookup("threats-of-violence")
            .expect("threats-of-violence in defaults");
        assert!(tv.severe);
        assert_eq!(tv.base_weight, 12);
    }

    #[test]
    fn defaults_hate_speech_is_non_severe() {
        let v = ReasonVocabulary::defaults();
        let hs = v.lookup("hate-speech").expect("hate-speech in defaults");
        assert!(!hs.severe);
        assert_eq!(hs.base_weight, 4);
    }

    #[test]
    fn defaults_iter_is_identifier_ascending() {
        let v = ReasonVocabulary::defaults();
        let ids: Vec<&str> = v.iter().map(|r| r.identifier.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "iter must yield ascending order");
    }

    #[test]
    fn defaults_descriptions_are_non_empty() {
        for r in ReasonVocabulary::defaults().iter() {
            assert!(
                !r.description.trim().is_empty(),
                "default reason '{}' has empty description",
                r.identifier
            );
        }
    }

    // ---------- from_config: absent block → defaults ----------

    #[test]
    fn absent_moderation_reasons_block_loads_defaults() {
        let cfg = config_with_reasons(serde_json::Value::Null);
        let v = ReasonVocabulary::from_config(&cfg).expect("from_config");
        assert_eq!(v, ReasonVocabulary::defaults());
    }

    // ---------- from_config: empty block → error ----------

    #[test]
    fn empty_moderation_reasons_block_is_rejected() {
        let cfg = config_with_reasons(serde_json::json!({}));
        let err = ReasonVocabulary::from_config(&cfg).expect_err("empty section must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("section is empty"),
            "error message must explain the empty-section problem: {msg}"
        );
    }

    // ---------- from_config: declared block → operator vocabulary ----------

    #[test]
    fn single_declared_reason_yields_one_entry_no_defaults() {
        let cfg = config_with_reasons(serde_json::json!({
            "custom-reason": {
                "base_weight": 5,
                "severe": false,
                "description": "an operator-defined reason"
            }
        }));
        let v = ReasonVocabulary::from_config(&cfg).expect("from_config");
        assert_eq!(v.len(), 1);
        assert!(
            v.lookup("custom-reason").is_some(),
            "operator's reason loaded"
        );
        assert!(
            v.lookup("hate-speech").is_none(),
            "shipped defaults must NOT be loaded when operator declares any block"
        );
    }

    #[test]
    fn operator_can_replace_default_identifier_at_different_weight() {
        // Operator wants the default 'spam' reason but at a higher
        // weight. They declare the full vocabulary they want; defaults
        // are not merged in.
        let cfg = config_with_reasons(serde_json::json!({
            "spam": {
                "base_weight": 5,
                "severe": false,
                "description": "Operator-tightened spam policy."
            }
        }));
        let v = ReasonVocabulary::from_config(&cfg).expect("from_config");
        assert_eq!(v.len(), 1);
        let spam = v.lookup("spam").expect("spam present");
        assert_eq!(
            spam.base_weight, 5,
            "operator's value overrides shipped default"
        );
    }

    #[test]
    fn severe_defaults_to_false_when_omitted() {
        let cfg = config_with_reasons(serde_json::json!({
            "minor-thing": {
                "base_weight": 1,
                "description": "trivial"
            }
        }));
        let v = ReasonVocabulary::from_config(&cfg).expect("from_config");
        let r = v.lookup("minor-thing").expect("present");
        assert!(!r.severe);
    }

    // ---------- validation: identifier ----------

    #[test]
    fn uppercase_identifier_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "Bad-Identifier": {
                "base_weight": 1,
                "description": "x"
            }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Bad-Identifier") || msg.contains("'B'"),
            "got: {msg}"
        );
    }

    #[test]
    fn identifier_starting_with_digit_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "1-leading-digit": { "base_weight": 1, "description": "x" }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("must start with"));
    }

    #[test]
    fn identifier_with_underscore_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "snake_case": { "base_weight": 1, "description": "x" }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("invalid char"));
    }

    #[test]
    fn identifier_too_long_rejected() {
        let long = "a".repeat(65);
        let cfg = config_with_reasons(serde_json::json!({
            long.clone(): { "base_weight": 1, "description": "x" }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("1-64 chars"));
    }

    #[test]
    fn empty_identifier_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "": { "base_weight": 1, "description": "x" }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("1-64 chars"));
    }

    // ---------- validation: weight ----------

    #[test]
    fn zero_base_weight_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "x": { "base_weight": 0, "description": "x" }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("base_weight must be >= 1"));
    }

    // ---------- validation: description ----------

    #[test]
    fn empty_description_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "x": { "base_weight": 1, "description": "" }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("description"));
    }

    #[test]
    fn whitespace_only_description_rejected() {
        let cfg = config_with_reasons(serde_json::json!({
            "x": { "base_weight": 1, "description": "   \t\n " }
        }));
        let err = ReasonVocabulary::from_config(&cfg).unwrap_err();
        assert!(format!("{err}").contains("description"));
    }

    // ---------- lookup ----------

    #[test]
    fn lookup_returns_none_for_nonexistent_identifier() {
        let v = ReasonVocabulary::defaults();
        assert!(v.lookup("nonexistent").is_none());
    }

    #[test]
    fn lookup_finds_default_identifiers() {
        let v = ReasonVocabulary::defaults();
        for id in &[
            "hate-speech",
            "harassment",
            "threats-of-violence",
            "csam",
            "spam",
            "misinformation",
            "nsfw",
            "other",
        ] {
            assert!(
                v.lookup(id).is_some(),
                "default identifier '{id}' must be present"
            );
        }
    }
}
