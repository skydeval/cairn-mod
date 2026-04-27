//! Pure-function action→label translation (§F21, #59).
//!
//! Turns an in-flight moderation action plus the operator's resolved
//! [`LabelEmissionPolicy`] into
//! a set of unsigned [`LabelDraft`]s. The recorder (#60) takes the
//! drafts, signs them via the existing labeler signing path, and
//! persists the resulting label rows alongside the
//! `subject_actions` row in one transaction.
//!
//! Same shape as the v1.4 calculators (#49 strike, #50 decay, #51
//! window): no I/O, no async, no signing, no DB. Heavy unit-test
//! coverage lives inline.
//!
//! # Decision rules
//!
//! [`resolve_action_labels`]:
//!
//! 1. `policy.enabled = false` → empty vec.
//! 2. [`LabelEmissionPolicy::resolve_action_label`] returns `None`
//!    (note never emits; warning gated on `warning_emits_label`;
//!    every other type emits its default or override) → empty vec.
//! 3. Otherwise → exactly one [`LabelDraft`]. The vec shape is
//!    forward-compatible with future per-action-multi-label
//!    surfaces (e.g., emit both a takedown label and an
//!    institutional-policy label); v1.5 ships exactly one entry
//!    per action.
//!
//! [`resolve_reason_labels`]:
//!
//! 1. `policy.enabled = false` → empty vec.
//! 2. `policy.emit_reason_labels = false` → empty vec.
//! 3. `action.reason_codes` empty → empty vec.
//! 4. `action.action_type == Note` → empty vec. Notes never emit
//!    labels of any kind.
//! 5. `action.action_type == Warning && !policy.warning_emits_label`
//!    → empty vec. The action label and reason labels share their
//!    suppression gate: a warning whose action label is suppressed
//!    can't surface reason labels alone (reasons-without-context
//!    is confusing to consumers, and the recovery path is
//!    asymmetric since you'd have to negate reason-only labels
//!    that were never paired with a takedown).
//! 6. Otherwise → one [`LabelDraft`] per `reason_code`, with
//!    `val = policy.reason_label_prefix + reason_code` and a fixed
//!    `severity = Inform`. v1.5 has no per-reason severity config;
//!    operators wanting different reason-label severities upgrade
//!    once that surface lands (post-v1.5 if there's demand).
//!
//! # Expiry semantics
//!
//! For `TempSuspension`, the action label and any reason labels
//! all carry `exp = action.expires_at` so consumer AppViews honor
//! the same expiry on the whole bundle. Per #63: ATProto's native
//! label expiry handles automatic negation in consumers — no
//! cairn-mod scheduled job. For other action types, `exp = None`
//! (takedown is permanent until revocation; indef_suspension
//! likewise; warning has no inherent expiry).
//!
//! # Subject URI
//!
//! `LabelDraft.uri` is the AT-URI or DID the label is *about*. For
//! account-level actions, the recorder passes
//! `subject_uri = None` and the draft's `uri` becomes the
//! `subject_did`. For record-level actions, the draft's `uri` is
//! the action's `subject_uri`. The `cid` is always `None` here —
//! the recorder fills it for record-level subjects from whatever
//! source-of-truth it has at signing time.
//!
//! # `cts` from `now`, not from `action.effective_at`
//!
//! The label's `cts` (creation timestamp) is the moment the label
//! is being emitted, not the action's `effective_at`. They're
//! equal in practice (the recorder calls these functions with
//! `now = effective_at` for immediate actions, which is every v1.4
//! action), but the input separation lets a future scheduled-action
//! pipeline emit labels at a different moment than the action's
//! effective_at without a signature mismatch.

use std::time::SystemTime;

use crate::config::{BlursToml, LocaleToml, SeverityToml};
use crate::moderation::types::ActionType;

use super::policy::LabelEmissionPolicy;

/// Inputs the emission core needs from the in-flight action.
///
/// Distinct from [`crate::moderation::types::ActionRecord`] — the
/// latter is a deliberately-narrow projection for the strike /
/// decay / window calculators (#49/#50/#51) and intentionally omits
/// `subject_did`, `subject_uri`, and `reason_codes`. The emission
/// core needs all three, so it consumes a purpose-specific input
/// type built by the recorder from the freshly-inserted row.
///
/// Same naming convention as the existing
/// `load_subject_actions_for_calc` projection helper in
/// `writer.rs` — "for X" suffix flags purpose-specific
/// projections vs. the canonical row shape.
#[derive(Debug, Clone)]
pub struct ActionForEmission {
    /// Graduated-action category. Drives the action-label gate
    /// (note never emits; warning gated on policy.warning_emits_label;
    /// others emit per policy).
    pub action_type: ActionType,
    /// `Some` for `TempSuspension` (drives the `exp` field on the
    /// emitted label so consumer AppViews honor the expiry without
    /// a scheduled negation, per #63). `None` for other types.
    pub expires_at: Option<SystemTime>,
    /// Account DID the action attributes to. Used as the label's
    /// `uri` when `subject_uri` is absent (account-level actions).
    pub subject_did: String,
    /// AT-URI for record-level actions. When `Some`, becomes the
    /// label's `uri`; otherwise the label targets the account DID.
    pub subject_uri: Option<String>,
    /// Reason identifiers from the operator's
    /// `[moderation_reasons]` vocabulary (#47). Drives the reason
    /// labels emitted alongside the action label.
    pub reason_codes: Vec<String>,
    /// CID for record-level subjects. Caller-supplied — the
    /// emission core does not resolve CIDs from the network. For
    /// account-level subjects, this is `None`. For record-level
    /// subjects (`subject_uri = Some(at://...)`), the recorder
    /// (#60) populates this from whatever source-of-truth it has
    /// at record time (typically the moderator's input). v1.5 also
    /// allows `None` here for record-level subjects — the protocol
    /// permits record-level labels without CID, just less specific.
    pub cid: Option<String>,
}

/// Unsigned label record produced by the emission core. The
/// recorder (#60) signs and persists; #62 revocation reuses this
/// type for negation labels.
///
/// Carries both wire-level fields (`val`, `neg`, `uri`, `cid`,
/// `cts`, `exp`) and operator-policy metadata (`severity`, `blurs`,
/// `locales`). The metadata isn't part of the signed wire record
/// itself — that's covered by the labeler's service-record
/// `labelValueDefinitions` per §F1 — but it travels with the draft
/// so the recorder's audit row can capture which severity was in
/// effect at emission time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelDraft {
    /// Label value (e.g. `!takedown`, `reason-hate-speech`).
    pub val: String,
    /// Severity hint per [`LabelEmissionPolicy`]. For v1.5 reason
    /// labels this is always `Inform`; for action labels it comes
    /// from the operator's [`crate::labels::policy::LabelSpec`]
    /// (default `Alert` for action types).
    pub severity: SeverityToml,
    /// Optional blur hint. Most graduated-action labels do not
    /// specify blurs since they represent account-level state, not
    /// content-level visual treatment.
    pub blurs: Option<BlursToml>,
    /// Optional localized display strings. Empty for reason labels
    /// in v1.5; populated for action labels iff the operator
    /// declared them in [`crate::config::LabelSpecToml::locales`].
    pub locales: Vec<LocaleToml>,
    /// Subject the label is *about* — either an AT-URI (record
    /// subject) or a DID (account subject).
    pub uri: String,
    /// Subject CID for record subjects. Always `None` here; the
    /// recorder fills this from its own context at signing time.
    pub cid: Option<String>,
    /// `false` for emission, `true` for negation. v1.5's emission
    /// core only produces `false` here; #62's revocation flow
    /// constructs the `true` case directly.
    pub neg: bool,
    /// Wall-clock the draft was minted. The recorder formats this
    /// as RFC-3339 Z when constructing the wire-level
    /// [`crate::label::Label`] for signing.
    pub cts: SystemTime,
    /// Expiry wall-clock for `TempSuspension` action labels and
    /// the reason labels that share their gate. `None` for other
    /// action types.
    pub exp: Option<SystemTime>,
}

/// Resolve the action label(s) for an in-flight action. Returns
/// at most one entry in v1.5; the `Vec` shape is forward-compatible
/// with future multi-label-per-action surfaces.
pub fn resolve_action_labels(
    action: &ActionForEmission,
    policy: &LabelEmissionPolicy,
    now: SystemTime,
) -> Vec<LabelDraft> {
    if !policy.enabled {
        return Vec::new();
    }

    let Some(spec) = policy.resolve_action_label(action.action_type) else {
        return Vec::new();
    };

    let uri = action
        .subject_uri
        .clone()
        .unwrap_or_else(|| action.subject_did.clone());

    let exp = exp_for(action);

    vec![LabelDraft {
        val: spec.val,
        severity: spec.severity,
        blurs: spec.blurs,
        locales: spec.locales,
        uri,
        cid: None,
        neg: false,
        cts: now,
        exp,
    }]
}

/// Resolve the reason labels for an in-flight action. Returns one
/// entry per `reason_code` when emission is enabled and the
/// action's gate permits.
pub fn resolve_reason_labels(
    action: &ActionForEmission,
    policy: &LabelEmissionPolicy,
    now: SystemTime,
) -> Vec<LabelDraft> {
    if !policy.enabled || !policy.emit_reason_labels || action.reason_codes.is_empty() {
        return Vec::new();
    }
    if matches!(action.action_type, ActionType::Note) {
        return Vec::new();
    }
    if matches!(action.action_type, ActionType::Warning) && !policy.warning_emits_label {
        // Reason labels share the warning's suppression gate —
        // see module docs for the rationale.
        return Vec::new();
    }

    let uri = action
        .subject_uri
        .clone()
        .unwrap_or_else(|| action.subject_did.clone());
    let exp = exp_for(action);

    action
        .reason_codes
        .iter()
        .map(|reason_code| LabelDraft {
            val: policy.resolve_reason_label_value(reason_code),
            // v1.5 fixes reason-label severity at Inform: reason
            // labels describe *why* a moderation event occurred,
            // not *what* effect it has, so they're advisory by
            // design. Per-reason severity config is deferred to a
            // future release if real demand surfaces.
            severity: SeverityToml::Inform,
            blurs: None,
            locales: Vec::new(),
            uri: uri.clone(),
            cid: None,
            neg: false,
            cts: now,
            exp,
        })
        .collect()
}

/// Compute the expiry stamp for an action's emitted labels.
/// `Some(action.expires_at)` for `TempSuspension`; `None` otherwise.
/// Note that v1.5 treats a `TempSuspension` with `expires_at = None`
/// as a degenerate input that emits a label without expiry —
/// validation that temp_suspension carries expires_at is the
/// recorder's contract (#63), not the emission core's concern.
fn exp_for(action: &ActionForEmission) -> Option<SystemTime> {
    match action.action_type {
        ActionType::TempSuspension => action.expires_at,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LabelEmissionPolicyToml, LabelSpecToml};
    use std::collections::BTreeMap;
    use std::time::{Duration, UNIX_EPOCH};

    // ---------- fixture builders ----------

    const SUBJECT_DID: &str = "did:plc:subject0000000000000000";
    const SUBJECT_URI: &str = "at://did:plc:subject0000000000000000/app.bsky.feed.post/aaa";

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(2_000_000_000)
    }

    fn account_action(action_type: ActionType, reasons: &[&str]) -> ActionForEmission {
        ActionForEmission {
            action_type,
            expires_at: None,
            subject_did: SUBJECT_DID.to_string(),
            subject_uri: None,
            reason_codes: reasons.iter().map(|s| s.to_string()).collect(),
            cid: None,
        }
    }

    fn record_action(action_type: ActionType, reasons: &[&str]) -> ActionForEmission {
        ActionForEmission {
            action_type,
            expires_at: None,
            subject_did: SUBJECT_DID.to_string(),
            subject_uri: Some(SUBJECT_URI.to_string()),
            reason_codes: reasons.iter().map(|s| s.to_string()).collect(),
            cid: None,
        }
    }

    fn temp_suspension_action(reasons: &[&str], expires_at: SystemTime) -> ActionForEmission {
        ActionForEmission {
            action_type: ActionType::TempSuspension,
            expires_at: Some(expires_at),
            subject_did: SUBJECT_DID.to_string(),
            subject_uri: None,
            reason_codes: reasons.iter().map(|s| s.to_string()).collect(),
            cid: None,
        }
    }

    /// Construct a policy by merging a serde_json patch into the
    /// defaults. Keeps tests focused on the diff from defaults
    /// rather than re-typing every field.
    fn policy(patch: serde_json::Value) -> LabelEmissionPolicy {
        let mut base = serde_json::json!({
            "service_did": "did:web:labeler.example",
            "service_endpoint": "https://labeler.example",
            "db_path": "/var/lib/cairn/cairn.db",
            "signing_key_path": "/etc/cairn/signing-key.hex",
        });
        if !patch.is_null() {
            base["label_emission"] = patch;
        }
        let cfg: crate::config::Config = serde_json::from_value(base).expect("config deserializes");
        LabelEmissionPolicy::from_config(&cfg).expect("policy resolves")
    }

    fn defaults_policy() -> LabelEmissionPolicy {
        LabelEmissionPolicy::defaults()
    }

    // Sanity: confirm the imported config types exist (otherwise
    // the import would be flagged unused). Kept as a compile-time
    // touchpoint because the brief's algorithm reads
    // LabelSpecToml + LabelEmissionPolicyToml field names.
    fn _toml_types_exist() -> (LabelSpecToml, LabelEmissionPolicyToml, BTreeMap<String, ()>) {
        unreachable!()
    }

    // ============================================================
    // resolve_action_labels
    // ============================================================

    #[test]
    fn action_labels_disabled_policy_returns_empty() {
        let p = policy(serde_json::json!({ "enabled": false }));
        assert!(
            resolve_action_labels(&account_action(ActionType::Takedown, &[]), &p, t0()).is_empty()
        );
    }

    #[test]
    fn action_labels_note_returns_empty() {
        let p = defaults_policy();
        assert!(
            resolve_action_labels(&account_action(ActionType::Note, &["spam"]), &p, t0())
                .is_empty()
        );
    }

    #[test]
    fn action_labels_warning_suppressed_by_default() {
        let p = defaults_policy();
        assert!(
            resolve_action_labels(&account_action(ActionType::Warning, &["spam"]), &p, t0())
                .is_empty()
        );
    }

    #[test]
    fn action_labels_warning_emits_when_flag_true() {
        let p = policy(serde_json::json!({ "warning_emits_label": true }));
        let out = resolve_action_labels(&account_action(ActionType::Warning, &["spam"]), &p, t0());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].val, "!warn");
        assert!(matches!(out[0].severity, SeverityToml::Inform));
        assert!(!out[0].neg);
    }

    #[test]
    fn action_labels_takedown_emits_default() {
        let p = defaults_policy();
        let out = resolve_action_labels(
            &account_action(ActionType::Takedown, &["hate-speech"]),
            &p,
            t0(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].val, "!takedown");
        assert!(matches!(out[0].severity, SeverityToml::Alert));
        assert_eq!(out[0].exp, None);
    }

    #[test]
    fn action_labels_indef_suspension_emits_hide_no_exp() {
        let p = defaults_policy();
        let out =
            resolve_action_labels(&account_action(ActionType::IndefSuspension, &[]), &p, t0());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].val, "!hide");
        assert_eq!(out[0].exp, None);
    }

    #[test]
    fn action_labels_temp_suspension_with_expiry_propagates_to_exp() {
        let p = defaults_policy();
        let exp = t0() + Duration::from_secs(7 * 86_400);
        let out = resolve_action_labels(&temp_suspension_action(&[], exp), &p, t0());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].val, "!hide");
        assert_eq!(out[0].exp, Some(exp));
    }

    #[test]
    fn action_labels_temp_suspension_without_expiry_emits_with_none_exp() {
        // Degenerate but legal at this layer — the recorder is
        // responsible for ensuring temp_suspension always carries
        // expires_at (#63 contract). #59 just translates whatever
        // it gets.
        let p = defaults_policy();
        let action = ActionForEmission {
            action_type: ActionType::TempSuspension,
            expires_at: None,
            subject_did: SUBJECT_DID.to_string(),
            subject_uri: None,
            reason_codes: vec![],
            cid: None,
        };
        let out = resolve_action_labels(&action, &p, t0());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].exp, None);
    }

    #[test]
    fn action_labels_operator_override_replaces_val() {
        let p = policy(serde_json::json!({
            "action_label_overrides": {
                "takedown": { "val": "!hideaway-takedown", "severity": "alert" }
            }
        }));
        let out = resolve_action_labels(&account_action(ActionType::Takedown, &[]), &p, t0());
        assert_eq!(out[0].val, "!hideaway-takedown");
    }

    #[test]
    fn action_labels_severity_override_applies_to_default_val() {
        let p = policy(serde_json::json!({
            "warning_emits_label": true,
            "severity_overrides": { "warning": "alert" }
        }));
        let out = resolve_action_labels(&account_action(ActionType::Warning, &[]), &p, t0());
        assert_eq!(out[0].val, "!warn"); // default val
        assert!(matches!(out[0].severity, SeverityToml::Alert)); // overridden severity
    }

    #[test]
    fn action_labels_account_subject_uses_did_as_uri() {
        let p = defaults_policy();
        let out = resolve_action_labels(&account_action(ActionType::Takedown, &[]), &p, t0());
        assert_eq!(out[0].uri, SUBJECT_DID);
        assert_eq!(out[0].cid, None);
    }

    #[test]
    fn action_labels_record_subject_uses_uri() {
        let p = defaults_policy();
        let out = resolve_action_labels(&record_action(ActionType::Takedown, &[]), &p, t0());
        assert_eq!(out[0].uri, SUBJECT_URI);
        assert_eq!(out[0].cid, None);
    }

    #[test]
    fn action_labels_cts_takes_now_arg() {
        let p = defaults_policy();
        let now = t0() + Duration::from_secs(42);
        let out = resolve_action_labels(&account_action(ActionType::Takedown, &[]), &p, now);
        assert_eq!(out[0].cts, now);
    }

    #[test]
    fn action_labels_blurs_and_locales_propagate_from_override() {
        let p = policy(serde_json::json!({
            "action_label_overrides": {
                "takedown": {
                    "val": "!hideaway-takedown",
                    "severity": "alert",
                    "blurs": "media",
                    "locales": [
                        { "lang": "en", "name": "Removed", "description": "Account removed by moderation" }
                    ]
                }
            }
        }));
        let out = resolve_action_labels(&account_action(ActionType::Takedown, &[]), &p, t0());
        assert!(matches!(out[0].blurs, Some(BlursToml::Media)));
        assert_eq!(out[0].locales.len(), 1);
        assert_eq!(out[0].locales[0].lang, "en");
    }

    // ============================================================
    // resolve_reason_labels
    // ============================================================

    #[test]
    fn reason_labels_disabled_policy_returns_empty() {
        let p = policy(serde_json::json!({ "enabled": false }));
        let action = account_action(ActionType::Takedown, &["spam", "hate-speech"]);
        assert!(resolve_reason_labels(&action, &p, t0()).is_empty());
    }

    #[test]
    fn reason_labels_emit_reason_labels_false_returns_empty() {
        let p = policy(serde_json::json!({ "emit_reason_labels": false }));
        let action = account_action(ActionType::Takedown, &["spam"]);
        assert!(resolve_reason_labels(&action, &p, t0()).is_empty());
    }

    #[test]
    fn reason_labels_empty_reason_codes_returns_empty() {
        let p = defaults_policy();
        let action = account_action(ActionType::Takedown, &[]);
        assert!(resolve_reason_labels(&action, &p, t0()).is_empty());
    }

    #[test]
    fn reason_labels_note_returns_empty_even_with_reasons() {
        let p = defaults_policy();
        let action = account_action(ActionType::Note, &["spam", "hate-speech"]);
        assert!(resolve_reason_labels(&action, &p, t0()).is_empty());
    }

    #[test]
    fn reason_labels_warning_suppressed_by_default() {
        // Same gate as action labels: if the warning's action label
        // is suppressed, reason labels are too.
        let p = defaults_policy();
        let action = account_action(ActionType::Warning, &["spam"]);
        assert!(resolve_reason_labels(&action, &p, t0()).is_empty());
    }

    #[test]
    fn reason_labels_warning_emits_when_warning_emits_label_true() {
        let p = policy(serde_json::json!({ "warning_emits_label": true }));
        let action = account_action(ActionType::Warning, &["spam"]);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].val, "reason-spam");
    }

    #[test]
    fn reason_labels_takedown_with_three_reasons_emits_three() {
        let p = defaults_policy();
        let action = account_action(ActionType::Takedown, &["spam", "hate-speech", "harassment"]);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out.len(), 3);
        let vals: Vec<&str> = out.iter().map(|d| d.val.as_str()).collect();
        assert_eq!(
            vals,
            vec!["reason-spam", "reason-hate-speech", "reason-harassment"]
        );
        for d in &out {
            assert!(matches!(d.severity, SeverityToml::Inform));
            assert!(!d.neg);
            assert_eq!(d.cts, t0());
            assert_eq!(d.uri, SUBJECT_DID);
        }
    }

    #[test]
    fn reason_labels_temp_suspension_inherits_action_exp() {
        let p = defaults_policy();
        let exp = t0() + Duration::from_secs(7 * 86_400);
        let action = temp_suspension_action(&["spam", "nsfw"], exp);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out.len(), 2);
        for d in &out {
            assert_eq!(d.exp, Some(exp));
        }
    }

    #[test]
    fn reason_labels_use_custom_prefix() {
        let p = policy(serde_json::json!({ "reason_label_prefix": "rsn-" }));
        let action = account_action(ActionType::Takedown, &["spam"]);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out[0].val, "rsn-spam");
    }

    #[test]
    fn reason_labels_use_empty_prefix_yields_bare_reason_codes() {
        let p = policy(serde_json::json!({ "reason_label_prefix": "" }));
        let action = account_action(ActionType::Takedown, &["spam"]);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out[0].val, "spam");
    }

    #[test]
    fn reason_labels_record_subject_uses_uri() {
        let p = defaults_policy();
        let action = record_action(ActionType::Takedown, &["spam"]);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out[0].uri, SUBJECT_URI);
    }

    #[test]
    fn reason_labels_takedown_has_no_exp() {
        let p = defaults_policy();
        let action = account_action(ActionType::Takedown, &["spam"]);
        let out = resolve_reason_labels(&action, &p, t0());
        assert_eq!(out[0].exp, None);
    }

    // ============================================================
    // determinism
    // ============================================================

    #[test]
    fn outputs_deterministic_for_same_inputs() {
        let p = defaults_policy();
        let action = account_action(ActionType::Takedown, &["spam", "hate-speech"]);
        let now = t0();
        let a = resolve_action_labels(&action, &p, now);
        let b = resolve_action_labels(&action, &p, now);
        assert_eq!(a, b);
        let r1 = resolve_reason_labels(&action, &p, now);
        let r2 = resolve_reason_labels(&action, &p, now);
        assert_eq!(r1, r2);
    }
}
