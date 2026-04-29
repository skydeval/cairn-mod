//! `[xrpc_gateway]` config block (§F23 inbound surface, #91, v1.7).
//!
//! Validated runtime config for the inbound XRPC gateway. The
//! gateway accepts proxied `tools.ozone.moderation.*` calls from
//! bsky-PDS users and forwarded `com.atproto.moderation.createReport`
//! calls from bsky-PDS instances pointed at cairn-mod as the report
//! service (per A6).
//!
//! v1.7 ships #91 (this file — config + router skeleton + 501) and
//! defers the auth (#93), replay cache (#94), and per-NSID handlers
//! (#95-#98) to subsequent issues. The `enabled = false` default
//! preserves v1.6 behavior unchanged: operators who don't opt in
//! see no new ports, no new routes, no new failure modes.
//!
//! # Validation rules
//!
//! Applied at config load via [`XrpcGatewayConfig::from_toml`]:
//!
//! - `enabled = false` → no further validation; all subfields
//!   ignored. The router does not mount and the bridge is a
//!   structural no-op.
//! - `enabled = true` requires `service_did` to be set and to
//!   parse as a syntactically-valid DID (`did:<method>:<id>`).
//!   Operators typically configure `did:web:<their-cairn-host>`
//!   and publish `.well-known/did.json` so callers can resolve
//!   the public key.
//! - `clock_skew_tolerance_seconds` defaults to 30. Bounds are
//!   `1..=300` (5 minutes is the upper limit of "reasonable"
//!   clock skew; longer indicates infrastructure problems and
//!   shouldn't be accommodated by relaxing JWT validation).
//! - `replay_cache_ttl_seconds` defaults to 90. Must be `>=
//!   clock_skew_tolerance_seconds + 60` so the cache outlives
//!   any JWT we'd accept (bsky-PDS mints 60s-TTL JWTs per the
//!   findings doc; if cairn-mod accommodates a clock-skew window
//!   on top of that, the replay cache must cover the worst case).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};

/// TOML projection of [`XrpcGatewayConfig`].
///
/// Construction is via deserialization from the operator's TOML
/// file, validated into the runtime [`XrpcGatewayConfig`] via
/// [`XrpcGatewayConfig::from_toml`]. Unknown sibling keys are
/// captured in [`Self::extras`] so a typo (e.g.
/// `clock_skew_seconds` instead of `clock_skew_tolerance_seconds`)
/// surfaces at config load instead of being silently ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct XrpcGatewayConfigToml {
    /// Master toggle. `false` (default) — gateway is off; the
    /// router does not mount. `true` — gateway is on; cairn-mod
    /// listens for `/xrpc/<nsid>` requests.
    #[serde(default)]
    pub enabled: bool,

    /// cairn-mod's published service DID. Required when
    /// `enabled = true`. JWTs presented to the gateway must list
    /// this DID as their `aud` claim.
    #[serde(default)]
    pub service_did: Option<String>,

    /// Clock-skew tolerance for JWT exp validation, in seconds.
    /// Defaults to 30. See module docs for the rationale.
    #[serde(default)]
    pub clock_skew_tolerance_seconds: Option<u32>,

    /// Replay-cache TTL in seconds. Defaults to 90. Must be
    /// `>= clock_skew_tolerance_seconds + 60`. See module docs.
    #[serde(default)]
    pub replay_cache_ttl_seconds: Option<u32>,

    /// Catch-all for typos. The flatten attribute collects every
    /// key not consumed by the named fields above. v1.7's
    /// resolver rejects each with a v1.7-specific message at
    /// config-load.
    #[serde(flatten, default)]
    pub extras: BTreeMap<String, serde_json::Value>,
}

/// Validated runtime config for the inbound XRPC gateway.
///
/// Constructed from [`XrpcGatewayConfigToml`] via
/// [`Self::from_toml`], which performs all cross-field
/// validation. Once constructed, the values are guaranteed valid
/// and can be used directly by the router and by the auth /
/// replay-cache infrastructure landing in #93 / #94.
///
/// `service_did` is `String` (not `Option<String>`) because the
/// disabled case is represented by NOT constructing this struct
/// at all (the resolver returns `Ok(None)` rather than
/// `Some(disabled_config)`); when an `XrpcGatewayConfig` exists,
/// `service_did` is always populated.
#[derive(Debug, Clone)]
pub struct XrpcGatewayConfig {
    /// Always `true` when an [`XrpcGatewayConfig`] is constructed.
    /// The disabled case never produces this struct, so the field
    /// is structurally redundant — but kept for forward-compat
    /// with v1.8's likely hot-reload feature, which may want to
    /// flip this without dropping the resolved struct.
    pub enabled: bool,

    /// cairn-mod's published service DID. Validated as
    /// syntactically-well-formed at construction time.
    pub service_did: String,

    /// Clock-skew tolerance for inbound JWT exp validation.
    /// Already in `Duration` form (vs. seconds-as-u32) so the
    /// auth layer (#93) doesn't have to reconvert on every
    /// request.
    pub clock_skew_tolerance: Duration,

    /// Replay-cache TTL. Same Duration-not-seconds rationale as
    /// `clock_skew_tolerance`.
    pub replay_cache_ttl: Duration,
}

impl XrpcGatewayConfig {
    /// Project the top-level [`crate::config::Config`] to the
    /// validated runtime gateway config.
    ///
    /// Returns `Ok(None)` when the operator omitted
    /// `[xrpc_gateway]` entirely or set `enabled = false`. Returns
    /// `Ok(Some(_))` with the validated config when enabled.
    /// Returns `Err` on any validation failure (missing required
    /// fields, malformed DID, out-of-range numeric bounds, unknown
    /// extras keys). The resolver is the single source of truth
    /// for "is the gateway runnable?" decisions in
    /// [`mod@crate::serve`].
    pub fn from_config(cfg: &crate::config::Config) -> Result<Option<Self>> {
        let Some(toml) = cfg.xrpc_gateway.as_ref() else {
            return Ok(None);
        };
        Self::from_toml(toml)
    }

    /// Validate a [`XrpcGatewayConfigToml`] into a runtime
    /// [`XrpcGatewayConfig`]. Test-friendly entry point that
    /// doesn't require a full [`crate::config::Config`].
    pub fn from_toml(toml: &XrpcGatewayConfigToml) -> Result<Option<Self>> {
        if !toml.enabled {
            // Disabled gateways skip ALL further validation —
            // operators may declare `[xrpc_gateway]` skeleton
            // sections with placeholder values for forward-compat
            // and we don't want to reject those. The active-block
            // case below applies validation strictly.
            reject_extras_pointing_to_typos(&toml.extras)?;
            return Ok(None);
        }

        reject_extras_pointing_to_typos(&toml.extras)?;

        let service_did = toml.service_did.as_ref().ok_or_else(|| {
            Error::Config("[xrpc_gateway].service_did is required when enabled = true".into())
        })?;
        validate_did(service_did)?;

        let skew_secs = toml.clock_skew_tolerance_seconds.unwrap_or(30);
        if !(1..=300).contains(&skew_secs) {
            return Err(Error::Config(format!(
                "[xrpc_gateway].clock_skew_tolerance_seconds = {skew_secs} \
                 is out of range (must be 1..=300)"
            )));
        }

        let ttl_secs = toml.replay_cache_ttl_seconds.unwrap_or(90);
        let min_ttl = u64::from(skew_secs) + 60;
        if u64::from(ttl_secs) < min_ttl {
            return Err(Error::Config(format!(
                "[xrpc_gateway].replay_cache_ttl_seconds = {ttl_secs} is below the \
                 minimum {min_ttl} (= clock_skew_tolerance_seconds + 60). \
                 The cache must outlive any JWT we'd accept; bsky-PDS mints \
                 60-second-TTL JWTs per findings §2.2."
            )));
        }

        Ok(Some(Self {
            enabled: true,
            service_did: service_did.clone(),
            clock_skew_tolerance: Duration::from_secs(u64::from(skew_secs)),
            replay_cache_ttl: Duration::from_secs(u64::from(ttl_secs)),
        }))
    }
}

/// Minimal syntactic DID validation. cairn-mod doesn't have a
/// crate-wide DID parser; this matches the
/// [`crate::cli::moderator`]'s `validate_did` posture (starts
/// with `"did:"`, has at least one identifier segment after the
/// method-name colon, no whitespace). v1.8's xrpc auth service
/// (#93) does the cryptographic resolve-and-verify; this is
/// purely the config-time well-formed check.
fn validate_did(did: &str) -> Result<()> {
    if !did.starts_with("did:") {
        return Err(Error::Config(format!(
            "[xrpc_gateway].service_did must start with 'did:'; got {did:?}"
        )));
    }
    let rest = &did["did:".len()..];
    let mut parts = rest.splitn(2, ':');
    let method = parts.next().unwrap_or("");
    let identifier = parts.next().unwrap_or("");
    if method.is_empty() || identifier.is_empty() {
        return Err(Error::Config(format!(
            "[xrpc_gateway].service_did must be 'did:<method>:<identifier>'; got {did:?}"
        )));
    }
    if did.chars().any(char::is_whitespace) {
        return Err(Error::Config(format!(
            "[xrpc_gateway].service_did contains whitespace: {did:?}"
        )));
    }
    Ok(())
}

fn reject_extras_pointing_to_typos(extras: &BTreeMap<String, serde_json::Value>) -> Result<()> {
    if extras.is_empty() {
        return Ok(());
    }
    let keys = extras
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::Config(format!(
        "[xrpc_gateway] has unknown key(s): {keys}. \
         v1.7 supports `enabled`, `service_did`, \
         `clock_skew_tolerance_seconds`, `replay_cache_ttl_seconds`. \
         Check spelling — typos surface here rather than being \
         silently ignored."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_toml() -> XrpcGatewayConfigToml {
        XrpcGatewayConfigToml {
            enabled: true,
            service_did: Some("did:web:cairn.example.com".into()),
            clock_skew_tolerance_seconds: None,
            replay_cache_ttl_seconds: None,
            extras: BTreeMap::new(),
        }
    }

    #[test]
    fn disabled_config_returns_none_no_field_validation() {
        // The disabled case ignores subfield content but still
        // catches typos in extras (early-typo-warning is the
        // operator-friendly default).
        let toml = XrpcGatewayConfigToml {
            enabled: false,
            // Deliberately bogus values — should not be rejected
            // because enabled=false short-circuits subfield
            // validation.
            service_did: Some("not-a-did".into()),
            clock_skew_tolerance_seconds: Some(0),
            replay_cache_ttl_seconds: Some(0),
            extras: BTreeMap::new(),
        };
        let result = XrpcGatewayConfig::from_toml(&toml).unwrap();
        assert!(result.is_none(), "disabled gateway resolves to None");
    }

    #[test]
    fn enabled_with_valid_fields_returns_some_with_defaults_filled() {
        let toml = enabled_toml();
        let cfg = XrpcGatewayConfig::from_toml(&toml).unwrap().unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.service_did, "did:web:cairn.example.com");
        assert_eq!(cfg.clock_skew_tolerance, Duration::from_secs(30));
        assert_eq!(cfg.replay_cache_ttl, Duration::from_secs(90));
    }

    #[test]
    fn enabled_without_service_did_errors() {
        let mut toml = enabled_toml();
        toml.service_did = None;
        let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("service_did is required"), "{msg}");
    }

    #[test]
    fn enabled_with_malformed_did_errors() {
        let cases = [
            "not-a-did",
            "did:",
            "did:method",      // missing identifier
            "did:method:",     // empty identifier
            "did::identifier", // empty method
            "did:web: contains space",
        ];
        for input in cases {
            let mut toml = enabled_toml();
            toml.service_did = Some(input.into());
            let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("service_did") && msg.contains(input),
                "expected service_did rejection for {input:?}; got {msg}"
            );
        }
    }

    #[test]
    fn clock_skew_zero_errors() {
        let mut toml = enabled_toml();
        toml.clock_skew_tolerance_seconds = Some(0);
        let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("clock_skew_tolerance_seconds"));
    }

    #[test]
    fn clock_skew_above_max_errors() {
        let mut toml = enabled_toml();
        toml.clock_skew_tolerance_seconds = Some(301);
        let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("clock_skew_tolerance_seconds"));
        assert!(msg.contains("301"));
    }

    #[test]
    fn replay_cache_below_min_errors() {
        // Default skew = 30; minimum TTL = 30 + 60 = 90.
        let mut toml = enabled_toml();
        toml.replay_cache_ttl_seconds = Some(89);
        let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("replay_cache_ttl_seconds"));
        assert!(msg.contains("89"));
        assert!(msg.contains("90")); // the computed minimum
    }

    #[test]
    fn replay_cache_min_relative_to_custom_skew() {
        // skew = 60 → min TTL = 120. 119 must reject; 120 must pass.
        let mut toml = enabled_toml();
        toml.clock_skew_tolerance_seconds = Some(60);
        toml.replay_cache_ttl_seconds = Some(119);
        assert!(XrpcGatewayConfig::from_toml(&toml).is_err());

        toml.replay_cache_ttl_seconds = Some(120);
        let cfg = XrpcGatewayConfig::from_toml(&toml).unwrap().unwrap();
        assert_eq!(cfg.replay_cache_ttl, Duration::from_secs(120));
        assert_eq!(cfg.clock_skew_tolerance, Duration::from_secs(60));
    }

    #[test]
    fn unknown_extras_key_rejected_with_helpful_message() {
        let mut toml = enabled_toml();
        toml.extras
            .insert("clock_skew_seconds".into(), serde_json::json!(30));
        let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("clock_skew_seconds"),
            "error names the offending key: {msg}"
        );
        assert!(
            msg.contains("clock_skew_tolerance_seconds"),
            "error suggests valid keys: {msg}"
        );
    }

    #[test]
    fn extras_rejected_even_when_disabled() {
        // Defense-in-depth: a disabled-but-typo'd block still
        // surfaces the typo so operators don't silently lose
        // their config when they later flip enabled = true.
        let toml = XrpcGatewayConfigToml {
            enabled: false,
            service_did: None,
            clock_skew_tolerance_seconds: None,
            replay_cache_ttl_seconds: None,
            extras: {
                let mut m = BTreeMap::new();
                m.insert("bogus_field".into(), serde_json::json!("value"));
                m
            },
        };
        let err = XrpcGatewayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("bogus_field"));
    }

    #[test]
    fn boundary_clock_skew_values_accepted() {
        // 1 and 300 are both inside the inclusive range.
        let mut toml = enabled_toml();
        toml.clock_skew_tolerance_seconds = Some(1);
        toml.replay_cache_ttl_seconds = Some(61);
        assert!(XrpcGatewayConfig::from_toml(&toml).is_ok());

        toml.clock_skew_tolerance_seconds = Some(300);
        toml.replay_cache_ttl_seconds = Some(360);
        assert!(XrpcGatewayConfig::from_toml(&toml).is_ok());
    }
}
