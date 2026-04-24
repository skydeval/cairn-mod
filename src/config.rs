//! Layered config loading.
//!
//! Precedence (lowest → highest): compiled-in defaults, then TOML file,
//! then environment variables prefixed `CAIRN_`. CLI-flag overrides land
//! once the clap surface grows subcommands.
//!
//! Per §5.1, signing-key private material is NEVER sourced through this
//! path. `signing_key_path` points at a file; the bytes are read only by
//! [`crate::signing_key::SigningKey::load_from_file`] with explicit
//! permission, ownership, and env-var-reject checks.

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::Result;

/// Default bind address when `bind_addr` is absent from config.
/// §F13: "expects reverse proxy for TLS." Loopback-only by default;
/// operators knowingly opt into `0.0.0.0:3000` when they run without
/// a reverse proxy on the same host.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";

/// Top-level Cairn configuration.
///
/// Fields grow with features; the struct is `non_exhaustive` so additions
/// are not a breaking change for downstream crates.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Config {
    /// The service DID Cairn runs as (§5.1).
    pub service_did: String,
    /// Publicly-reachable base URL where this Cairn instance serves HTTP
    /// and WebSocket endpoints (e.g., `https://labeler.example`). Emitted
    /// as the `serviceEndpoint` value in the `AtprotoLabeler` entry of
    /// `/.well-known/did.json` so consumers can discover where to call.
    ///
    /// This is distinct from [`Self::bind_addr`] — typical production
    /// deployments bind `127.0.0.1:3000` behind a reverse proxy but
    /// advertise the public `https://labeler.example` URL here.
    /// Validated at load time as a URL.
    pub service_endpoint: String,
    /// Where `cairn serve` binds its HTTP listener. Defaults to
    /// [`DEFAULT_BIND_ADDR`] (`127.0.0.1:3000`) if omitted.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// SQLite database file. Parent directory must exist; the file
    /// itself is created on first run by
    /// [`crate::storage::open`] alongside embedded migrations.
    pub db_path: PathBuf,
    /// Signing key file (§5.1). Mode 0600, owned by the running user,
    /// hex-encoded 32-byte secp256k1 private key. Env-var delivery of
    /// the key material is explicitly rejected — see
    /// [`crate::signing_key::SIGNING_KEY_ENV_REJECTED`].
    pub signing_key_path: PathBuf,
    /// Admin-endpoint policy (§F12). Defaults to an empty table,
    /// meaning `admin.applyLabel` accepts any label value ≤128 bytes
    /// (matches the existing [`crate::AdminConfig`] default).
    #[serde(default)]
    pub admin: AdminConfigToml,
    /// Labeler policy (§F1) — the `app.bsky.labeler.service` record
    /// content. Required for `cairn publish-service-record`; other
    /// subcommands don't consume it, so it's optional at load time.
    /// When absent, `publish-service-record` surfaces a clear error.
    #[serde(default)]
    pub labeler: Option<LabelerConfigToml>,
    /// Operator PDS auth surface (§F1 service record publishing).
    /// The operator's identity is the DID that OWNS the labeler
    /// account — distinct from moderators who authenticate to Cairn
    /// (§5.2) and distinct from Cairn's own signing key (§5.1).
    #[serde(default)]
    pub operator: Option<OperatorConfigToml>,
}

/// TOML projection of [`crate::AdminConfig`]. Separate from the runtime
/// type because (a) `AdminConfig` is constructed from a vector of owned
/// strings and doesn't itself derive `Deserialize`, (b) keeping the
/// wire shape here avoids coupling the server module to figment/serde.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AdminConfigToml {
    /// Operator-declared label values. When `Some`, `applyLabel` only
    /// accepts values in this set. When absent, any val ≤128 bytes is
    /// accepted.
    #[serde(default)]
    pub label_values: Option<Vec<String>>,
}

/// Labeler policy (§F1, §6.4) — the content of the
/// `app.bsky.labeler.service` record that `cairn publish-service-record`
/// emits to the operator's PDS. Field-name mapping to the wire shape is
/// via `#[serde(rename)]` at the runtime-side boundary in
/// [`crate::service_record`]; TOML stays snake_case for operator ergonomics.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct LabelerConfigToml {
    /// Short-name list of labels this instance will emit (§6.4
    /// `policies.labelValues`). Every value here must also have a
    /// matching definition in `label_value_definitions` unless it's a
    /// global well-known value (§6.5). Publishing rejects if a non-
    /// global identifier has no definition.
    pub label_values: Vec<String>,
    /// Per-label metadata entries (§6.4
    /// `policies.labelValueDefinitions`). Empty vec is legal — means
    /// only global values, no custom definitions.
    #[serde(default)]
    pub label_value_definitions: Vec<LabelValueDefinitionToml>,
    /// Optional §6.4 `reasonTypes`. Typically the
    /// `com.atproto.moderation.defs#reason*` set matching createReport
    /// (§F11).
    #[serde(default)]
    pub reason_types: Vec<String>,
    /// Optional §6.4 `subjectTypes` (e.g. `["account", "record"]`).
    #[serde(default)]
    pub subject_types: Vec<String>,
    /// Optional §6.4 `subjectCollections` (e.g.
    /// `["app.bsky.feed.post"]`).
    #[serde(default)]
    pub subject_collections: Vec<String>,
}

/// Single entry in `labelValueDefinitions`. §6.4 constraints:
/// `severity` + `blurs` + `locales` required; `locales` must be
/// non-empty; `default_setting` + `adult_only` optional.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct LabelValueDefinitionToml {
    /// The label value this definition describes (matches an entry
    /// in [`LabelerConfigToml::label_values`]).
    pub identifier: String,
    /// §6.4 severity — how consumers should weight this label.
    pub severity: SeverityToml,
    /// §6.4 blur policy — whether consumer UIs should obscure
    /// content or media on a match.
    pub blurs: BlursToml,
    /// Optional §6.4 default consumer-side setting. Omit to let
    /// consumers pick their own default.
    #[serde(default)]
    pub default_setting: Option<DefaultSettingToml>,
    /// Optional §6.4 flag marking the label as 18+ only.
    #[serde(default)]
    pub adult_only: Option<bool>,
    /// Non-empty list of localized display strings (§6.4 requires
    /// ≥1 locale per definition).
    pub locales: Vec<LocaleToml>,
}

/// §6.4 severity enum.
#[derive(Debug, Clone, Copy, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityToml {
    /// Informational; consumers typically don't gate on this.
    Inform,
    /// Alert the viewer; consumers generally surface a warning.
    Alert,
    /// No severity signal.
    None,
}

/// §6.4 blur policy — what consumer UIs should obscure on a match.
#[derive(Debug, Clone, Copy, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlursToml {
    /// Blur the post / record body.
    Content,
    /// Blur embedded media only.
    Media,
    /// No blurring.
    None,
}

/// §6.4 default consumer-side setting.
#[derive(Debug, Clone, Copy, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultSettingToml {
    /// Consumers default to showing the content with no treatment.
    Ignore,
    /// Consumers default to surfacing a warning.
    Warn,
    /// Consumers default to hiding the content.
    Hide,
}

/// Localized display strings for a label value definition (§6.4).
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct LocaleToml {
    /// BCP-47 language tag (e.g. `"en"`, `"fr-CA"`).
    pub lang: String,
    /// Short display name shown in consumer UIs.
    pub name: String,
    /// Longer explanation, typically shown on tooltip / expand.
    pub description: String,
}

/// Operator-side PDS auth config (§F1). Scope is narrow — just the
/// PDS URL + session file path. Named `[operator]` today; if future
/// operator-identity fields land (contact, alerts, etc.) the table
/// stays small enough to nest those in, or split to `[operator.pds]`
/// then.
#[derive(Debug, Clone, Deserialize)]
pub struct OperatorConfigToml {
    /// PDS base URL (e.g. `https://bsky.social`). No default — the
    /// labeler owner's PDS varies per deployment.
    pub pds_url: String,
    /// On-disk path for the operator session file. Written by
    /// `cairn operator-login`, read by `cairn publish-service-record`.
    /// Same §5.3 invariants as the moderator session file (mode 0600,
    /// owned by running user) via the shared
    /// `crate::credential_file` helper.
    pub session_path: std::path::PathBuf,
}

fn default_bind_addr() -> SocketAddr {
    DEFAULT_BIND_ADDR
        .parse()
        .expect("DEFAULT_BIND_ADDR is a valid socket address")
}

impl Config {
    /// Post-load validation run by [`Config::load`]. Exposed so call
    /// sites that construct a `Config` directly (e.g., tests) can
    /// share the same rule set.
    pub fn validate(&self) -> Result<()> {
        url::Url::parse(&self.service_endpoint).map_err(|e| {
            crate::error::Error::Signing(format!("config.service_endpoint is not a valid URL: {e}"))
        })?;
        // Path existence of db_path / signing_key_path is checked at
        // use time by storage::open and SigningKey::load_from_file —
        // duplicating here would just double-fail and lose the
        // specific cause.
        Ok(())
    }

    /// Load configuration from the default TOML location + env
    /// overrides (see [`Self::load_from`] for the full precedence
    /// rules). The default location is `CAIRN_CONFIG` env var, or
    /// `/etc/cairn/cairn.toml` if unset.
    pub fn load() -> Result<Self> {
        let toml_path: PathBuf = std::env::var_os("CAIRN_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/cairn/cairn.toml"));
        Self::load_from(Some(&toml_path))
    }

    /// Load configuration with an explicit TOML path (or `None` to
    /// skip the file layer entirely and rely on env overrides).
    ///
    /// Sources, low to high precedence:
    /// 1. Compiled-in defaults (`bind_addr` if unset, empty admin
    ///    table).
    /// 2. `toml_path` if `Some` and the file exists.
    /// 3. Environment variables prefixed `CAIRN_`
    ///    (e.g. `CAIRN_SERVICE_DID`).
    ///
    /// `cairn serve --config <path>` routes through this without
    /// mutating process env (which is `unsafe` under Rust 2024 and
    /// blocked by the crate's `#![forbid(unsafe_code)]`).
    pub fn load_from(toml_path: Option<&std::path::Path>) -> Result<Self> {
        let mut fig = Figment::new();
        if let Some(p) = toml_path {
            if p.is_file() {
                fig = fig.merge(Toml::file(p));
            }
        }
        fig = fig.merge(Env::prefixed("CAIRN_"));

        let cfg: Config = fig.extract()?;
        cfg.validate()?;
        Ok(cfg)
    }
}

impl From<AdminConfigToml> for crate::AdminConfig {
    fn from(t: AdminConfigToml) -> Self {
        crate::AdminConfig {
            label_values: t.label_values,
        }
    }
}
