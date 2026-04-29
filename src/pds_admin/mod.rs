//! PDS-admin outbound bridge (§F23, v1.7).
//!
//! Operator-config-gated bridge that translates cairn-mod
//! moderation actions into PDS-side enforcement calls. v1.7 ships
//! bsky-PDS support only (`[pds_admin.ozone]`); Aurora-Locus
//! support lands in v1.8.
//!
//! v1.7 issues lay down the foundation in dependency order:
//!
//! - **#83 (this module's [`config`])** — `[pds_admin]` config
//!   block parsing, validation, env-var resolution. No HTTP code.
//! - **#84** — `PdsAdminBackend` trait + `BackendError` enum.
//! - **#85** — `pds_admin_audit` table + audit-chain integration.
//! - **#86–#90** — `OzoneBackend` implementation: HTTP client,
//!   admin Basic auth, per-method bodies, startup probe.
//!
//! See [`crate::pds_admin::config`] for the v1.7 config surface
//! and `.design-notes/v1_7-architectural-decisions.md` §A11 for
//! the schema rationale.

pub mod config;

pub use config::{
    ActionMapEntry, AdminPassword, BackendMethod, OzoneBackendConfig, PdsAdminBackendConfig,
    PdsAdminPolicy,
};
