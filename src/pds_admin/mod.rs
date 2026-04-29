//! PDS-admin outbound bridge (§F23, v1.7).
//!
//! Operator-config-gated bridge that translates cairn-mod
//! moderation actions into PDS-side enforcement calls. v1.7 ships
//! bsky-PDS support only (`[pds_admin.ozone]`); Aurora-Locus
//! support lands in v1.8.
//!
//! v1.7 issues lay down the foundation in dependency order:
//!
//! - **#83 ([`config`])** — `[pds_admin]` config block parsing,
//!   validation, env-var resolution. No HTTP code.
//! - **#84 ([`backend`])** — [`PdsAdminBackend`] trait +
//!   [`BackendError`] enum + [`BackendActionId`] opaque newtype
//!   + [`Subject`] shared type. Type-only; no implementations.
//! - **#85** — `pds_admin_audit` table + audit-chain integration.
//! - **#86–#90** — `OzoneBackend` implementation: HTTP client,
//!   admin Basic auth, per-method bodies, startup probe.
//!
//! See [`config`] for the v1.7 config surface, [`backend`] for
//! the trait + error types, and
//! `.design-notes/v1_7-architectural-decisions.md` §A11 / §A2 /
//! §A5 for the schema and trait rationale.

pub mod backend;
pub mod config;
pub mod types;

pub use backend::{BackendActionId, BackendError, PdsAdminBackend};
pub use config::{
    ActionMapEntry, AdminPassword, BackendMethod, OzoneBackendConfig, PdsAdminBackendConfig,
    PdsAdminPolicy,
};
pub use types::Subject;
