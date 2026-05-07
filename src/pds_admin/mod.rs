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
//! - **#85 ([`audit`])** — `pds_admin_audit` table +
//!   audit-chain integration. Hash-chains into the same chain as
//!   `audit_log` (§F10) per §A13.
//! - **#86 ([`ozone`])** — `OzoneBackend` skeleton: struct,
//!   constructor, helper functions, trait impl with
//!   `unimplemented!()` placeholders for #87/#88. Label methods
//!   already return `Unsupported` per §A5 (final v1.7 behavior).
//! - **#87 ([`ozone`] body + [`dispatch`])** —
//!   `OzoneBackend::takedown_account` body via
//!   `com.atproto.admin.updateSubjectStatus`; integration into
//!   the recordAction pipeline via [`dispatch::PdsAdminBridge`]
//!   and [`dispatch::dispatch_after_record_action`].
//! - **#88–#90** — remaining `OzoneBackend` method bodies +
//!   startup probe.
//!
//! See [`config`] for the v1.7 config surface, [`backend`] for
//! the trait + error types, [`audit`] for the persistence layer,
//! [`ozone`] for the bsky-PDS backend, [`dispatch`] for the
//! recordAction integration glue, and
//! `.design-notes/v1_7-architectural-decisions.md` §A2 / §A4 /
//! §A5 / §A11 / §A13 for the trait, outbound auth, label-bridge,
//! schema, and audit-chain rationale.

pub mod audit;
pub mod backend;
pub mod config;
pub mod dispatch;
pub mod ozone;
pub mod types;

pub use audit::{
    AuditOutcome, PdsAdminAuditRecord, get_pds_admin_audit, list_pds_admin_audit_for_action,
    record_pds_admin_call,
};
pub use backend::{BackendActionId, BackendError, BackendInitError, PdsAdminBackend, ProbeReport};
pub use config::{
    ActionMapEntry, AdminPassword, BackendMethod, OzoneBackendConfig, PdsAdminBackendConfig,
    PdsAdminPolicy,
};
pub use dispatch::{
    DispatchContext, PdsAdminBridge, RevokeDispatchContext, dispatch_after_record_action,
    dispatch_after_revoke_action,
};
pub use ozone::OzoneBackend;
pub use types::{
    AuditTrailEntryRead, AuditTrailEntryWrite, CAPABILITY_CLASSIFICATIONS,
    CapabilityClassification, CapabilityVersion, PaginationCursor, Subject, classification_for,
    parse_capability_string,
};
