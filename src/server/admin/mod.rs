//! `tools.cairn.admin.*` handlers (§F12).
//!
//! Each endpoint lives in its own file; [`admin_router`] wires them
//! together under one `Extension<AdminState>` so sub-modules don't
//! need to duplicate state plumbing. Per-request auth + role + CORS
//! gating is centralized in the shared `common::verify_and_authorize`
//! helper inside this module.

use std::sync::Arc;

use axum::Extension;
use axum::Router;
use axum::routing::{get, post};
use sqlx::{Pool, Sqlite};

use crate::auth::AuthContext;
use crate::writer::WriterHandle;

mod apply_label;
mod audit_view;
mod common;
mod confirm_pending_action;
mod dismiss_pending_action;
mod flag_reporter;
mod get_audit_log;
mod get_report;
mod get_subject_history;
mod get_subject_strikes;
mod get_trust_chain;
mod list_audit_log;
mod list_labels;
mod list_reports;
mod negate_label;
mod record_action;
mod report_view;
mod resolve_report;
mod retention_sweep;
mod revoke_action;
mod subject_action_view;

/// Operator configuration for admin endpoints. Kept separate from the
/// subscribe/query configs so operators can tune label-value policy
/// without touching read-side knobs.
#[derive(Debug, Clone, Default)]
pub struct AdminConfig {
    /// Operational allowlist for `applyLabel` (§F12 `InvalidLabelValue`).
    /// When `Some`, `applyLabel` rejects values not in this set.
    /// When `None`, any val ≤128 bytes is accepted — the §F11
    /// anti-leak principle applies: the error message on reject
    /// does NOT enumerate the allowed values.
    ///
    /// Distinct from [`Self::declared_label_values`] (the trust-chain
    /// surface for the labeler's *declared* taxonomy). They typically
    /// match in production but conceptually differ — the allowlist
    /// gates incoming writes; the declared list documents what the
    /// labeler publishes.
    ///
    /// Future: a #9 service-record update may derive this from the
    /// published `app.bsky.labeler.service` record so the lexicon set
    /// and the runtime policy stay in lockstep.
    pub label_values: Option<Vec<String>>,

    /// Service DID surfaced in `tools.cairn.admin.getTrustChain` (#36).
    /// Mirrors `Config::service_did`; populated at admin_router
    /// construction in `serve::run`. Default empty for tests that
    /// don't exercise the trust-chain endpoint.
    pub service_did: String,

    /// Service endpoint URL surfaced in
    /// `tools.cairn.admin.getTrustChain` (#36). Mirrors
    /// `Config::service_endpoint`. Default empty for tests that
    /// don't exercise the trust-chain endpoint.
    pub service_endpoint: String,

    /// Labeler-declared label values from the `[labeler]` config
    /// block — surfaced by `tools.cairn.admin.getTrustChain` as the
    /// trust-chain "taxonomy" snapshot. `None` when the deployment
    /// runs without `[labeler]` (§F19 labeler-absent path); the
    /// trust-chain endpoint then reports `serviceRecord: null`.
    /// Distinct from [`Self::label_values`] above — see that field's
    /// doc comment.
    pub declared_label_values: Option<Vec<String>>,
}

/// Build a Router exposing the tools.cairn.admin.* endpoints
/// registered so far. Compose with subscribe/query/createReport
/// routers via `Router::merge`.
///
/// `strike_policy` is the resolved v1.4 `[strike_policy]` (#48); the
/// strikes read endpoint consults the threshold + decay window when
/// projecting the wire envelope. Pass the same instance the writer
/// task holds — `serve::run` resolves once at startup and clones
/// here.
pub fn admin_router(
    pool: Pool<Sqlite>,
    writer: WriterHandle,
    auth: Arc<AuthContext>,
    config: AdminConfig,
    strike_policy: crate::moderation::policy::StrikePolicy,
) -> Router {
    let state = common::AdminState {
        pool,
        writer,
        auth,
        config: Arc::new(config),
        strike_policy: Arc::new(strike_policy),
    };
    Router::new()
        .route(
            "/xrpc/tools.cairn.admin.applyLabel",
            post(apply_label::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.negateLabel",
            post(negate_label::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.listLabels",
            get(list_labels::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.listReports",
            get(list_reports::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.getReport",
            get(get_report::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.resolveReport",
            post(resolve_report::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.flagReporter",
            post(flag_reporter::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.listAuditLog",
            get(list_audit_log::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.getAuditLog",
            get(get_audit_log::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.retentionSweep",
            post(retention_sweep::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.getTrustChain",
            get(get_trust_chain::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.recordAction",
            post(record_action::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.revokeAction",
            post(revoke_action::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.getSubjectHistory",
            get(get_subject_history::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.getSubjectStrikes",
            get(get_subject_strikes::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.confirmPendingAction",
            post(confirm_pending_action::handler),
        )
        .route(
            "/xrpc/tools.cairn.admin.dismissPendingAction",
            post(dismiss_pending_action::handler),
        )
        .layer(Extension(state))
}
