//! `tools.cairn.admin.*` handlers (§F12).
//!
//! Each endpoint lives in its own file; [`admin_router`] wires them
//! together under one `Extension<AdminState>` so sub-modules don't
//! need to duplicate state plumbing. Per-request auth + role + CORS
//! gating is centralized in [`common::verify_and_authorize`].

use std::sync::Arc;

use axum::Extension;
use axum::Router;
use axum::routing::{get, post};
use sqlx::{Pool, Sqlite};

use crate::auth::AuthContext;
use crate::writer::WriterHandle;

mod apply_label;
mod common;
mod list_labels;
mod negate_label;

// Future sessions add: list_reports, get_report, resolve_report,
// flag_reporter (#15); list_audit_log (#17). Each registers another
// route in `admin_router` below.

/// Operator configuration for admin endpoints. Kept separate from the
/// subscribe/query configs so operators can tune label-value policy
/// without touching read-side knobs.
#[derive(Debug, Clone, Default)]
pub struct AdminConfig {
    /// Operator-declared label values (§F12 `InvalidLabelValue`).
    /// When `Some`, `applyLabel` rejects values not in this set.
    /// When `None`, any val ≤128 bytes is accepted — the §F11
    /// anti-leak principle applies: the error message on reject
    /// does NOT enumerate the allowed values.
    ///
    /// Future: a #9 service-record update may derive this from the
    /// published `app.bsky.labeler.service` record so the lexicon set
    /// and the runtime policy stay in lockstep.
    pub label_values: Option<Vec<String>>,
}

/// Build a Router exposing the tools.cairn.admin.* endpoints
/// registered so far. Compose with subscribe/query/createReport
/// routers via `Router::merge`.
pub fn admin_router(
    pool: Pool<Sqlite>,
    writer: WriterHandle,
    auth: Arc<AuthContext>,
    config: AdminConfig,
) -> Router {
    let state = common::AdminState {
        pool,
        writer,
        auth,
        config: Arc::new(config),
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
        .layer(Extension(state))
}
