//! Per-NSID handler bodies for the inbound XRPC gateway
//! (#95-#98, v1.7).
//!
//! Each module here implements one of the four allowlisted NSIDs
//! from [`crate::xrpc_gateway::Nsid`], translating the inbound
//! Ozone wire shape into cairn-mod's internal write surface
//! (`WriterHandle::record_action` / `revoke_action` / etc.) per
//! §A14's "one canonical action-recording path".
//!
//! The router in [`crate::xrpc_gateway::router`] wires these into
//! axum routes after auth + membership + replay middleware so each
//! handler runs only for fully-authorized requests.

use sqlx::{Pool, Sqlite};

use crate::writer::WriterHandle;

pub mod create_report;
pub mod emit_event;
pub mod projections;
pub mod query_events;
pub mod query_statuses;

/// Shared state every gateway handler receives via `Extension`.
///
/// Carries the [`WriterHandle`] (so handlers can call into the
/// canonical recordAction pipeline) and the SQLite pool (used for
/// queries that aren't owned by the writer task — e.g.,
/// `modEventReverseTakedown`'s lookup of the most-recent unrevoked
/// Takedown action_id for a subject).
///
/// `Clone` is intentional: axum's `Extension` layer hands a clone
/// to each handler invocation. `WriterHandle` and `Pool<Sqlite>`
/// are both cheap to clone (channel-sender + connection-pool
/// arc-clone respectively).
#[derive(Clone)]
pub struct XrpcGatewayState {
    /// Channel handle to the single writer task. Same instance the
    /// admin-XRPC handlers and CLI write paths use — §A14 demands
    /// every action passes through this surface so strike state,
    /// label emission, and audit-chain append are atomic.
    pub writer: WriterHandle,
    /// SQLite pool for read-side queries. Distinct from the
    /// writer's transaction context: handlers use this for
    /// lookups that don't mutate state (e.g., finding the action
    /// row to revoke).
    pub pool: Pool<Sqlite>,
    /// cairn-mod's labeler service DID — same value
    /// `[xrpc_gateway].service_did` resolves to. Read handlers
    /// (#97 / #98) use this as the `labels.src` filter when
    /// projecting the active-label set per subject; without it,
    /// labels emitted by other labelers (against the same subject
    /// DID via cairn-mod's PDS) would leak into cairn-mod's
    /// status views.
    pub service_did: String,
}
