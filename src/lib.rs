//! Cairn — lightweight Rust-native ATProto labeler.
//!
//! This crate is a library surface (`cairn_mod`) plus a binary
//! (`cairn`) for running a standalone labeler. The library modules
//! mirror the §10 architecture of the [design doc][cairn-design]:
//! storage, writer (single-writer task pattern, §F5), signing
//! (§6.2), auth (§5.2), HTTP routers (§F3/F4/F11/F12), and CLI.
//!
//! Start points:
//! - [`server::router`] for the subscribeLabels + queryLabels
//!   public surface.
//! - [`admin_router`] for the `tools.cairn.admin.*` endpoints.
//! - [`serve::run`] for the full binary lifecycle.
//!
//! [cairn-design]: https://github.com/skydeval/cairn-mod/blob/main/cairn-design.md

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod auth;
pub mod cli;
pub mod config;
pub mod credential_file;
pub mod error;
pub mod label;
pub mod moderation;
pub mod moderators;
pub mod report;
pub mod serve;
pub mod server;
pub mod service_record;
pub mod signing;
pub mod signing_key;
pub mod storage;
pub mod writer;

pub use auth::{AuthConfig, AuthContext, AuthError, VerifiedCaller};
pub use config::Config;
pub use error::{Error, Result};
pub use label::Label;
pub use server::{
    AdminConfig, CreateReportConfig, RetentionConfig, SubscribeConfig, admin_router,
    create_report_router, current_retention_floor, did_document_router, health_router,
    router as subscribe_router, serve, wellknown_router,
};
pub use signing::{canonical_bytes, label_to_lex_value_with_sig, sign_label, verify_label};
pub use signing_key::SigningKey;
pub use writer::{
    ApplyLabelRequest, LabelEvent, NegateLabelRequest, SweepBatchResult, SweepRequest, SweepResult,
    WriterHandle, spawn as spawn_writer,
};
