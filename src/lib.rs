//! Cairn — lightweight Rust-native ATProto labeler.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cli;
pub mod config;
pub mod credential_file;
pub mod error;
pub mod label;
pub mod report;
pub mod serve;
pub mod server;
pub mod signing;
pub mod signing_key;
pub mod storage;
pub mod writer;

pub use auth::{AuthConfig, AuthContext, AuthError, VerifiedCaller};
pub use config::Config;
pub use error::{Error, Result};
pub use label::Label;
pub use server::{
    AdminConfig, CreateReportConfig, SubscribeConfig, admin_router, create_report_router,
    did_document_router, router as subscribe_router, serve, wellknown_router,
};
pub use signing::{canonical_bytes, label_to_lex_value_with_sig, sign_label, verify_label};
pub use signing_key::SigningKey;
pub use writer::{
    ApplyLabelRequest, LabelEvent, NegateLabelRequest, WriterHandle, spawn as spawn_writer,
};
