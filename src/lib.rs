//! Cairn — lightweight Rust-native ATProto labeler.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod error;
pub mod label;
pub mod server;
pub mod signing;
pub mod signing_key;
pub mod storage;
pub mod writer;

pub use auth::{AuthConfig, AuthContext, AuthError, VerifiedCaller};
pub use config::Config;
pub use error::{Error, Result};
pub use label::Label;
pub use server::{SubscribeConfig, router as subscribe_router, serve};
pub use signing::{canonical_bytes, label_to_lex_value_with_sig, sign_label, verify_label};
pub use signing_key::SigningKey;
pub use writer::{
    ApplyLabelRequest, LabelEvent, NegateLabelRequest, WriterHandle, spawn as spawn_writer,
};
