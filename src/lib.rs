//! Cairn — lightweight Rust-native ATProto labeler.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod label;
pub mod signing;
pub mod signing_key;
pub mod storage;
pub mod writer;

pub use config::Config;
pub use error::{Error, Result};
pub use label::Label;
pub use signing::{canonical_bytes, sign_label, verify_label};
pub use signing_key::SigningKey;
pub use writer::{
    ApplyLabelRequest, LabelEvent, NegateLabelRequest, WriterHandle, spawn as spawn_writer,
};
