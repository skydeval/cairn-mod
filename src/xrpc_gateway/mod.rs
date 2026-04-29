//! Inbound XRPC gateway (§F23 inbound surface, v1.7).
//!
//! Operator-config-gated HTTP listener for inbound moderation
//! traffic. v1.7 ships the structural foundation (#91 — config +
//! router skeleton + 501 catch-all) and defers auth (#93), replay
//! cache (#94), and per-NSID handlers (#95-#98) to subsequent
//! issues:
//!
//! - **#91 ([`config`], [`router`])** — `[xrpc_gateway]` config
//!   block + router skeleton mounting at `/xrpc/<nsid>` and
//!   returning 501 `MethodNotImplemented` for every NSID.
//! - **#92** — NSID allowlist enum (the four
//!   `tools.ozone.moderation.*` shapes from §A6 plus
//!   `com.atproto.moderation.createReport`); unrecognized NSIDs
//!   keep returning 501 with the same envelope shape.
//! - **#93** — `XrpcAuthService`: ATProto service-auth JWT
//!   verification per §A8. Uses cairn-mod's existing DID resolver
//!   (extending it for service DIDs).
//! - **#94** — replay cache (in-memory, 90s window, jti dedupe)
//!   + `xrpc_known_callers` / `xrpc_trusted_pdses` tables.
//! - **#95-#98** — per-NSID handler bodies. `emitEvent` lands
//!   first since it exercises the full inbound→recordAction
//!   integration (§A14).
//!
//! See `.design-notes/v1_7-architectural-decisions.md` §A6 / §A7
//! / §A8 / §A14 for the inbound-direction architecture rationale.

pub mod config;
pub mod error;
pub mod nsid;
pub mod router;

pub use config::{XrpcGatewayConfig, XrpcGatewayConfigToml};
pub use error::XrpcGatewayError;
pub use nsid::Nsid;
pub use router::build_router;
