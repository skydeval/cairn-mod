//! Standalone mock PDS for the `tests/e2e/quickstart.sh` rot-check (#10).
//!
//! Listens on a fixed loopback address and serves the four PDS
//! endpoints the README's Quickstart workflow exercises:
//!
//!   POST /xrpc/com.atproto.server.createSession
//!   GET  /xrpc/com.atproto.repo.getRecord
//!   POST /xrpc/com.atproto.repo.putRecord
//!   POST /xrpc/com.atproto.server.refreshSession
//!
//! Built as a Cargo example so it's outside the published crate
//! (`cargo install cairn-mod` users don't get it). The e2e script
//! invokes via `cargo build --release --example mock_pds` and then
//! runs the binary directly.
//!
//! Logic mirrors `tests/support/mock_pds.rs` but is intentionally
//! a separate, narrower copy: examples can't `use crate::tests::*`,
//! and the e2e flow needs a smaller surface than the full unit-
//! test fixture (no JWT-minting paths, no fault-injection knobs).
//! If `tests/support/mock_pds.rs` evolves materially, this file
//! likely needs a parallel update — flagged in the comment block
//! above each handler.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const DEFAULT_BIND: &str = "127.0.0.1:5174";
const DEFAULT_OPERATOR_DID: &str = "did:plc:mockoperator0000000000000000";
const MOCK_HANDLE: &str = "alice.bsky.social";

/// Stored state for the mock PDS. The `service_record` slot starts
/// empty; the first putRecord populates it; subsequent getRecords
/// return what was stored.
#[derive(Default)]
struct State_ {
    service_record: Option<(String, Value)>, // (cid, value)
}

#[derive(Clone)]
struct Inner {
    state: Arc<Mutex<State_>>,
    operator_did: String,
}

#[tokio::main]
async fn main() {
    // Args via env to avoid pulling clap into examples. Defaults work
    // for the e2e script; overrides are only useful for ad-hoc local
    // debugging.
    let bind: SocketAddr = std::env::var("MOCK_PDS_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND.to_string())
        .parse()
        .expect("MOCK_PDS_ADDR is a valid SocketAddr");
    let operator_did =
        std::env::var("MOCK_PDS_OPERATOR_DID").unwrap_or_else(|_| DEFAULT_OPERATOR_DID.to_string());

    let inner = Inner {
        state: Arc::new(Mutex::new(State_::default())),
        operator_did,
    };

    let app = Router::new()
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .with_state(inner);

    let listener = TcpListener::bind(bind)
        .await
        .expect("bind mock PDS listener");
    eprintln!("mock_pds listening on http://{bind}");
    axum::serve(listener, app)
        .await
        .expect("mock PDS axum::serve");
}

/// `createSession`: accept any handle/password and return canned
/// session tokens. Mirrors the production atproto shape so cairn's
/// `cli::pds::PdsClient::create_session` deserializes cleanly.
async fn create_session(State(inner): State<Inner>, Json(_body): Json<Value>) -> Response {
    Json(json!({
        "did": inner.operator_did,
        "handle": MOCK_HANDLE,
        "accessJwt": "mock-access-jwt",
        "refreshJwt": "mock-refresh-jwt",
    }))
    .into_response()
}

/// `refreshSession`: accept whatever Authorization arrives and
/// return new canned tokens. Not exercised by the happy-path
/// quickstart flow but included so transient session-refresh paths
/// in cairn don't blow up against the mock.
async fn refresh_session() -> Response {
    Json(json!({
        "did": DEFAULT_OPERATOR_DID,
        "handle": MOCK_HANDLE,
        "accessJwt": "mock-access-jwt-refreshed",
        "refreshJwt": "mock-refresh-jwt-refreshed",
    }))
    .into_response()
}

#[derive(Deserialize)]
struct GetRecordParams {
    repo: String,
    collection: String,
    rkey: String,
}

/// `getRecord`: return what was last `putRecord`'d for the labeler
/// service record, or 404 with `RecordNotFound` if nothing has been
/// published yet. The §F1 startup-verify path in `cairn serve`
/// checks this; `publish-service-record` also checks it for
/// idempotency before writing.
async fn get_record(State(inner): State<Inner>, Query(params): Query<GetRecordParams>) -> Response {
    let state = inner.state.lock().await;
    if params.collection != "app.bsky.labeler.service" || params.rkey != "self" {
        return xrpc_error(
            axum::http::StatusCode::NOT_FOUND,
            "RecordNotFound",
            "unknown collection or rkey for the mock",
        );
    }
    let Some((cid, value)) = state.service_record.as_ref() else {
        return xrpc_error(
            axum::http::StatusCode::NOT_FOUND,
            "RecordNotFound",
            "no service record published yet",
        );
    };
    Json(json!({
        "uri": format!("at://{}/{}/{}", params.repo, params.collection, params.rkey),
        "cid": cid,
        "value": value,
    }))
    .into_response()
}

/// `putRecord`: store the supplied record, mint a synthetic CID
/// (sufficient for the e2e flow — cairn validates structure, not
/// the CID's hash content). The §F1 swap-race path is NOT
/// exercised here since the e2e flow is single-shot.
async fn put_record(State(inner): State<Inner>, Json(body): Json<Value>) -> Response {
    let value = body
        .get("record")
        .cloned()
        .unwrap_or_else(|| body.get("value").cloned().unwrap_or(Value::Null));
    let mut state = inner.state.lock().await;
    let new_cid = format!(
        "bafyreimocked{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    );
    state.service_record = Some((new_cid.clone(), value));
    Json(json!({
        "uri": "at://did:plc:mockoperator0000000000000000/app.bsky.labeler.service/self",
        "cid": new_cid,
    }))
    .into_response()
}

fn xrpc_error(status: axum::http::StatusCode, error: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "message": message,
        })),
    )
        .into_response()
}
