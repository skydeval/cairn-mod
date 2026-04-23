//! Mock PDS fixture — the 4 endpoints the CLI depends on (§5.3):
//! `createSession`, `refreshSession`, `deleteSession`,
//! `getServiceAuth`.
//!
//! Serves plain HTTP on 127.0.0.1:<ephemeral>. `getServiceAuth`
//! mints real ES256K JWTs signed by the fixture keypair; a test
//! that pairs this with a [`crate::support`]-style MockDidResolver
//! serving the same public key can verify through to Cairn's
//! production `AuthContext::verify_service_auth` — that is the
//! agreement test (§J-15 of the criteria).
//!
//! Behavior-injection via the atomic counters on [`MockPdsState`]:
//!   - `force_get_service_auth_401_next` — one-shot "PDS replies
//!     401 on the next getServiceAuth", exercises the
//!     auto-refresh path in the CLI.
//!   - `force_refresh_401` — one-shot "refreshSession fails",
//!     exercises the "re-login required" branch.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use proto_blue_crypto::{K256Keypair, Keypair as _, Signer as _};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Fixture private key for the moderator. Shared with tests that
/// set up a matching DID document in a MockDidResolver.
pub const MOCK_MODERATOR_PRIV_HEX: &str =
    "b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a";

/// App password the mock accepts at `createSession`.
pub const MOCK_APP_PASSWORD: &str = "correct-horse-battery-staple";

/// Handle the mock echoes back. Tests that assert session.handle
/// compare against this.
pub const MOCK_HANDLE: &str = "alice.bsky.social";

/// Counters + rotatable token state. Tests read the counters to
/// assert call counts and set `force_*_401_next` to inject
/// one-shot failures.
#[derive(Default)]
pub struct MockPdsState {
    pub create_session_calls: AtomicUsize,
    pub refresh_session_calls: AtomicUsize,
    pub delete_session_calls: AtomicUsize,
    pub get_service_auth_calls: AtomicUsize,
    pub force_get_service_auth_401_next: AtomicUsize,
    pub force_refresh_401: AtomicUsize,
    /// Current access token the mock accepts. Rotated on each
    /// `refreshSession`.
    pub current_access: Mutex<String>,
    /// Current refresh token the mock accepts. Rotated on each
    /// `refreshSession`.
    pub current_refresh: Mutex<String>,
}

/// Everything a test needs to interact with the mock. Fields are
/// `#[allow(dead_code)]` because each integration test binary only
/// reaches for a subset (e.g., `cli_login` doesn't touch `state`).
#[allow(dead_code)]
pub struct MockPds {
    pub addr: SocketAddr,
    pub state: Arc<MockPdsState>,
    /// The DID the mock returns in `createSession` response. Tests
    /// that validate Cairn agreement register this DID in the
    /// MockDidResolver with the fixture public key.
    pub moderator_did: String,
}

impl MockPds {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

#[derive(Clone)]
struct Inner {
    state: Arc<MockPdsState>,
    moderator_did: String,
}

fn keypair() -> K256Keypair {
    K256Keypair::from_private_key(&hex::decode(MOCK_MODERATOR_PRIV_HEX).unwrap()).unwrap()
}

/// Spawn the mock PDS. Returns once the listener is bound; handlers
/// run on tokio::spawn in the background.
pub async fn spawn(moderator_did: impl Into<String>) -> MockPds {
    let moderator_did = moderator_did.into();
    let state = Arc::new(MockPdsState {
        current_access: Mutex::new("initial-access-jwt".into()),
        current_refresh: Mutex::new("initial-refresh-jwt".into()),
        ..Default::default()
    });
    let inner = Inner {
        state: state.clone(),
        moderator_did: moderator_did.clone(),
    };

    let router = Router::new()
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(get_service_auth),
        )
        .with_state(inner);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service()).await.ok();
    });

    MockPds {
        addr,
        state,
        moderator_did,
    }
}

// ---------- handlers ----------

#[derive(Deserialize)]
struct CreateSessionBody {
    identifier: String,
    password: String,
}

async fn create_session(
    State(inner): State<Inner>,
    Json(body): Json<CreateSessionBody>,
) -> Response {
    inner
        .state
        .create_session_calls
        .fetch_add(1, Ordering::SeqCst);
    if body.password != MOCK_APP_PASSWORD {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "invalid app password",
        );
    }
    let access = inner.state.current_access.lock().await.clone();
    let refresh = inner.state.current_refresh.lock().await.clone();
    Json(json!({
        "accessJwt": access,
        "refreshJwt": refresh,
        "did": inner.moderator_did,
        "handle": MOCK_HANDLE,
        // Echo identifier back into handle field if the caller sent
        // a DID (not used by tests today, but matches real PDS
        // behavior loosely).
        "_identifier_echo": body.identifier,
    }))
    .into_response()
}

async fn refresh_session(State(inner): State<Inner>, headers: HeaderMap) -> Response {
    inner
        .state
        .refresh_session_calls
        .fetch_add(1, Ordering::SeqCst);

    if inner.state.force_refresh_401.swap(0, Ordering::SeqCst) > 0 {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "ExpiredToken",
            "refresh token expired",
        );
    }

    let bearer = match extract_bearer(&headers) {
        Some(b) => b,
        None => {
            return xrpc_error(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "missing bearer",
            );
        }
    };
    if bearer != *inner.state.current_refresh.lock().await {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "stale refresh token",
        );
    }

    // Rotate both tokens.
    let n = inner.state.refresh_session_calls.load(Ordering::SeqCst);
    let new_access = format!("access-jwt-v{n}");
    let new_refresh = format!("refresh-jwt-v{n}");
    *inner.state.current_access.lock().await = new_access.clone();
    *inner.state.current_refresh.lock().await = new_refresh.clone();

    Json(json!({
        "accessJwt": new_access,
        "refreshJwt": new_refresh,
    }))
    .into_response()
}

/// **Divergence from real PDS behavior:** a production PDS
/// invalidates the refresh token on successful `deleteSession` —
/// subsequent `refreshSession` calls with the same token return
/// 401. This mock does NOT invalidate on delete; the token stays
/// accepted by `refresh_session` until it rotates normally.
///
/// This is intentional: the CLI's logout flow only calls
/// `deleteSession` once and then drops the session entirely, so
/// the post-delete refresh path is unreachable in production. But
/// if a future test writer exercises "delete, then try refresh
/// with the old token and expect 401," they will get a misleading
/// pass here. Extend the mock (invalidate-on-delete flag) before
/// writing such a test.
async fn delete_session(State(inner): State<Inner>, headers: HeaderMap) -> Response {
    inner
        .state
        .delete_session_calls
        .fetch_add(1, Ordering::SeqCst);
    let bearer = match extract_bearer(&headers) {
        Some(b) => b,
        None => {
            return xrpc_error(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "missing bearer",
            );
        }
    };
    if bearer != *inner.state.current_refresh.lock().await {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "stale refresh token",
        );
    }
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct GetServiceAuthParams {
    aud: String,
    lxm: String,
}

async fn get_service_auth(
    State(inner): State<Inner>,
    headers: HeaderMap,
    Query(params): Query<GetServiceAuthParams>,
) -> Response {
    inner
        .state
        .get_service_auth_calls
        .fetch_add(1, Ordering::SeqCst);

    if inner
        .state
        .force_get_service_auth_401_next
        .swap(0, Ordering::SeqCst)
        > 0
    {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "ExpiredToken",
            "access token expired",
        );
    }

    let bearer = match extract_bearer(&headers) {
        Some(b) => b,
        None => {
            return xrpc_error(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "missing bearer",
            );
        }
    };
    if bearer != *inner.state.current_access.lock().await {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "stale access token",
        );
    }

    let token = mint_service_auth_jwt(&inner.moderator_did, &params.aud, &params.lxm);
    Json(json!({ "token": token })).into_response()
}

fn mint_service_auth_jwt(iss: &str, aud: &str, lxm: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = json!({
        "iss": iss,
        "aud": aud,
        "exp": now + 60,
        "iat": now,
        "jti": format!("jti-mockpds-{}", uuid::Uuid::new_v4()),
        "lxm": lxm,
    });
    let header = json!({"alg": "ES256K", "typ": "JWT"});
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h = engine.encode(header.to_string());
    let p = engine.encode(claims.to_string());
    let input = format!("{h}.{p}");
    let sig = keypair().sign(input.as_bytes()).unwrap();
    format!("{h}.{p}.{}", engine.encode(sig))
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn xrpc_error(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error": error, "message": message}))).into_response()
}

/// Construct a DID document serving the fixture public key at
/// `#atproto` for the given DID. Lets tests wire up a
/// MockDidResolver that agrees with the mock PDS's signing key.
pub fn fixture_did_document(did: &str) -> Value {
    let pubkey = proto_blue_crypto::format_multikey("ES256K", &keypair().public_key_compressed());
    json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "publicKeyMultibase": pubkey,
        }],
    })
}
