//! `cairn login` — §5.3 interactive auth, no password flag.
//!
//! Flow:
//! 1. Resolve Cairn service DID: either `--cairn-did` override, or
//!    fetch `<cairn_server>/.well-known/did.json` (deferred for #18).
//! 2. Exchange handle + app-password at the PDS
//!    (`createSession`).
//! 3. Build SessionFile using the authoritative DID from the
//!    `createSession` response — never trust user-supplied DID over
//!    what the PDS authenticated.
//! 4. Write atomically (0600, sibling tempfile + rename).
//! 5. Return session + path for the caller to print the warning.
//!
//! Note: the interactive password prompt lives in `main.rs`, not
//! here. [`login`] takes the app password as a `&str` so tests can
//! drive it without a TTY.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use super::error::CliError;
use super::pds::PdsClient;
use super::session::SessionFile;

/// Shape of a did.json document, minimal projection — only `id` is
/// consumed. Cairn's `.well-known/did.json` (from #18) will follow
/// the standard did:web format.
#[derive(Debug, Deserialize)]
struct DidJsonMin {
    id: String,
}

/// Log a moderator in against the given PDS + Cairn server, persist
/// the resulting session, and return the written value.
///
/// `cairn_did_override` corresponds to the `--cairn-did` flag (Q1
/// fallback): when `Some`, skip the `.well-known/did.json` fetch.
/// Useful both as an escape hatch and during the window where
/// #18's endpoint hasn't shipped.
pub async fn login(
    cairn_server: &str,
    pds_url: &str,
    handle: &str,
    app_password: &str,
    cairn_did_override: Option<&str>,
    session_path: &Path,
) -> Result<SessionFile, CliError> {
    let cairn_service_did = match cairn_did_override {
        Some(d) => d.to_string(),
        None => fetch_cairn_service_did(cairn_server).await?,
    };

    let pds = PdsClient::new(pds_url)?;
    let resp = pds.create_session(handle, app_password).await?;

    let session = SessionFile {
        version: crate::cli::session::SESSION_VERSION,
        cairn_server_url: cairn_server.to_string(),
        cairn_service_did,
        pds_url: pds_url.to_string(),
        // Authoritative: the DID the PDS authenticated, not the
        // user-supplied handle.
        moderator_did: resp.did,
        moderator_handle: resp.handle,
        access_jwt: resp.access_jwt,
        refresh_jwt: resp.refresh_jwt,
    };
    session.save(session_path)?;
    Ok(session)
}

/// GET `<cairn_server>/.well-known/did.json` and extract `id`. No
/// signature verification — the did.json-based discovery is
/// integrity-gated by TLS on the Cairn server URL, and a
/// misdirected `aud` only prevents the resulting JWT from being
/// accepted by the real Cairn (the PDS still signs for the correct
/// `iss`). The trust root is the user-supplied Cairn URL.
async fn fetch_cairn_service_did(cairn_server: &str) -> Result<String, CliError> {
    let url = format!(
        "{}/.well-known/did.json",
        cairn_server.trim_end_matches('/')
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest build");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|source| CliError::Http {
            url: url.clone(),
            source,
        })?;
    if !resp.status().is_success() {
        return Err(CliError::CairnStatus {
            url,
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        });
    }
    let bytes = resp.bytes().await.map_err(|source| CliError::Http {
        url: url.clone(),
        source,
    })?;
    let doc: DidJsonMin =
        serde_json::from_slice(&bytes).map_err(|source| CliError::MalformedResponse {
            url: url.clone(),
            source,
        })?;
    Ok(doc.id)
}

/// §5.3 warning text. Kept as a function so `main.rs` prints it
/// verbatim and tests can spot-check it without spawning the
/// binary.
pub fn post_login_warning(session: &SessionFile, session_path: &Path) -> String {
    format!(
        "Logged in as {did}.\n\
         Session cached at {path}.\n\
         \n\
         WARNING: this session file is a moderator credential equivalent\n\
         to your PDS app password. Protect it accordingly. Anyone with\n\
         read access to this file can act as you at {server} until you\n\
         run `cairn logout` or the session expires at the PDS.",
        did = session.moderator_did,
        path = session_path.display(),
        server = session.cairn_server_url,
    )
}
