//! `cairn operator-login` — interactive app-password exchange for the
//! operator's PDS account (§F1).
//!
//! Mirrors `cairn login` (#16) structurally but writes a distinct
//! session file at `config.operator.session_path`. The operator
//! identity is the DID that owns the labeler PDS account — not a
//! moderator authenticating to Cairn. The two session files coexist.
//!
//! The interactive password prompt lives in `main.rs`; [`login`]
//! takes the password as a `&str` so tests can drive it without a
//! TTY.

use std::path::Path;

use super::error::CliError;
use super::operator_session::OperatorSession;
use super::pds::PdsClient;

/// Authenticate against the operator's PDS, persist the session.
/// Returns the written session so `main.rs` can print a warning
/// that mirrors §5.3's security notice (the file is moderator-
/// credential-equivalent for THEIR PDS).
pub async fn login(
    pds_url: &str,
    handle: &str,
    app_password: &str,
    session_path: &Path,
) -> Result<OperatorSession, CliError> {
    let pds = PdsClient::new(pds_url)?;
    let resp = pds.create_session(handle, app_password).await?;

    let session = OperatorSession {
        version: super::operator_session::OPERATOR_SESSION_VERSION,
        pds_url: pds_url.to_string(),
        operator_did: resp.did,
        operator_handle: resp.handle,
        access_jwt: resp.access_jwt,
        refresh_jwt: resp.refresh_jwt,
    };
    session
        .save(session_path)
        .map_err(|e| CliError::Config(format!("writing operator session: {e}")))?;
    Ok(session)
}

/// §F1-flavored warning that mirrors §5.3's moderator warning. The
/// operator session is powerful — anyone with read access can push
/// arbitrary records to the labeler's PDS account, not just update
/// the service record.
pub fn post_login_warning(session: &OperatorSession, path: &Path) -> String {
    format!(
        "Logged in as operator {did}.\n\
         Session cached at {path}.\n\
         \n\
         WARNING: this session file authenticates as the LABELER's PDS\n\
         account. Anyone with read access to this file can push records\n\
         to {pds}, including overwriting the service record. Protect\n\
         it like the app password itself — a stolen file lives until\n\
         `cairn operator-logout` revokes it or the PDS session expires.",
        did = session.operator_did,
        path = path.display(),
        pds = session.pds_url,
    )
}
