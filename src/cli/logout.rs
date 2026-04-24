//! `cairn logout` — revoke at PDS, then remove local file.
//!
//! Per Q3 in the criteria confirmation: if PDS `deleteSession`
//! fails (network down, 5xx, etc.) we STILL remove the local
//! session file. The user's intent is "sever access"; refusing
//! local cleanup when the PDS is unreachable leaves them with both
//! a live PDS session AND a locally-usable session file — strictly
//! worse than just a live PDS session. PDS failure is logged at
//! warn level so operators can follow up.

use std::path::Path;

use super::error::CliError;
use super::pds::{PdsClient, PdsError};
use super::session::{self, SessionFile};

/// Outcome of a logout call. Tests assert on this to distinguish
/// "PDS revoked + local cleaned" from "PDS failed, local cleaned
/// anyway" from "no session at all."
#[derive(Debug, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// No session file on disk — `cairn logout` is a no-op.
    NotLoggedIn,
    /// Happy path: PDS accepted `deleteSession` AND the local
    /// session file was removed.
    RevokedAndRemoved,
    /// Local session file was removed, but the PDS
    /// `deleteSession` call failed (network, 5xx, stale token).
    /// Per Q3 decision, local cleanup proceeds regardless; the
    /// PDS-side session stays live until it expires naturally.
    RemovedLocalOnlyPdsFailed,
}

/// Revoke at PDS (best-effort) + remove local session file.
/// Returns the outcome so `main.rs` can choose the user-facing
/// message without string-matching.
pub async fn logout(session_path: &Path) -> Result<LogoutOutcome, CliError> {
    let session = match SessionFile::load(session_path)? {
        Some(s) => s,
        None => return Ok(LogoutOutcome::NotLoggedIn),
    };

    let pds_ok = match PdsClient::new(&session.pds_url) {
        Ok(client) => try_revoke(&client, &session).await,
        Err(_) => false,
    };

    // Local cleanup regardless of PDS outcome. `session::delete`
    // is idempotent — an absent file on racy cleanup is fine.
    session::delete(session_path)?;

    if pds_ok {
        Ok(LogoutOutcome::RevokedAndRemoved)
    } else {
        Ok(LogoutOutcome::RemovedLocalOnlyPdsFailed)
    }
}

async fn try_revoke(pds: &PdsClient, session: &SessionFile) -> bool {
    match pds.delete_session(&session.refresh_jwt).await {
        Ok(()) => true,
        Err(e) => {
            emit_pds_warning(&session.pds_url, &e);
            false
        }
    }
}

fn emit_pds_warning(pds_url: &str, err: &PdsError) {
    tracing::warn!(
        pds = %pds_url,
        error = %err,
        "PDS deleteSession failed; local session file will be removed regardless"
    );
}
