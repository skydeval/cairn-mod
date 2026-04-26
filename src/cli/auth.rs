//! Shared CLI auth helpers (#28).
//!
//! Centralizes the `acquire_service_auth` orchestration — get a
//! Cairn-bound service-auth token from the operator's PDS, with
//! one-shot refresh-and-retry on a 401 from `getServiceAuth`. The
//! refresh path also persists the rotated tokens back to the
//! session file on disk so the next CLI invocation starts with
//! current credentials (§5.3).
//!
//! Callers (cli/audit.rs, cli/report.rs, cli/retention.rs,
//! cli/trust_chain.rs) used to carry byte-identical local copies of
//! this function. Factoring threshold per session N3 was 6+
//! identical copies; the trust-chain CLI (#37) brought the count
//! to 8 callsites across 4 modules and tripped the rule.

use std::path::Path;

use super::error::CliError;
use super::pds::{PdsClient, PdsError};
use super::session::SessionFile;

/// Acquire a service-auth token bound to the given lexicon method,
/// refreshing the moderator session file in-place on a 401.
///
/// Behavior contract preserved from the pre-factor copies:
///
/// 1. Call `getServiceAuth(access_jwt, cairn_service_did, lxm)`.
/// 2. On `Unauthorized { context: "getServiceAuth" }`, refresh
///    the session via `refreshSession(refresh_jwt)`, write the
///    rotated tokens back to `session_path` (mode 0600 owner
///    invariants per §5.3), then retry `getServiceAuth` once.
/// 3. Any other PDS error propagates as `CliError::Pds`.
///
/// One-shot retry — a second 401 is propagated, not chained into
/// another refresh.
pub(super) async fn acquire_service_auth(
    pds: &PdsClient,
    session: &mut SessionFile,
    session_path: &Path,
    lxm: &str,
) -> Result<String, CliError> {
    match pds
        .get_service_auth(&session.access_jwt, &session.cairn_service_did, lxm)
        .await
    {
        Ok(t) => Ok(t),
        Err(PdsError::Unauthorized {
            context: "getServiceAuth",
            ..
        }) => {
            let refreshed = pds.refresh_session(&session.refresh_jwt).await?;
            session.access_jwt = refreshed.access_jwt;
            session.refresh_jwt = refreshed.refresh_jwt;
            session.save(session_path)?;
            Ok(pds
                .get_service_auth(&session.access_jwt, &session.cairn_service_did, lxm)
                .await?)
        }
        Err(other) => Err(other.into()),
    }
}
