//! NSID allowlist for the inbound XRPC gateway (#92, v1.7).
//!
//! Per §A7, the set of inbound NSIDs cairn-mod accepts is a
//! **hard-coded Rust enum baked into the binary, not config-
//! extensible**. Operators cannot widen the surface via TOML.
//! Defense-in-depth: bsky-PDS does not validate NSIDs before
//! forwarding (per bsky findings §5.3-5.4), so cairn-mod is the
//! entire validation layer for proxied / forwarded calls. Keeping
//! the allowlist in code (rather than config) means an operator
//! misconfiguration cannot accidentally widen the surface.
//!
//! New NSIDs require a code change + recompile + redeploy. This
//! is the right tradeoff for v1.7's tight surface (four
//! endpoints); reconsider for v1.10+ when the surface grows
//! toward full Ozone parity.
//!
//! # Case sensitivity
//!
//! NSIDs are case-sensitive per the ATProto spec. Both
//! [`Nsid::from_path_segment`] and the router's `Router::route`
//! match case-sensitively (the latter is axum 0.8's default).
//! `tools.ozone.moderation.EmitEvent` (capital E) does NOT match
//! [`Nsid::ToolsOzoneModerationEmitEvent`] — it falls through to
//! the unknown-NSID handler and returns 501. Tested.

use axum::http::{Method, Uri};

/// The allowlisted NSIDs cairn-mod's `xrpc_gateway` accepts inbound.
///
/// v1.7 ships four endpoints — two POST mutations and two GET
/// reads — covering the proxied moderation surface (per §A6). The
/// per-NSID handlers in #95-#98 fill in real bodies; #92 (this
/// issue) lands the named-but-unimplemented stubs that return 501
/// with NSID-specific envelope wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nsid {
    /// `com.atproto.moderation.createReport` — PDS-forwarded user
    /// reports. Auth: PDS-signed service-auth JWT (the PDS attests
    /// to who `reportedBy` is). Body lands in #96.
    ComAtprotoModerationCreateReport,

    /// `tools.ozone.moderation.emitEvent` — User-originated
    /// proxied mutations. Auth: user-signed service-auth JWT (the
    /// user is the issuer). Body lands in #95.
    ToolsOzoneModerationEmitEvent,

    /// `tools.ozone.moderation.queryStatuses` — Read-only state
    /// queries. Auth: user-signed service-auth JWT. Body lands in
    /// #97.
    ToolsOzoneModerationQueryStatuses,

    /// `tools.ozone.moderation.queryEvents` — Read-only audit-log
    /// queries. Auth: user-signed service-auth JWT. Body lands in
    /// #98.
    ToolsOzoneModerationQueryEvents,
}

impl Nsid {
    /// Map a URL path segment to an [`Nsid`] variant. `None` for
    /// any NSID not on the v1.7 allowlist (the caller responds
    /// with the standard `MethodNotImplemented` 501 envelope per
    /// the [`crate::xrpc_gateway::router`]).
    ///
    /// Case-sensitive. `tools.ozone.moderation.EmitEvent` (capital
    /// E) returns `None` — NSIDs are case-sensitive per the
    /// ATProto spec.
    pub fn from_path_segment(s: &str) -> Option<Self> {
        match s {
            "com.atproto.moderation.createReport" => Some(Self::ComAtprotoModerationCreateReport),
            "tools.ozone.moderation.emitEvent" => Some(Self::ToolsOzoneModerationEmitEvent),
            "tools.ozone.moderation.queryStatuses" => Some(Self::ToolsOzoneModerationQueryStatuses),
            "tools.ozone.moderation.queryEvents" => Some(Self::ToolsOzoneModerationQueryEvents),
            _ => None,
        }
    }

    /// Inverse of [`Self::from_path_segment`]. Used for log lines
    /// and 501 / 405 envelope construction.
    pub fn as_path_segment(self) -> &'static str {
        match self {
            Self::ComAtprotoModerationCreateReport => "com.atproto.moderation.createReport",
            Self::ToolsOzoneModerationEmitEvent => "tools.ozone.moderation.emitEvent",
            Self::ToolsOzoneModerationQueryStatuses => "tools.ozone.moderation.queryStatuses",
            Self::ToolsOzoneModerationQueryEvents => "tools.ozone.moderation.queryEvents",
        }
    }

    /// HTTP method this NSID accepts. v1.7's two mutating NSIDs
    /// are POST; the two read NSIDs are GET, matching bsky-PDS's
    /// shapes per findings §6.3. Used by the router's per-NSID
    /// MethodRouter to return 405 (with the XRPC-shape envelope)
    /// for method mismatches.
    pub fn http_method(self) -> Method {
        match self {
            Self::ComAtprotoModerationCreateReport | Self::ToolsOzoneModerationEmitEvent => {
                Method::POST
            }
            Self::ToolsOzoneModerationQueryStatuses | Self::ToolsOzoneModerationQueryEvents => {
                Method::GET
            }
        }
    }
}

/// Extract the v1.7-allowlisted [`Nsid`] from a request URI's path.
///
/// Returns `Some(Nsid)` when the path matches `/xrpc/<allowlisted-nsid>`
/// exactly (case-sensitive); returns `None` when the path doesn't
/// have the `/xrpc/` prefix or the segment after isn't on the
/// allowlist.
///
/// Used by both the auth middleware (#93) and the router's
/// fallback handler (#92) to keep path-extraction logic
/// consistent. Lifting the logic into a single helper means the
/// two callers can't drift on edge cases (trailing slashes,
/// percent-encoding, etc.) — they share the function and they
/// share the test coverage.
pub fn extract_nsid_from_request_uri(uri: &Uri) -> Option<Nsid> {
    uri.path()
        .strip_prefix("/xrpc/")
        .and_then(Nsid::from_path_segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant in one place — the round-trip test iterates
    /// here so a future variant addition forces test coverage.
    fn all_variants() -> [Nsid; 4] {
        [
            Nsid::ComAtprotoModerationCreateReport,
            Nsid::ToolsOzoneModerationEmitEvent,
            Nsid::ToolsOzoneModerationQueryStatuses,
            Nsid::ToolsOzoneModerationQueryEvents,
        ]
    }

    #[test]
    fn from_path_segment_recognizes_all_v1_7_nsids() {
        assert_eq!(
            Nsid::from_path_segment("com.atproto.moderation.createReport"),
            Some(Nsid::ComAtprotoModerationCreateReport)
        );
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.emitEvent"),
            Some(Nsid::ToolsOzoneModerationEmitEvent)
        );
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.queryStatuses"),
            Some(Nsid::ToolsOzoneModerationQueryStatuses)
        );
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.queryEvents"),
            Some(Nsid::ToolsOzoneModerationQueryEvents)
        );
    }

    #[test]
    fn from_path_segment_returns_none_for_unallowlisted_nsids() {
        // Plausible-but-unsupported NSIDs (Ozone has many more
        // than v1.7's four; cairn-mod's surface is a deliberate
        // subset per §A6).
        for s in [
            "tools.ozone.moderation.somethingElse",
            "tools.ozone.moderation.emitEventV2",
            "com.atproto.moderation.deleteReport",
            "com.atproto.server.createSession",
        ] {
            assert_eq!(Nsid::from_path_segment(s), None, "{s}");
        }
    }

    #[test]
    fn from_path_segment_returns_none_for_garbage_inputs() {
        for s in ["", " ", "/", "not-an-nsid", "tools.ozone", "."] {
            assert_eq!(Nsid::from_path_segment(s), None, "{s:?}");
        }
    }

    #[test]
    fn from_path_segment_is_case_sensitive() {
        // ATProto NSIDs are case-sensitive. The allowlist match
        // must NOT silently accept different-case inputs;
        // capital-E `EmitEvent` is a different NSID from
        // `emitEvent` and would route to a 501-via-fallback.
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.EmitEvent"),
            None
        );
        assert_eq!(
            Nsid::from_path_segment("Com.Atproto.Moderation.CreateReport"),
            None
        );
        assert_eq!(
            Nsid::from_path_segment("TOOLS.OZONE.MODERATION.EMITEVENT"),
            None
        );
    }

    #[test]
    fn as_path_segment_round_trips_with_from_path_segment() {
        for n in all_variants() {
            assert_eq!(
                Nsid::from_path_segment(n.as_path_segment()),
                Some(n),
                "round-trip failed for {n:?}"
            );
        }
    }

    #[test]
    fn extract_from_uri_recognizes_allowlisted_paths() {
        let uri: Uri = "/xrpc/tools.ozone.moderation.emitEvent".parse().unwrap();
        assert_eq!(
            extract_nsid_from_request_uri(&uri),
            Some(Nsid::ToolsOzoneModerationEmitEvent)
        );
    }

    #[test]
    fn extract_from_uri_returns_none_for_non_xrpc_path() {
        let uri: Uri = "/health".parse().unwrap();
        assert_eq!(extract_nsid_from_request_uri(&uri), None);
    }

    #[test]
    fn extract_from_uri_returns_none_for_unknown_nsid_under_xrpc() {
        let uri: Uri = "/xrpc/com.atproto.moderation.deleteReport".parse().unwrap();
        assert_eq!(extract_nsid_from_request_uri(&uri), None);
    }

    #[test]
    fn extract_from_uri_strips_query_string_implicitly_via_path() {
        // `Uri::path()` returns just the path component without
        // query string. Pinning that here so a future caller
        // doesn't accidentally pass `uri.to_string()` (which
        // would include the query) into the helper.
        let uri: Uri = "/xrpc/tools.ozone.moderation.queryStatuses?subject=did:plc:x"
            .parse()
            .unwrap();
        assert_eq!(
            extract_nsid_from_request_uri(&uri),
            Some(Nsid::ToolsOzoneModerationQueryStatuses)
        );
    }

    #[test]
    fn http_method_matches_v1_7_surface() {
        // Pin per-NSID method per §A6's wire shapes: createReport
        // and emitEvent are mutating (POST); queryStatuses /
        // queryEvents are reads (GET). #92's router uses these to
        // produce 405 for method mismatches.
        assert_eq!(
            Nsid::ComAtprotoModerationCreateReport.http_method(),
            Method::POST
        );
        assert_eq!(
            Nsid::ToolsOzoneModerationEmitEvent.http_method(),
            Method::POST
        );
        assert_eq!(
            Nsid::ToolsOzoneModerationQueryStatuses.http_method(),
            Method::GET
        );
        assert_eq!(
            Nsid::ToolsOzoneModerationQueryEvents.http_method(),
            Method::GET
        );
    }
}
