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
//! `Nsid::Ozone(OzoneModerationNsid::EmitEvent)` — it falls
//! through to the unknown-NSID handler and returns 501. Tested.

use axum::http::{Method, Uri};

/// The allowlisted NSIDs cairn-mod's `xrpc_gateway` accepts inbound.
///
/// v1.7 ships four endpoints — two POST mutations and two GET
/// reads — covering the proxied moderation surface (per §A6). The
/// per-NSID handlers in #95-#98 fill in real bodies; #92 lands the
/// named-but-unimplemented stubs that return 501 with
/// NSID-specific envelope wording.
///
/// **Dual-dialect layout (v1.8.1, §4.6).** The enum nests a
/// dialect discriminator so subsequent Workstream A releases can
/// slot `tools.aurora.*` NSIDs in as pure additions
/// ([`AuroraNsid`] is uninhabited at v1.8.1; v1.8.2 adds its
/// first variant). The refactor is structural only — the accepted
/// set is byte-identical to v1.7's four NSIDs, and
/// `com.atproto.moderation.createReport` stays a top-level
/// variant because it belongs to neither moderation dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nsid {
    /// `tools.ozone.moderation.*` dialect (the v1.7 surface).
    Ozone(OzoneModerationNsid),
    /// `tools.aurora.*` dialect — no variants at v1.8.1;
    /// populated from v1.8.2 as consumed capabilities land.
    Aurora(AuroraNsid),
    /// `com.atproto.moderation.createReport` — PDS-forwarded user
    /// reports. Auth: PDS-signed service-auth JWT (the PDS attests
    /// to who `reportedBy` is). Body landed in #96.
    CreateReport,
}

/// The `tools.ozone.moderation.*` dialect's allowlisted NSIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OzoneModerationNsid {
    /// `tools.ozone.moderation.emitEvent` — User-originated
    /// proxied mutations. Auth: user-signed service-auth JWT (the
    /// user is the issuer). Body landed in #95.
    EmitEvent,
    /// `tools.ozone.moderation.queryStatuses` — Read-only state
    /// queries. Auth: user-signed service-auth JWT. Body landed
    /// in #97.
    QueryStatuses,
    /// `tools.ozone.moderation.queryEvents` — Read-only audit-log
    /// queries. Auth: user-signed service-auth JWT. Body landed
    /// in #98.
    QueryEvents,
}

/// The `tools.aurora.*` dialect's NSIDs cairn-mod knows about.
///
/// First populated at v1.8.2 (§4.6). **Outbound reference only at
/// v1.8.2**: [`Nsid::from_path_segment`] deliberately does NOT
/// map these — the inbound gateway continues to accept exactly
/// the v1.7 set. cairn-mod's outbound Rust backend dispatches to
/// these NSIDs; inbound acceptance of the aurora dialect, if it
/// ever lands, is its own release decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuroraNsid {
    /// `tools.aurora.admin.emitEvent` — the unified
    /// moderation-action endpoint the v1.8.2 RustBackend
    /// dispatches takedowns/suspensions/restores/record
    /// takedowns to.
    AdminEmitEvent,
    /// `tools.aurora.moderator.queryEvents` — moderator
    /// event-stream read (v1.8.3).
    ModeratorQueryEvents,
    /// `tools.aurora.moderator.queryStatuses` — per-DID
    /// moderation-status read (v1.8.3).
    ModeratorQueryStatuses,
    /// `tools.aurora.moderator.getEvent` — single-event fetch
    /// (v1.8.4).
    ModeratorGetEvent,
    /// `tools.aurora.moderator.getSubjectContext` — subject
    /// contextual-metadata fetch (v1.8.4).
    ModeratorGetSubjectContext,
    /// `tools.aurora.moderator.getSubjectHistory` — per-DID
    /// action-history read (v1.8.4).
    ModeratorGetSubjectHistory,
    /// `tools.aurora.moderator.listAppeals` — appeal listing
    /// (v1.8.4).
    ModeratorListAppeals,
    /// `tools.aurora.moderator.getAppeal` — single-appeal fetch
    /// with lifecycle timeline (v1.8.4).
    ModeratorGetAppeal,
    /// `tools.aurora.admin.getAuditTrail` — hash-chained audit
    /// trail read (v1.8.6).
    AdminGetAuditTrail,
    /// `tools.aurora.admin.getAuditEntry` — single audit-chain
    /// entry fetch (v1.8.6).
    AdminGetAuditEntry,
}

impl AuroraNsid {
    /// The emitEvent NSID string — single-sourced here for the
    /// outbound dispatch path and log lines.
    pub const NSID_STR: &'static str = "tools.aurora.admin.emitEvent";

    /// NSID wire string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AdminEmitEvent => Self::NSID_STR,
            Self::ModeratorQueryEvents => "tools.aurora.moderator.queryEvents",
            Self::ModeratorQueryStatuses => "tools.aurora.moderator.queryStatuses",
            Self::ModeratorGetEvent => "tools.aurora.moderator.getEvent",
            Self::ModeratorGetSubjectContext => "tools.aurora.moderator.getSubjectContext",
            Self::ModeratorGetSubjectHistory => "tools.aurora.moderator.getSubjectHistory",
            Self::ModeratorListAppeals => "tools.aurora.moderator.listAppeals",
            Self::ModeratorGetAppeal => "tools.aurora.moderator.getAppeal",
            Self::AdminGetAuditTrail => "tools.aurora.admin.getAuditTrail",
            Self::AdminGetAuditEntry => "tools.aurora.admin.getAuditEntry",
        }
    }
}

impl Nsid {
    /// Map a URL path segment to an [`Nsid`] variant. `None` for
    /// any NSID not on the allowlist (the caller responds with
    /// the standard `MethodNotImplemented` 501 envelope per the
    /// [`crate::xrpc_gateway::router`]).
    ///
    /// Case-sensitive. `tools.ozone.moderation.EmitEvent` (capital
    /// E) returns `None` — NSIDs are case-sensitive per the
    /// ATProto spec.
    pub fn from_path_segment(s: &str) -> Option<Self> {
        match s {
            "com.atproto.moderation.createReport" => Some(Self::CreateReport),
            "tools.ozone.moderation.emitEvent" => Some(Self::Ozone(OzoneModerationNsid::EmitEvent)),
            "tools.ozone.moderation.queryStatuses" => {
                Some(Self::Ozone(OzoneModerationNsid::QueryStatuses))
            }
            "tools.ozone.moderation.queryEvents" => {
                Some(Self::Ozone(OzoneModerationNsid::QueryEvents))
            }
            _ => None,
        }
    }

    /// Inverse of [`Self::from_path_segment`]. Used for log lines
    /// and 501 / 405 envelope construction.
    pub fn as_path_segment(self) -> &'static str {
        match self {
            Self::CreateReport => "com.atproto.moderation.createReport",
            Self::Ozone(OzoneModerationNsid::EmitEvent) => "tools.ozone.moderation.emitEvent",
            Self::Ozone(OzoneModerationNsid::QueryStatuses) => {
                "tools.ozone.moderation.queryStatuses"
            }
            Self::Ozone(OzoneModerationNsid::QueryEvents) => "tools.ozone.moderation.queryEvents",
            Self::Aurora(a) => a.as_str(),
        }
    }

    /// HTTP method this NSID accepts. The two mutating NSIDs are
    /// POST; the two read NSIDs are GET, matching bsky-PDS's
    /// shapes per findings §6.3. Used by the router's per-NSID
    /// MethodRouter to return 405 (with the XRPC-shape envelope)
    /// for method mismatches.
    pub fn http_method(self) -> Method {
        match self {
            Self::CreateReport | Self::Ozone(OzoneModerationNsid::EmitEvent) => Method::POST,
            Self::Ozone(OzoneModerationNsid::QueryStatuses | OzoneModerationNsid::QueryEvents) => {
                Method::GET
            }
            // Outbound-referenced only (never produced by
            // from_path_segment); emitEvent is a mutation, the
            // moderator reads are GET.
            Self::Aurora(AuroraNsid::AdminEmitEvent) => Method::POST,
            Self::Aurora(
                AuroraNsid::ModeratorQueryEvents
                | AuroraNsid::ModeratorQueryStatuses
                | AuroraNsid::ModeratorGetEvent
                | AuroraNsid::ModeratorGetSubjectContext
                | AuroraNsid::ModeratorGetSubjectHistory
                | AuroraNsid::ModeratorListAppeals
                | AuroraNsid::ModeratorGetAppeal
                | AuroraNsid::AdminGetAuditTrail
                | AuroraNsid::AdminGetAuditEntry,
            ) => Method::GET,
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
            Nsid::CreateReport,
            Nsid::Ozone(OzoneModerationNsid::EmitEvent),
            Nsid::Ozone(OzoneModerationNsid::QueryStatuses),
            Nsid::Ozone(OzoneModerationNsid::QueryEvents),
        ]
    }

    /// v1.8.2: the aurora dialect gains its first NSID —
    /// **outbound reference only**. The inbound gateway must NOT
    /// recognize it: `from_path_segment` returns `None` for the
    /// emitEvent NSID while the variant's `as_str` /
    /// `as_path_segment` produce the wire string for outbound
    /// dispatch and log lines. Inbound acceptance of the aurora
    /// dialect is a deliberate future release decision, not a
    /// side effect of populating the enum.
    #[test]
    fn aurora_nsid_is_outbound_reference_only_at_v1_8_2() {
        assert_eq!(
            AuroraNsid::AdminEmitEvent.as_str(),
            "tools.aurora.admin.emitEvent"
        );
        assert_eq!(AuroraNsid::NSID_STR, "tools.aurora.admin.emitEvent");
        assert_eq!(
            Nsid::Aurora(AuroraNsid::AdminEmitEvent).as_path_segment(),
            "tools.aurora.admin.emitEvent"
        );
        assert_eq!(
            Nsid::Aurora(AuroraNsid::AdminEmitEvent).http_method(),
            Method::POST
        );
        // Inbound recognition deliberately absent.
        assert_eq!(
            Nsid::from_path_segment("tools.aurora.admin.emitEvent"),
            None
        );
        let uri: Uri = "/xrpc/tools.aurora.admin.emitEvent".parse().unwrap();
        assert_eq!(extract_nsid_from_request_uri(&uri), None);
    }

    /// v1.8.3/v1.8.4: the seven `tools.aurora.moderator.*` read
    /// variants — same outbound-reference-only posture as
    /// emitEvent. All GET; none inbound-recognized.
    #[test]
    fn aurora_moderator_read_nsids_are_outbound_get_only() {
        let variants = [
            (
                AuroraNsid::ModeratorQueryEvents,
                "tools.aurora.moderator.queryEvents",
            ),
            (
                AuroraNsid::ModeratorQueryStatuses,
                "tools.aurora.moderator.queryStatuses",
            ),
            (
                AuroraNsid::ModeratorGetEvent,
                "tools.aurora.moderator.getEvent",
            ),
            (
                AuroraNsid::ModeratorGetSubjectContext,
                "tools.aurora.moderator.getSubjectContext",
            ),
            (
                AuroraNsid::ModeratorGetSubjectHistory,
                "tools.aurora.moderator.getSubjectHistory",
            ),
            (
                AuroraNsid::ModeratorListAppeals,
                "tools.aurora.moderator.listAppeals",
            ),
            (
                AuroraNsid::ModeratorGetAppeal,
                "tools.aurora.moderator.getAppeal",
            ),
            (
                AuroraNsid::AdminGetAuditTrail,
                "tools.aurora.admin.getAuditTrail",
            ),
            (
                AuroraNsid::AdminGetAuditEntry,
                "tools.aurora.admin.getAuditEntry",
            ),
        ];
        for (variant, wire) in variants {
            assert_eq!(variant.as_str(), wire);
            assert_eq!(Nsid::Aurora(variant).as_path_segment(), wire);
            assert_eq!(Nsid::Aurora(variant).http_method(), Method::GET, "{wire}");
            // Inbound recognition deliberately absent.
            assert_eq!(Nsid::from_path_segment(wire), None, "{wire}");
            let uri: Uri = format!("/xrpc/{wire}").parse().unwrap();
            assert_eq!(extract_nsid_from_request_uri(&uri), None, "{wire}");
        }
    }

    #[test]
    fn from_path_segment_recognizes_all_v1_7_nsids() {
        assert_eq!(
            Nsid::from_path_segment("com.atproto.moderation.createReport"),
            Some(Nsid::CreateReport)
        );
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.emitEvent"),
            Some(Nsid::Ozone(OzoneModerationNsid::EmitEvent))
        );
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.queryStatuses"),
            Some(Nsid::Ozone(OzoneModerationNsid::QueryStatuses))
        );
        assert_eq!(
            Nsid::from_path_segment("tools.ozone.moderation.queryEvents"),
            Some(Nsid::Ozone(OzoneModerationNsid::QueryEvents))
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
            Some(Nsid::Ozone(OzoneModerationNsid::EmitEvent))
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
            Some(Nsid::Ozone(OzoneModerationNsid::QueryStatuses))
        );
    }

    #[test]
    fn http_method_matches_v1_7_surface() {
        // Pin per-NSID method per §A6's wire shapes: createReport
        // and emitEvent are mutating (POST); queryStatuses /
        // queryEvents are reads (GET). #92's router uses these to
        // produce 405 for method mismatches.
        assert_eq!(Nsid::CreateReport.http_method(), Method::POST);
        assert_eq!(
            Nsid::Ozone(OzoneModerationNsid::EmitEvent).http_method(),
            Method::POST
        );
        assert_eq!(
            Nsid::Ozone(OzoneModerationNsid::QueryStatuses).http_method(),
            Method::GET
        );
        assert_eq!(
            Nsid::Ozone(OzoneModerationNsid::QueryEvents).http_method(),
            Method::GET
        );
    }
}
