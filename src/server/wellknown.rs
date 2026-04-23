//! Embedded lexicon bundle + `.well-known/lexicons/…` endpoint (§8 + §F13).
//!
//! Cairn's custom lexicons live in the repo at
//! `lexicons/tools/cairn/admin/*.json`. They are bundled into the
//! binary via [`include_dir::include_dir!`] so a cargo-installed
//! `cairn` carries authoritative schema even when offline.
//!
//! **Two canonical serving locations.** §8 pins
//! `https://cairn.tools/.well-known/lexicons/tools/cairn/admin/{name}.json`
//! as the network-wide canonical URL (a GitHub Pages site tracked
//! separately under the #24 "cairn.tools landing" work). Each running
//! Cairn instance **also** serves the same bytes from its own
//! `/.well-known/lexicons/…` so operators can self-host, and so
//! consumers that cannot reach `cairn.tools` have a fallback. Both
//! serving locations are fed by the same JSON files in this repo.
//!
//! **RFC uncertainty.** Lexicon resolution is under active ATProto
//! RFC ([bluesky-social/atproto#3074]). The `.well-known/lexicons/`
//! path is Cairn's forward-compatible convention, not a finalized
//! spec. If the RFC lands on a different path, §F12 documents the
//! migration plan — this module is the pivot point.
//!
//! **Public by design.** Schemas are public, unauthenticated, and
//! CORS-open (no `Origin` restriction). A misconfigured CORS layer
//! would be the bug; a browser page fetching the schema for a
//! lexicon viewer is the intended use case.
//!
//! [bluesky-social/atproto#3074]: https://github.com/bluesky-social/atproto/issues/3074

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use include_dir::{Dir, include_dir};
use serde_json::json;

/// Compile-time snapshot of `lexicons/tools/cairn/admin/`. Adding a
/// new `.json` file to that directory is picked up on the next
/// build; forgetting to register it is impossible — the compiler is
/// the forcing function, not a test.
pub const LEXICON_BUNDLE: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/lexicons/tools/cairn/admin");

/// The NSID prefix every bundled lexicon must share. Checked at
/// build time (via the unit test below) and at runtime lookup.
pub const LEXICON_NSID_PREFIX: &str = "tools.cairn.admin";

/// Expected bundle contents — the 9 files §8 enumerates. The unit
/// tests below assert set-equality so an accidental file addition or
/// removal surfaces immediately.
pub const EXPECTED_LEXICON_STEMS: &[&str] = &[
    "applyLabel",
    "defs",
    "flagReporter",
    "getReport",
    "listAuditLog",
    "listLabels",
    "listReports",
    "negateLabel",
    "resolveReport",
];

/// Build a router exposing the `.well-known/lexicons/…` read endpoint.
/// The router carries no state — all lookups hit [`LEXICON_BUNDLE`].
///
/// Compose via [`axum::Router::merge`] alongside
/// [`crate::server::admin_router`] and the other per-feature
/// routers when the `cairn serve` binary lands.
pub fn wellknown_router() -> Router {
    Router::new().route(
        "/.well-known/lexicons/tools/cairn/admin/{name}",
        get(serve_lexicon),
    )
}

/// Return the embedded JSON for `tools.cairn.admin.<stem>` where
/// `{name}` is `<stem>.json`. Anything else is 404 — we do not
/// serve extension-less aliases or alternate NSID trees.
async fn serve_lexicon(Path(name): Path<String>) -> Response {
    let Some(stem) = name.strip_suffix(".json") else {
        return not_found();
    };
    // The route pattern already pins `tools/cairn/admin/` as the
    // path prefix, so the lookup file is just `{stem}.json`.
    let file_name = format!("{stem}.json");
    let Some(file) = LEXICON_BUNDLE.get_file(&file_name) else {
        return not_found();
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        file.contents().to_vec(),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "NotFound",
            "message": "lexicon not found",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;

    /// Every bundled filename strips to a known stem + `.json` —
    /// no stray files, no missing ones. This is the "someone
    /// accidentally dropped a draft.json into lexicons/" guard.
    #[test]
    fn bundle_contains_exactly_the_expected_set() {
        let have: BTreeSet<String> = LEXICON_BUNDLE
            .files()
            .map(|f| {
                f.path()
                    .file_name()
                    .expect("file in bundle")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let want: BTreeSet<String> = EXPECTED_LEXICON_STEMS
            .iter()
            .map(|s| format!("{s}.json"))
            .collect();
        assert_eq!(
            have, want,
            "embedded lexicon set drifted from EXPECTED_LEXICON_STEMS"
        );
    }

    /// Every file parses as JSON. A malformed lexicon in the repo
    /// would otherwise serve as-is and fail consumers at fetch
    /// time.
    #[test]
    fn every_bundled_file_parses_as_json() {
        for file in LEXICON_BUNDLE.files() {
            let contents = file.contents();
            serde_json::from_slice::<Value>(contents).unwrap_or_else(|e| {
                panic!("file {} does not parse as JSON: {e}", file.path().display())
            });
        }
    }

    /// The top-level `id` field must match
    /// `tools.cairn.admin.<stem-of-filename>`. Catches an
    /// accidentally-copy-pasted lexicon that kept the wrong `id`.
    #[test]
    fn every_lexicon_id_matches_its_filename_stem() {
        for file in LEXICON_BUNDLE.files() {
            let stem = file
                .path()
                .file_stem()
                .expect("file has stem")
                .to_string_lossy()
                .into_owned();
            let doc: Value = serde_json::from_slice(file.contents()).unwrap();
            let id = doc
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("file {stem}.json missing top-level id"));
            let expected = format!("{LEXICON_NSID_PREFIX}.{stem}");
            assert_eq!(
                id, expected,
                "lexicon file {stem}.json has id {id:?}; expected {expected:?}"
            );
        }
    }
}
