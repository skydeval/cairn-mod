//! Lexicon-shape tests for `lexicons/tools/cairn/public/*.json`
//! (#54). Mirrors the per-file checks in `tests/lexicons.rs` but
//! scoped to the public namespace, with one namespace-crossing
//! addition: cross-references like
//! `tools.cairn.admin.defs#subjectStrikeState` (used by
//! `getMyStrikeState`) must resolve against the combined admin +
//! public def set.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

const ADMIN_DIR: &str = "lexicons/tools/cairn/admin";
const PUBLIC_DIR: &str = "lexicons/tools/cairn/public";

#[derive(Deserialize)]
struct LexiconDoc {
    lexicon: i32,
    id: String,
    defs: serde_json::Map<String, Value>,
}

fn json_files_in(dir: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("open dir {dir}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    out.sort();
    out
}

fn parse(path: &PathBuf) -> (String, LexiconDoc, Value) {
    let raw = fs::read_to_string(path).expect("read");
    let doc: LexiconDoc =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path:?}: parse LexiconDoc: {e}"));
    let value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path:?}: parse Value: {e}"));
    (raw, doc, value)
}

#[test]
fn public_lexicons_parse_with_required_top_level_fields() {
    let files = json_files_in(PUBLIC_DIR);
    assert!(!files.is_empty(), "no public lexicons found");
    for path in &files {
        let (_, doc, _) = parse(path);
        assert_eq!(doc.lexicon, 1, "{path:?}: lexicon version must be 1");
        assert!(!doc.id.is_empty(), "{path:?}: id empty");
        assert!(!doc.defs.is_empty(), "{path:?}: defs empty");
    }
}

#[test]
fn public_lexicon_ids_match_file_paths() {
    for path in &json_files_in(PUBLIC_DIR) {
        let (_, doc, _) = parse(path);
        let stem = path.file_stem().and_then(|s| s.to_str()).expect("stem");
        let expected = format!("tools.cairn.public.{stem}");
        assert_eq!(doc.id, expected, "{path:?}: id vs path");
    }
}

#[test]
fn public_lexicons_have_query_shape() {
    // v1.4 ships zero public procedures; every public lexicon is a
    // query. If a future endpoint adds a procedure, this test
    // becomes more like the admin version (per-stem set).
    for path in &json_files_in(PUBLIC_DIR) {
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "defs" {
            continue;
        }
        let (_, _, v) = parse(path);
        let main = &v["defs"]["main"];
        assert_eq!(
            main["type"].as_str().unwrap_or(""),
            "query",
            "{stem}: every public endpoint in v1.4 must be a query"
        );
        assert!(
            main["parameters"].is_object(),
            "{stem}: query missing `parameters` object"
        );
        assert!(
            main.get("input").is_none(),
            "{stem}: query must not have `input`"
        );
    }
}

#[test]
fn public_lexicons_have_descriptions() {
    for path in &json_files_in(PUBLIC_DIR) {
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "defs" {
            continue;
        }
        let (_, _, v) = parse(path);
        let desc = v["defs"]["main"]["description"].as_str().unwrap_or("");
        assert!(!desc.is_empty(), "{path:?}: `defs.main.description` empty");
    }
}

#[test]
fn public_internal_refs_resolve_against_combined_namespace() {
    // Build the known def set from BOTH admin and public dirs so a
    // public-side ref to admin's `defs#subjectStrikeState` resolves.
    // External refs (com.atproto.* / app.bsky.*) are skipped in
    // walk_refs.
    let mut known: HashSet<String> = HashSet::new();
    for dir in [ADMIN_DIR, PUBLIC_DIR] {
        for path in json_files_in(dir) {
            let (_, _, v) = parse(&path);
            let id = v["id"].as_str().unwrap().to_string();
            if let Some(defs) = v["defs"].as_object() {
                for key in defs.keys() {
                    known.insert(format!("{id}#{key}"));
                }
                if defs.contains_key("main") {
                    known.insert(id);
                }
            }
        }
    }

    for path in &json_files_in(PUBLIC_DIR) {
        let (_, _, v) = parse(path);
        let self_id = v["id"].as_str().unwrap().to_string();
        walk_refs(&v, &self_id, &known, path);
    }
}

fn walk_refs(v: &Value, self_id: &str, known: &HashSet<String>, path: &PathBuf) {
    match v {
        Value::Object(map) => {
            if map.get("type").and_then(|t| t.as_str()) == Some("ref")
                && let Some(r) = map.get("ref").and_then(|r| r.as_str())
            {
                let resolved = if let Some(local) = r.strip_prefix('#') {
                    format!("{self_id}#{local}")
                } else {
                    r.to_string()
                };
                if resolved.starts_with("tools.cairn.") {
                    assert!(
                        known.contains(&resolved),
                        "{path:?}: unresolved ref {resolved} — \
                         add the def to admin/public defs.json or fix the ref"
                    );
                }
            }
            for v in map.values() {
                walk_refs(v, self_id, known, path);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                walk_refs(v, self_id, known, path);
            }
        }
        _ => {}
    }
}

#[test]
fn public_lexicon_format_drift() {
    // Same canonical-format check as admin's. Catches indent /
    // trailing-newline drift across hand edits.
    for path in &json_files_in(PUBLIC_DIR) {
        let raw = fs::read_to_string(path).expect("read");
        let value: Value = serde_json::from_str(&raw).expect("parse");
        let mut canonical = serde_json::to_string_pretty(&value).expect("reserialize");
        canonical.push('\n');
        assert_eq!(
            raw, canonical,
            "{path:?}: format drift — re-save with `serde_json::to_string_pretty` + trailing newline"
        );
    }
}

#[test]
fn public_expected_endpoint_files_present() {
    let expected: HashSet<&str> = HashSet::from(["getMyStrikeState"]);
    let present: HashSet<String> = json_files_in(PUBLIC_DIR)
        .iter()
        .map(|p| p.file_stem().unwrap().to_str().unwrap().to_string())
        .collect();
    for name in &expected {
        assert!(
            present.contains(*name),
            "missing public lexicon: {name}.json"
        );
    }
    for name in &present {
        assert!(
            expected.contains(name.as_str()),
            "unexpected public lexicon: {name}.json — add to expected set"
        );
    }
}

#[test]
fn public_declared_error_names_are_from_known_set() {
    // Public endpoints share the admin error vocabulary for any
    // names that overlap. v1.4 has only SubjectNotFound here.
    let allowed: HashSet<&str> = HashSet::from([
        "SubjectNotFound",
        // (other public-only error names land here as endpoints grow)
    ]);
    for path in &json_files_in(PUBLIC_DIR) {
        let (_, _, v) = parse(path);
        if let Some(errors) = v["defs"]["main"]["errors"].as_array() {
            for err in errors {
                let name = err["name"].as_str().unwrap_or("");
                assert!(
                    allowed.contains(name),
                    "{path:?}: undeclared error `{name}`"
                );
            }
        }
    }
}
