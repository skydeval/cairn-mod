//! Validates the JSON files under `lexicons/tools/cairn/admin/` meet
//! §8 / §F12 invariants:
//!
//! - Each file parses as well-formed JSON.
//! - `lexicon == 1` and `id` matches the file path.
//! - Procedures and queries use the shape §F12 prescribes
//!   (`input` vs `parameters`).
//! - Every cross-file `$ref` into `tools.cairn.admin.*` resolves to a
//!   def that actually exists.
//! - Every declared error name is drawn from the set the handlers may
//!   emit (§F12 "custom errors used").
//! - Each file is byte-identical to its canonical 2-space-indented
//!   serialization. Catches indent/trailing-whitespace drift that
//!   otherwise accumulates across hand edits.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

const LEX_DIR: &str = "lexicons/tools/cairn/admin";

#[derive(Deserialize)]
struct LexiconDoc {
    lexicon: i32,
    id: String,
    defs: serde_json::Map<String, Value>,
}

fn all_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(LEX_DIR)
        .expect("open lexicons dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no lexicon files found in {LEX_DIR}");
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
fn every_lexicon_parses_with_required_top_level_fields() {
    for path in all_files() {
        let (_, doc, _) = parse(&path);
        assert_eq!(doc.lexicon, 1, "{path:?}: lexicon version must be 1");
        assert!(!doc.id.is_empty(), "{path:?}: id empty");
        assert!(!doc.defs.is_empty(), "{path:?}: defs empty");
    }
}

#[test]
fn lexicon_ids_match_file_paths() {
    // File at lexicons/tools/cairn/admin/applyLabel.json must declare
    // id: "tools.cairn.admin.applyLabel". Prevents drift between the
    // filesystem layout and NSIDs embedded in the file.
    for path in all_files() {
        let (_, doc, _) = parse(&path);
        let stem = path.file_stem().and_then(|s| s.to_str()).expect("stem");
        let expected = format!("tools.cairn.admin.{stem}");
        assert_eq!(doc.id, expected, "{path:?}: id vs path");
    }
}

#[test]
fn procedures_have_input_queries_have_parameters() {
    // §F12: procedures = JSON body, queries = query-string.
    let procedures: HashSet<&str> =
        HashSet::from(["applyLabel", "negateLabel", "resolveReport", "flagReporter"]);
    let queries: HashSet<&str> =
        HashSet::from(["listLabels", "listReports", "getReport", "listAuditLog"]);

    for path in all_files() {
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "defs" {
            continue; // shared definitions, no method shape to check
        }
        let (_, _, v) = parse(&path);
        let main = &v["defs"]["main"];
        let ty = main["type"].as_str().unwrap_or("");
        if procedures.contains(stem) {
            assert_eq!(ty, "procedure", "{stem}: expected procedure");
            assert!(
                main["input"].is_object(),
                "{stem}: procedure missing `input` object"
            );
            assert!(
                main.get("parameters").is_none(),
                "{stem}: procedure must not have `parameters`"
            );
        } else if queries.contains(stem) {
            assert_eq!(ty, "query", "{stem}: expected query");
            assert!(
                main["parameters"].is_object(),
                "{stem}: query missing `parameters` object"
            );
            assert!(
                main.get("input").is_none(),
                "{stem}: query must not have `input`"
            );
        } else {
            panic!("unknown endpoint: {stem}. Update the test's procedures/queries sets.");
        }
    }
}

#[test]
fn every_method_has_description() {
    for path in all_files() {
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "defs" {
            continue;
        }
        let (_, _, v) = parse(&path);
        let desc = v["defs"]["main"]["description"].as_str().unwrap_or("");
        assert!(
            !desc.is_empty(),
            "{path:?}: `defs.main.description` empty — describe what the endpoint does"
        );
    }
}

/// Collect every fully-qualified def (`nsid#name`) across all files,
/// plus each `id` itself (which is shorthand for the `main` def).
fn collect_known_defs() -> HashSet<String> {
    let mut known = HashSet::new();
    for path in all_files() {
        let (_, _, v) = parse(&path);
        let id = v["id"].as_str().unwrap().to_string();
        if let Some(defs) = v["defs"].as_object() {
            for key in defs.keys() {
                known.insert(format!("{id}#{key}"));
            }
            if defs.contains_key("main") {
                // Bare `nsid` (no fragment) is equivalent to `nsid#main`.
                known.insert(id);
            }
        }
    }
    known
}

fn walk_refs(v: &Value, self_id: &str, known: &HashSet<String>, path: &PathBuf) {
    match v {
        Value::Object(map) => {
            if map.get("type").and_then(|t| t.as_str()) == Some("ref") {
                if let Some(r) = map.get("ref").and_then(|r| r.as_str()) {
                    let resolved = if let Some(local) = r.strip_prefix('#') {
                        format!("{self_id}#{local}")
                    } else {
                        r.to_string()
                    };
                    // Only validate refs into our own namespace. Refs to
                    // Bluesky lexicons (`com.atproto.*`, `app.bsky.*`)
                    // are external and can't be checked from this
                    // repo's files alone.
                    if resolved.starts_with("tools.cairn.") {
                        assert!(
                            known.contains(&resolved),
                            "{path:?}: unresolved ref {resolved} — \
                             add the def to the appropriate file or fix the ref"
                        );
                    }
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
fn every_internal_ref_resolves() {
    let known = collect_known_defs();
    for path in all_files() {
        let (_, _, v) = parse(&path);
        let self_id = v["id"].as_str().unwrap().to_string();
        walk_refs(&v, &self_id, &known, &path);
    }
}

#[test]
fn declared_error_names_are_from_known_set() {
    // §F12 identifies the custom error names Cairn may emit. Any name
    // outside this set in an `errors` array is either a typo or an
    // undocumented error that needs to be added to the design doc and
    // the README first.
    let allowed: HashSet<&str> = HashSet::from([
        "LabelNotFound",
        "ReportNotFound",
        "InvalidLabelValue",
        // ModeratorNotFound is reserved but not currently emitted — if
        // an endpoint begins emitting it, add here + to lexicons/README.md.
    ]);
    for path in all_files() {
        let (_, _, v) = parse(&path);
        if let Some(errors) = v["defs"]["main"]["errors"].as_array() {
            for err in errors {
                let name = err["name"].as_str().unwrap_or("");
                assert!(
                    allowed.contains(name),
                    "{path:?}: undeclared error `{name}` — \
                     add to lexicons/README.md + `allowed` set in this test"
                );
            }
        }
    }
}

#[test]
fn format_drift_test_reserializes_byte_identical() {
    // Canonical form: serde_json::to_string_pretty (2-space indent,
    // keys in file order via the `preserve_order` feature), plus a
    // trailing newline. Catches tab/space mixing, missing trailing
    // newlines, and key-order churn from `jq -S` passes.
    for path in all_files() {
        let raw = fs::read_to_string(&path).expect("read");
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
fn expected_endpoint_files_all_present() {
    // Guards against an NSID being added to the handler code without
    // the lexicon file shipping, and vice versa.
    let expected: HashSet<&str> = HashSet::from([
        "defs",
        "applyLabel",
        "negateLabel",
        "listLabels",
        "listReports",
        "getReport",
        "resolveReport",
        "flagReporter",
        "listAuditLog",
    ]);
    let present: HashSet<String> = all_files()
        .iter()
        .map(|p| p.file_stem().unwrap().to_str().unwrap().to_string())
        .collect();
    for name in &expected {
        assert!(present.contains(*name), "missing lexicon: {name}.json");
    }
    for name in &present {
        assert!(
            expected.contains(name.as_str()),
            "unexpected lexicon file: {name}.json — add to this test's `expected` set + README"
        );
    }
}
