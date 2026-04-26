# Cairn lexicons

Custom XRPC lexicons under the `tools.cairn.admin.*` namespace. These
definitions are the wire contract for Cairn's moderator-facing admin
endpoints; clients (CLI, SDKs, other servers) rely on the shapes here
being stable.

## Directory convention

Lexicons live at `lexicons/<nsid-with-slashes>.json`, mirroring ATProto
convention. An NSID like `tools.cairn.admin.applyLabel` is stored at
`lexicons/tools/cairn/admin/applyLabel.json`. The `id` field inside the
JSON file must match this path exactly — the test suite asserts this.

## v1 endpoints

| NSID                                       | Kind      | Role      | Purpose                                    |
|--------------------------------------------|-----------|-----------|--------------------------------------------|
| `tools.cairn.admin.applyLabel`             | procedure | mod/admin | Apply a label to a subject.                |
| `tools.cairn.admin.negateLabel`            | procedure | mod/admin | Withdraw a previously-applied label.       |
| `tools.cairn.admin.listLabels`             | query     | mod/admin | Admin label listing (sees negated/expired).|
| `tools.cairn.admin.listReports`            | query     | mod/admin | Paginated report listing.                  |
| `tools.cairn.admin.getReport`              | query     | mod/admin | Full report body (reason text included).   |
| `tools.cairn.admin.resolveReport`          | procedure | mod/admin | Resolve a report, optionally apply label.  |
| `tools.cairn.admin.flagReporter`           | procedure | mod/admin | Flag/unflag a reporter DID.                |
| `tools.cairn.admin.listAuditLog`           | query     | admin     | Audit log inspection.                      |
| `tools.cairn.admin.getAuditLog`            | query     | admin     | Single audit log entry by id.              |
| `tools.cairn.admin.getTrustChain`          | query     | admin     | Trust-chain transparency surface.          |
| `tools.cairn.admin.retentionSweep`         | procedure | admin     | One-shot retention sweep of expired labels.|
| `tools.cairn.admin.defs`                   | —         | —         | Shared types (`#reportView`, `#auditEntry`, `#signingKeyEntry`, `#maintainerEntry`, `#serviceRecordSummary`, `#instanceInfo`). |

Role enforcement is in the handler (#14–17), not in the lexicon.

## Query vs procedure

- **Procedure** (`type: "procedure"`): JSON body input (`input: { encoding, schema }`).
  Used for state-changing operations.
- **Query** (`type: "query"`): query-string parameters (`parameters: { type: "params", properties }`).
  Used for reads.

The lexicon test asserts each endpoint uses the kind §F12 prescribes.

## Declared error names

Per §F12, **every custom error emitted by a handler must be declared in
the corresponding lexicon's `errors` array**. Standard XRPC errors
(`AuthenticationRequired`, `Forbidden`, `InvalidRequest`, `NotFound`,
`RateLimitExceeded`, `InternalServerError`) are NOT re-declared — they
are implicit to all XRPC endpoints.

Currently declared custom error names:

- `LabelNotFound` — no currently-applied label for the target tuple
  (`negateLabel`).
- `ReportNotFound` — report id does not exist (`getReport`,
  `resolveReport`).
- `AuditEntryNotFound` — audit log id does not exist (`getAuditLog`).
- `InvalidLabelValue` — label value is not in the operator's declared
  set (`applyLabel`, `resolveReport`).

`ModeratorNotFound` is mentioned in §F12 as a reserved name but no v1
endpoint emits it; it is not declared on any method today. Add to an
endpoint's `errors` array only when that endpoint genuinely emits it.

## `resolveReport` atomicity requirement

`resolveReport` optionally carries an `applyLabel` sub-object. When
supplied, the implementation (landing in #14/#15) **MUST** commit the
label INSERT, the report status UPDATE, and the audit entry in a single
SQLite transaction. A client that receives a success response must be
able to trust that either (a) all three changes landed, or (b) none did.
Partial-failure states are not allowed.

## Adding a new lexicon

1. Pick an NSID under `tools.cairn.*`. Sub-namespaces (`admin`,
   `public`, etc.) are per the design doc — don't invent new ones
   without updating §8.
2. Create the file at the path matching the NSID.
3. Set `lexicon: 1`, `id: "tools.cairn.admin.<name>"`, and one or more
   defs. The primary method goes under `defs.main`.
4. Declare every custom error name the handler may emit in
   `defs.main.errors`. Do NOT declare standard XRPC errors.
5. Add the NSID to the table above and update the test expectations in
   `tests/lexicons.rs` (`PROCEDURES` / `QUERIES` sets).
6. Ensure the file matches the canonical serialization: 2-space indent,
   trailing newline, keys in insertion order. The format-drift test
   catches deviations.

## Versioning

**Never break, only add.** Adding optional fields is backward-compatible;
removing or retyping fields is not. Semantic changes require a new NSID
(e.g., `tools.cairn.admin.v2.applyLabel`). Existing clients continue
working against the v1 NSID.

## Serving (out of scope for #12)

These files ship as embedded bytes in the Cairn binary and are served
at `https://<host>/.well-known/lexicons/tools/cairn/admin/{name}.json`
per §F12. Bundling + serving is #18. **This is a Cairn convention, not
a finalized ATProto spec** — lexicon resolution is under active
[RFC](https://github.com/bluesky-social/atproto/issues/3074). The path
is chosen for forward-compatibility with well-known-based proposals.
