# Cairn — Design Doc

**Project:** `cairn`
**Tagline:** A lightweight, Rust-native ATProto labeler with a clean path from Skyware-scope to Ozone-scope.
**Domain:** cairn.tools
**NSID:** `tools.cairn.*`
**Language:** Rust
**Status:** Draft
**Methodology:** VDD/IAR
**Author:** Chrys

---

## 1. Problem

The ATProto labeler ecosystem has two existing options and a gap between them.

**Ozone** is Bluesky's official labeling service. It's TypeScript, ships with a full Next.js web UI, runs on PostgreSQL, and is designed for operators running moderation at network scale. It's powerful but heavy — installing it is non-trivial, and its feature surface is far larger than most community labelers need. It's also tightly coupled to the `tools.ozone.*` namespace and its own opinionated workflows.

**Skyware's labeler** (TypeScript, `@skyware/labeler`) is the opposite: a minimal library that implements the core labeler endpoints and nothing else. It's used when Ozone is overkill. But "nothing else" leaves real gaps — no report intake, no admin API beyond the library's internal methods, no audit trail. Skyware gets you protocol-compliant; it doesn't get you a working moderation pipeline.

In Rust, there is nothing. `atrium-api` and `jacquard` cover the general XRPC surface including label subscription as a consumer, but no standalone labeler server library exists. Rust ATProto infrastructure is growing (Blacksky's `rsky`, Doll's `proto-blue` SDK and Aurora-Locus PDS, Aurora-Prism AppView), and the lack of a Rust labeler is an increasingly visible gap.

Cairn fills that gap with a deliberately different shape from either Ozone or Skyware.

## 2. Why not Ozone, why not Skyware

**Why not Ozone:**
- Heavy dependency footprint (Next.js, Postgres, Redis, full stack).
- Tightly coupled to a specific web UI that not every operator wants.
- `tools.ozone.*` namespace forces Ozone's workflow assumptions on every consumer.
- Single-operator-runs-everything model; harder to compose with external systems.

**Why not Skyware:**
- No report intake — moderators can apply labels but users can't submit reports.
- No admin API beyond the library — building a separate admin UI or automation means re-implementing everything on top.
- No audit trail primitive — moderation actions aren't inherently recorded with who/when/why.
- TypeScript runtime with all that implies for single-binary deployment and resource footprint.

**Cairn's niche:**
- Rust-native: single statically-linked binary, SQLite storage, deploys to any VPS with one file.
- Report intake from day one (unlike Skyware).
- Audit trail as a first-class primitive (unlike Skyware).
- Compact admin XRPC surface for programmatic use by CLI, future web UIs, or integration with other systems.
- Roadmap to signal intake, review queue, and richer admin API — without cramming them into v1.

**Release strategy:** Cairn v1 is the minimal shippable labeler — protocol-correct, auditable, with real report intake and a clean admin surface. It is deliberately scoped smaller than Ozone. Subsequent releases expand toward Ozone-feature-parity territory (review queue, takedowns, team management, web UI) guided by real v1 usage, not speculative design. Shipping v1 on time matters more than shipping a complete tool late; the v1.1+ roadmap is where ambition lives.

## 3. Solution (v1)

Cairn v1 is a standalone labeler server with **two intake paths** and one outbound protocol surface.

**Intake paths:**
1. **Direct moderator action** (CLI or admin XRPC): a human decides, Cairn records and emits.
2. **User reports** (`com.atproto.moderation.createReport`): a user flags content; it lands in a report inbox for moderator review.

**Outbound protocol surface:**
- `com.atproto.label.queryLabels` (HTTP, public)
- `com.atproto.label.subscribeLabels` (WebSocket, public)
- Published `app.bsky.labeler.service` record (rkey `self`) declaring label definitions

All moderator actions — whether from CLI or XRPC — converge on the same **audit log**. Every label emitted can be traced back to the moderator who created it and the reason they gave.

## 4. Threat Model

Cairn is a public-side tool that touches moderation. The following threats are explicitly in scope, and Cairn is designed to address them.

1. **Moderator attribution is sensitive.** A public label that leaks "moderator did:plc:xyz decided this" creates harassment risk for moderators. Cairn exposes only the *labeler* DID in emitted labels; moderator identity is admin-API-only.
2. **Report content is sensitive.** Users reporting harassment or abuse trust the labeler to hold that content in confidence. Report bodies never appear in public endpoints and never in logs. Encryption at rest is deferred to v1.1; in v1, the documented boundary is that operators are trusted with their host.
3. **Audit trail must be preserved against accidental modification.** Every moderation action is logged with actor, timestamp, reason, and outcome — append-only at the application layer via SQL triggers. The trigger defends against bugs in Cairn's own code, not against direct DB tampering. Cryptographic tamper detection (hash-chaining) is a v1.1 feature.
4. **Labels are protocol-public by design.** Cairn emits labels cryptographically signed for network-wide consumption. It does not try to hide the labels themselves — that would break the whole protocol contract. The exposure discipline is about *metadata around labels*, not the labels themselves.
5. **Non-enumeration applies to resource lookups, not endpoint discoverability.** Admin endpoints return documented XRPC errors (`AuthenticationRequired`, `Forbidden`) at the endpoint level. Specific *resource lookups* by opaque ID return `NotFound` when the caller lacks authorization to know.
6. **Moderator → Cairn authentication uses ATProto service auth.** See §5.
7. **Report intake is authenticated.** Reports are submitted only by callers who can prove a DID via service auth. Anonymous reports are not accepted in v1.
8. **Denial-of-service via expensive inputs is mitigated by rate limits and caps.** Per-DID rate limits, global ceilings on pending reports, report body size caps, per-IP WebSocket connection caps, bounded replay retention. See §11.

### 4.1 Out-of-scope threats

The following are **not** defended against and must be mitigated by operational practice:

1. **Malicious operator.** Cairn does not defend against the operator of its host. The operator has the signing key, the database, and the config; they can emit arbitrary labels, modify the audit log, or forge historical records.
2. **Host compromise.** If the host is compromised, the signing key and session state are compromised.
3. **Privileged network observer on Cairn's host path.** Outbound DNS/HTTPS traffic from Cairn's host can be correlated to admin actions.
4. **Compromised moderator PDS session.** ATProto service auth means a valid PDS session on a moderator's account can mint service-auth JWTs against Cairn. See §5.2.
5. **Time-correlation attacks against moderator identity.** An observer correlating label emission timestamps with a moderator's public Bluesky activity can probabilistically link labels to moderators. Inherent to any useful audit trail.
6. **Signing key accidentally removed from DID document.** If an operator removes the labeler's signing key (verification method `#atproto_label`) from the DID document, all historical labels signed with that key will fail to verify at consumers — catastrophic for the labeler's credibility. Operators must never remove a labeler signing key from the DID document without first rotating (v1.1) and allowing consumers time to observe both keys.

### 4.2 Operator-trust trust-chain (README audience)

Subscribers of a Cairn-hosted labeler should understand:

1. **Labels are trusted by communities to the extent the operator is trusted.** A subscriber to `did:plc:some-cairn-labeler` is trusting the operator's current and past judgment. If the operator silently swaps intent (becomes malicious, sells the DID, is compromised) there is no protocol-level mechanism for subscribers to detect this.
2. **Historical labels can be forged by a malicious operator with DB access.** v1's audit log is not cryptographically linked to the labels table. v1.1's hash-chaining audit log is a prerequisite (but not sufficient) for historical-label integrity.
3. **One operator per instance is a single point of compromise for that labeler.** Operators who want to reduce this risk should consider publishing transparency records (e.g., a monthly signed Merkle root of the audit log to the labeler's PDS). Out of scope for v1 but enabled by v1.1's hash-chaining.

## 5. Authentication Model

### 5.1 Labeler service identity

Cairn runs on behalf of a **service DID** — a DID with a PDS account, an `app.bsky.labeler.service` record (rkey `self`) declaring what Cairn labels, and a cryptographic signing key published in the DID document at verification method `#atproto_label`.

The signing key is k256 (secp256k1), per the ATProto crypto spec. Per spec, "this key may have the same value as the `#atproto` signing key used for repository signatures"; operators may choose to share or separate these keys.

The service DID and signing key are configured once at deployment:
- The DID is declared in config.
- **The signing key's private material is loaded from a file on disk only.** Env-var key material is explicitly rejected.
- On load, Cairn verifies the key file has mode `0600` and is owned by the running user; Cairn refuses to start if the file is group- or world-readable.
- The key type has a custom `Debug` impl that redacts, is not `Serialize`, and uses `zeroize` on drop. Enforced by newtype wrapping.
- The private key is never written to disk after load, never logged, never included in any error message or response body.
- Cairn does not handle PLC operations itself.

### 5.2 Moderator authentication via service auth

Moderators authenticate to Cairn's admin endpoints using **ATProto service auth** tokens signed by their repo signing key (verification method `#atproto`).

The flow:

1. The moderator's client obtains a short-lived service auth JWT from the moderator's PDS via `com.atproto.server.getServiceAuth` (or equivalent), signed with the moderator's repo signing key, with:
   - `iss`: moderator's DID
   - `aud`: Cairn's service DID
   - `exp`: short-lived (≤60s from issuance)
   - `iat`: issuance timestamp
   - `jti`: unique JWT identifier (for replay protection)
   - `lxm`: the resolved lexicon method name of the Cairn admin endpoint being called (e.g., `tools.cairn.admin.applyLabel`)
2. The client sends this JWT as a `Bearer` token in the `Authorization` header.
3. Cairn verifies the JWT in this specific order:
   - **Algorithm allowlist:** the JWT `alg` header must be `ES256K`. Any other algorithm — including `none`, `HS256`, `ES256` (P-256 is not the repo signing key algorithm for most ATProto accounts) — is rejected immediately.
   - **Structural:** JWT is well-formed with all expected claims (`iss`, `aud`, `exp`, `iat`, `jti`, `lxm`) present.
   - **Signature:** Resolve the `iss` DID document (see §5.4), extract the key at verification method `#atproto`, verify the signature (constant-time). Signature check happens before claim checks to prevent token-scanning via error timing.
   - **Claims:** `aud` matches Cairn's service DID exactly. `exp` is in the future (with ±30s clock skew tolerance). `iat` is not more than 30s in the future. `lxm` matches the **resolved lexicon method name** for the endpoint being called (not the raw URL path).
   - **Replay check:** `jti` is not present in the replay cache (see below).
   - **Authorization:** The verified `iss` DID is present in the `moderators` table and has the required role for the method.
4. Any check failure returns a generic `AuthenticationRequired` response with no details about which check failed.

**Replay protection:** Cairn maintains an in-memory replay cache of `(iss, jti)` pairs with TTL equal to the token's remaining validity (bounded by max-`exp` window of 90s including skew). Presenting a JWT whose `jti` is already in the cache is rejected. **Cache size is capped at 100,000 entries with LRU eviction.** If an eviction would drop a `jti` whose TTL has not yet expired, that `jti` loses replay protection for the remainder of its TTL — an acceptable trade-off given that (a) admin call rates on a typical labeler are far below 100k/90s, and (b) even with eviction an attacker must intercept a live JWT to replay it, which is the same attack surface as the TTL window itself. This closes the 60-second replay window under normal load without unbounded memory growth.

**Inherent limitation (documented for moderators):** ATProto service auth derives moderator authority from the moderator's repo signing key, the same key used for all ATProto operations on their account. Anyone who can induce the moderator's PDS to sign a service-auth JWT — including via an app-password session — has the same authority as the moderator at Cairn. **Moderators should use short-lived, frequently-rotated app passwords and treat them as Cairn credentials.** This is a property of ATProto service auth, not a Cairn-specific flaw.

### 5.3 CLI ergonomics

The Cairn CLI (`cairn`) exposes subcommands that internally construct service auth tokens. The moderator configures once:

```
cairn config set moderator.did did:plc:xyz
cairn config set moderator.pds https://bsky.social
cairn login
```

The `login` flow prompts for a PDS app password, obtains a PDS session, and stores the session file at `$XDG_CONFIG_HOME/cairn/session.json` with mode `0600`. Cairn refuses to read the session file if it has broader permissions or is owned by a different user.

Then CLI commands work without further prompting. The CLI obtains a fresh service auth JWT per admin call, including a random `jti` for replay protection. At `login` time, Cairn warns the operator that the session file is a moderator credential equivalent to their PDS app password and should be protected accordingly.

For scripted/CI use, a long-lived PDS session can be provided via `CAIRN_SESSION_FILE`.

### 5.4 DID document caching and revocation

Verifying service auth requires resolving the caller's DID document.

- **Positive cache TTL: 60 seconds.** Matches service auth `exp` window.
- **Negative cache TTL: 5 seconds.**
- **Cache is in-memory only**, keyed by DID.
- On cache miss, resolve via:
  - **`did:plc`:** `GET https://plc.directory/{did}` over HTTPS with TLS verification. (Config option `plc.directory_url` allows pointing at a mirror.)
  - **`did:web`:** per the did:web spec. For a DID with no path component (`did:web:example.com`), resolve at `https://example.com/.well-known/did.json`. For a DID with path components (`did:web:example.com:users:alice`), resolve at `https://example.com/users/alice/did.json` — **no `.well-known` component**. Cairn's did:web resolver must handle both forms correctly.
- On resolution failure (network error, TLS error, non-2xx response, malformed response): **fail closed**. Request rejected with `AuthenticationRequired`. Failure is negatively cached. Failure is logged at `warn` level.
- Verification method selection: Cairn looks in the DID document's `verificationMethod` array and matches by the fragment ID (`#atproto` for moderator repo keys; `#atproto_label` for labeler signing keys). Keys are published as `Multikey` verification methods with `publicKeyMultibase` encoding; Cairn decodes this format to obtain the k256 public key.
- **Future (v1.1):** subscribe to the PLC operations log for real-time rotation observation.

### 5.5 Why not OAuth

OAuth is the direction ATProto auth is moving. For v1, service auth is implementable without OAuth server infrastructure, and the CLI use case is better served by service auth (no callback URL, no browser dependency). v2.0 may add OAuth as an alternative.

## 6. Label Wire Format

**This section is the precise protocol contract.** Every field, every byte, every encoding decision that affects interoperability is defined here. Subsequent feature verification criteria reference this section as the source of truth.

### 6.1 Label record (`com.atproto.label.defs#label`)

A label is a CBOR object with these fields (definitive list per the ATProto spec):

| Field | Type | Required | Description |
|---|---|---|---|
| `ver` | integer | required (always `1` in v1 of the protocol) | Label format version |
| `src` | string (DID) | required | The labeler's DID |
| `uri` | string (AT-URI or DID) | required | Subject: an `at://` URI for records, a DID for accounts |
| `cid` | string (CID) | optional | Present when the label applies to a specific version of a record; absent when the label applies to an account or to all versions of a record |
| `val` | string (≤128 bytes) | required | The label value |
| `neg` | boolean | optional (defaults to false) | If true, this is a negation event |
| `cts` | string (RFC-3339 datetime) | required | Created-at timestamp |
| `exp` | string (RFC-3339 datetime) | optional | Expiration timestamp |
| `sig` | bytes | required for emission | Signature over the label |

**Field enforcement in Cairn v1:**

- `ver` is always `1` and is always present in the label, both in the signed bytes and in the wire format.
- `src` is always Cairn's configured service DID.
- `uri` is validated as a well-formed AT-URI or DID at intake. Malformed returns `InvalidRequest`.
- `cid` is optional at the CLI and XRPC. `cairn label apply <subject> <value> [--cid <cid>]` accepts a CID. When present, the label is record-version-pinned; when absent, the label applies at the repo or record-collection level per the URI's shape.
- `val` is treated as case-sensitive, stored and emitted verbatim, never normalized. The 128-byte length cap is validated at intake (rejected with `InvalidRequest` if exceeded).
- `neg` defaults to false; negation events set `neg: true` explicitly.
- `cts` is monotonic: Cairn guarantees that within a given `(src, uri, val)` tuple, each event (apply or negate) has `cts` strictly greater than the prior event's `cts` for that tuple. This is enforced by clamping to `max(wall_clock_now, prior_cts + 1ms)` at emission time, protecting against wall-clock regression (NTP adjustments, system clock changes). `cts` is serialized with millisecond precision and `Z` timezone (e.g., `2026-04-22T14:32:17.938Z`). Cairn emits `cts` only in `Z` form in v1; consumers that sort by lexicographic string comparison will work correctly as a result, but Cairn does not commit to this as a wire-protocol invariant — consumers should parse `cts` as RFC 3339 datetime and compare semantically. **Implication for rapid same-tuple re-emission:** the 1ms clamp means a single tuple can emit at most 1000 events/sec; rapid re-labels within that window will produce `cts` values slightly ahead of wall clock. This is spec-legal and is the correct behavior — `cts` is a labeler-assigned timestamp, not a wall-clock guarantee.
- `exp` is optional; when present, is stored but not enforced in v1 (enforcement is v1.1).
- `sig` is always present on emitted labels. See §6.3.

### 6.2 Canonical encoding for signing

Per the ATProto spec:

1. Construct the label object using **only** the specified schema fields (no `$type`, no Lexicon metadata, no unspecified fields).
2. Include the `ver` field.
3. **Omit the `sig` field.**
4. Encode as DAG-CBOR / DRISL canonical form. **Terminology note:** "DAG-CBOR canonical," "DRISL canonical encoding," and "canonical CBOR" are used interchangeably in this doc and mean the same thing — the ATProto canonical DAG-CBOR profile as implemented by `proto-blue`'s DRISL module. Constraints:
   - Map keys sorted lexicographically by byte value
   - No indefinite-length items
   - No floating-point (including NaN/Infinity)
   - Shortest-form integer encoding
   - Strict-mode
5. Hash the resulting CBOR bytes with SHA-256.
6. Sign the **raw 32 SHA-256 hash bytes** (not hex-encoded) using k256 with **RFC 6979 deterministic nonces** and **low-S** enforcement.
7. The signature is stored in `sig` as CBOR bytes in **raw 64-byte `(r, s)` compact form** — NOT DER encoding.

### 6.3 Signature verification

A consumer verifying a label:
1. Fetches the label source's DID document.
2. Extracts the key at verification method `#atproto_label`.
3. Decodes the Multikey / publicKeyMultibase format to obtain the k256 public key.
4. Reconstructs the canonical CBOR of the label with `sig` removed and `ver` included.
5. Hashes with SHA-256.
6. Verifies the 64-byte compact signature against the hash bytes.

If Cairn's emission diverges from this process at any step, consumers reject the label. This is why §6.2 is precise.

### 6.4 `app.bsky.labeler.service` record structure

The service record published to the labeler's PDS at rkey `self` (required — any other rkey is a protocol violation):

```
{
  "$type": "app.bsky.labeler.service",
  "createdAt": "<RFC-3339 datetime>",     // required
  "policies": {                            // required, nested object
    "labelValues": ["<val1>", "<val2>"],   // required array of strings
    "labelValueDefinitions": [             // optional but recommended
      {
        "identifier": "<val>",             // required
        "severity": "inform" | "alert" | "none",  // required
        "blurs": "content" | "media" | "none",    // required
        "defaultSetting": "ignore" | "warn" | "hide",  // optional
        "adultOnly": boolean,              // optional
        "locales": [                       // required array; at least one entry
          {
            "lang": "<BCP-47 tag>",
            "name": "<short display name>",
            "description": "<longer description>"
          }
        ]
      }
    ]
  },
  "reasonTypes": ["com.atproto.moderation.defs#reasonSpam", ...],  // optional
  "subjectTypes": ["account", "record"],   // optional
  "subjectCollections": ["app.bsky.feed.post", ...]  // optional
}
```

**Notes:**
- `labelValues` and `labelValueDefinitions` are nested under `policies`, **not** at top level.
- `createdAt` is set once at initial publish and preserved on subsequent updates (content-hash comparison for idempotency ignores `createdAt`).
- `severity` and `blurs` are required enums per the `app.bsky.labeler.service` lexicon — a config that omits them for any defined label will fail to publish a valid service record.
- `locales` is a required array with at least one entry per `labelValueDefinition`.

### 6.5 Known / global label values

Bluesky's `com.atproto.label.defs` declares a set of well-known global label values: `!hide`, `!no-promote`, `!warn`, `!no-unauthenticated`, `dmca-violation`, `doxxing`, `porn`, `sexual`, `nudity`, `nsfl`, `gore`. Labelers may emit these with their spec-defined semantics; they are **not** redefined by Cairn's `labelValueDefinitions`. If an operator's config lists a global value, Cairn treats it as a declaration-of-intent to emit that well-known value with its standard meaning. Custom `labelValueDefinitions` should use non-colliding values.

### 6.6 Rate limits (inherited from the network)

Bluesky's labeler rate-limit guidance (observed, not spec): **5 labels/second, 5000/hour, 50000/day.** Cairn does not enforce these internally (an operator can exceed them if their PDS/AppView tolerates it), but the README includes them as operational guidance.

## 7. Features

Every feature has verification criteria. The criteria are the VDD contract: a feature is not "done" until the criteria pass.

### F1. Labeler service declaration

Publish an `app.bsky.labeler.service` record to the labeler's own PDS at rkey `self`.

**Verification:**
- Config file defines label values and their definitions (identifier, severity, blurs, locales with at least one entry per definition).
- On startup, Cairn renders the service record per §6.4 and publishes it with `rkey: self`.
- Record validates against `app.bsky.labeler.service` lexicon via `atrium-api` parsing.
- **Idempotency:** Cairn computes a content hash of the rendered record excluding `createdAt`. If the hash matches the currently-published record's content hash (also computed excluding `createdAt`), no write occurs. `createdAt` is preserved from the prior record when content is unchanged.
- Any structural change (new label value, changed severity, added locale, etc.) triggers `swapRecord` with the prior CID.
- **Swap race handling:** if `swapRecord` fails because the prior CID no longer matches, Cairn **refuses to start** with an error directing the operator to ensure only one Cairn instance runs per labeler DID. No automatic retry loop.
- A decision log of "published / skipped / failed" is recorded in the audit log.

### F2. Label signing per §6.2

Every emitted label is signed per the wire-format spec in §6.

**Verification:**
- `ver: 1` is present in every emitted label, both in the bytes used for signing and in the wire output.
- `sig` is removed before canonical encoding for signing.
- SHA-256 hash of the canonical bytes is signed directly (raw 32 bytes), not a hex encoding.
- k256 signing uses RFC 6979 deterministic nonces.
- Low-S is enforced at emission (not just verification). High-S emissions are a bug.
- Signature wire format is raw 64-byte `(r, s)` compact, NOT DER.
- Verification method ID for the labeler's public key in its own DID document is `#atproto_label`.
- **Parity test corpus** at `tests/fixtures/signature-corpus/`:
  - Generated from a pinned `@atproto/api` version (version recorded in the corpus's README).
  - Covers labels with every combination of optional-field presence: (a) label with no `cid` and no `exp`, (b) label with `cid` only, (c) label with `exp` only, (d) label with both `cid` and `exp`, (e) negation (`neg: true`) of each of the above.
  - For each case, the corpus includes: the label object, the canonical CBOR bytes (before signing), the SHA-256 hash, and the expected signature bytes.
  - Cairn must produce byte-identical CBOR and byte-identical signatures for the corpus inputs using the corpus's test key material.
- Signature validation tests: valid signature verifies, tampered label fails, wrong-key fails, high-S emission is rejected at emit time, `@atproto/api`-produced signatures verify in Cairn's verifier code path.
- Signing key type constraints from §5.1 (redacting Debug, no Serialize, zeroize on drop) are enforced as compile-time invariants via newtype wrapping.

### F3. `com.atproto.label.queryLabels` endpoint

**Verification:**
- `uriPatterns` parameter is **required** (per lexicon). Missing or empty-array returns `InvalidRequest`.
- `uriPatterns` glob semantics: trailing `*` means prefix match; absence of `*` means exact match. `*` anywhere other than trailing position is treated as a literal character (matching Ozone's behavior).
- `sources` parameter, if provided, filters by label source. Cairn filters results to labels where `src = Cairn's service DID`; if `sources` is provided and does not include Cairn's DID, return an empty `labels` array (not an error).
- `limit` default is 50, maximum 250 (per spec). Values outside [1, 250] return `InvalidRequest`.
- `cursor` is an opaque string to the client; internally Cairn uses a format distinct from the `subscribeLabels` sequence number.
- Response shape: `{ cursor?: string, labels: Label[] }`. `cursor` is present in the response only if more results remain.
- Negated labels are excluded from results.
- Expired labels (where `exp` is in the past) are excluded from results.
- Malformed `uriPatterns` (non-string, malformed AT-URI in exact-match position, etc.) return `InvalidRequest`. A well-formed but unknown subject returns empty results (not an error) — matching Ozone.
- **CORS policy:** accepts requests from any origin (public read endpoint), never echoes credentials (`Access-Control-Allow-Credentials` never sent).

### F4. `com.atproto.label.subscribeLabels` endpoint

WebSocket event stream per the Lexicon (`message` union of `#labels` and `#info`, with `FutureCursor` as the only declared error).

**Frame format:**
- Each wire message is two concatenated DAG-CBOR objects: a header `{op, t}` followed by a body.
- `op: 1` indicates a message; `t` is the message type ref (`"#labels"` or `"#info"`).
- `op: -1` indicates an error; body is `{error: string, message?: string}`. Connection is closed after an error frame.
- `#labels` message body shape (from lexicon): `{seq: integer, labels: Label[]}`. The `seq` is a **per-frame** identifier; a frame may contain one or more labels, all stamped with the same `seq`. Consumers resume with `cursor = <last-seen-seq>` to get frames with `seq > last-seen-seq`.
- `#info` message body shape: `{name: string, message?: string}`. The only `name` Cairn emits is `OutdatedCursor` (per Bluesky convention).

**Cursor semantics (matching Ozone / Lexinomicon):**
- If `cursor` is omitted: start streaming live from current head. No replay.
- If `cursor` is an integer ≤ 0 or less than the oldest retained seq: send an `#info` frame with `name: OutdatedCursor` containing the oldest retained seq in the optional `message`, then begin streaming from the oldest retained seq.
- If `cursor` is a non-negative integer ≤ current head seq: begin streaming from frames where `seq > cursor`.
- If `cursor` is a non-negative integer greater than current head seq: send an error frame with `error: "FutureCursor"` and close the connection.
- If `cursor` fails to parse as a signed 64-bit integer (non-integer string, empty string, value outside i64 range): close the WebSocket with close code `1008` (policy violation). No `FutureCursor` error frame is sent — the cursor isn't future, it's invalid, and `FutureCursor` is reserved for the specific "cursor exceeds head" case.

**Per-frame semantics:**
- In v1, Cairn emits one label per frame (frame's `labels` array contains exactly one label). This is the simplest behavior and matches current Ozone output. Batching multiple labels per frame is a v1.1 possibility for throughput; v1 consumers must tolerate either.
- Frames are emitted in strictly increasing `seq` order within a single client connection.
- An apply event is excluded from replay if any later negation exists for the same `(src, uri, val)` tuple, regardless of subsequent re-applies. Each negation frame and each re-apply frame remains in replay at its own seq. This matches the spec: "Labels which have been redacted have the original label removed from the stream, but the negation remains."

**Retention:**
- Default: 180 days (rolling window). Older frames are dropped from the replay log.
- Config option `retention.max_sequence_age_days` tunes or disables retention.

**Connection lifecycle:**
- Client sends only WebSocket control frames (ping/pong). Any application data frame received from the client results in immediate connection close.
- Ping interval 30s, pong timeout 90s. Pong timeout → close.
- Per-connection bounded send buffer (default 1024 events). Slow subscriber that fills the buffer has their connection closed (no `#info` frame — there's no spec mechanism for a backpressure info; just close with reason).
- Backfill batching: server paginates internally during replay (up to 1000 sequence rows per batch) to avoid loading full history into memory.
- **Global connection cap: default 256 concurrent subscribers.** Excess connections close immediately.
- **Per-IP connection cap: default 8 concurrent subscribers per IP.** Enforced in-process. `contrib/` reverse-proxy configs enforce this independently for defense in depth.
- Optional shared-backfill optimization: multiple clients catching up from near-identical cursors may be satisfied from a shared buffer (implementation detail; protocol-transparent).

**Verification:**
- Frame format matches spec (two-CBOR-object concatenation with `{op, t}` header).
- Every case above has a corresponding integration test that reads frames from the consumer side and validates structure.
- Specifically: Ozone's own firehose output parses cleanly through Cairn's consumer code, and Cairn's output parses cleanly through `atrium-api`'s consumer code.

### F5. Label persistence with monotonic sequence

Labels and negations are assigned strictly monotonic `seq` numbers at commit time. This section describes server-side frame seq; it does not add fields to the label record itself (`seq` lives on the `#labels` frame, not on the label).

**Writer architecture:**
- SQLite in WAL mode with `busy_timeout` = 5000ms.
- All writes go through a **single writer task** owning an async mpsc receiver.
- Writer transaction: `INSERT INTO label_sequence DEFAULT VALUES RETURNING seq` → construct label record with this event's `cts` → canonical encode + sign → `INSERT INTO labels` → notify subscribers.
- Reads concurrent (WAL supports this).
- **Single-instance invariant:** `server_instance_lease` row with unique instance ID and heartbeat. Heartbeat every 10 seconds. Startup with a valid lease (heartbeat <60s old) **refuses to start**. Clean shutdown releases the lease.
- **`cts` monotonicity:** per §6.1, within each `(src, uri, val)` tuple the writer ensures `cts` strictly increases across successive events by clamping: `event_cts = max(wall_now, prev_event_cts_for_tuple + 1ms)`.

**Verification:**
- Sequence numbers are strictly monotonic, never reused, never rolled back.
- Property test: 100 concurrent write requests produce contiguous `seq` values with no gaps, no duplicates, no reordering within the stream.
- Schema supports efficient cursor queries (indexed on seq), efficient per-subject queries (indexed on uri), and efficient `prev_cts` lookup during monotonicity clamp (composite index on `(src, uri, val)`).
- `cts` monotonicity test: emit → system-clock-regress → emit; the second event's `cts` must be strictly greater than the first's.
- Instance-lease test: starting a second Cairn against the same SQLite file while the first is running produces a clear error and non-zero exit code.

### F6. Label negation

Removing a label emits a new event with `neg: true`, same `(src, uri, val)`, new `cts` per §6.1 monotonicity.

**Verification:**
- Negation event is a full `Label` record per §6 — including `ver`, `src`, `uri`, `val`, `cts`, `neg: true`, and **its own independently-computed signature** over its own canonical encoding. It does not reuse the original label's signature.
- After negation, `queryLabels` no longer returns the negated label.
- After negation, `subscribeLabels` replay from cursor=0 omits the original apply event but includes the negation event (matching spec).
- Negating a label that doesn't exist returns XRPC `LabelNotFound` (a custom error declared in `tools.cairn.admin.negateLabel`'s lexicon).
- Re-applying after negation produces a fresh label with current `cts` (clamped for monotonicity per §F5) and a new `seq`.
- Property test: apply → negate → reapply, verifying each has strictly increasing `cts` and `seq`, each carries its own valid signature.

### F7. Label expiry (schema only, enforcement deferred)

Labels can be created with an `exp` timestamp. Expired labels are excluded from query responses.

**Verification:**
- `exp` field is stored correctly when provided.
- `queryLabels` excludes labels whose `exp` is in the past (evaluated at query time against server wall clock).
- `subscribeLabels` replay includes labels with `exp` regardless of whether `exp` is past; expiry is computed client-side per established ATProto convention (Ozone does not emit "expiry events").
- Schema supports `exp` without requiring a migration when v1.1 adds scheduled-expiry-enforcement.

### F8. Signing key rotation (schema only, operation deferred)

**Verification:**
- `signing_keys` table has validity ranges per key (`valid_from`, `valid_to`).
- Key lookup at verification time uses the key valid at the label's `cts`.
- Adding a new key to the schema (without actual rotation) doesn't break existing label verification.

### F9. CLI label management

**Verification:**
- `cairn label apply <subject> <value> [--cid <cid>] [--reason <text>] [--exp <datetime>]` creates and emits a label.
- `cairn label negate <subject> <value> [--cid <cid>]` negates an existing label. The `--cid` flag is required if the label was applied with a CID (the negation must target the same `(src, uri, val)` tuple including any CID pinning).
- `cairn label list [--subject <did>] [--value <val>] [--source <moderator-did>]` queries.
- `cairn report list [--status pending|resolved]`
- `cairn report view <report-id>`
- `cairn report resolve <report-id> [--label <value>] [--reason <text>]`
- `cairn report flag <reporter-did>` suppresses future reports from the reporter DID (sets their rate limit to zero). Use `cairn report unflag <reporter-did>` to reverse.
- `cairn moderator add <did> --role <mod|admin>`
- `cairn moderator remove <did>`
- `cairn moderator list`
- `cairn audit list [--actor <did>] [--action <type>] [--since <when>]`
- `cairn login`
- All commands exit non-zero on error with specific exit codes per error class.
- `--json` flag on read commands for machine consumption.

### F10. Audit log

Every moderation action writes an immutable row.

**Actions logged:** label applied, label negated, report resolved, reporter flagged, moderator granted/revoked, signing key added, labeler service record published or updated.

**Verification:**
- Every F1/F6/F9/F11 action produces exactly one audit entry.
- `TRIGGER BEFORE UPDATE/DELETE RAISE ABORT` on the audit_log table. **The trigger is a correctness defense, not a security defense.** Anyone with direct SQLite file access can drop the trigger, modify the DB, or replace the file. Cryptographic tamper detection (hash-chaining) is a v1.1 feature.
- Entries include: action type, actor DID, timestamps (seq + wall clock), target identifiers (including `cid` when relevant), outcome, reason string.
- Log never includes report body content, signal payloads (v1.1), or secret material.
- Audit log exposure of `(actor, timestamp, subject)` creates correlation risk (§4.1.5); inherent.

### F11. Report intake

Implements `com.atproto.moderation.createReport` per the lexicon.

**Authentication (required):**
- Service auth JWT required: `aud` = Cairn's service DID, `lxm` = `com.atproto.moderation.createReport`.
- JWT verification per §5.2 (including `alg: ES256K`, `jti` replay check).
- The verified `iss` is the report's authenticated source DID.
- Anonymous reports are rejected.

**Input validation:**
- `reasonType` is validated against the spec-defined enum: `com.atproto.moderation.defs#reasonSpam`, `#reasonViolation`, `#reasonMisleading`, `#reasonSexual`, `#reasonRude`, `#reasonOther`. Unknown values return `InvalidRequest`.
- `subject` must be one of:
  - `com.atproto.admin.defs#repoRef` (for account-level reports)
  - `com.atproto.repo.strongRef` (for record-level reports, including `uri` and `cid`)
- Subject existence is **not verified** at intake; Cairn accepts reports about subjects that may not exist (matching Ozone).
- `reason` text is optional, capped at **2KB**. Larger bodies return `InvalidRequest`.

**Response shape (per spec):**
```
{
  id: <integer>,
  createdAt: <datetime>,
  reasonType: <string>,
  reason?: <string>,
  subject: <union>,
  reportedBy: <DID>    // the verified iss from the service auth JWT
}
```

**Rate limits and DoS defense:**
- Per-verified-DID rate limit: default 10 reports per hour.
- Global pending-reports cap: 10,000. At cap, new reports return `RateLimitExceeded`. **Worst-case pending storage:** 10,000 reports × (2KB body + ~500B overhead) ≈ 25MB before the cap engages — well below the disk-space guard threshold.
- Disk-space guard: if SQLite DB size exceeds configured limit (default 5GB), the report endpoint returns a generic error (label emission continues to work).
- Reporter suppression (from `flagReporter`): suppressed DIDs get `RateLimitExceeded` responses with no indication they've been suppressed.
- Report body never returned by public endpoints, never written to logs (even at debug level).
- **CORS policy:** `createReport` rejects cross-origin browser requests. Requests with **no `Origin` header** (non-browser clients — CLI tools, server-to-server calls) are accepted. Requests **with an `Origin` header** are accepted only if the origin is in the operator-configured allowlist `cors.createreport.allowed_origins` (default: empty — no browser origins permitted). Mismatched `Origin` returns HTTP 403. This prevents a malicious web page from causing a visitor's browser to submit a report while not blocking legitimate non-browser callers.

### F12. Admin XRPC API (v1 surface)

Namespace: `tools.cairn.admin.*`. Auth: ATProto service auth (§5).

**v1 endpoints:**
- `tools.cairn.admin.applyLabel` (procedure)
- `tools.cairn.admin.negateLabel` (procedure)
- `tools.cairn.admin.listLabels` (query)
- `tools.cairn.admin.listReports` (query)
- `tools.cairn.admin.getReport` (query, returns full report content)
- `tools.cairn.admin.resolveReport` (procedure)
- `tools.cairn.admin.flagReporter` (procedure)
- `tools.cairn.admin.listAuditLog` (query)

**Verification:**
- Lexicons written in `lexicons/tools/cairn/admin/`, one JSON file per endpoint plus a shared `defs.json`.
- **Every custom error name used by Cairn is declared in the `errors` array of the corresponding lexicon.** Custom errors used include: `LabelNotFound`, `ReportNotFound`, `ModeratorNotFound`, `InvalidLabelValue`. Standard XRPC errors (`AuthenticationRequired`, `InvalidRequest`, `InternalServerError`) are not re-declared.
- Cairn **does not** attempt to emit custom errors on Bluesky-owned lexicons (`subscribeLabels`, `queryLabels`, `createReport`) beyond what those lexicons declare.
- **Error name consistency:** `RateLimitExceeded` is used everywhere for rate-limit-style errors (Cairn does not use both `TooManyRequests` and `RateLimited`).
- Service auth on every admin endpoint. Unauth returns `AuthenticationRequired` (HTTP 401). Authed-but-unauthorized returns `Forbidden` (HTTP 403).
- Role-based authorization: `mod` can apply/negate/resolve/flagReporter; `admin` additionally accesses audit log.
- `NotFound` for resource-lookup-by-opaque-ID (e.g., `getReport` with unknown ID).
- Query endpoints use `parameters` (query-string) input; procedure endpoints use JSON body input.
- `tools.cairn.admin.defs` contains shared types (`#reportView`, `#auditEntry`, `#moderator`, etc.) referenced by other endpoints via `tools.cairn.admin.defs#<name>`.
- **Lexicon publishing:** lexicons are served at `https://cairn.tools/.well-known/lexicons/tools/cairn/admin/{name}.json`. **This is a Cairn convention, not a finalized ATProto spec** — lexicon resolution is under active RFC (bluesky-social/atproto#3074). The path is chosen for forward-compatibility with the well-known/HTTPS-based proposals. Cairn documents this clearly rather than claiming spec compliance for lexicon publishing.

### F13. Single binary + SQLite deployment

**Verification:**
- `cargo install cairn-labeler` produces a working binary named `cairn`.
- First run creates the SQLite schema via embedded migrations.
- `contrib/` includes:
  - systemd service file template.
  - **Caddyfile** with: TLS termination, per-IP rate limits on `createReport` (burst 3, rate 10/hour), per-IP connection limits on `subscribeLabels` (8 concurrent), HSTS, no-cache headers for admin endpoints.
  - **nginx.conf** with equivalent protections.
- README has a separate **"Production Checklist"** section covering TLS, reverse-proxy rate limits, key file permissions, backup policy, monitoring, and the trust-chain disclosures from §4.2 prominently.
- Binary's static resources (migrations, lexicon bundle for `.well-known` endpoints) compiled in.
- Default port binding documented; Cairn expects reverse proxy for TLS.

## 8. Lexicons

Cairn defines custom lexicons in `lexicons/tools/cairn/admin/*.json`.

**Served at:** `https://cairn.tools/.well-known/lexicons/tools/cairn/admin/{name}.json` (Cairn convention; see §F12 note on lexicon resolution).

**Lexicon set:**

- `tools.cairn.admin.applyLabel` (procedure)
- `tools.cairn.admin.negateLabel` (procedure)
- `tools.cairn.admin.listLabels` (query)
- `tools.cairn.admin.listReports` (query)
- `tools.cairn.admin.getReport` (query)
- `tools.cairn.admin.resolveReport` (procedure)
- `tools.cairn.admin.flagReporter` (procedure)
- `tools.cairn.admin.listAuditLog` (query)
- `tools.cairn.admin.defs` (shared definitions)

**Every custom error name is declared in its method's `errors` array.**

**Versioning strategy:** "never break, only add." Semantic changes require a new NSID (`tools.cairn.admin.v2.*`). Adding optional fields is backward-compatible.

## 9. Technology Choices

| Concern | Crate | Reasoning |
|---|---|---|
| Async runtime | `tokio` | Guild-default |
| HTTP server | `axum` | Tokio-native |
| WebSocket | `tokio-tungstenite` | Low-level framing control |
| ATProto primitives (DAG-CBOR/DRISL canonical encoding, CIDs, k256 with RFC 6979 + low-S, Multikey encoding, DID resolution) | `proto-blue` (see §15 contingency) | Doll's Rust SDK; DRISL normalization and deterministic signing are load-bearing for signature parity with `@atproto/api` |
| Database | `sqlx` with SQLite | Compile-time checked queries |
| Migrations | `sqlx migrate` | Embedded |
| CLI | `clap` v4 derive | Standard |
| Errors | `thiserror` (lib) + `anyhow` (CLI) | |
| Logging | `tracing` | Structured |
| Config | `figment` with env + TOML file | Layered |
| Testing | `wiremock`, `sqlx-test`, `proptest` | |
| Key material | Custom newtype wrapper: redacting `Debug`, `zeroize` on drop, no `Serialize` | §5.1 compile-time enforcement |

Config precedence: CLI flags > environment variables > TOML config file > compiled-in defaults. Signing key material is file-only (§5.1).

## 10. Architecture

```
┌─────────────────────────────────────────────────┐
│  CLI binary  |  HTTP server (axum router)       │
├─────────────────────────────────────────────────┤
│  XRPC/API handlers                              │
│  - Public: queryLabels, subscribeLabels         │
│  - Authenticated: createReport (service auth)   │
│  - Admin: tools.cairn.admin.* (service auth)    │
├─────────────────────────────────────────────────┤
│  Core services                                  │
│  - LabelService (apply/negate/query)            │
│  - ReportService (intake + resolution +         │
│    reporter suppression)                        │
│  - AuditService (append-only log)               │
│  - AuthService (JWT verification with alg       │
│    allowlist, replay-cache, DID resolution,     │
│    Multikey decoding, role check)               │
├─────────────────────────────────────────────────┤
│  Writer task (single-writer pattern)            │
│  - Owns mpsc receiver for all write commands    │
│  - Sequence assignment + cts-monotonicity       │
│    clamp + canonical encode + sign + commit     │
│  - Notifies subscribers                         │
├─────────────────────────────────────────────────┤
│  Storage layer (SQLx + SQLite, WAL mode)        │
│  - Schema: labels, label_sequence, keys,        │
│    signing_keys, reports, moderators,           │
│    audit_log, labeler_config,                   │
│    server_instance_lease, suppressed_reporters, │
│    service_record_state                         │
└─────────────────────────────────────────────────┘
```

**Hot path (label emission):**

```
moderator CLI / XRPC
  → service auth verified (§5.2 order: alg → structural → sig → claims → replay → authz)
  → role check
  → write command to writer channel
  → writer task:
    BEGIN
    seq = nextval
    cts = max(wall_now, prev_cts_for_tuple + 1ms)
    construct label per §6.1
    canonical encode per §6.2 (no sig, include ver:1)
    SHA-256
    sign (RFC 6979 deterministic, low-S)
    attach sig as raw 64-byte (r,s)
    INSERT label
    COMMIT
    broadcast to subscribers
  → subscriber send loop: frame per §F4 → write to WebSocket (bounded buffer)
```

**Crate layout:** single crate for v1. Module boundaries match the layer diagram.

## 11. Out of Scope for v1

Deferred to v1.1 or later (see §18):

1. Webhook signal intake.
2. Review queue.
3. Source management.
4. Report encryption at rest.
5. Label expiry enforcement job.
6. Signing key rotation operation.
7. Moderator/role management XRPC endpoints.
8. OAuth authentication.
9. Web UI.
10. Ozone lexicon compatibility.
11. Automated firehose watching.
12. Multi-tenant mode.
13. Label mirroring / translation.
14. Appeals flow.
15. Webhook-out.
16. Audit log hash-chaining (and transparency records).
17. PLC log subscription for real-time key-rotation observation.
18. Cross-language interop tests (beyond Rust consumer).
19. Multi-label-per-frame batching in `subscribeLabels`.
20. **Observability and operator-facing health introspection** (Prometheus-style `/metrics` endpoint, structured health-check endpoint, per-operator dashboards). v1 provides `tracing`-based structured logs only. Operators who need metrics can scrape logs; a dedicated metrics surface is v1.1. This is called out explicitly because a reviewer would otherwise wonder if it was an oversight.

## 12. Security Considerations

Complements §4 and §5. This is the attacker's-eye view for code review.

- **Service auth verification order (§5.2):** `alg` allowlist → structural → signature → claims → replay → authorization. Signature verified before claim checks to prevent timing-based oracles.
- **`alg` allowlist:** `ES256K` only. `alg: none`, `HS256`, `ES256`, etc. rejected outright.
- **`jti` replay cache:** in-memory, bounded TTL; closes the 60s replay window.
- **Service auth is only as strong as the moderator's PDS session.** Documented (§4.1.4, §5.2); mitigated by moderator hygiene.
- **DID resolution and caching (§5.4):** 60s positive, 5s negative, fail-closed, `did:web` path-component handling.
- **Signing key confidentiality (§5.1):** file-only, 0600, redacting Debug, zeroize, never serialized/logged.
- **Label wire format correctness (§6):** `ver: 1` always, `sig` removed before signing, SHA-256 of canonical CBOR, raw 64-byte compact signature, RFC 6979, low-S. Parity corpus enforced.
- **`cts` monotonicity (§6.1, §F5):** wall-clock regression cannot produce out-of-order events for the same tuple.
- **Sequence atomicity (§F5):** single writer task + transaction + lease.
- **Single-instance invariant (§F5):** lease table prevents dual-instance corruption of seq, signing, and service-record state.
- **Subscribe caps (§F4):** global and per-IP connection caps; bounded send buffer; slow-subscriber disconnect; cursor=0 cost bounded by retention.
- **Report DoS (§F11):** auth required, 2KB body cap, per-verified-DID rate limit, global pending cap, disk guard, CORS rejection.
- **Report-based harassment of moderators (§F11):** `flagReporter` suppression.
- **CORS (§F3, §F11):** `createReport` rejects cross-origin; `queryLabels` allows but never echoes credentials.
- **SQL injection:** `sqlx` compile-time-checked; no string interpolation.
- **Non-enumeration narrowed to resource lookups (§4.5).**
- **Audit log trigger is correctness not security (§F10).**
- **`lxm` binding (§F12):** resolved lexicon method name, not URL path. No catch-all admin routes.
- **CLI session file (§5.3):** 0600, XDG path, refuses broader permissions.
- **Signing key in DID document (§4.1.6):** removal is catastrophic; operators warned in Production Checklist.

## 13. Testing Strategy

- **Unit tests** per module.
- **Integration tests:** wiremock for HTTP, in-memory SQLite for DB.
- **Property tests (`proptest`):** sequence monotonicity, cursor replay correctness, DAG-CBOR canonical round-trip, `cts` monotonicity under wall-clock regression.
- **Signature parity test suite (§F2):** checked-in corpus from pinned `@atproto/api` version with coverage of every optional-field combination.
- **Ozone interop spot-test:** at least one end-to-end validation that a Cairn-emitted label parses cleanly in `@atproto/api`'s consumer path. v1 documents this was verified manually; v1.1 automates.
- **atrium-api interop test:** Cairn emits, `atrium-api` consumer subscribes, labels parse and verify.
- **Adversarial security test suite:** unauth admin access, malformed JWT, wrong `aud`/`lxm`/`alg`, `jti` replay, expired `exp`, future `iat`, DID resolution failure fail-closed, audit-log tamper attempts, oversized report bodies, report floods (single DID, many DIDs), dual-instance startup, WS connection flood, `cts` regression emission.
- **Live tests** behind `--features live` against a local PDS (Aurora-Locus or Bluesky reference).

## 14. Shipping

Cairn v1 ships as a focused release: protocol-correct, self-contained, and notably smaller than Ozone in feature surface. This is intentional. Users who need Ozone's full moderation workflow (review queue, takedowns, team management, web UI) should use Ozone today and consider migrating to Cairn when v1.1+ delivers those features. Users who want a Rust-native labeler without Ozone's dependency footprint are Cairn v1's target audience.

- `cargo publish` as `cairn-labeler` (the bare name `cairn` is placeholder-squatted on crates.io). The produced binary is named `cairn` via the `[[bin]]` target, so end-users run `cairn` after `cargo install cairn-labeler`.
- Pre-built binaries (Linux x86_64, macOS arm64+x86_64, Windows x86_64) via GitHub Actions.
- `cairn.tools` hosting: **GitHub Pages with custom domain (CNAME)**. Zero ongoing cost, handles static JSON at `.well-known/lexicons/` paths with correct `Content-Type` (configured via `.nojekyll` + proper file extensions, or via a minimal build step that emits files with correct MIME types).
- README contents: install, quickstart, **Production Checklist**, security caveats, out-of-scope list, comparison to Ozone/Skyware, contribution guide, **§4.2 trust-chain disclosures prominently placed**, observed network rate limits (§6.6), unsigned-binaries friction note (see below).
- **Binary signing (decision):** macOS and Windows binaries are **unsigned**. README documents the Gatekeeper ("cannot verify developer" — `xattr -d com.apple.quarantine cairn` or right-click-open) and SmartScreen ("unrecognized publisher") friction. SHA-256 checksums are published alongside binaries in each GitHub Release for verification. Signing with Apple Developer ($99/yr) and Windows EV cert (several hundred/yr) is a v1.1+ consideration if adoption justifies the cost.
- **Semver commitment:** library crate (`cairn` as a Rust dependency, if anyone consumes it that way) follows strict semver. CLI output format and admin XRPC surface follow strict semver — breaking changes require a major-version bump. DB schema migrations run automatically on upgrade via embedded `sqlx migrate`; the operator does not run a separate command. Internal implementation details (module structure, private types) are not covered by semver.
- **CI strict mode:** `cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings` (default lint groups only, not pedantic/nursery), `cargo fmt --check`, `cargo sqlx prepare --check` to keep compile-time query artifacts fresh.
- MSRV: Rust 1.85+ (inherited from `proto-blue` edition 2024).
- **Cross-platform build:** Linux x86_64 (GNU and musl static), Linux aarch64, macOS arm64 + x86_64, Windows x86_64. Built via GitHub Actions with `cross` or `cargo-zigbuild` where cross-compilation is needed. Build procedure verified end-to-end on clean runners before release (not just "works on my machine").
- Detailed release procedure and rollback policy: see §19 (Release Runbook).

## 15. proto-blue Dependency & Contingency

Cairn depends on `proto-blue` for ATProto primitives (DAG-CBOR/DRISL, CIDs, Multikey encoding, k256 with RFC 6979 + low-S, DID resolution).

**Path A (preferred):** `proto-blue` is on crates.io at release time.

**Path B (contingency):** vendor the needed subset (DRISL canonical encoding, Multikey encoding/decoding, k256 with RFC 6979 + low-S, DID doc parsing including `did:web` path-component handling). **Honest scope estimate:** 2–4 weekends of vendoring, parity-testing, and edge-case debugging. DRISL edge cases (integer-encoding boundaries, map-key byte ordering, empty-map-vs-missing-field) are the specific risk. **MSRV under Path B:** Cairn holds the same MSRV (Rust 1.85+) whether depending on `proto-blue` or vendoring its subset. Vendored code will be updated to match proto-blue's MSRV if upstream advances, to preserve straightforward re-adoption.

**Vendored-code maintenance policy:** reviewed monthly against upstream; security fixes ported within 7 days; non-security changes batched quarterly.

**Path C (fallback):** `proto-blue` abandoned. Switch to `atrium-api` primitives, vendor the rest.

**Decision deadline:** **six weeks before planned v1 release.** This replaces the previous 2-week deadline; Path B's real cost makes a tighter window untenable. If Path B is triggered, the extra weeks are working time, not planning time.

## 16. Project-Level Verification Criteria

### 16.1 Hard gates (pass/fail)

Cairn v1 cannot ship until all of these are true:

- F1–F13 verification criteria all pass.
- §12 security considerations all have corresponding tests.
- `cargo clippy --all-targets -- -D warnings` passes clean (default lint groups).
- `cargo test --all-targets` passes on CI for every published target (Linux x86_64 GNU + musl, Linux aarch64, macOS arm64 + x86_64, Windows x86_64).
- `cargo sqlx prepare --check` passes on CI.
- Cairn published to crates.io; `proto-blue` dependency satisfied via crates.io (Path A) or vendored subset (Path B per §15).
- Release binaries with SHA-256 checksums downloadable from GitHub Releases.
- `cairn.tools` is live with docs and lexicon bundle.
- atrium-api interop test passes (Cairn-emitted labels consumed by `atrium-api` subscriber code).
- Ozone interop spot-test: at least one Cairn-emitted label has been parsed and signature-verified by `@atproto/api` (manually verified; documented in release notes).
- Signature parity corpus (§F2) passes byte-identical tests for every optional-field combination.
- `tests/e2e/quickstart.sh` runs end-to-end on a clean Linux environment in under 30 minutes, emitting a label that the included local consumer test harness verifies.

### 16.2 Release-readiness signals (soft gates)

These are not pass/fail but are explicitly checked before cutting a release candidate:

- **First external installer.** One named person other than Chrys has installed Cairn from a release-candidate branch and successfully emitted a verifying label. Name the person before the README-quickstart issue in §21 (the first-external-installer issue); brief them on what to test; give them an ETA. Their feedback is a pre-release gate against a branch, not a post-release verification against `main`.
- **Adversarial review cycles have all been run and findings resolved to author satisfaction.** "Resolved" means: addressed in the doc or code, explicitly declined with a recorded rationale, or deferred to a v1.1+ issue with a link. Each round's findings are tracked as a crosslink issue so the disposition is visible.
- **Production Checklist dry-run.** Chrys themselves (or the first external installer, if that's arranged) has walked through the Production Checklist end-to-end against a fresh deployment. This is the stopwatch for the 30-minute quickstart plus the full operator-hardening path.

The signals exist because they're real release-quality indicators. They are soft gates because each depends on external people or judgment that cannot be made fully mechanical. Labeling them as soft rather than hard keeps the release-decision honest: if the external tester never appears, the release-decision is Chrys's call, not an indefinite wait.

## 17. Open Questions

1. ~~Crate name at publish time.~~ **Settled:** `cairn-labeler` on crates.io (bare `cairn` is squatted); binary name remains `cairn` via `[[bin]]` target.
2. Retention default tuning (180 days is a first guess).
3. Report rate limit (10/hour/DID is a first guess).
4. Transparency-record format for v1.1 (decided before v1.1 kickoff).
5. When to split into workspace crates (not in v1).
6. **First external installer identity.** Named before the README-quickstart issue in §21 is started; preferably a Guild member or ATProto-Rust community member with the context to give useful feedback.

## 18. v1.1 Roadmap

- Webhook signal intake.
- Review queue with distinct workflows for signal items vs. reports.
- Source management with negation-on-revocation default.
- Report encryption at rest (AES-256-GCM-SIV, per-report DEKs, rotatable master key).
- Label expiry enforcement job.
- Signing key rotation procedure (with DID doc update, audit, and consumer-observation grace period).
- Moderator/role management XRPC.
- Audit log hash-chaining + transparency records.
- PLC operations-log subscription.
- Cross-language interop tests (TypeScript consumer).
- Multi-label-per-frame batching in `subscribeLabels`.
- Observability surface: `/metrics` Prometheus endpoint (labels emitted, reports received, subscriber count, DID resolution failure rate, auth rejection rate by cause), health-check endpoint suitable for load-balancer probes, structured-log conventions.

**Scope discipline:** v1 ships before v1.1 work begins.

## 19. Release Runbook

Cairn is a single-maintainer project. The release procedure minimizes the number of simultaneous moving parts and makes every step reversible (where possible) or pre-verified (where not).

### 19.1 Pre-release (1 week before target date)

1. **All hard gates (§16.1) pass on `main`.**
2. **All soft gates (§16.2) checked.** First external installer has tested a release-candidate branch. Adversarial findings resolved or explicitly deferred.
3. **Cargo.toml metadata complete:** `description`, `license` (MIT OR Apache-2.0 — matching `proto-blue` and Rust ecosystem norm), `repository`, `homepage`, `documentation`, `readme`, `keywords`, `categories`. `include` explicitly lists `src/**`, `migrations/**`, `lexicons/**`, `contrib/**`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`.
4. **`cargo publish --dry-run` succeeds.** Inspect the generated `.crate` file contents; confirm no stray large assets and no secrets.
5. **CHANGELOG.md v1.0.0 entry drafted.** Following Keep a Changelog format.
6. **Announcement post drafts prepared** for target surfaces (Bluesky post at minimum; potentially Guild channel, no HN post in week 1). **Announcement drafts exist but are NOT pre-scheduled** — posting must be a manual step on release day, after the publish completes. This prevents the failure mode of announcements going live while publish is still failing.
7. **GitHub issue templates in place:** bug report, feature request, and a redirect-to-SECURITY.md for vulnerability reports.
8. **SECURITY.md published** (see §20).
9. **Tag created but not pushed.** `git tag -s v1.0.0` (signed tag using the SSH signing key established at repo init).

### 19.2 Release day

Order of operations (each step waits for the previous to succeed):

1. **`cargo publish`.** Crate goes to crates.io. Verify published page loads.
2. **Push tag.** `git push origin v1.0.0`. Triggers the GitHub Actions release workflow.
3. **CI builds binaries** for each target. Wait for completion. Verify every target produced a binary.
4. **GitHub Release published.** Release notes attach binaries + SHA-256 checksums. Uses CHANGELOG v1.0.0 entry as the body.
5. **`cairn.tools` deployed.** Install instructions point at the now-published version. `.well-known/lexicons/` bundle live.
6. **Announcement posted** to prepared surfaces.
7. **Post-release issue opened in crosslink** for tracking any week-1 feedback and hotfix coordination.

### 19.3 Failure modes and rollback

- **`cargo publish` fails** (missing metadata, name taken, etc.): fix, bump to `1.0.1` if the registry recorded a partial attempt (rare), re-run `--dry-run`, re-publish. The failed `1.0.0` attempt on crates.io cannot be retried — if any bytes were accepted, `1.0.0` is consumed.
- **Binary build fails on one target:** either delay release until fixed, or ship without that target and document the gap. Do not publish a GitHub Release with incomplete binaries and fill them in later — users who downloaded during the gap have mismatched versions.
- **Post-publish critical bug discovered:** `cargo yank --version 1.0.0` immediately. Yanking does not delete but prevents new dependents. Investigate, prepare `1.0.1`, publish the fix. Document the issue and the fix in the next release notes honestly.
- **Announcement went out before publish completed:** acknowledge openly. Fix the publish, note the timeline in the announcement thread.

### 19.4 Week-1 post-release

1. Monitor GitHub issues daily.
2. Check crosslink for logged issue patterns.
3. Respond to security-sensitive reports within 48 hours (see §20 SLA).
4. Defer non-urgent feature requests to v1.1 planning, not same-week fixes.
5. Hold a retrospective entry in crosslink: what slipped, what worked, what v1.1 needs.

## 20. Maintenance & Disclosure

Cairn is a solo-maintained project with a real dependency chain (Hideaway, future community labelers). This section exists to set expectations for maintenance burden, disclosure processes, and what "unmaintained" would mean.

### 20.1 Security disclosure (SECURITY.md)

A `SECURITY.md` at the repo root contains:

- **Contact:** a dedicated email address (not a personal one) — e.g., `security@cairn.tools`. Email forwarding to the maintainer is configured via the domain registrar.
- **Disclosure timeline:** acknowledge within 48 hours. Coordinated-disclosure period of 90 days by default, negotiable.
- **Scope:** signing-key handling, auth verification paths, label-integrity issues, DoS vectors affecting operators. Report-content leaks. Anything in §12.
- **Out of scope:** bugs in dependencies (report upstream); issues only reachable via operator negligence (host compromise, leaked config).
- **Response:** fix in next patch release; yank affected versions if severity warrants; publish an advisory via GitHub's security-advisory mechanism.

### 20.2 Issue-triage SLA (informal)

- **Security reports:** 48-hour acknowledgment, same-week fix for CRITICAL.
- **Bug reports:** weekly triage, fix cadence depends on severity.
- **Feature requests:** best-effort, batched into v1.x releases.
- **PRs:** reviewed within a week if CI-green and aligned with scope.

### 20.3 Semver and schema-migration commitment

Per §14: library/CLI/XRPC surface follows semver. DB migrations run automatically on upgrade. Breaking changes require a major version bump.

### 20.4 Maintenance handoff

If the project is unmaintained for six months (no commits, no issue responses), a MAINTAINERS.md in the repo names a fallback path: preference to transfer ownership to a named Guild or ATProto-Rust community member if they accept. Better than silent abandonment. The specific handoff target is TBD and will be named before v1.0 release.

## 21. Decomposition Sketch (for Crosslink)

Epic: **Cairn v1.0**

Issues, in dependency order. Estimates are in "evenings" (~2-3 focused hours each) and are honest rather than aspirational.

1. **Scaffolding** (1 evening): crate, CI, error types, config loading, key-material newtype.
2. **Storage schema + migrations** (1 evening): all tables from §10 architecture.
3. **Writer task + LabelService apply/negate + sequence + `cts`-monotonicity clamp + instance lease** (2 evenings — F5, F6, §6.1).
4. **Canonical encoding + signing + parity corpus** (3–4 evenings — F2, §6.2). **This issue is the highest-risk in the plan.** RFC 6979, low-S, SHA-256, raw 64-byte compact; parity corpus at `tests/fixtures/signature-corpus/` regenerated from a pinned `@atproto/api` version. DRISL edge-case debugging (map-key byte ordering, integer-encoding boundaries, optional-field absence) is the specific risk. **Estimate assumes proto-blue's DRISL is parity-correct with `@atproto/api`; if a divergence surfaces, budget +1 week to resolve either upstream or via vendoring.**
5. **`queryLabels` endpoint** (1 evening — F3): sources filter, uriPatterns validation, limit/cursor, CORS.
6. **`subscribeLabels` endpoint** (3 evenings — F4): frame format, cursor semantics, `#labels` + `#info`, `FutureCursor` error, retention, per-IP caps, backfill batching.
7. **Labeler service record publication** (1 evening — F1, §6.4): idempotency (excluding `createdAt` from hash), swap-race fail-start.
8. **CLI: `cairn label` commands** (1 evening — F9 subset): including `--cid`.
9. **Audit log core** (1 evening — F10): trigger documented as correctness defense.
10. **Auth: JWT + DID resolution** (4–5 evenings — §5): alg allowlist, structural checks, DID doc caching with Multikey decoding and `did:web` path-component handling (the non-obvious subtlety), `jti` replay cache with LRU eviction.
11. **Lexicon definitions** (1 evening — §8): all custom errors declared in `errors` arrays; query vs. procedure input shapes correct.
12. **Admin XRPC: label endpoints** (1 evening — F12 subset): `lxm` check on resolved method name.
13. **Report intake** (2 evenings — F11): service auth, response shape per spec, `reasonType` enum validation, body cap, pending cap, disk guard, CORS rejection, suppression.
14. **Admin XRPC: report endpoints including `flagReporter`** (1 evening — F12 subset).
15. **CLI: `cairn report`, `cairn login`** (1 evening — F9 subset).
16. **Admin XRPC: `listAuditLog` + CLI `cairn audit`** (half an evening — F12 subset).
17. **Embedded lexicon bundle + `.well-known/lexicons/` endpoint** (half an evening — F12, §8).
18. **`contrib/`** (half an evening — F13): Caddyfile, nginx.conf, systemd service file.
19. **README (quickstart + install)** (1 evening): explicit step-by-step; tested against `tests/e2e/quickstart.sh`.
20. **README (Production Checklist + trust-chain disclosures + network rate-limit guidance)** (1 evening).
21. **Rustdoc pass** (1 evening): every public item commented; `cargo doc --no-deps --all-features` clean.
22. **`examples/` directory** (1 evening): minimum 2 example programs demonstrating common flows.
23. **`cairn.tools` landing page** (1 evening): GitHub Pages, install instructions, link to docs, `.well-known/lexicons/` routing.
24. **OSS table-stakes files** (1 evening): LICENSE-MIT + LICENSE-APACHE, CONTRIBUTING.md, CODE_OF_CONDUCT.md (Contributor Covenant), SECURITY.md, CHANGELOG.md (Keep a Changelog format with v1.0.0 entry skeleton), issue templates, MAINTAINERS.md.
25. **Adversarial review rounds 4 and 5 follow-up fixes** — *already complete before implementation began; merged into this doc. Included here for historical completeness, not as an open issue.*
26. **CI hardening** (1 evening): verify release workflow on clean runners for every target; `cargo sqlx prepare --check`; dry-run the release procedure on a test tag.
27. **Release workflow** (1–2 evenings — see §19): GitHub Actions, binary builds with checksums, crates.io publish with `--dry-run` first, `cairn.tools` deploy, announcement post drafts, rollback procedure documented.

**Total evening estimate:** ~34–40 evenings. At 5 evenings/week: **7–8 weeks of focused work.** Realistic, given the Firehose-consumer-and-VKS velocity baseline. Issue #4 is the most likely source of slippage — a DRISL parity divergence could add a week. Budget accordingly rather than pad every estimate.

**Rounds 1–3 are complete** (design-doc reviews; findings folded into the doc you're reading). They are not open issues and are noted here for historical completeness only.