# cairn-mod — Design Doc

**Project:** `cairn`
**Tagline:** A lightweight, Rust-native ATProto labeler with a clean path from Skyware-scope to Ozone-scope.
**Domain:** cairn.tools
**NSID:** `tools.cairn.*`
**Language:** Rust
**Status:** Draft
**Methodology:** VDD/IAR
**Author:** skydeval

---

## 1. Problem

The ATProto labeler ecosystem has two existing options and a gap between them.

**Ozone** is Bluesky's official labeling service. It's TypeScript, ships with a full Next.js web UI, runs on PostgreSQL, and is designed for operators running moderation at network scale. It's powerful but heavy — installing it is non-trivial, and its feature surface is far larger than most community labelers need. It's also tightly coupled to the `tools.ozone.*` namespace and its own opinionated workflows.

**Skyware's labeler** (TypeScript, `@skyware/labeler`) is the opposite: a minimal library that implements the core labeler endpoints and nothing else. It's used when Ozone is overkill. But "nothing else" leaves real gaps — no report intake, no admin API beyond the library's internal methods, no audit trail. Skyware gets you protocol-compliant; it doesn't get you a working moderation pipeline.

In Rust, there is nothing. `atrium-api` and `jacquard` cover the general XRPC surface including label subscription as a consumer, but no standalone labeler server library exists. Rust ATProto infrastructure is growing (Blacksky's `rsky`, Doll's `proto-blue` SDK and Aurora-Locus PDS, Aurora-Prism AppView), and the lack of a Rust labeler is an increasingly visible gap.

cairn-mod fills that gap with a deliberately different shape from either Ozone or Skyware.

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

**cairn-mod's niche:**
- Rust-native: single statically-linked binary, SQLite storage, deploys to any VPS with one file.
- Report intake from day one (unlike Skyware).
- Audit trail as a first-class primitive (unlike Skyware).
- Compact admin XRPC surface for programmatic use by CLI, future web UIs, or integration with other systems.
- Roadmap to signal intake, review queue, and richer admin API — without cramming them into v1.

**Release strategy:** cairn-mod v1 is the minimal shippable labeler — protocol-correct, auditable, with real report intake and a clean admin surface. It is deliberately scoped smaller than Ozone. Subsequent releases expand toward Ozone-feature-parity territory (review queue, takedowns, team management, web UI) guided by real v1 usage, not speculative design. Shipping v1 on time matters more than shipping a complete tool late; the v1.1+ roadmap is where ambition lives.

## 3. Solution (v1)

cairn-mod v1 is a standalone labeler server with **two intake paths** and one outbound protocol surface.

**Intake paths:**
1. **Direct moderator action** (CLI or admin XRPC): a human decides, cairn-mod records and emits.
2. **User reports** (`com.atproto.moderation.createReport`): a user flags content; it lands in a report inbox for moderator review.

**Outbound protocol surface:**
- `com.atproto.label.queryLabels` (HTTP, public)
- `com.atproto.label.subscribeLabels` (WebSocket, public)
- Published `app.bsky.labeler.service` record (rkey `self`) declaring label definitions

All moderator actions — whether from CLI or XRPC — converge on the same **audit log**. Every label emitted can be traced back to the moderator who created it and the reason they gave.

## 4. Threat Model

cairn-mod is a public-side tool that touches moderation. The following threats are explicitly in scope, and cairn-mod is designed to address them.

1. **Moderator attribution is sensitive.** A public label that leaks "moderator did:plc:xyz decided this" creates harassment risk for moderators. cairn-mod exposes only the *labeler* DID in emitted labels; moderator identity is admin-API-only.
2. **Report content is sensitive.** Users reporting harassment or abuse trust the labeler to hold that content in confidence. Report bodies never appear in public endpoints and never in logs. Encryption at rest is deferred to v1.1; in v1, the documented boundary is that operators are trusted with their host.
3. **Audit trail must be preserved against accidental modification.** Every moderation action is logged with actor, timestamp, reason, and outcome — append-only at the application layer via SQL triggers. The trigger defends against bugs in cairn-mod's own code, not against direct DB tampering. Cryptographic tamper detection (hash-chaining) is a v1.1 feature.
4. **Labels are protocol-public by design.** cairn-mod emits labels cryptographically signed for network-wide consumption. It does not try to hide the labels themselves — that would break the whole protocol contract. The exposure discipline is about *metadata around labels*, not the labels themselves.
5. **Non-enumeration applies to resource lookups, not endpoint discoverability.** Admin endpoints return documented XRPC errors (`AuthenticationRequired`, `Forbidden`) at the endpoint level. Specific *resource lookups* by opaque ID return `NotFound` when the caller lacks authorization to know.
6. **Moderator → cairn-mod authentication uses ATProto service auth.** See §5.
7. **Report intake is authenticated.** Reports are submitted only by callers who can prove a DID via service auth. Anonymous reports are not accepted in v1.
8. **Denial-of-service via expensive inputs is mitigated by rate limits and caps.** Per-DID rate limits, global ceilings on pending reports, report body size caps, per-IP WebSocket connection caps, bounded replay retention. See §11.

### 4.1 Out-of-scope threats

The following are **not** defended against and must be mitigated by operational practice:

1. **Malicious operator.** cairn-mod does not defend against the operator of its host. The operator has the signing key, the database, and the config; they can emit arbitrary labels, modify the audit log, or forge historical records.
2. **Host compromise.** If the host is compromised, the signing key and session state are compromised.
3. **Privileged network observer on cairn-mod's host path.** Outbound DNS/HTTPS traffic from cairn-mod's host can be correlated to admin actions.
4. **Compromised moderator PDS session.** ATProto service auth means a valid PDS session on a moderator's account can mint service-auth JWTs against cairn-mod. See §5.2.
5. **Time-correlation attacks against moderator identity.** An observer correlating label emission timestamps with a moderator's public Bluesky activity can probabilistically link labels to moderators. Inherent to any useful audit trail.
6. **Signing key accidentally removed from DID document.** If an operator removes the labeler's signing key (verification method `#atproto_label`) from the DID document, all historical labels signed with that key will fail to verify at consumers — catastrophic for the labeler's credibility. Operators must never remove a labeler signing key from the DID document without first rotating (v1.1) and allowing consumers time to observe both keys.

### 4.2 Operator-trust trust-chain (README audience)

Subscribers of a cairn-mod-hosted labeler should understand:

1. **Labels are trusted by communities to the extent the operator is trusted.** A subscriber to `did:plc:some-cairn-labeler` is trusting the operator's current and past judgment. If the operator silently swaps intent (becomes malicious, sells the DID, is compromised) there is no protocol-level mechanism for subscribers to detect this.
2. **Historical labels can be forged by a malicious operator with DB access.** v1's audit log is not cryptographically linked to the labels table. v1.1's hash-chaining audit log is a prerequisite (but not sufficient) for historical-label integrity.
3. **One operator per instance is a single point of compromise for that labeler.** Operators who want to reduce this risk should consider publishing transparency records (e.g., a monthly signed Merkle root of the audit log to the labeler's PDS). Out of scope for v1 but enabled by v1.1's hash-chaining.
4. **Operators set their own moderation policy.** cairn-mod's strike-calculation rules — base weights per reason, dampening curve, decay function, good-standing threshold, cache freshness window — live in operator config (see §F20.2 / §F20.3 / §F20.4 / §F20.9). Operators can verify their own labeler's behavior against their declared policy by reading the config alongside the audit log; subscribers comparing two cairn-mod-hosted labelers can observe policy variation directly (a labeler weighting `hate-speech` at 4 strikes is not the same as one weighting it at 8, and that difference is visible from operator config alone, not hidden behavior). The trade-off is symmetric: operators can be permissive or inconsistent, and cairn-mod does not enforce a single moderation philosophy. cairn-mod's contribution is making policy declarable and observable, not adjudicating what the policy should be.
5. **Internal moderation state and protocol-visible labels are different surfaces, both observable.** cairn-mod's account moderation state model (§F20) records actions in cairn-mod's own database; the label emission system (§F21) translates those actions into ATProto labels that AppViews and other consumers can honor or ignore. The translation rules — which action types emit which labels, with what severity and expiry — live in operator config (`[label_emission]`; see §F21.1 for the default mapping table and override knobs). They are observable on both sides: operators read config alongside the audit log to verify their own labeler's emission, and subscribers comparing two cairn-mod-hosted labelers can see policy variation in both layers (action recording AND label emission). Operators retain the same latitude as disclosure 4: a deployment may emit `!hideaway-takedown` instead of `!takedown`, gate warnings on or off, customize blurs and locales — all visible from config. The invariant cairn-mod enforces is that *every recorded action either emits or explicitly doesn't*, and that revocation atomically negates whatever was emitted. Notes never emit (defense-in-depth at the resolver, regardless of operator override attempts). cairn-mod's contribution is making the translation declarable and observable, not adjudicating what the mapping should be.
6. **Pending action visibility is moderator-tier only.** cairn-mod's public read endpoints (`tools.cairn.public.getMyStrikeState`, with `activeLabels` per §F21.8) surface the labels actually emitted but do not surface pending actions awaiting moderator review. Subscribers see what cairn-mod has *done* — actions on the wire — not what cairn-mod *might* do. Operators retain pending visibility via the admin XRPC + CLI (§F22.10); subjects do not. Reasoning: pending action info isn't actionable for the subject (they cannot defend themselves against a moderator's pending review they don't know exists), pre-emptive disclosure creates pressure on moderators reviewing flags, and cairn-mod's transparency posture has limits — this is one of them. Operators who want subjects to see pending state explicitly (e.g., for a "you're on review; here's what for" workflow) can build that surface on top of the admin endpoints — cairn-mod ships the substrate, not the UX.

## 5. Authentication Model

### 5.1 Labeler service identity

cairn-mod runs on behalf of a **service DID** — a DID with a PDS account, an `app.bsky.labeler.service` record (rkey `self`) declaring what cairn-mod labels, and a cryptographic signing key published in the DID document at verification method `#atproto_label`.

The signing key is k256 (secp256k1), per the ATProto crypto spec. Per spec, "this key may have the same value as the `#atproto` signing key used for repository signatures"; operators may choose to share or separate these keys.

The service DID and signing key are configured once at deployment:
- The DID is declared in config.
- **The signing key's private material is loaded from a file on disk only.** Env-var key material is explicitly rejected.
- On load, cairn-mod verifies the key file has mode `0600` and is owned by the running user; cairn-mod refuses to start if the file is group- or world-readable.
- The key type has a custom `Debug` impl that redacts, is not `Serialize`, and uses `zeroize` on drop. Enforced by newtype wrapping.
- The private key is never written to disk after load, never logged, never included in any error message or response body.
- cairn-mod does not handle PLC operations itself.

### 5.2 Moderator authentication via service auth

Moderators authenticate to cairn-mod's admin endpoints using **ATProto service auth** tokens signed by their repo signing key (verification method `#atproto`).

The flow:

1. The moderator's client obtains a short-lived service auth JWT from the moderator's PDS via `com.atproto.server.getServiceAuth` (or equivalent), signed with the moderator's repo signing key, with:
   - `iss`: moderator's DID
   - `aud`: cairn-mod's service DID
   - `exp`: short-lived (≤60s from issuance)
   - `iat`: issuance timestamp
   - `jti`: unique JWT identifier (for replay protection)
   - `lxm`: the resolved lexicon method name of the cairn-mod admin endpoint being called (e.g., `tools.cairn.admin.applyLabel`)
2. The client sends this JWT as a `Bearer` token in the `Authorization` header.
3. cairn-mod verifies the JWT in this specific order:
   - **Algorithm allowlist:** the JWT `alg` header must be `ES256K`. Any other algorithm — including `none`, `HS256`, `ES256` (P-256 is not the repo signing key algorithm for most ATProto accounts) — is rejected immediately.
   - **Structural:** JWT is well-formed with all expected claims (`iss`, `aud`, `exp`, `iat`, `jti`, `lxm`) present.
   - **Signature:** Resolve the `iss` DID document (see §5.4), extract the key at verification method `#atproto`, verify the signature (constant-time). Signature check happens before claim checks to prevent token-scanning via error timing.
   - **Claims:** `aud` matches cairn-mod's service DID exactly. `exp` is in the future (with ±30s clock skew tolerance). `iat` is not more than 30s in the future. `lxm` matches the **resolved lexicon method name** for the endpoint being called (not the raw URL path).
   - **Replay check:** `jti` is not present in the replay cache (see below).
   - **Authorization:** The verified `iss` DID is present in the `moderators` table and has the required role for the method.
4. Any check failure returns a generic `AuthenticationRequired` response with no details about which check failed.

**Replay protection:** cairn-mod maintains an in-memory replay cache of `(iss, jti)` pairs with TTL equal to the token's remaining validity (bounded by max-`exp` window of 90s including skew). Presenting a JWT whose `jti` is already in the cache is rejected. **Cache size is capped at 100,000 entries with LRU eviction.** If an eviction would drop a `jti` whose TTL has not yet expired, that `jti` loses replay protection for the remainder of its TTL — an acceptable trade-off given that (a) admin call rates on a typical labeler are far below 100k/90s, and (b) even with eviction an attacker must intercept a live JWT to replay it, which is the same attack surface as the TTL window itself. This closes the 60-second replay window under normal load without unbounded memory growth.

**Inherent limitation (documented for moderators):** ATProto service auth derives moderator authority from the moderator's repo signing key, the same key used for all ATProto operations on their account. Anyone who can induce the moderator's PDS to sign a service-auth JWT — including via an app-password session — has the same authority as the moderator at cairn-mod. **Moderators should use short-lived, frequently-rotated app passwords and treat them as cairn-mod credentials.** This is a property of ATProto service auth, not a cairn-mod-specific flaw.

### 5.3 CLI ergonomics

The cairn-mod CLI (`cairn`) exposes subcommands that internally construct service auth tokens. The moderator configures once:

```
cairn config set moderator.did did:plc:xyz
cairn config set moderator.pds https://bsky.social
cairn login
```

The `login` flow prompts for a PDS app password, obtains a PDS session, and stores the session file at `$XDG_CONFIG_HOME/cairn/session.json` with mode `0600`. cairn-mod refuses to read the session file if it has broader permissions or is owned by a different user.

Then CLI commands work without further prompting. The CLI obtains a fresh service auth JWT per admin call, including a random `jti` for replay protection. At `login` time, cairn-mod warns the operator that the session file is a moderator credential equivalent to their PDS app password and should be protected accordingly.

For scripted/CI use, a long-lived PDS session can be provided via `CAIRN_SESSION_FILE`.

### 5.4 DID document caching and revocation

Verifying service auth requires resolving the caller's DID document.

- **Positive cache TTL: 60 seconds.** Matches service auth `exp` window.
- **Negative cache TTL: 5 seconds.**
- **Cache is in-memory only**, keyed by DID.
- On cache miss, resolve via:
  - **`did:plc`:** `GET https://plc.directory/{did}` over HTTPS with TLS verification. (Config option `plc.directory_url` allows pointing at a mirror.)
  - **`did:web`:** per the did:web spec. For a DID with no path component (`did:web:example.com`), resolve at `https://example.com/.well-known/did.json`. For a DID with path components (`did:web:example.com:users:alice`), resolve at `https://example.com/users/alice/did.json` — **no `.well-known` component**. cairn-mod's did:web resolver must handle both forms correctly.
- On resolution failure (network error, TLS error, non-2xx response, malformed response): **fail closed**. Request rejected with `AuthenticationRequired`. Failure is negatively cached. Failure is logged at `warn` level.
- Verification method selection: cairn-mod looks in the DID document's `verificationMethod` array and matches by the fragment ID (`#atproto` for moderator repo keys; `#atproto_label` for labeler signing keys). Keys are published as `Multikey` verification methods with `publicKeyMultibase` encoding; cairn-mod decodes this format to obtain the k256 public key.
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

**Field enforcement in cairn-mod v1:**

- `ver` is always `1` and is always present in the label, both in the signed bytes and in the wire format.
- `src` is always cairn-mod's configured service DID.
- `uri` is validated as a well-formed AT-URI or DID at intake. Malformed returns `InvalidRequest`.
- `cid` is optional at the CLI and XRPC. `cairn label apply <subject> <value> [--cid <cid>]` accepts a CID. When present, the label is record-version-pinned; when absent, the label applies at the repo or record-collection level per the URI's shape.
- `val` is treated as case-sensitive, stored and emitted verbatim, never normalized. The 128-byte length cap is validated at intake (rejected with `InvalidRequest` if exceeded).
- `neg` defaults to false; negation events set `neg: true` explicitly.
- `cts` is monotonic: cairn-mod guarantees that within a given `(src, uri, val)` tuple, each event (apply or negate) has `cts` strictly greater than the prior event's `cts` for that tuple. This is enforced by clamping to `max(wall_clock_now, prior_cts + 1ms)` at emission time, protecting against wall-clock regression (NTP adjustments, system clock changes). `cts` is serialized with millisecond precision and `Z` timezone (e.g., `2026-04-22T14:32:17.938Z`). cairn-mod emits `cts` only in `Z` form in v1; consumers that sort by lexicographic string comparison will work correctly as a result, but cairn-mod does not commit to this as a wire-protocol invariant — consumers should parse `cts` as RFC 3339 datetime and compare semantically. **Implication for rapid same-tuple re-emission:** the 1ms clamp means a single tuple can emit at most 1000 events/sec; rapid re-labels within that window will produce `cts` values slightly ahead of wall clock. This is spec-legal and is the correct behavior — `cts` is a labeler-assigned timestamp, not a wall-clock guarantee.
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

If cairn-mod's emission diverges from this process at any step, consumers reject the label. This is why §6.2 is precise.

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

Bluesky's `com.atproto.label.defs` declares a set of well-known global label values: `!hide`, `!no-promote`, `!warn`, `!no-unauthenticated`, `dmca-violation`, `doxxing`, `porn`, `sexual`, `nudity`, `nsfl`, `gore`. Labelers may emit these with their spec-defined semantics; they are **not** redefined by cairn-mod's `labelValueDefinitions`. If an operator's config lists a global value, cairn-mod treats it as a declaration-of-intent to emit that well-known value with its standard meaning. Custom `labelValueDefinitions` should use non-colliding values.

### 6.6 Rate limits (inherited from the network)

Bluesky's labeler rate-limit guidance (observed, not spec): **5 labels/second, 5000/hour, 50000/day.** cairn-mod does not enforce these internally (an operator can exceed them if their PDS/AppView tolerates it), but the README includes them as operational guidance.

## 7. Features

Every feature has verification criteria. The criteria are the VDD contract: a feature is not "done" until the criteria pass.

### F1. Labeler service declaration

Publish an `app.bsky.labeler.service` record to the labeler's own PDS at rkey `self`.

**Verification:**
- Config file defines label values and their definitions (identifier, severity, blurs, locales with at least one entry per definition).
- On startup, cairn-mod renders the service record per §6.4 and publishes it with `rkey: self`.
- Record validates against `app.bsky.labeler.service` lexicon via `atrium-api` parsing.
- **Idempotency:** cairn-mod computes a content hash of the rendered record excluding `createdAt`. If the hash matches the currently-published record's content hash (also computed excluding `createdAt`), no write occurs. `createdAt` is preserved from the prior record when content is unchanged.
- Any structural change (new label value, changed severity, added locale, etc.) triggers `swapRecord` with the prior CID.
- **Swap race handling:** if `swapRecord` fails because the prior CID no longer matches, cairn-mod **refuses to start** with an error directing the operator to ensure only one cairn-mod instance runs per labeler DID. No automatic retry loop.
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
  - cairn-mod must produce byte-identical CBOR and byte-identical signatures for the corpus inputs using the corpus's test key material.
- Signature validation tests: valid signature verifies, tampered label fails, wrong-key fails, high-S emission is rejected at emit time, `@atproto/api`-produced signatures verify in cairn-mod's verifier code path.
- Signing key type constraints from §5.1 (redacting Debug, no Serialize, zeroize on drop) are enforced as compile-time invariants via newtype wrapping.

### F3. `com.atproto.label.queryLabels` endpoint

**Verification:**
- `uriPatterns` parameter is **required** (per lexicon). Missing or empty-array returns `InvalidRequest`.
- `uriPatterns` glob semantics: trailing `*` means prefix match; absence of `*` means exact match. `*` anywhere other than trailing position is treated as a literal character (matching Ozone's behavior).
- `sources` parameter, if provided, filters by label source. cairn-mod filters results to labels where `src = cairn-mod's service DID`; if `sources` is provided and does not include cairn-mod's DID, return an empty `labels` array (not an error).
- `limit` default is 50, maximum 250 (per spec). Values outside [1, 250] return `InvalidRequest`.
- `cursor` is an opaque string to the client; internally cairn-mod uses a format distinct from the `subscribeLabels` sequence number.
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
- `#info` message body shape: `{name: string, message?: string}`. The only `name` cairn-mod emits is `OutdatedCursor` (per Bluesky convention).

**Cursor semantics (matching Ozone / Lexinomicon):**
- If `cursor` is omitted: start streaming live from current head. No replay.
- If `cursor` is an integer ≤ 0 or less than the oldest retained seq: send an `#info` frame with `name: OutdatedCursor` containing the oldest retained seq in the optional `message`, then begin streaming from the oldest retained seq.
- If `cursor` is a non-negative integer ≤ current head seq: begin streaming from frames where `seq > cursor`.
- If `cursor` is a non-negative integer greater than current head seq: send an error frame with `error: "FutureCursor"` and close the connection.
- If `cursor` fails to parse as a signed 64-bit integer (non-integer string, empty string, value outside i64 range): close the WebSocket with close code `1008` (policy violation). No `FutureCursor` error frame is sent — the cursor isn't future, it's invalid, and `FutureCursor` is reserved for the specific "cursor exceeds head" case.

**Per-frame semantics:**
- In v1, cairn-mod emits one label per frame (frame's `labels` array contains exactly one label). This is the simplest behavior and matches current Ozone output. Batching multiple labels per frame is a v1.1 possibility for throughput; v1 consumers must tolerate either.
- Frames are emitted in strictly increasing `seq` order within a single client connection.
- An apply event is excluded from replay if any later negation exists for the same `(src, uri, val)` tuple, regardless of subsequent re-applies. Each negation frame and each re-apply frame remains in replay at its own seq. This matches the spec: "Labels which have been redacted have the original label removed from the stream, but the negation remains."

**Retention:**
- Default: 180 days (rolling window). Older frames are dropped from the replay log.
- The cutoff lives in `[subscribe].retention_days` (`SubscribeConfig::retention_days`, source of truth — read by both `query_oldest_retained` and the sweep). `None` disables retention; the sweep then becomes a no-op.
- Sweep execution policy lives in `[retention]` (separate block per the C2 split): `sweep_enabled` (default `true`), `sweep_run_at_utc_hour` (0..=23, default 4 — quiet hour), `sweep_batch_size` (default 1000). Validated at config-load time; out-of-range values fail-start.
- The sweep runs through the writer task (§F5 single-writer invariant). `WriteCommand::Sweep` is dispatched ONE batch at a time so the writer's biased select can interleave Apply/Negate/ResolveReport between batches — sweep latency impact on normal writes is bounded by the per-batch DELETE cost (~ms on SQLite, even with 1000-row batches).
- Two trigger paths: (1) the writer's internal `sweep_check_timer` fires daily at the configured UTC hour, runs the sweep directly via `handle_sweep`, and emits INFO/ERROR tracing logs (no audit row — scheduled sweeps are maintenance, not moderation); (2) operator-initiated via `tools.cairn.admin.retentionSweep` (admin role only), which writes one `audit_log` row per call with `action = retention_sweep`, `actor_did = JWT iss`, and a JSON `reason` carrying `{rows_deleted, batches, duration_ms, retention_days_applied}`. The CLI surface is `cairn retention sweep`.
- Mid-run failure logs and exits the current run; batched DELETEs are naturally idempotent (no resumption cursor needed) — the next scheduled fire or the next manual run continues from whatever rows remain.
- The retention floor is computed by SQL filter (`WHERE created_at >= cutoff_ms`) rather than a stored marker, so sweep deletions do not move the floor — the read-side `OutdatedCursor` decision is invariant under sweep. `tests/writer.rs::sweep_does_not_change_subscriber_visible_floor` is the load-bearing assertion guarding this contract.

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
- Specifically: Ozone's own firehose output parses cleanly through cairn-mod's consumer code, and cairn-mod's output parses cleanly through `atrium-api`'s consumer code.

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
- Instance-lease test: starting a second cairn-mod against the same SQLite file while the first is running produces a clear error and non-zero exit code.

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

**Actions logged:** label applied, label negated, report resolved, reporter flagged/unflagged, moderator granted/revoked, signing key added, labeler service record published or updated, labeler service record unpublished, retention sweep (operator-initiated only — scheduled fires don't audit per §F4), subject action recorded, subject action revoked.

**Verification:**
- Every F1/F6/F9/F11 action produces exactly one audit entry.
- `TRIGGER BEFORE UPDATE/DELETE RAISE ABORT` on the audit_log table. **The trigger is a correctness defense, not a security defense.** Anyone with direct SQLite file access can drop the trigger, modify the DB, or replace the file. Cryptographic tamper detection (hash-chaining) is a v1.1 feature.
- Entries include: action type, actor DID, timestamps (seq + wall clock), target identifiers (including `cid` when relevant), outcome, reason string.
- Log never includes report body content, signal payloads (v1.1), or secret material.
- Audit log exposure of `(actor, timestamp, subject)` creates correlation risk (§4.1.5); inherent.

### F11. Report intake

Implements `com.atproto.moderation.createReport` per the lexicon.

**Authentication (required):**
- Service auth JWT required: `aud` = cairn-mod's service DID, `lxm` = `com.atproto.moderation.createReport`.
- JWT verification per §5.2 (including `alg: ES256K`, `jti` replay check).
- The verified `iss` is the report's authenticated source DID.
- Anonymous reports are rejected.

**Input validation:**
- `reasonType` is validated against the spec-defined enum: `com.atproto.moderation.defs#reasonSpam`, `#reasonViolation`, `#reasonMisleading`, `#reasonSexual`, `#reasonRude`, `#reasonOther`. Unknown values return `InvalidRequest`.
- `subject` must be one of:
  - `com.atproto.admin.defs#repoRef` (for account-level reports)
  - `com.atproto.repo.strongRef` (for record-level reports, including `uri` and `cid`)
- Subject existence is **not verified** at intake; cairn-mod accepts reports about subjects that may not exist (matching Ozone).
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
- **Every custom error name used by cairn-mod is declared in the `errors` array of the corresponding lexicon.** Custom errors used include: `LabelNotFound`, `ReportNotFound`, `ModeratorNotFound`, `InvalidLabelValue`. Standard XRPC errors (`AuthenticationRequired`, `InvalidRequest`, `InternalServerError`) are not re-declared.
- cairn-mod **does not** attempt to emit custom errors on Bluesky-owned lexicons (`subscribeLabels`, `queryLabels`, `createReport`) beyond what those lexicons declare.
- **Error name consistency:** `RateLimitExceeded` is used everywhere for rate-limit-style errors (cairn-mod does not use both `TooManyRequests` and `RateLimited`).
- Service auth on every admin endpoint. Unauth returns `AuthenticationRequired` (HTTP 401). Authed-but-unauthorized returns `Forbidden` (HTTP 403).
- Role-based authorization: `mod` can apply/negate/resolve/flagReporter; `admin` additionally accesses audit log.
- `NotFound` for resource-lookup-by-opaque-ID (e.g., `getReport` with unknown ID).
- Query endpoints use `parameters` (query-string) input; procedure endpoints use JSON body input.
- `tools.cairn.admin.defs` contains shared types (`#reportView`, `#auditEntry`, `#moderator`, etc.) referenced by other endpoints via `tools.cairn.admin.defs#<name>`.
- **Lexicon publishing:** lexicons are served at `https://cairn.tools/.well-known/lexicons/tools/cairn/admin/{name}.json`. **This is a cairn-mod convention, not a finalized ATProto spec** — lexicon resolution is under active RFC (bluesky-social/atproto#3074). The path is chosen for forward-compatibility with the well-known/HTTPS-based proposals. cairn-mod documents this clearly rather than claiming spec compliance for lexicon publishing.

### F13. Single binary + SQLite deployment

**Verification:**
- `cargo install cairn-mod` produces a working binary named `cairn`.
- First run creates the SQLite schema via embedded migrations.
- `contrib/` includes:
  - systemd service file template.
  - **Caddyfile** with: TLS termination, per-IP rate limits on `createReport` (burst 3, rate 10/hour), per-IP connection limits on `subscribeLabels` (8 concurrent), HSTS, no-cache headers for admin endpoints.
  - **nginx.conf** with equivalent protections.
- README has a separate **"Production Checklist"** section covering TLS, reverse-proxy rate limits, key file permissions, backup policy, monitoring, and the trust-chain disclosures from §4.2 prominently.
- Binary's static resources (migrations, lexicon bundle for `.well-known` endpoints) compiled in.
- Default port binding documented; cairn-mod expects reverse proxy for TLS.

### F14. Health and readiness probe endpoints (v1.1)

Two unauthenticated HTTP endpoints for orchestrator integration (Kubernetes livenessProbe / readinessProbe, systemd watchdogs, load-balancer health checks).

**`GET /health`** — liveness probe. Always returns 200 with `{"status": "ok", "version": "<crate version>"}` as long as the process can accept a connection and service a request. No dependencies are checked. A failing liveness probe means "restart the pod," so baking DB or writer checks into it would cause needless pod restarts on transient hiccups that `/ready` already handles by flipping traffic away.

**`GET /ready`** — readiness probe. Returns 200 on all-ok, 503 on any check failure. Body shape identical in both cases:

```json
{
  "status": "ok" | "degraded",
  "version": "<crate version>",
  "checks": {
    "database":     "ok" | "failed",
    "signing_key":  "ok" | "failed",
    "label_stream": "ok" | "degraded"
  }
}
```

**Why each check is meaningful:**

- **database** (`SELECT 1` against the SQLite pool). Every request path that writes a label, report, or audit row funnels through the pool; an unreachable pool means cairn-mod cannot serve traffic. `ok | failed` because the pool either executes a trivial query or it doesn't — there is no intermediate lagging state.
- **signing_key** (`signing_keys` table has at least one row with `valid_to IS NULL`). This matches `/.well-known/did.json`'s existing 503 semantics — without a signing key row, consumers cannot verify any label cairn-mod emits, so the service is not operationally ready. Using the same DB-row signal as did.json means both endpoints agree on "can we serve labels."
- **label_stream** (writer's `shutdown_signal` is `false` AND `server_instance_lease.last_heartbeat` is within `LEASE_STALE_MS` of now). Flipped to `degraded` if either condition fails. `LEASE_STALE_MS` (60s) is reused deliberately: the system already has one notion of "this writer is dead" at the lease-handoff boundary, and `/ready`'s degraded threshold aligns with it exactly. Two different thresholds would be inconsistent. The distinction between `failed` and `degraded` is load-bearing — a stream lagging past its heartbeat window is operationally distinct from a pool that cannot execute a query, and the type system preserves that distinction.

**Checks run in parallel** via `tokio::join!`; they are independent and the pool accepts concurrent reads.

**Known gap:** a writer task that is alive and heartbeating but internally wedged on processing `WriteCommand` messages would pass the label_stream check. Closing the gap would require adding a `Ping` WriteCommand variant so `/ready` could exercise the actual command path. Deferred as a v1.2+ consideration.

**Contract for orchestrator consumers:** `/health` failure → restart the pod; `/ready` 503 → stop routing new traffic, keep the pod alive long enough to surface the degraded state in logs + metrics. Both endpoints are cheap (one SQL round-trip max) and safe to probe as often as the orchestrator sees fit; no rate-limiting is applied.

**Verification:**

- `/health` returns 200 `{"status": "ok", "version": "..."}` against any running instance.
- `/ready` returns 200 with all `checks.*` = "ok" on a healthy instance.
- `/ready` returns 503 with `checks.database = "failed"` when the SQLite pool is unreachable.
- `/ready` returns 503 with `checks.signing_key = "failed"` when `signing_keys` has no active row.
- `/ready` returns 503 with `checks.label_stream = "degraded"` when the lease heartbeat is stale past `LEASE_STALE_MS`.
- Both endpoints are reachable without an `Authorization` header (unauthenticated by design).

### F15. Dependency security scanning in CI (v1.1)

Two tools enforce supply-chain posture on every change to `main` and a third trigger catches out-of-band advisory publications against already-pinned deps.

**Tools and triggers:**

- **`cargo-audit`** — scans `Cargo.lock` against the RustSec advisory database. Runs as a CI job on push to `main` + every PR; also runs on a daily `cron` schedule (`.github/workflows/security-audit.yml`) that opens a tracking issue when advisories fire. The scheduled run exists because the advisory DB updates out-of-band — a dep pinned today may have a new advisory tomorrow without any local commit.
- **`cargo-deny`** — runs four independent checks (advisories, licenses, bans, sources) configured by `deny.toml` at repo root. CI job on push to `main` + every PR.

Both tools are pinned to explicit versions (see CONTRIBUTING.md's **Security scanning tools** section — currently `cargo-audit 0.22.1` / `cargo-deny 0.19.4`). The pinning rationale: the scanner is part of the security posture, so its version should be auditable and change deliberately, not silently. Bumps are deliberate commits, not drive-bys.

**Hard-fail posture:**

All three jobs are blocking. Any advisory not explicitly ignored, any license outside the allowlist, any duplicate crate pattern marked `deny`, any non-crates.io source fails the gate. This was a v1.0 → v1.1 posture upgrade: #13 originally planned `continue-on-error` pending a triage policy; deferring the gate until the policy existed, then flipping to hard-fail once it did.

**Escape-hatch pattern for accepted risks:**

Hard-fail is only workable if there's a documented way to accept a specific risk. That mechanism is:

1. In `deny.toml`, add an entry to `[[advisories.ignore]]` with an `id` and a `reason` naming the risk, the reachability analysis, and the fix availability.
2. Add a `# Review: YYYY-MM-DD` comment above the entry with a date ≤ 180 days out. `cargo-deny 0.19` doesn't support a structured `expiration` field, so the review date lives in the comment form. A `grep -n 'Review:' deny.toml` is the human audit tool on each review cycle.
3. If the advisory also fires in `cargo-audit` (it may not — see asymmetry note below), add the ID to the `--ignore` flag in both `.github/workflows/ci.yml`'s audit step and `.github/workflows/security-audit.yml`'s audit step. IDs MUST mirror between the three locations; drift means one tool opens issues for risks another accepts.

**Tool asymmetry worth documenting:**

`cargo-deny` and `cargo-audit` share the RustSec advisory database but disagree on scope. `cargo-deny` respects Cargo feature flags when building its active-dep graph — dependencies gated behind features we don't enable are NOT evaluated for advisories. `cargo-audit` scans `Cargo.lock` unconditionally, flagging anything that's present regardless of feature activation. An advisory that appears ONLY in `cargo-audit` output belongs as an `--ignore` flag in the workflow YAMLs, NOT in `deny.toml`'s ignore list — adding it to `deny.toml` produces an `advisory-not-detected` warning. `deny.toml`'s comment header documents this so a future contributor doesn't re-derive it.

**Worked example — the rsa ignore:**

v1.1's CI launched with exactly one accepted advisory: [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (rsa 0.9.x Marvin timing sidechannel, medium severity, no fix available). `sqlx-macros-core` unconditionally imports all sqlx driver crates for macro expansion, including `sqlx-mysql` which transitively depends on `rsa`. cairn-mod builds `sqlx` with `default-features = false` and enables only `{ runtime-tokio, sqlite, macros, migrate }` — `sqlx-mysql`'s code never links into the binary. `cargo-deny` recognizes this via feature-flag analysis and stays silent; `cargo-audit` does not and flags the advisory. Ignore is applied in both `.github/workflows/ci.yml` and `.github/workflows/security-audit.yml`; `deny.toml`'s `ignore` list is empty and documents why.

**Scheduled-run issue behavior:**

When the daily scheduled `cargo-audit` fires on a new advisory, it opens an issue titled `Daily audit: advisories detected on main (YYYY-MM-DD)` with the `security` label and the full audit output as the body. Same-day re-runs gracefully noop because `gh issue create` refuses the duplicate title. Persistent advisories produce one issue per day until acknowledged + resolved (either fixed in a commit or added to the ignore list with dated rationale).

**Verification:**

- `cargo audit --deny warnings --ignore <IDs>` passes locally with the same `--ignore` list CI uses.
- `cargo deny check` passes all four categories locally.
- `deny.toml` contains an `ignore` comment header explaining the asymmetry with `cargo-audit`'s CLI flag.
- Every entry in `deny.toml`'s `[[advisories.ignore]]` has a `Review: YYYY-MM-DD` comment ≤ 180 days out.
- CI's `audit` and `deny` jobs block merges on any failure.
- The scheduled workflow's `gh issue create` has `issues: write` permission.

### F16. Moderator management CLI (v1.1)

`cairn moderator {add, remove, list}` — three one-shot subcommands for managing the `moderators` table from the host running cairn-mod. All three accept `--config <path>` with the same semantics as `cairn serve`, open the same SQLite DB, and exit immediately. They acquire **no** single-instance lease and so are safe to run while `cairn serve` is up against the same DB.

**Subcommands:**

```
cairn moderator add <did> --role <mod|admin> [--update-role] [--json] [--config <path>]
cairn moderator remove <did> [--force] [--json] [--config <path>]
cairn moderator list [--role <mod|admin>] [--json] [--config <path>]
```

**`add` semantics:**

- New DID → row inserted, role assigned, `added_at = now()`.
- Existing DID with the same role → no-op (`Unchanged`); not an error.
- Existing DID with a different role → `DuplicateBlocked` unless `--update-role` is set, in which case the role is overwritten and `RoleUpdated` is reported with the previous value.
- `DuplicateBlocked` is a USAGE-coded error (exit 2).

**`remove` semantics:**

- Existing DID → row deleted (`Removed`).
- Nonexistent DID → USAGE-coded error (exit 2). The "if it looks weird, tell the operator" posture rules out silent success.
- Last-admin guard: removing the only `admin`-role row is blocked unless `--force` is set. The guard checks the target's role + `count_admins()` before issuing the DELETE; the SELECT-then-DELETE window is acceptable for a one-shot CLI tool (no concurrent-CLI threat model). `--force` skips the check entirely; use it deliberately.

**`list` semantics:**

- No `--role` → all moderators.
- `--role mod` or `--role admin` → filtered set.
- Output ordered by `added_at ASC, did ASC` for deterministic consumption (tests + scripts pipe through `jq` reliably).

**`added_by` semantics (decision C):**

The `moderators.added_by` column is nullable. CLI-initiated inserts leave it `NULL` because the CLI has no attested caller identity — there is no JWT `iss`, no signed request, and the OS user the CLI runs as isn't a DID. Three options were considered and rejected:

- **Sentinel string `"cli"`**: violates the column's DID-shape semantic. A future audit query that joins `moderators.added_by` against the `did` column elsewhere would silently miss CLI-attributed rows.
- **Required `--added-by <did>` flag**: ceremonial for the bootstrap case (the operator hasn't even shipped a moderator yet). Optional flag: easy to forget, falls back to one of the above.
- **NULL** (chosen): honest — the column is meant for HTTP-admin attribution via JWT `iss`, and that semantic is preserved cleanly. Operators auditing membership history should read NULL as "added via CLI / direct DB write," not "unknown."

A regression test (`add_emits_null_added_by_from_cli`) pins this so a future "ergonomics" PR that introduces a default sentinel is caught explicitly.

**`--json` output contracts:**

- `add` → `{"action":"add","did":"...","role":"mod"|"admin","result":"inserted"|"role_updated"|"unchanged","previous_role":"..."}` (`previous_role` present only on `role_updated`).
- `remove` → `{"action":"remove","did":"...","result":"removed"}`. Failures (not found, last admin) emit human errors to stderr + USAGE exit; they do NOT emit a JSON line.
- `list` → JSON array of `{"did":"...","role":"...","added_by":"..."|null,"added_at":"<RFC 3339 UTC>"}`. Empty list → `[]`.

**Architectural note — shared `Role` type:**

The `Role` enum lives in `src/moderators.rs` (a neutral, non-server module) so both the HTTP admin auth path (`server::admin::common::verify_and_authorize`) and the CLI consume the same value set. The CLI's clap argument is a thin `RoleArg` wrapper with a `From<RoleArg> for Role` adapter — this keeps clap's `ValueEnum` derive out of non-CLI modules while preserving a 1:1 mapping that surfaces in any future PR that adds a role.

**Verification:**

- `cairn moderator add <did> --role mod` inserts a row with role=mod, `added_at` non-zero, `added_by IS NULL`.
- `cairn moderator add <did> --role admin` on an existing mod errors with USAGE; `--update-role` allows the change and reports the previous role.
- `cairn moderator remove <did>` on the only admin errors with USAGE; `--force` allows it.
- `cairn moderator list --json` is a JSON array; the per-row shape parses without coercion.
- All three subcommands work while `cairn serve` is running against the same DB (no lease conflict).

### F17. Report management CLI (v1.1)

Admin-side report workflow via `cairn report {list, view, resolve, flag, unflag}` (#7). All five subcommands wrap the `tools.cairn.admin.*` HTTP endpoints — they are NOT direct-DB tools.

**Architectural choice — HTTP over direct-DB.** Considered direct-DB during scoping (parallel to `cairn moderator`'s pattern from §F16) and rejected for three load-bearing reasons:

1. **Audit attribution.** The mutating subcommands (`resolve`, `flag`, `unflag`) write `audit_log` rows. HTTP path: server uses JWT `iss` → `actor_did` is the real moderator DID. Direct DB: no attested caller → `actor_did = NULL`, silently corrupting the audit trail for exactly the events operators most want to reconstruct.
2. **§F11 reason-leak invariant.** The server enforces "report body never returned by list-style endpoints" at the type level (`ReportListEntry` has no `reason` field; `ReportDetail` does). A direct-DB CLI would have to re-implement that invariant — a load-bearing duplication risk.
3. **No bootstrap problem.** `cairn moderator` is direct-DB because of bootstrap (no admin exists when reports are being processed, by definition admins exist). The chicken-and-egg argument that justifies direct-DB for `moderator` doesn't apply.

**Subcommands and the handlers they wrap:**

- `cairn report list [--status <s>] [--reported-by <did>] [--limit N] [--cursor <c>] [--json]`
  Wraps `tools.cairn.admin.listReports` (mod OR admin role). Returns the reason-less `ReportListEntry` projection per §F11.
- `cairn report view <id> [--json]`
  Wraps `tools.cairn.admin.getReport` (mod OR admin role). Returns `ReportDetail` with the reason body included — admin-authenticated access permits this per §F11.
- `cairn report resolve <id> [--apply-label-val <v> --apply-label-uri <u> [--apply-label-cid <c>] [--apply-label-exp <ts>]] [--reason <text>] [--json]`
  Wraps `tools.cairn.admin.resolveReport` (mod OR admin role). The `--apply-label-*` group is all-or-none — clap's `requires` attribute pairs `--apply-label-val` with `--apply-label-uri`. Omitting the group resolves without applying a label (the "dismiss" workflow); the schema has no separate `'dismissed'` status.
- `cairn report flag <did> [--reason <text>] [--json]`
- `cairn report unflag <did> [--reason <text>] [--json]`
  Both wrap `tools.cairn.admin.flagReporter` (mod OR admin role) with `suppressed: true` and `suppressed: false` respectively. Server audits as `reporter_flagged` / `reporter_unflagged`.

**Pagination.** `list` exposes `--cursor` and emits the next-cursor in both human (trailing `next cursor: ...` line) and JSON (top-level `cursor` field) output. Auto-pagination is deliberately out of scope; consumers chain calls themselves.

**Verification:**

- Each subcommand's `format_*_human` and `format_*_json` are pure functions of the typed response, tested without HTTP mocking.
- `tests/cli_report_admin.rs::resolve_with_label_applies_and_resolves` asserts `audit_log.actor_did = <moderator DID>` after resolve — the load-bearing attribution check.
- `tests/cli_report_admin.rs::list_returns_seeded_reports` asserts the JSON output contains no `reason` field, mirroring §F11's reason-leak invariant in test form.

### F18. Audit log CLI (v1.1)

`cairn audit list` (#6). Read-only inspection of the `audit_log` table via the `tools.cairn.admin.listAuditLog` HTTP endpoint.

**Admin role only.** Server uses `verify_and_authorize_admin_only`; moderators receive 403. The rationale: the audit log records moderator actions, and read access to the full set is reserved for admins to avoid the "moderators silently auditing one another" pattern.

**Subcommand:**

- `cairn audit list [--actor <did>] [--action <a>] [--outcome success|failure] [--since <rfc3339>] [--until <rfc3339>] [--limit N] [--cursor <c>] [--json]`

`--since` and `--until` are RFC-3339 strings on the wire; the server parses them via `parse_rfc3339_ms`. The CLI does no client-side conversion (server-side parser stays the source of truth).

**No `cairn audit show <id>`.** The corresponding `getAuditLog` HTTP endpoint doesn't exist; it's tracked as a separate v1.2 follow-up. v1.1 ships list-only.

**Read-only contract.** The `audit_log` table has SQL triggers that abort UPDATE and DELETE; the CLI surface mirrors this by exposing only a read operation. There is no `--force` flag or mutation path on this subcommand.

**Pagination.** Same shape as `cairn report list`: `--cursor` + emitted `next cursor` in both output formats.

**Verification:**

- `tests/cli_audit.rs::list_admin_only_moderator_role_receives_403` asserts the admin-only contract — seeds the moderator as `mod` (not `admin`) and confirms the 403 response.
- Each filter (`actor`, `action`, `outcome`) has its own happy-path test.
- `format_list_*` are pure-function tested with synthetic typed responses.

### F19. Service record verify on startup (v1.1)

`cairn serve` performs a verify-only check at startup before binding the HTTP listener (#8). The local `[labeler]` config is rendered into an `app.bsky.labeler.service` record body; its content-hash (excluding `createdAt` per §F1 idempotency) is compared against the published record fetched from `<operator.pds_url>/<service_did>` via the unauthenticated `com.atproto.repo.getRecord`. Drift / absent / unreachable each fail-start with a distinct exit code so orchestrators (and operators) can branch.

**Architectural choice — verify-only, not auto-publish.** Two paths were considered when #8 was scoped:

- **Path A (full auto-publish)**: serve startup calls into `publish_service_record::publish`, doing a PDS write if local drift is detected. Requires operator credentials on the serve host. Considered and rejected.
- **Path B (verify-only)**: serve startup does an unauthenticated read; mismatch → fail-start; reconciliation goes through the explicit `cairn publish-service-record` subcommand on the operator's host. Adopted.

Three load-bearing reasons the verify-only path won:

1. Identity-domain / label-emission separation. The labeler protocol distinguishes the operator (publishes records to the operator's PDS, owns the DID) from the labeler server (signs and broadcasts labels). Auto-publish blurs this — serve becomes a PDS writer, which means operator credentials live on the long-running serve host.
2. Explicit > implicit. Auto-publish hides operator intent: a config edit silently rewrites the published record on next restart. Verify-only surfaces the change as a fail-start, requiring the operator to deliberately publish via the existing CLI.
3. The `cairn publish-service-record` subcommand already exists as the explicit place for PDS mutations. Duplicating that capability into serve would create two write surfaces with overlapping but not identical preconditions.

**Failure modes and exit codes:**

| Code | `CliError` variant | Meaning |
|---|---|---|
| 12 | `ServiceRecordDrift { pds_url, service_did, summary }` | Record exists, content-hash differs |
| 13 | `ServiceRecordAbsent { pds_url, service_did }` | No record published yet |
| 14 | `ServiceRecordUnreachable { pds_url, cause }` | Could not reach PDS to fetch |

The codes intentionally separate transient infra failure (14, retry) from operator-action-required cases (12 + 13). `systemd` and orchestrator restart loops can branch.

**Drift summary.** The drift error message names which fields drifted — label values, definition count, reason types, subject types — with side-by-side local vs. published values. When all four match but content hashes differ, the message points at per-definition contents (severity / blurs / locales) as the drift surface to inspect. Not raw JSON dumps; human-readable enumeration.

**Labeler-absent narrow scope.** Configs without a `[labeler]` block skip verify with an info-log. NOT a general opt-out — operator-facing deployments declare a labeler. Test harnesses, embedders, and custom workflows that don't publish a service record are out of scope for the gate. `[labeler]` present + `[operator]` missing remains a fail-start (real misconfig, not a hole in the gate).

**Lease cleanup.** Verify happens after `spawn_writer` (lease acquired) and before HTTP bind. On verify failure, `writer.shutdown()` is called before returning the error so the `server_instance_lease` row is released; a subsequent startup attempt isn't blocked. Asserted in `tests/serve_verify.rs` via `COUNT(*) FROM server_instance_lease = 0` post-failure across all four failure-path tests.

**No opt-out flag.** v1.1 has no `--skip-verify` or equivalent. The whole point of the gate is to catch drift; a flag would re-introduce the drift class via forgetfulness. Decided explicitly during scoping; revisit only if a real emergency case surfaces post-launch.

**Implementation notes:**

- `service_record::content_hash_value(serde_json::Value)` was added alongside the existing `content_hash(&ServiceRecord)` so the verify path can hash the PDS-returned record without round-tripping through a `ServiceRecord` struct. The struct's `Serialize`-only derives use `&'static str` for several fields, which would prevent symmetric `Deserialize` without a parallel read-side type.
- `PdsClient::get_record(repo, collection, rkey)` was added (#8 commit 1) — `Result<Option<GetRecordResponse>, PdsError>` shape: `Ok(None)` covers HTTP 404 OR XRPC `RecordNotFound` body (PDS implementations vary), `Err(PdsError::Network)` covers transport-level failures, other errors map through the unreachable code.
- The verify code lives inline in `serve.rs` as `mod verify` per the session decision. Extract to a free-standing module if it grows past ~80 lines.

**Verification:**

- `tests/serve_verify.rs::serve_starts_when_pds_record_matches` — happy path.
- `tests/serve_verify.rs::serve_fails_with_drift_exit_code_when_records_differ` — exit code 12 + drift summary names the field.
- `tests/serve_verify.rs::serve_fails_with_absent_exit_code_when_record_404s` — exit code 13.
- `tests/serve_verify.rs::serve_fails_with_unreachable_exit_code_on_pds_503` — exit code 14 via UnexpectedStatus.
- `tests/serve_verify.rs::serve_fails_with_unreachable_exit_code_on_truly_unreachable_pds` — exit code 14 via Network/transport error (uses an unbound port to force connection-refused).
- All four failure-path tests assert `COUNT(*) FROM server_instance_lease = 0` post-failure (lease release invariant).
- Inline `serve::verify::tests` covers the drift-summary helper (label_values drift, definition_count drift, per-definition fallback).

### F20. Account moderation state model (v1.4)

Graduated-action moderation surface. Where Ozone has binary active/takendown, cairn-mod tracks a per-subject strike balance with operator-configurable weights, dampening for first-time offenders, and time-based decay. The labeler still emits ATProto labels (label emission against this state model is a future-release concern, see §F20.10), but the moderation actions themselves are now first-class records with their own audit surface, recorder, and read endpoints.

The §F20 contract: every moderation action against a subject — warning, note, suspension, takedown — is recorded as a row in `subject_actions`, with the strike value resolved at action time and frozen on the row for forensic durability. Reads project that history through the decay calculator on every fetch, so cached values can never produce a misleading answer. Operators configure the strike-calculation rules (reason weights, dampening curve, decay window) declaratively in `[moderation_reasons]` and `[strike_policy]`; cairn-mod's job is to apply those rules consistently and surface them transparently. See §4.2 disclosure 4 for the trust-chain framing.

#### F20.1. Action types

Five action types, declared in the `subject_actions.action_type` SQL CHECK constraint and mirrored in [`crate::moderation::types::ActionType`]:

- `warning` — operator-issued warning to the subject. Zero strikes by definition.
- `note` — internal moderator annotation. Not visible to the subject; never carries strikes. Useful for "saw this, didn't act" annotations that should still appear in history.
- `temp_suspension` — time-bounded suspension. Carries strikes. Requires an ISO-8601 `duration` (e.g. `P7D`); the recorder computes `expires_at` from `effective_at + duration`.
- `indef_suspension` — open-ended suspension. Carries strikes. Revocation is the only path back to good standing while active.
- `takedown` — account takedown. Carries strikes; not a suspension (does not trigger decay-freeze).

Strike-bearing vs zero-strike is enforced by [`ActionType::contributes_strikes`]: `warning` and `note` always resolve to `strike_value_applied = 0` regardless of the reasons attached, even if a recorder bug or future write path passes a non-zero base. The recorder's defense-in-depth zero-override pins this invariant.

Reasons are attached to every action type, including zero-strike ones — a `warning` with `reason = ["hate-speech"]` provides context for the historical row even though no strikes accumulate. The reason vocabulary is operator-shared across action types; there is no "warning-only" reason set.

#### F20.2. Reasons

Reasons are operator-declared in the `[moderation_reasons.<identifier>]` TOML blocks of `cairn.toml`. Each entry has:

- `base_weight` (integer ≥ 1) — strike weight applied at action time, before dampening.
- `severe` (boolean, default `false`) — when `true`, the reason bypasses dampening regardless of subject standing. Severe reasons always count at full `base_weight`.
- `description` (non-empty string) — operator-facing label. Not a policy statement about how operators should act on it; the description is for the operator's own UI and runbook reference, not for users or external consumers.

Identifiers are lowercase-kebab-case (`a-z`, `0-9`, `-`; must start with a letter; 1-64 chars). Validated at config load.

**Shipped defaults** (eight entries, loaded when the operator's config has no `[moderation_reasons.*]` blocks):

| Identifier | Base weight | Severe |
|---|---|---|
| `hate-speech` | 4 | no |
| `harassment` | 4 | no |
| `threats-of-violence` | 12 | yes |
| `csam` | 999 | yes |
| `spam` | 2 | no |
| `misinformation` | 3 | no |
| `nsfw` | 2 | no |
| `other` | 2 | no |

**Operator-extensibility rule**: the moment any `[moderation_reasons.*]` block is declared, defaults are NOT loaded. Either accept the full default set, or declare every reason from scratch. This prevents accidental mixing of operator-declared and shipped-default reasons; operators who want a near-default vocabulary with one tweak copy the eight defaults plus the additional entry.

A bare `[moderation_reasons]` header with no sub-blocks is rejected at config load — that's almost certainly a typo, and silently treating it as "load defaults" would mask the operator's intent.

For multi-reason actions, the recorder selects a single dominant reason for strike calculation: severe wins regardless of weight; among same-severity reasons, highest `base_weight` wins; ties on `base_weight` resolve to the first-listed reason for determinism. The full `reason_codes` list is stored on the row.

#### F20.3. Strike calculation and dampening

The strike calculator (a pure function — no I/O, frozen at action time) consumes four inputs: the subject's current strike count, the dominant reason's base/severe, the resolved policy, and the action's 1-indexed position within the current good-standing window. It produces a `StrikeApplication` with three fields stored verbatim on the new row: `applied`, `was_dampened`, `base_weight`.

**Good standing**: `current_strike_count < good_standing_threshold` (default 3). New offenses while in good standing get dampened per the curve.

**Dampening curve**: per-position weights for in-good-standing offenses. Default `[1, 2]`. Length always equals `max(0, threshold - 1)` — see worked example below. Strictly ascending, each entry ≥ 1.

**Decision rules** (in order):

1. Severe reason → full `base_weight`, `was_dampened = false`. Bypasses the curve regardless of standing.
2. Out of good standing (`current_count >= threshold`) → full `base_weight`, `was_dampened = false`.
3. In good standing, position covered → `applied = min(curve[position - 1], base_weight)`, `was_dampened = true`. The cap means dampening can lower a strike value below the curve entry but never raise it above the reason's declared base.
4. In good standing, position past the curve → full `base_weight`, `was_dampened = false`. Defensive branch — normally unreachable under the curve-length convention, but handled cleanly for unusual operator policies.

**Worked example** (default policy: threshold 3, curve `[1, 2]`, hate-speech base 4):

| Offense # | Pre-state | Result |
|---|---|---|
| 1st | current=0, good standing | curve[0] = 1 strike applied |
| 2nd | current=1, good standing | curve[1] = 2 strikes applied (running 3) |
| 3rd | current=3, AT threshold (out of good standing) | full base = 4 strikes applied (running 7) |
| 4th | current=7, well past | full base = 4 strikes applied |

A severe action (e.g. CSAM, base 999) at any pre-state applies its full base — bypassing both the curve and any standing check.

**Frozen-at-action-time invariant**: `was_dampened`, `strikes_at_time_of_action`, and `strike_value_applied` are written to the `subject_actions` row at the moment of recording and never recomputed. Years later, an operator can verify exactly what state the user was in when this decision was made, even after policy edits. Position counting (the input to the calculator) reads `was_dampened` from prior rows as the in-good-standing predicate; this signal is stable across `[strike_policy]` edits because it was frozen at each prior action's time.

The position-in-window input is computed by the recorder before calling the strike calculator; it counts in-window unrevoked strike-bearing actions where the prior action's `was_dampened` flag is `true`. This separation keeps the strike calculator pure and the position computation in the recorder where DB access is appropriate.

#### F20.4. Decay

Strike contributions decay over time. Operator-configurable shape via `[strike_policy].decay_function`:

- `linear` (default) — decays linearly from full at `effective_at` to zero at `effective_at + decay_window_days`. Formula: `applied * max(0, 1 - elapsed_days / window_days)`.
- `exponential` — half-life decay tuned so ~1% remains at the window boundary. Half-life ≈ `window_days / log_2(100)` ≈ `window_days / 6.64`.

`decay_window_days` (default 90) lives on the policy, not the variant — both `linear` and `exponential` consume the same window. Decay is computed at read time; the calculator sums the per-action contributions in `f64` and rounds once at the end so many small actions don't lose precision through accumulated rounding.

**Suspension freezes decay** (controlled by `suspension_freezes_decay`, default `true`). v1.4 ships a deliberate simplification:

- **Only the most recent unrevoked suspension affects decay.** Earlier suspensions in history do not retroactively pause decay.
- **If that suspension is currently active**: decay is paused at the suspension's `effective_at`. Actions before the suspension cap their elapsed clock at that boundary; actions during the suspension contribute their full `strike_value_applied` (elapsed = 0).
- **If that suspension has expired** (only possible for `temp_suspension`): decay resumes from the expiry. Actions before lose `(suspension.expires_at - suspension.effective_at)` from their elapsed clock; actions during start their decay clock from the expiry.
- **Revoked suspensions never freeze decay**, even retroactively. A revoked suspension is treated as if it never happened — decay resumes from the original `effective_at` of every other action.

Multiple-suspension-history accuracy is a v1.5 refinement; the v1.4 simplification is sufficient for the strike model's intended use cases.

Decay state is recomputed on every read; the cache table (§F20.9) holds a snapshot for performance, but v1.4 read endpoints intentionally bypass the cache.

#### F20.5. Revocation

Any action can be revoked via `WriteCommand::RevokeAction`. Revocation:

- Sets `revoked_at`, `revoked_by_did`, and `revoked_reason` on the original row. The schema's no-update-except-revoke trigger permits exactly this NULL→non-NULL transition; all other column changes abort. Revocation is one-way — re-revocation and un-revocation both abort at the trigger.
- Recomputes the subject's strike state and updates the cache. Revoked actions are excluded from `current_strike_count` but still appear in `raw_total` and `revoked_count` for forensic display.
- Writes a hash-chained `audit_log` row (`subject_action_revoked`) referencing the revoked action's id.

Revocation never produces a separate row — the original row's revocation columns are the durable record. This keeps the `subject_actions` table append-only-with-one-exception and means the action's full history (recorded → revoked) is reachable through a single id lookup.

#### F20.6. Schema

Two tables, declared in `migrations/0003_account_moderation_state.sql`:

- **`subject_actions`** — append-only log of moderation actions. Columns include `subject_did`, optional `subject_uri` (for record-level actions), `actor_did`, `action_type`, `reason_codes` (JSON-encoded), `effective_at` / `expires_at` epoch-ms timestamps, the strike accounting trio (`strike_value_base`, `strike_value_applied`, `was_dampened`), `strikes_at_time_of_action`, the revocation columns (`revoked_at`, `revoked_by_did`, `revoked_reason`, all NULL until revoked), and `audit_log_id` linking to §F10's audit chain.
- **`subject_strike_state`** — single-row-per-account cache. Columns: `subject_did` (PK), `current_strike_count`, `last_action_at`, `last_recompute_at`. No triggers; freely updateable as the recorder writes through and §F20.9's recompute helper updates on stale-read.

**Triggers on `subject_actions`** (correctness defense, not security defense — same posture as §F10's audit_log triggers):

- `subject_actions_no_update_except_revoke BEFORE UPDATE` — aborts any UPDATE that changes the immutable columns. The revocation columns are exempt for the NULL→non-NULL transition only; once set, further changes also abort (no re-revocation).
- `subject_actions_no_delete BEFORE DELETE` — unconditionally aborts.

**Audit-log integration**: every recordAction and every revokeAction writes a hash-chained `audit_log` row in the same transaction as the `subject_actions` mutation, via the §F10 / v1.3 hash-chain pathway. The audit row carries the resolved action_id, action_type, primary reason, full reason_codes list, applied strike value, and `was_dampened` flag — enough for forensic reconstruction without joining back to `subject_actions`. §F10's actions list gains `subject_action_recorded` and `subject_action_revoked`.

Strike accounting unifies at the account level: `subject_actions` rows can target either a DID (account-level action) or an `at://`-URI (record-level action), but `subject_strike_state` is keyed by the parent account DID only.

#### F20.7. XRPC surface

Two namespaces: `tools.cairn.admin.*` for moderator/operator-tier endpoints, and `tools.cairn.public.*` (new in v1.4) for user-facing endpoints.

**Admin (Mod or Admin role; same auth gate as §F12 endpoints):**

- `tools.cairn.admin.recordAction` (procedure) — record a graduated-action event. Backed by `WriteCommand::RecordAction`. Returns `actionId`, `strikeValueBase`, `strikeValueApplied`, `wasDampened`, `strikesAtTimeOfAction`.
- `tools.cairn.admin.revokeAction` (procedure) — revoke a previously-recorded row. Backed by `WriteCommand::RevokeAction`. Returns `actionId`, `revokedAt`.
- `tools.cairn.admin.getSubjectHistory` (query) — paginated list of subject_actions rows for a subject. Cursor on the trailing row's id. Optional filters: `subjectUri`, `since`, `includeRevoked`.
- `tools.cairn.admin.getSubjectStrikes` (query) — current strike state for a subject. Returns `currentStrikeCount`, `rawTotal`, `decayedCount`, `revokedCount`, `goodStanding`, optional `activeSuspension`, optional `decayWindowRemainingDays`, optional `lastActionAt`.

Lexicon errors declared in the lexicon files: `InvalidReason`, `InvalidActionType`, `DurationRequired`, `DurationNotAllowed`, `SubjectUriMismatch`, `ActionNotFound`, `ActionAlreadyRevoked`, `SubjectNotFound`. Every name appears in the corresponding `errors[]` array; same lexicon-declaration discipline as §F12.

**Public (`tools.cairn.public.getMyStrikeState`, no role required, browser-safe CORS):**

- ATProto service-auth required — same JWT verification as the admin endpoints.
- Authorization is **self-identity**: the verified `iss` IS the subject. There is no `subject` parameter on the endpoint by design; querying someone else's state requires Mod or Admin role on the admin endpoint.
- Returns the same wire shape as `getSubjectStrikes` via cross-namespace lexicon ref to `tools.cairn.admin.defs#subjectStrikeState`. Single source of truth for the field set.
- CORS allow-any-origin, mirroring `com.atproto.label.queryLabels` from §F3 — public endpoints are intended for browser-side AppView callers. Admin endpoints continue to reject `Origin` outright.

The `tools.cairn.public.*` namespace establishes the convention: ATProto service auth + self-identity authorization + browser-safe CORS. Future user-facing endpoints (e.g., a `getMyActionHistory` companion to `getMyStrikeState`) follow this pattern.

`SubjectNotFound` (404) on the read endpoints fires only when the subject_did has never been actioned. Once any row exists, all subsequent reads return 200 — even if filters reduce the result set to empty. Matches the intuition "the subject is known to the system" vs "the subject matched my filter."

#### F20.8. Operator CLIs

Moderator-tier subcommands under `cairn moderator` (HTTP-routed; require a moderator session via `cairn login`):

- `cairn moderator action <subject> --type <type> --reason <code> ...` — generic record-action form.
- `cairn moderator warn <subject> --reason <code>` — sugar for `--type warning`.
- `cairn moderator note <subject> <text>` — sugar for `--type note`; positional `<text>` becomes the row's note.
- `cairn moderator revoke <action-id> [--reason <text>]` — revoke a row.
- `cairn moderator history <subject>` — paginated tabular history with the `--since` / `--limit` / `--cursor` / `--no-include-revoked` filters from `getSubjectHistory`.
- `cairn moderator strikes <subject>` — current strike state with active suspension (if any) and trajectory hint.

These are distinct from the v1.1-era `cairn moderator add/remove/list` commands (operator-tier, direct-DB, manage who CAN moderate). The new commands are moderator-tier (HTTP-routed via admin XRPC, manage what moderators DO). The split: operator-policy commands run direct-DB while `cairn serve` may be down; moderator-action commands run against a live `cairn serve` and require a moderator's PDS session for service-auth.

#### F20.9. Cache management

The `subject_strike_state` cache is a performance hint, not a source of truth. v1.4 invariants:

- **Write-through**: every recordAction and revokeAction UPSERTs the cache in the same transaction as the `subject_actions` mutation.
- **Read endpoints bypass the cache**: `getSubjectStrikes` and `getMyStrikeState` always recompute from `subject_actions` via the decay calculator. A stale cache row can never produce a misleading public read.
- **Lazy recompute-on-read helper** (`crate::moderation::cache::get_or_recompute_strike_count`) — for v1.5+ consumers that want O(1) "is this subject past threshold right now?" without a full history walk. Reads the cache; returns the cached count if `now - last_recompute_at < cache_freshness_window_seconds` (default 3600); otherwise loads history, runs the decay calculator, writes back, and returns the recomputed count. Cache write-back failures are best-effort: logged but the recomputed count still returns to the caller.
- **Missing cache returns a typed error** (`Error::StrikeCacheMissing`). Same semantic as the read endpoints' `SubjectNotFound`: the subject has never been actioned. v1.5 consumers wanting optimistic "never-actioned == 0" semantics wrap with `unwrap_or(0)`.

The freshness window is operator-tunable via `[strike_policy].cache_freshness_window_seconds`. v1.4 ships the helper but has zero in-tree consumers — landing the cache management alongside the cache write path that the recorder establishes (instead of split across releases) keeps the invariants reviewable in one place.

No background refresh job in v1.4. Lazy recompute-on-read is sufficient for v1.4's needs; scheduling adds real complexity (lease coordination, restart handling) that defers cleanly to v1.5+ when a real performance need surfaces.

#### F20.10. Deferred to future releases

The v1.4 contribution is the moderation state model: how actions are recorded, how strikes accumulate and decay, how operators configure the rules, how reads surface the state. Several adjacent capabilities are deliberately out of scope:

- **Label emission against moderation state** — shipped in v1.5 (see §F21). The bridge between `subject_actions` and the `labels` table now lives in the recorder.
- **Policy automation** (v1.6) — automatic action recording when a subject's strike count crosses a threshold. v1.4's recorder is moderator-driven; v1.5's emission flow doesn't change that. v1.6 will add operator-config-gated automatic-action paths. The cache management surface in §F20.9 ships ahead of this consumer.
- **Multiple-suspension-history accuracy in decay** (v1.6+) — v1.4's "only the most recent unrevoked suspension affects decay" simplification is documented in §F20.4. Full history fidelity adds complexity disproportionate to any v1.4 / v1.5 use case.
- **Background cache refresh job** (v1.6+) — see §F20.9.
- **Accessory bot or Web UI** for user-facing strike-state rendering — separate project from cairn-mod itself; `getMyStrikeState` is the substrate, not the UI.
- **Per-reason decay overrides** (v1.6+) — currently all reasons share the same decay function and window; per-reason tuning is conceivable but not motivated.

### F21. Label emission against moderation state (v1.5)

Bridge from §F20's internal moderation state to the protocol-visible labeler surface. Where v1.4 records actions to `subject_actions` and runs decay calculations against them, v1.5 takes that same action stream and translates it into ATProto labels — emitted to the `labels` table, signed by the labeler key, broadcast on `subscribeLabels`, surfaced by `queryLabels`, and negated on revocation. The internal moderation state (§F20) and the protocol-visible label state are now two synchronized views of the same underlying decisions; operators configure the translation declaratively, and consumers honor the labels via the existing ATProto consumer surface.

The §F21 contract: every recordAction that produces strikes (or warnings opted into emission) atomically signs and persists ATProto label records alongside the `subject_actions` row, the strike-state cache update, and the audit_log row. Every revokeAction atomically emits negation labels for every label that the original action emitted. Operators declare the action-type-to-label mapping in `[label_emission]`; subscribers can verify both layers independently. See §4.2 disclosure 5 for the trust-chain framing.

#### F21.1. Action-to-label mapping

Each action type maps to at most one action label `val`, optionally accompanied by reason labels (§F21.2). Defaults:

| Action type | Action label `val` | Severity | Carries `exp`? | Emits by default? |
|---|---|---|---|---|
| `takedown` | `!takedown` | `alert` | no | yes |
| `indef_suspension` | `!hide` | `alert` | no | yes |
| `temp_suspension` | `!hide` | `alert` | yes (= `expires_at`) | yes |
| `warning` | `!warn` | `inform` | no | only if `warning_emits_label = true` |
| `note` | — | — | — | never |

Notes never emit labels. Notes are internal forensic context for operators, not protocol-visible moderation surface; this is enforced at the resolver layer regardless of any operator-declared override (defense-in-depth — even an `action_label_overrides.note` entry in config does not produce a label).

Warnings are gated on `warning_emits_label`. Default is `false`: warnings are recorded as `subject_actions` rows for forensic and good-standing purposes but do not produce wire labels. Operators who want public-facing warnings flip the flag in their `[label_emission]` block.

**[label_emission] config block.** Operator-declared via `cairn.toml`:

- `enabled` (bool, default `true`) — master toggle. When `false`, every emission gate closes; recordAction still records the row, just without a label tail.
- `warning_emits_label` (bool, default `false`) — opt-in for warning emission. When `true`, warnings emit per the action-type table above.
- `emit_reason_labels` (bool, default `true`) — top-level gate on §F21.2 reason emission. When `false`, the action label still emits but no `reason-<code>` labels accompany it.
- `reason_label_prefix` (string, default `"reason-"`) — prefixed onto each `reason_code` to form reason labels' `val`. Empty prefix is permitted but logs a startup warning (the bare reason code becomes the label val, which can collide with other custom vals).
- `[label_emission.action_label_overrides.<action_type>]` — per-action-type overrides. Each entry replaces the default `val` plus optionally `severity`, `blurs`, `locales`. The `note` action type is permitted as a key for symmetry but the resolver still returns no label.
- `[label_emission.severity_overrides]` — lighter-weight knob: change just the severity for an action type without re-declaring the full label spec. Ignored when an `action_label_overrides` entry exists for the same action type (the explicit override's severity wins).

**Cross-action `val` uniqueness.** The config loader rejects two `action_label_overrides` entries with the same `val`. Each label value must discriminate to exactly one action type: revocation (§F21.3) reads `subject_actions.emitted_label_uri` and constructs a negation that targets the same `(src, uri, val)` tuple. If two action types could emit the same `val`, revocation routing would be ambiguous.

#### F21.2. Reason labels

In addition to the action label, an action with non-empty `reason_codes` emits one reason label per code:

- `val = reason_label_prefix + reason_code` (e.g., `reason-spam`, `reason-hate-speech` under the default prefix).
- `severity = inform` (fixed at this layer in v1.5 — reason labels describe *why* a moderation event occurred, not *what* effect it has, so they're advisory by design). Per-reason severity is deferred to v1.6+ if real demand surfaces.
- `blurs = None`, `locales = []`.
- `uri` and `cid` mirror the action label's targeting (account-level → `subject_did`; record-level → `subject_uri`).
- `cts` matches the action label's emission time; `exp` matches the action's `expires_at` (so a `temp_suspension`'s reason labels expire alongside the action label).

**Gate composition.** Reason emission requires all of: `[label_emission].enabled = true`, `emit_reason_labels = true`, non-empty `reason_codes`, action type ≠ `note`, and (for warnings) `warning_emits_label = true`. The warning gate is shared between action label and reason labels by design — a warning whose action label is suppressed cannot surface reason labels alone (reasons-without-context confuses consumers, and the recovery path is asymmetric since reason-only labels would have to be negated even though they were never paired with a wire-visible action label).

**Worked example** (default prefix, default policy, takedown with reasons `["hate-speech", "harassment"]` against `did:plc:abc`):

| Emission order | `val` | `uri` | `severity` | `exp` |
|---|---|---|---|---|
| 1 | `!takedown` | `did:plc:abc` | `alert` | — |
| 2 | `reason-hate-speech` | `did:plc:abc` | `inform` | — |
| 3 | `reason-harassment` | `did:plc:abc` | `inform` | — |

#### F21.3. Negation on revocation

Revoking an action atomically emits negation labels for every label that the original action emitted. The mechanism is ATProto's standard negation: a fresh label record with `neg = true` targeting the same `(src, uri, val)` tuple as the original. Consumers honoring the labeler's stream see the negation supersede the original; the original record stays in place as forensic record.

**Val-from-storage rule.** The negation reads `val` from `subject_actions.emitted_label_uri` (action label) and `subject_action_reason_labels.emitted_label_uri` (reason labels), NOT from a fresh policy lookup at revocation time. If an operator edits `[label_emission].action_label_overrides` between the action's emission and its revocation, the stored val is what was actually emitted on the wire — using a re-resolved val would produce a "negation" that doesn't actually negate anything because it targets a different tuple. The val must match the original tuple for negation to work; storage is the source of truth for what was emitted.

**Negation is unconditional.** The recorder does not consult `[label_emission].enabled` or `warning_emits_label` at revocation time. Even when emission has been disabled since the action was recorded, prior emissions exist on the wire and must be negated; otherwise consumer AppViews would honor a stale takedown forever. The "is this action_type emittable now?" gate from §F21.1 governs emission only; negation has no such gate.

**Negations carry no `exp`.** Even when negating a `temp_suspension` whose original labels carried an expiry, the negation itself is a permanent statement that supersedes the original. Expiring the negation would resurrect the original label in consumer caches.

**Linkage rows preserved.** `subject_action_reason_labels` rows are NOT deleted on revocation. They are forensic record of "at this point in time, these labels were emitted." The negation labels are the protocol-visible signal; the linkage rows are the audit substrate.

#### F21.4. Temp-suspension expiry via ATProto's native `exp`

For `temp_suspension`, the emitted action label and every reason label carry `exp = action.expires_at` (RFC-3339 in the wire record). ATProto's label record schema (§F7) defines `exp` as the wall-clock at which consumers stop honoring the label; AppView consumers natively respect this. cairn-mod does **not** run a scheduled job to emit a negation when `exp` passes — the native exp is the right primitive, and a scheduled job would be a redundant second source of truth.

Two timestamps run in parallel and flip together by design:

- `subject_actions.expires_at` drives the §F20.4 decay calculator. Once past, the suspension stops freezing decay; strike contributions from prior actions resume their decay clocks.
- `labels.exp` drives consumer AppView visibility. Once past, the label is no longer applied to the subject in consumer feeds.

Because these are derived from the same input (`effective_at + duration_iso`), they always have the same value. The two surfaces are independent in implementation but converge on the same wall-clock.

Revoking a `temp_suspension` early follows §F21.3: negations with `exp = None` ship in the same transaction as the revocation. Consumers see the negation supersede before `exp` would have fired naturally.

#### F21.5. Idempotency

The recorder applies a defense-in-depth idempotency guard between the `subject_actions` INSERT and the emission step:

- **Action-label gate:** if `subject_actions.emitted_label_uri` is already non-NULL, the action-label emission loop skips entirely.
- **Reason-label gate:** for each reason code in the request, if a `subject_action_reason_labels` row already exists for `(action_id, reason_code)`, that reason's emission is skipped.

In v1.5's normal recordAction flow the row was just INSERTed inside the same transaction with `emitted_label_uri = NULL` and no linkage rows yet, so both gates are structurally a no-op in production. They exist to protect against future paths (backfill migrations, retry helpers, alternate write paths) where a row might already carry emission state, and against bugs that would otherwise silently produce duplicate `(src, uri, val)` records on the wire.

The reason-label `subject_action_reason_labels` PK on `(action_id, reason_code)` is the SQL-level safety net: any duplicate INSERT aborts at the constraint regardless of whether the application-level gate fired.

The audit row's `emitted_labels` list is built from drafts BEFORE the guard runs (the audit row writes before the INSERT, by §F20's predict-then-verify pattern). In v1.5 normal flow the guard never fires, so audit-recorded intent matches reality. If a future defensive scenario fires the guard and skips work, the audit row may claim more emissions than landed — accepted as a v1.5 limitation, since the divergence is structurally unreachable from any code path that v1.5 ships. Future re-emission paths are responsible for handling audit accordingly.

#### F21.6. Customization for deployments

The customization-via-config-in-shared-schema principle from §F20.2 (operator-declared reason vocabulary) extends directly to label emission. Different deployments — Hideaway, Northsky, Eurosky, Speakeasy, Blacksky, others — use the same cairn-mod code paths but declare different `[label_emission]` config:

- A community-tier labeler emphasizing operator branding might declare `action_label_overrides.takedown.val = "!hideaway-takedown"` so consumer AppViews see the deployment-specific value.
- A labeler with stricter visibility intent might set `severity_overrides.warning = "alert"` to give warnings more consumer-side weight.
- A labeler with custom blurs (e.g., obscuring NSFW content under a `media` blur) configures `action_label_overrides.<type>.blurs` per action type.
- A labeler with consumer-localized strings declares `action_label_overrides.<type>.locales` with `{lang, name, description}` per supported language.

The recorder's path is the same across deployments. What differs is config — observable at startup time and verifiable against emitted label streams. This matches §F20.2's reason-vocabulary stance: cairn-mod's job is making policy declarable and observable, not adjudicating what the policy should be.

#### F21.7. Schema linkage and audit log integration

Two schema changes from migration `0004_label_emission.sql` (#57):

- **`subject_actions.emitted_label_uri`** (TEXT, nullable). Despite the column name, it stores the action label's `val`, not a URI: ATProto labels have no canonical URIs, and the discriminator within `(src=service_did, uri=subject, val)` is the val alone (the labeler's `src` and the subject's `uri` are recoverable from the row). Populated in the same transaction as the action INSERT (NULL → non-NULL once); the schema trigger from §F20.6 is rewritten to permit this single transition (mirroring the revocation columns' NULL → non-NULL exception). Any further change aborts. Column name predates the realization that labels lack canonical URIs; locked once shipped.

- **`subject_action_reason_labels`** — composite-PK `(action_id, reason_code)` linkage table. Columns: `action_id` (FK → `subject_actions.id`), `reason_code` (operator-vocabulary identifier from §F20.2), `emitted_label_uri` (the val, same convention as above), `emitted_at` (epoch-ms wall-clock at emission). One row per emitted reason label; written once on emit, preserved across revocation per §F21.3.

**Audit log integration.** The audit chain (§F10 / v1.3) extends to cover emitted and negated label vals:

- Every `recordAction` audit row's reason JSON gains `emitted_labels: [{val, uri}, ...]` — one entry per label this action will produce, in (action label first, reason labels by request order) sequence. Empty array when emission is gated (note, suppressed warning, policy disabled).
- Every `revokeAction` audit row's reason JSON gains `negated_labels: [{val, uri}, ...]` — the same shape, listing each negation. Empty array when the revoked action emitted nothing.

The hash chain locks both the action plus its emitted/negated label vals. Forensic verification proves not only "this action happened" but also "these specific labels were emitted alongside it" or "these specific labels were negated by this revocation." A consumer rebuilding the chain from the audit log can verify the labels table by walking each `subject_action_recorded` row and checking that `emitted_labels` matches the labels table's records for the action's tuple.

#### F21.8. Public introspection and operator CLI

Two read surfaces shipped alongside emission:

**`subjectStrikeState.activeLabels`** (`tools.cairn.public.getMyStrikeState` and the admin-tier `tools.cairn.admin.getSubjectStrikes`, sharing the projection per §F20.7). One entry per non-revoked action that emitted labels and whose action label has not been negated. Action-centric grouping: each entry has `val` (action label), `actionId`, `actionType`, `reasonCodes` (array of bare codes — clients prefix with `reason_label_prefix` to recover reason-label vals), and optional `expiresAt`. Ordered most-recent-action-first. Cache-bypass invariant from §F20.9 extends here: the projection always reads `subject_actions`, `subject_action_reason_labels`, and the `labels` table directly; no caching layer in front.

`exp`-passed labels are INCLUDED in `activeLabels`. The labels table is the source of truth for what cairn-mod has emitted; AppView-side honor of `exp` is the consumer's responsibility per §F7. Clients wanting a strictly-honored-now view filter on `expiresAt < now` themselves.

**`cairn moderator labels <subject>`** (HTTP-routed, moderator-tier). Mirrors `cairn moderator strikes` in flag pattern but renders `activeLabels` as the primary output. Default human format is tabular (one row per emitted label — action label plus one per reason code, all sharing the action's context columns); `--json` emits just the `activeLabels` array, not the full strikes envelope. Operators wanting the full state continue to use `cairn moderator strikes --json`.

#### F21.9. Deferred to future releases

The v1.5 contribution is the action → label translation: how operators declare the mapping, how emission lands atomically with the action INSERT, how revocation negates, how reads expose the active set. Several adjacent capabilities are deliberately out of scope:

- **Policy automation** — shipped in v1.6 (see §F22). The bridge from threshold-crossing to automatic action (mode=auto) or pending-for-review (mode=flag) now lives in the recorder, with operator-declared rules in `[policy_automation]`.
- **PDS administrative actions** (v1.7+) — operator-config-gated bridge to `com.atproto.admin.*` on operator-controlled PDSes. Operators provide PDS admin credentials and declare which action types translate into PDS-level account state changes; cairn-mod calls the admin endpoints in lockstep with label emission. **Default is labeler-only when `[pds_admin]` is absent or disabled** — the existing labels-only surface remains the unchanged baseline for community-tier deployments.
- **Per-reason severity overrides** (v1.6+ if demand) — currently all reason labels are `inform`. Per-reason tuning is conceivable but not motivated.
- **Per-reason decay overrides** — already deferred per §F20.10; the v1.5 emission surface does not change the calculus.
- **Background cache refresh job** — already deferred per §F20.9; activeLabels recomputation rides the same cache-bypass posture and inherits the same deferral.
- **Single-JOIN optimization for `activeLabels`** — the v1.5 implementation uses an N+1 query pattern (one SELECT per candidate action). Acceptable for v1.5's bounded-history use cases; query optimization deferred until profiling against real deployments surfaces a need.
- **CID plumbing for record-level subjects** — `ActionForEmission.cid` exists but v1.5 always passes `None` (subject CIDs aren't yet plumbed through `RecordActionRequest`). Record-level labels without CID are protocol-valid, just less specific. Wiring through `tools.cairn.admin.recordAction` + the operator CLI is a future ticket.

### F22. Policy automation (v1.6)

Bridge from §F20's strike accounting and §F21's label emission to operator-declared automatic action. Where v1.4 records actions to `subject_actions`, runs decay against them, and surfaces the strike state, and v1.5 translates that action stream into ATProto labels, v1.6 closes the loop: operators declare rules in `[policy_automation.rules.<name>]` sub-blocks, and the recorder evaluates those rules inside every recordAction transaction. When a subject's strike count crosses a declared threshold, the rule fires — either auto-recording a consequent action (mode=auto) or queueing a `pending_policy_actions` row for moderator review (mode=flag). Both paths hash-chain into the audit log alongside the precipitating action and any emitted labels. See §4.2 disclosure 6 for the trust-chain framing on pending visibility.

The §F22 contract: every recordAction transaction evaluates the operator's policy automation rules against the strike state before-and-after the precipitating action. At most one rule fires per transaction (severity ordering breaks ties); the firing's consequence — auto-recorded action OR pending row — commits atomically with the precipitating action, its emitted labels, and a single hash-chained audit row. Conservative idempotency holds: a rule fires once per subject until the firing is explicitly resolved (revoked, dismissed, or confirmed-then-revoked). Takedown is terminal and cascades; pendings stay forensic record across the cascade.

#### F22.1. Policy rule shape and config block

Operators declare rules in their TOML config:

```toml
[policy_automation]
enabled = true

[policy_automation.rules.warn_at_5]
threshold_strikes = 5
action_type = "warning"
mode = "auto"
reason_codes = ["policy-threshold"]

[policy_automation.rules.flag_indef_at_15]
threshold_strikes = 15
action_type = "indef_suspension"
mode = "flag"
reason_codes = ["repeated_violation"]

[policy_automation.rules.temp_at_10]
threshold_strikes = 10
action_type = "temp_suspension"
mode = "auto"
duration = "P7D"
reason_codes = ["policy-threshold"]
```

Per-rule fields:

- `threshold_strikes` (required, ≥1): the count at which the rule fires when crossed from below.
- `action_type` (required): one of `warning` / `note` / `temp_suspension` / `indef_suspension` / `takedown`.
- `mode` (required): `auto` (synthetic-policy-recorded action lands inside the same transaction) or `flag` (`pending_policy_actions` row lands awaiting moderator review).
- `duration` (required for `temp_suspension`, rejected otherwise): ISO-8601 duration. The same parser the moderator-recorded path uses (`P{n}D`, `P{n}W`, `PT{n}H`, `PT{n}M`, `PT{n}S`, and combinations).
- `reason_codes` (required, non-empty): identifiers from `[moderation_reasons]`. Validated at config load; the rule's reasons must all exist in the operator's vocabulary.

Rule-naming convention: lowercase ASCII, digits, and underscores; `[a-z][a-z0-9_]{0,63}`. Names are unique within `[policy_automation]`. The block is optional — when absent, the policy engine is disabled and the recorder behaves identically to v1.5.

#### F22.2. Threshold-crossing semantics

The rule matcher requires a *strict crossing*: `state_before.current_count < rule.threshold_strikes && state_after.current_count >= rule.threshold_strikes`. Already-above events do not re-fire; staying-below events do not fire.

Conservative idempotency closes the firing window after a rule matches. The window stays closed until the rule's prior firing is resolved:

| Prior firing                  | Window state | Re-fire allowed? |
|---|---|---|
| Auto-recorded action, unrevoked       | closed | no |
| Auto-recorded action, revoked         | open   | yes (next crossing) |
| Pending, unresolved                   | closed | no |
| Pending, dismissed                    | open   | yes (next crossing) |
| Pending, confirmed → action unrevoked | closed | no |
| Pending, confirmed → action revoked   | open   | yes (next crossing) |

The revocation-and-recross path requires both: the prior firing's row revoked (or pending dismissed / confirmed-then-revoked) AND the strike count dropping back below threshold so a future action can cross it from below. For a threshold-1 rule whose auto-action is a warning (zero-strike), revoking just the auto-warning isn't enough — the strike count is still at 1 from the precipitating action; the precipitating action itself must also be revoked (or naturally decay) before the next crossing can occur.

The "decay-and-recross fires the rule again" semantic is **deferred to v1.7+** (§F22.11). v1.6 ships conservative idempotency only; pure-function unit tests (`src/policy/evaluator.rs::tests`) cover the decay-aware crossing logic in isolation, but the full lifecycle through the recorder doesn't yet treat decay as a window-opening event.

#### F22.3. Severity ordering and rule selection

When multiple rules match a single crossing event, severity order resolves: `takedown > indef_suspension > temp_suspension > warning > note`. Within the same severity, the higher-threshold rule wins (catches the "you got further past the rule" case). Exactly one rule fires per recordAction; the others' windows stay open and may fire on future crossings.

If the highest-severity matching rule has already fired (window closed per §F22.2), the evaluator falls through to the next-highest matching rule whose window is open. If every matching rule's window is closed, the recorder writes the precipitating action without firing anything.

A pre-existing unrevoked Takedown blocks every rule firing — the evaluator's takendown gate fires unconditionally before any crossing check (§F22.5).

#### F22.4. Auto vs flag mode

`mode = "auto"`: the rule's consequence is a real `subject_actions` row inserted in the same transaction as the precipitating action. The auto-action carries `actor_kind = 'policy'`, `actor_did = "did:internal:policy"`, and `triggered_by_policy_rule = "<rule name>"`. Label emission runs through the §F21 path — action label + reason labels per the operator's `[label_emission]` mapping. The auto-action itself can in turn fire cascading consequences if it is a Takedown (§F22.6).

`mode = "flag"`: the rule's consequence is a `pending_policy_actions` row. No `subject_actions` row, no label emission. The pending row carries the rule's proposed shape (`action_type`, `duration`, `reason_codes`, `triggered_by_policy_rule`) and a foreign-key reference to the precipitating action via `triggering_action_id`. The pending awaits moderator review through the read + resolve surfaces (§F22.10).

Mode applies forward only. Pending rows already in the queue keep the mode they were created under; if an operator changes a rule's mode in config and reloads, the existing pendings are unaffected — they resolve via the same confirm/dismiss surfaces. New rule firings after the reload use the new mode.

#### F22.5. Pending action resolution: confirm and dismiss

A pending action is resolved by exactly one of two moderator-tier surfaces:

**Confirm** (`tools.cairn.admin.confirmPendingAction`, `cairn moderator pending confirm`): promotes the pending's proposed action to a real `subject_actions` row. The materialized row carries `actor_kind = 'moderator'` (the moderator takes responsibility by confirming), `actor_did = <moderator DID>`, AND `triggered_by_policy_rule = <pending's rule>` for forensic provenance. Label emission runs; strike state recomputes; the pending row's resolution columns transition NULL → 'confirmed' with `confirmed_action_id` linking forward to the materialized row. Strike values for the materialized action are computed at confirmation time, not proposal time — the moderator's decision is what the strike state should reflect; `expires_at` for `temp_suspension` re-anchors on the confirmation wall-clock.

The confirm path defends against a `SubjectTakendown` race: if a takedown lands between the pending's creation and the confirm call, the confirm rejects with the `SubjectTakendown` error rather than materialize an action that contradicts terminal-state semantics. In steady state this is unreachable (the takedown's cascade auto-dismisses the pending — §F22.6); the defensive check closes the race.

**Dismiss** (`tools.cairn.admin.dismissPendingAction`, `cairn moderator pending dismiss`): marks the pending resolved without creating any `subject_actions` row. No label emission, no strike-state recompute. The pending's `resolution` column transitions NULL → 'dismissed'; `confirmed_action_id` stays NULL (dismissed pendings never link forward). The moderator's optional `--reason` lands on the audit row's `moderator_reason` field, not on the pending row itself — the pending table tracks resolution state; rationale lives in audit (a single-concern split simpler than adding a `resolved_reason` column).

The schema's BEFORE-UPDATE trigger on `pending_policy_actions` permits each resolution column's NULL → non-NULL transition exactly once. Re-resolution attempts (a second confirm or a confirm-after-dismiss) abort at the trigger; the recorder also checks pre-UPDATE and surfaces `PendingAlreadyResolved` for a clean lexicon error.

#### F22.6. Auto-dismissal on takedown

Takedown is terminal. When a Takedown row INSERTs against a subject — whether moderator-recorded, policy-auto-recorded, or confirmed-pending-promoted — every unresolved `pending_policy_actions` row for that subject auto-dismisses inside the same transaction. The cascade closes the loop: a takendown subject can't have moderator-actionable pendings linger (the confirm path's `SubjectTakendown` defensive check would reject them anyway), so the recorder cleans up at the boundary.

The cascade attribution depends on the takedown's path:

- Moderator-recorded takedown → cascaded pendings' `resolved_by_did` is the moderator's DID.
- Policy-auto-recorded takedown → cascaded pendings' `resolved_by_did` is the synthetic policy DID (`did:internal:policy`).
- Confirmed-pending takedown → cascaded pendings' `resolved_by_did` is the confirming moderator's DID (the confirm flow's UPDATE to 'confirmed' on the just-confirmed pending lands first, so the cascade naturally excludes it via the `WHERE resolution IS NULL` filter).

The cascade audit rows reuse the same `audit_log.action` value as the explicit moderator dismiss (`pending_policy_action_dismissed`), discriminated by a `triggered_by` field in the reason JSON: `"moderator_dismissed"` (manual) vs `"takedown_terminal"` (cascade). The cascade shape additionally carries `takedown_action_id` cross-referencing the triggering subject_actions row; audit consumers filter via `json_extract(reason, '$.triggered_by')`.

Revocation of a takedown does **not** un-dismiss the cascaded pendings. They stay dismissed as forensic record — the moderator's takedown decision was what closed them, and revoking the takedown doesn't retroactively change that the cascade ran. If the subject later decay-and-recrosses (or moderator-action-and-recrosses) a threshold whose rule's prior firing was cascade-dismissed, a new pending fires per the conservative idempotency rules (§F22.2); the old cascade-dismissed pending is unaffected.

#### F22.7. Schema linkage and audit log integration

Two schema additions in migration `0005_policy_automation.sql`:

`subject_actions` gains:
- `actor_kind` (TEXT NOT NULL DEFAULT 'moderator'; CHECK in 'moderator' | 'policy'). Existing rows backfill to 'moderator'. New rows from the moderator path set 'moderator' explicitly; auto-recorded rows set 'policy'. Confirmed-pending rows set 'moderator' (the moderator takes responsibility by confirming).
- `triggered_by_policy_rule` (TEXT NULL). The rule name that produced the row, NULL for moderator-recorded actions the engine had no hand in. Preserved through the pending → confirmed pipeline.

The `subject_actions_no_update_except_revoke` trigger from #46 / #57 is extended: both new columns are write-once at INSERT.

New table `pending_policy_actions` (id, subject_did, subject_uri, action_type, duration_ms, reason_codes, triggered_by_policy_rule, triggered_at, triggering_action_id FK→subject_actions(id), resolution, resolved_at, resolved_by_did, confirmed_action_id FK→subject_actions(id)). Same write-once-on-NULL-to-non-NULL trigger pattern as `subject_actions.revoked_*` and `subject_actions.emitted_label_uri` (#46 / #57): the four resolution columns transition once and freeze. DELETE aborts unconditionally.

Audit vocabulary additions:

- `pending_policy_action_confirmed` — moderator confirms a pending; reason JSON cross-references `pending_id`, `action_id`, `triggered_by_policy_rule`, plus the materialized action's shape.
- `pending_policy_action_dismissed` — pending resolved without a materialized action. Two shapes share the same `audit_log.action` value, discriminated by reason JSON's `triggered_by` field: `moderator_dismissed` (#75 manual dismiss; carries `moderator_reason`) and `takedown_terminal` (#76 cascade auto-dismiss; carries `takedown_action_id`).

There is no separate `pending_policy_action_created` audit row. Pending creation rides the precipitating action's `subject_action_recorded` audit row, which gains a `policy_consequence` field cross-referencing the pending's id (`{rule_fired, mode, pending_action_id}`). For mode=auto firings, the same `policy_consequence` field cross-references the auto-action's id (`{rule_fired, mode, auto_action_id}`). The hash chain locks the bundle (precipitating action + policy consequence + cascade dismissals) atomically.

`cairn audit verify` continues to walk the chain across the policy automation surface; the v1.3 hash-chaining (§F10) is unchanged in shape.

#### F22.8. Synthetic actor DID for policy-recorded actions

Auto-recorded actions land with `actor_did = "did:internal:policy"` — a hardcoded synthetic DID identifying the policy automation engine itself. The DID has no PDS, no DID document, no signing key; it exists only as a string discriminator in cairn-mod's database and in audit-log `actor_did` fields.

The source of truth for "who recorded this" is the `actor_kind` column (`'moderator'` vs `'policy'`); the synthetic DID is a human-readable convenience for forensic readers and operator dashboards. Moderator-confirmed pendings produce subject_actions rows with the moderator's real DID as `actor_did` and `actor_kind = 'moderator'`; the rule's name lives on `triggered_by_policy_rule` for provenance.

Operators who want a different synthetic identifier can settle that in a future ticket (the constant lives in `crate::policy::automation::SYNTHETIC_POLICY_ACTOR_DID`); v1.6 ships the hardcoded value.

#### F22.9. Public introspection: pending state is NOT visible

The public read endpoints from §F21.8 are unchanged. `tools.cairn.public.getMyStrikeState`'s response carries the same `subjectStrikeState` envelope including `activeLabels`, where activeLabels reflects only labels emitted from confirmed (or moderator-recorded, or auto-recorded) actions. Pending actions, dismissed pendings, cascade audit context, and moderator rationale are NOT surfaced via the public surface.

Reasoning per §4.2 disclosure 6: pending state isn't actionable for the subject (they cannot defend themselves against a moderator's pending review they don't know exists), pre-emptive disclosure creates pressure on moderators reviewing flags, and cairn-mod's transparency posture has limits — this is one of them. Subscribers see what cairn-mod has *done*, not what cairn-mod *might* do.

#### F22.10. Operator surfaces (admin XRPC + CLI)

Read:

- `tools.cairn.admin.listPendingActions` (query) — paginated newest-first list with optional `subject` and `resolution` filters. Mod or Admin role. Returns `SubjectNotFound` (404) when the `subject` filter is provided and no `pending_policy_actions` row exists for that DID.
- `tools.cairn.admin.getPendingAction` (query) — single row by id. Mod or Admin role. Returns `PendingActionNotFound` (404) when the id doesn't exist.

Write:

- `tools.cairn.admin.confirmPendingAction` (procedure) — promote pending → materialized action. Errors: `PendingActionNotFound`, `PendingAlreadyResolved`, `SubjectTakendown` (defensive race-closer).
- `tools.cairn.admin.dismissPendingAction` (procedure) — resolve pending without action. Errors: `PendingActionNotFound`, `PendingAlreadyResolved`. No `SubjectTakendown` check (explicit dismissal works regardless of takedown state — and is in fact the cleanup path the cascade automates).

CLI (HTTP-routed via the admin XRPC; no direct DB):

- `cairn moderator pending list [--subject <DID>] [--cursor] [--limit] [--json]` — tabular id / subject / action_type / rule / triggered_at / days-since-triggered.
- `cairn moderator pending view <pending-id> [--json]` — multi-line context.
- `cairn moderator pending confirm <pending-id> [--reason "..."] [--json]` — `--reason` lands on the materialized action's `notes` column.
- `cairn moderator pending dismiss <pending-id> [--reason "..."] [--json]` — `--reason` lands in the audit row's `moderator_reason` field.

The CLI's `--resolution` filter on `list` is not exposed in v1.6 — the CLI is the moderator review queue (defaults to unresolved); confirmed/dismissed pendings remain reachable via the admin XRPC if needed. A future ticket can expose the filter if real workflow demand surfaces.

#### F22.11. Deferred to future releases

The v1.6 contribution is policy automation: rule declaration, threshold-crossing detection, mode=auto / mode=flag dispatch, conservative idempotency, takedown cascade, moderator review surfaces. Several adjacent capabilities are deliberately out of scope:

- **Decay-and-recross re-firing** (v1.7+ if real demand surfaces) — v1.6's conservative idempotency requires explicit resolution (revoke / dismiss) to open a rule's window. A rule whose firing decayed below threshold but isn't explicitly resolved stays closed; the next crossing doesn't re-fire. Operators who want decay-driven re-firing can layer it via revocation tooling. v1.6 prioritizes operational predictability — operators don't get surprised by automated re-firing as decay timing approaches a crossing.
- **Mode-applies-forward configuration mutation** (v1.7+) — config-reload semantics for in-flight pendings (changing a rule's mode after pendings exist for it) are deliberately untested at the integration layer for v1.6. Pure-function evaluator tests cover the relevant decision logic; the writer's config is currently spawn-time-only, so config-mutation requires a process restart anyway.
- **PDS administrative actions** (v1.7+) — operator-config-gated bridge to `com.atproto.admin.*` on operator-controlled PDSes, layering on top of v1.6's auto-recorded actions. **Default is labeler-only when `[pds_admin]` is absent or disabled** — the v1.6 default-disabled posture preserved from v1.5 §F21.9 carries forward.
- **Webhook-driven pending creation** (v1.8+ if demand) — v1.6's pendings come exclusively from operator-declared threshold-crossing rules. External automated systems wanting to queue pendings (e.g., a third-party classifier) would land their own pending rows via a future endpoint.
- **Policy-rule audit reports** (v1.8+ if demand) — operator-facing analytics: "how often did rule X fire? what's the confirm-vs-dismiss rate?" The data is in `audit_log` + `pending_policy_actions` already; aggregate views are a follow-on.

## 8. Lexicons

cairn-mod defines custom lexicons in `lexicons/tools/cairn/admin/*.json`.

**Served at:** `https://cairn.tools/.well-known/lexicons/tools/cairn/admin/{name}.json` (cairn-mod convention; see §F12 note on lexicon resolution).

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

Deferred to a future release (see §18):

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
16. PLC log subscription for real-time key-rotation observation.
17. Cross-language interop tests (beyond Rust consumer).
18. Multi-label-per-frame batching in `subscribeLabels`.
19. **Operator-facing metrics surface** (Prometheus-style `/metrics` endpoint, per-operator dashboards). v1 provides `tracing`-based structured logs only; the `/health` and `/ready` probe endpoints (§F14, shipped v1.1) cover orchestrator-driven liveness checks. Operators who need metrics today can scrape logs; a dedicated metrics surface is a future release. This is called out explicitly because a reviewer would otherwise wonder if it was an oversight.

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
- **Ozone interop spot-test:** at least one end-to-end validation that a cairn-mod-emitted label parses cleanly in `@atproto/api`'s consumer path. v1 documents this was verified manually; v1.1 automates.
- **atrium-api interop test:** cairn-mod emits, `atrium-api` consumer subscribes, labels parse and verify.
- **Adversarial security test suite:** unauth admin access, malformed JWT, wrong `aud`/`lxm`/`alg`, `jti` replay, expired `exp`, future `iat`, DID resolution failure fail-closed, audit-log tamper attempts, oversized report bodies, report floods (single DID, many DIDs), dual-instance startup, WS connection flood, `cts` regression emission.
- **Live tests** behind `--features live` against a local PDS (Aurora-Locus or Bluesky reference).

## 14. Shipping

cairn-mod v1 ships as a focused release: protocol-correct, self-contained, and notably smaller than Ozone in feature surface. This is intentional. Users who need Ozone's full moderation workflow (review queue, takedowns, team management, web UI) should use Ozone today and consider migrating to cairn-mod when v1.1+ delivers those features. Users who want a Rust-native labeler without Ozone's dependency footprint are cairn-mod v1's target audience.

- `cargo publish` as `cairn-mod` (the bare name `cairn` is placeholder-squatted on crates.io; a claim attempt on `cairn` via help@crates.io is a low-priority post-v1 follow-up — see §17). The produced binary is named `cairn` via the `[[bin]]` target, so end-users run `cairn` after `cargo install cairn-mod`.
- **Install path:** `cargo install cairn-mod` from crates.io is the canonical install. Source builds via `cargo build --release` work for anyone with a Rust toolchain. Pre-built binaries are not published — cairn-mod is server software designed for Linux deployment behind a reverse proxy (Caddy/nginx + systemd, see [contrib/](contrib/)), and operators in that target audience already have a build environment.
- `cairn.tools` hosting: **GitHub Pages with custom domain (CNAME)**. Zero ongoing cost, handles static JSON at `.well-known/lexicons/` paths with correct `Content-Type` (configured via `.nojekyll` + proper file extensions, or via a minimal build step that emits files with correct MIME types).
- README contents: install, quickstart, **Production Checklist**, security caveats, out-of-scope list, comparison to Ozone/Skyware, contribution guide, **§4.2 trust-chain disclosures prominently placed**, observed network rate limits (§6.6).
- **Semver commitment:** library crate (`cairn` as a Rust dependency, if anyone consumes it that way) follows strict semver. CLI output format and admin XRPC surface follow strict semver — breaking changes require a major-version bump. DB schema migrations run automatically on upgrade via embedded `sqlx migrate`; the operator does not run a separate command. Internal implementation details (module structure, private types) are not covered by semver.
- **CI strict mode:** `cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings` (default lint groups only, not pedantic/nursery), `cargo fmt --check`, `cargo sqlx prepare --check` to keep compile-time query artifacts fresh.
- MSRV: Rust 1.88+ (inherited from `proto-blue` edition 2024).
- Detailed release procedure and rollback policy: see §19 (Release Runbook).

## 15. proto-blue Dependency & Contingency

cairn-mod depends on `proto-blue` for ATProto primitives (DAG-CBOR/DRISL, CIDs, Multikey encoding, k256 with RFC 6979 + low-S, DID resolution).

**Path A (preferred):** `proto-blue` is on crates.io at release time.

**Path B (contingency):** vendor the needed subset (DRISL canonical encoding, Multikey encoding/decoding, k256 with RFC 6979 + low-S, DID doc parsing including `did:web` path-component handling). **Honest scope estimate:** 2–4 weekends of vendoring, parity-testing, and edge-case debugging. DRISL edge cases (integer-encoding boundaries, map-key byte ordering, empty-map-vs-missing-field) are the specific risk. **MSRV under Path B:** cairn-mod holds the same MSRV (Rust 1.88+) whether depending on `proto-blue` or vendoring its subset. Vendored code will be updated to match proto-blue's MSRV if upstream advances, to preserve straightforward re-adoption.

**Vendored-code maintenance policy:** reviewed monthly against upstream; security fixes ported within 7 days; non-security changes batched quarterly.

**Path C (fallback):** `proto-blue` abandoned. Switch to `atrium-api` primitives, vendor the rest.

**Decision deadline:** **six weeks before planned v1 release.** This replaces the previous 2-week deadline; Path B's real cost makes a tighter window untenable. If Path B is triggered, the extra weeks are working time, not planning time.

## 16. Project-Level Verification Criteria

### 16.1 Hard gates (pass/fail)

cairn-mod v1 cannot ship until all of these are true:

- F1–F13 verification criteria all pass.
- §12 security considerations all have corresponding tests.
- `cargo clippy --all-targets -- -D warnings` passes clean (default lint groups).
- `cargo test --all-targets` passes on CI on the published Linux x86_64 toolchain at MSRV and current stable.
- `cargo sqlx prepare --check` passes on CI.
- cairn-mod published to crates.io; `proto-blue` dependency satisfied via crates.io (Path A) or vendored subset (Path B per §15).
- atrium-api interop test passes (cairn-mod-emitted labels consumed by `atrium-api` subscriber code).
- Ozone interop spot-test: at least one cairn-mod-emitted label has been parsed and signature-verified by `@atproto/api` (manually verified; documented in release notes).
- Signature parity corpus (§F2) passes byte-identical tests for every optional-field combination.
- `tests/e2e/quickstart.sh` runs end-to-end on a clean Linux environment in under 30 minutes, emitting a label that the included local consumer test harness verifies.

### 16.2 Release-readiness signals (soft gates)

These are not pass/fail but are explicitly checked before cutting a release candidate:

- **First external installer.** One named person other than skydeval has installed cairn-mod from a release-candidate branch and successfully emitted a verifying label. Name the person before the README-quickstart issue in §21 (the first-external-installer issue); brief them on what to test; give them an ETA. Their feedback is a pre-release gate against a branch, not a post-release verification against `main`.
- **Adversarial review cycles have all been run and findings resolved to author satisfaction.** "Resolved" means: addressed in the doc or code, explicitly declined with a recorded rationale, or deferred to a v1.1+ issue with a link. Each round's findings are tracked as a chainlink issue so the disposition is visible.
- **Production Checklist dry-run.** skydeval themselves (or the first external installer, if that's arranged) has walked through the Production Checklist end-to-end against a fresh deployment. This is the stopwatch for the 30-minute quickstart plus the full operator-hardening path.

The signals exist because they're real release-quality indicators. They are soft gates because each depends on external people or judgment that cannot be made fully mechanical. Labeling them as soft rather than hard keeps the release-decision honest: if the external tester never appears, the release-decision is skydeval's call, not an indefinite wait.

## 17. Open Questions

1. **Crate name on crates.io.** Currently shipping as `cairn-mod` (the name held by the scaffold). The bare `cairn` is placeholder-squatted; a claim attempt via help@crates.io is a low-priority post-v1 follow-up. If successful, rename and publish a 1.x move that re-exports from the new name for one release cycle. Binary name remains `cairn` via the `[[bin]]` target regardless of crate-name outcome.
2. Retention default tuning (180 days is a first guess).
3. Report rate limit (10/hour/DID is a first guess).
4. Transparency-record format for v1.1 (decided before v1.1 kickoff).
5. When to split into workspace crates (not in v1).
6. **First external installer identity.** Named before the README-quickstart issue in §21 is started; preferably a Guild member or ATProto-Rust community member with the context to give useful feedback.

## 18. Future Roadmap

- Webhook signal intake.
- Review queue with distinct workflows for signal items vs. reports.
- Source management with negation-on-revocation default.
- Report encryption at rest (AES-256-GCM-SIV, per-report DEKs, rotatable master key).
- Label expiry enforcement job.
- Signing key rotation procedure (with DID doc update, audit, and consumer-observation grace period).
- Moderator/role management XRPC (CLI shipped in v1.1 per §F16; XRPC versions deferred).
- PLC operations-log subscription.
- Cross-language interop tests (TypeScript consumer).
- Multi-label-per-frame batching in `subscribeLabels`.
- Operator-facing metrics surface: `/metrics` Prometheus endpoint (labels emitted, reports received, subscriber count, DID resolution failure rate, auth rejection rate by cause) and structured-log conventions. (`/health` and `/ready` probe endpoints shipped in v1.1 — see §F14.)
- Account moderation state model shipped in v1.4 (see §F20). Label emission against moderation state shipped in v1.5 (see §F21). Policy automation shipped in v1.6 (see §F22) — operator-declared rules trigger automatic action recording (mode=auto) or moderator-review pending rows (mode=flag) when subjects cross strike thresholds, with conservative idempotency, takedown cascade, and a confirm/dismiss moderator surface. Items still deferred:
  - PDS administrative actions (v1.7+). Operator-config-gated bridge that translates emitted labels (and the v1.6 auto-recorded actions layered on top) into PDS-level account state changes by calling `com.atproto.admin.*` on operator-controlled PDSes. **Default is labeler-only when `[pds_admin]` is absent or disabled** — the existing labels-only surface remains the unchanged baseline for community-tier deployments. Operators who run a PDS for their community (e.g., Hideaway with Prism credentials, or any deployment with admin access to its members' PDSes) opt in by declaring credentials and the per-action-type mapping; cairn-mod calls the admin endpoints in lockstep with label emission.
  - Decay-and-recross re-firing (v1.7+ if demand). v1.6 ships conservative idempotency: a rule's window opens only on explicit resolution (revoke / dismiss / confirm-then-revoke). A future release may treat decay-driven count drops as window-opening events; deferred for operational predictability.
  - Mode-applies-forward configuration mutation (v1.7+). Config-reload semantics for in-flight pendings (changing a rule's mode after pendings exist for it) are deliberately untested at the integration layer for v1.6; the writer's config is currently spawn-time-only.
  - Multiple-suspension-history accuracy in decay (v1.7+). v1.4 ships the "only-most-recent-unrevoked-suspension" simplification.
  - Background cache refresh job for `subject_strike_state` (v1.7+). v1.4 ships lazy recompute-on-read; v1.5 / v1.6 didn't change the cache surface; a background job adds lease coordination + restart-handling complexity that defers cleanly until a real performance need surfaces.
  - Per-reason decay overrides (v1.7+). All reasons currently share one decay function and window.
  - Per-reason severity overrides on emitted reason labels (v1.7+ if demand). v1.5 fixes reason-label severity at `inform`; per-reason tuning is conceivable but not motivated.
  - Webhook-driven pending creation (v1.8+ if demand). v1.6's pendings come exclusively from operator-declared threshold-crossing rules. External automated systems (e.g., third-party classifiers) wanting to queue pendings would land their own pending rows via a future endpoint.
  - Policy-rule audit reports (v1.8+ if demand). Operator-facing analytics — "how often did rule X fire? what's the confirm-vs-dismiss rate?" — over the data already in `audit_log` + `pending_policy_actions`.
  - Accessory bot or Web UI for user-facing strike-state rendering — separate project from cairn-mod itself; `tools.cairn.public.getMyStrikeState` (with `activeLabels` from §F21.8) is the substrate, not the UI.

**Continued v1.x trajectory.** Subsequent v1.x releases continue toward Ozone parity for community-tier deployments. Full parity expected around v1.10 (review queue with distinct workflows for signals vs reports, source management with negation-on-revocation default, webhook signal intake, team management refinement). The v1.x sequence is incremental and each release ships in isolation; the trajectory is not a commitment to any particular release sequencing.

**Future direction: cairn-mod-enterprise (open scope).** A platform-tier sibling project for large-scale deployments — Postgres backend, multi-node coordination, observability primitives, HA posture, scheduled jobs, operational tooling — is contemplated as eventual direction but not currently in scope. The split between community-tier (single-binary SQLite, what cairn-mod is today) and enterprise-tier (cluster-aware Postgres) lets the community-tier surface stay tight while the enterprise-tier project absorbs the operational complexity that doesn't belong in a single-maintainer crate. No version commitment; depends on community-tier completion plus genuine adoption pull. Could land alongside v1.x as a separate project, or anchor v2.0 as a unification of both. Deferred for explicit decision when the conditions are clearer.

## 19. Release Runbook

cairn-mod is a single-maintainer project. The release procedure minimizes the number of simultaneous moving parts and makes every step reversible (where possible) or pre-verified (where not).

### 19.1 Pre-release prerequisites

These must be true before starting §19.2's procedure. Items 1 and 2 verify per-release; items 3–5 are setup invariants that should still hold and are spot-checked at release time so silent drift surfaces here rather than in production.

1. **All hard gates (§16.1) pass on `main`.**
2. **All soft gates (§16.2) checked.**
3. **Cargo.toml metadata complete:** `description`, `license` (MIT OR Apache-2.0 — matching `proto-blue` and Rust ecosystem norm), `repository`, `homepage`, `documentation`, `readme`, `keywords`, `categories`. `include` explicitly lists `src/**`, `migrations/**`, `lexicons/**`, `contrib/**`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`.
4. **GitHub issue templates in place:** bug report, feature request, and a redirect-to-SECURITY.md for vulnerability reports.
5. **SECURITY.md published** (see §20).

### 19.2 Release procedure

The release procedure is a manual sequence run from the maintainer's host. v1.0's design envisioned a GitHub Actions workflow (`.github/workflows/release.yml`) doing some of this automatically; that workflow is no longer the canonical path. The manual flow documented here is what's been used for v1.1, v1.2, and v1.3.

**Phase C is the irreversibility point.** Step 10 (`cargo publish`) consumes the version on crates.io if any bytes are accepted; a partial-publish failure cannot be retried at the same version. See §19.3 for rollback posture.

#### Phase A: Readiness

1. **Make the release commit.** Single commit that bumps `Cargo.toml` version to `<X.Y.Z>`, fills the `[<X.Y.Z>] - <YYYY-MM-DD>` entry in `CHANGELOG.md` (with `[Unreleased]` reset above it), updates the README stable-release callout (link + "current stable release" prose), and regenerates `Cargo.lock` via `cargo build`.
2. **Push and verify CI is green** on `origin/main` for the release commit. Do not proceed past green.

#### Phase B: Manual end-to-end verification

Exercise the new version's user-visible features against a real PDS deployment (e.g., `modtest22`). The release crate is identical to what `cargo install cairn-mod` consumers will get; this phase catches behavior gaps CI couldn't reach because CI doesn't run against actual PDS endpoints.

3. **Build:** `cargo build --release` from the repo root.
4. **Stage the binary:** `cp target/release/cairn ~/cairn-test/cairn && chmod +x ~/cairn-test/cairn`. Use a clean test directory so artifacts from prior releases don't pollute the verification.
5. **Sanity-check:** `~/cairn-test/cairn --version` prints `cairn <X.Y.Z>`.
6. **Exercise each user-visible feature** added in this version against the test PDS. Cover happy paths and the documented edge cases (lease conflict, unauthenticated, etc.).
7. **If anything fails, stop.** Fix in a new commit on `main`, push, re-verify CI is green, then resume from step 3. Do not proceed to publish with a known regression.

#### Phase C: Release ceremony

8. **`cargo publish --dry-run`** from the repo root. Inspect the output:
   - Test-fixture skip warnings are normal.
   - Confirm the published `.crate` size is sane (no stray large assets).
   - Confirm the dry-run's compile step succeeds — this is the same compile crates.io will run at real publish.
9. **`cargo publish`.** Wait for completion, then visit `https://crates.io/crates/cairn-mod` and confirm `<X.Y.Z>` is listed as the latest version. Irreversible — see §19.3 if it fails.
10. **Sign and push the release tag:**
    ```
    git tag -s v<X.Y.Z> -m "v<X.Y.Z> — <theme>"
    git push origin v<X.Y.Z>
    ```
    The signing key is the SSH key established at repo init.
11. **Extract the release notes** from CHANGELOG:
    ```
    sed -n '/^## \[<X.Y.Z>\]/,/^## \[/p' CHANGELOG.md | sed '$d' > /tmp/v<X.Y>-notes.md
    cat /tmp/v<X.Y>-notes.md
    ```
    The `cat` is for eyeball-verification — confirm the right section was extracted with no truncation.
12. **Create the GitHub Release:**
    ```
    gh release create v<X.Y.Z> \
      --title "v<X.Y.Z> — <theme>" \
      --notes-file /tmp/v<X.Y>-notes.md
    ```
13. **Verify:** `gh release view v<X.Y.Z>` and visit `https://github.com/skydeval/cairn-mod/releases/tag/v<X.Y.Z>` in a browser. Confirm the page renders with the right title, notes, and source archives (GitHub auto-generates source tarball + zip from the tag — no separate upload needed).

### 19.3 Failure modes and rollback

- **`cargo publish --dry-run` fails** (Phase C step 8): fix the issue in a new commit on `main`, push, re-verify CI is green, then re-run dry-run. No state on crates.io is affected.
- **`cargo publish` fails** (Phase C step 9, the real one): if the registry accepted any bytes, the version on crates.io is consumed and cannot be retried. Bump to `<X.Y.Z+1>`, fix the underlying issue in a new release commit, restart from Phase A. crates.io is append-only — the failed `<X.Y.Z>` cannot be reused.
- **Post-publish critical bug discovered:** `cargo yank --version <X.Y.Z>` immediately. Yanking does not delete but prevents new dependents. Investigate, prepare `<X.Y.Z+1>`, publish the fix. Document the issue and the fix honestly in the next release notes.
- **`gh release create` fails after the tag is pushed** (Phase C step 12): the tag is fine on `origin`. `gh release create v<X.Y.Z> --title ... --notes-file ...` is idempotent against an existing tag — re-running creates the missing Release object. If `gh release view v<X.Y.Z>` returns nothing, retry the create command.

### 19.4 Post-release monitoring

Release-cadence-agnostic monitoring is part of normal maintenance per §20.2's issue-triage SLA: security reports get a 48-hour acknowledgment regardless of how recent the last release was, bug reports flow through weekly triage, feature requests batch into the next minor. A retrospective note in chainlink for each release ("what slipped, what worked, what next-version needs") is good practice but is not a gated part of the runbook.

## 20. Maintenance & Disclosure

cairn-mod is a solo-maintained project with a real dependency chain (Hideaway, future community labelers). This section exists to set expectations for maintenance burden, disclosure processes, and what "unmaintained" would mean.

### 20.1 Security disclosure (SECURITY.md)

A `SECURITY.md` at the repo root contains:

- **Contact:** `security@mod.cairn.tools` — a dedicated email address (not a personal one), subdomain-scoped to `mod.cairn.tools` so mail setup doesn't gate on apex-domain DNS and so other `cairn.tools` subprojects can configure their own contacts independently. Forwarded to the maintainer via the domain registrar.
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

Handoff policy lives in [MAINTAINERS.md](MAINTAINERS.md) — the durable source of truth. The v1.0 posture is archive-on-silence (if the maintainer becomes unresponsive for ~6 months, the repo is archived; users should fork if long-term continuity matters). The policy may change in future versions; check MAINTAINERS.md for the current state.

## 21. Decomposition Sketch (for Crosslink)

Epic: **cairn-mod v1.0**

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
24. **OSS table-stakes files** (1 evening): LICENSE-MIT + LICENSE-APACHE, CONTRIBUTING.md, CODE_OF_CONDUCT.md (Contributor Covenant), SECURITY.md, CHANGELOG.md (Keep a Changelog format; ships with an `[Unreleased]` section only — dated version entries are added by the release workflow at publish time), issue templates, MAINTAINERS.md.
25. **Adversarial review rounds 4 and 5 follow-up fixes** — *already complete before implementation began; merged into this doc. Included here for historical completeness, not as an open issue.*
26. **CI hardening** (1 evening): verify release workflow on clean runners for every target; `cargo sqlx prepare --check`; dry-run the release procedure on a test tag.
27. **Release workflow** (1–2 evenings — see §19): GitHub Actions, binary builds with checksums, crates.io publish with `--dry-run` first, `cairn.tools` deploy, announcement post drafts, rollback procedure documented.

**Total evening estimate:** ~34–40 evenings. At 5 evenings/week: **7–8 weeks of focused work.** Realistic, given the Firehose-consumer-and-VKS velocity baseline. Issue #4 is the most likely source of slippage — a DRISL parity divergence could add a week. Budget accordingly rather than pad every estimate.

**Rounds 1–3 are complete** (design-doc reviews; findings folded into the doc you're reading). They are not open issues and are noted here for historical completeness only.