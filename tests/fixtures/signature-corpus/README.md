# Cairn ↔ @atproto parity corpus

Byte-exact fixtures that pin Cairn's canonical DAG-CBOR + secp256k1 signing
pipeline against the TypeScript reference implementation (§F2, §6.2, §6.3).
The Rust test at [`tests/signature_parity.rs`](../../signature_parity.rs)
asserts that `proto-blue`'s `lex_cbor::encode` + `K256Keypair::sign`
produce byte-identical `.cbor` and `.sig` for every fixture.

## Reference versions (resolved, 2026-04-22)

Captured from `package-lock.json` at the time the fixtures in this directory
were generated:

- `@atproto/crypto@0.4.5` — canonical signing path (`Secp256k1Keypair.sign`).
- `@ipld/dag-cbor@9.2.2` — canonical DAG-CBOR encoder (what `@atproto` uses
  internally for record canonicalization).
- `@noble/curves@1.9.7` — secp256k1 RFC 6979 + low-S primitive backing
  `@atproto/crypto`.
- `@noble/hashes@1.8.0` — SHA-256 primitive.

Corresponding `@atproto/api` release at this time: **`0.19.11`**. `@atproto/api`
is the user-visible package named by the issue spec; it depends transitively
on `@atproto/crypto` + `@ipld/dag-cbor`, which are what actually implement
the canonicalization and signing we claim parity with. Those two are what
this corpus pins.

## Regeneration

### Prerequisites

- **Node.js ≥ 20** — the generator uses `node:crypto` WebCrypto-style digests
  and ESM import syntax. Verify with `node --version`.
- **npm** (bundled with Node) — used to install the pinned dev deps.
- **A clean working tree for this directory** — `git status
  tests/fixtures/signature-corpus/` should be empty before you start, so the
  regeneration diff is unambiguous.

### Steps

All paths are relative to the repository root.

```bash
# 1. Install the pinned reference implementation (@atproto/crypto,
#    @ipld/dag-cbor, and their transitive @noble/* deps). Uses the
#    committed package-lock.json, so the resolution is reproducible.
cd tests/fixtures/signature-corpus
npm install

# 2. Run the generator. Writes 10 fixtures × 4 files (.json, .cbor,
#    .sha256, .sig) plus KEY.json. Overwrites any existing fixtures.
npm run generate

# 3. Verify proto-blue agrees byte-for-byte. All three tests must pass;
#    failure here means a real parity regression — DO NOT regenerate to
#    make it green, fix the encoder.
cd ../../..
SQLX_OFFLINE=true cargo test --test signature_parity
```

### Expected output from step 2

```
01-minimal: cbor=158B sig=64B
02-cid: cbor=223B sig=64B
03-exp: cbor=188B sig=64B
04-cid-exp: cbor=253B sig=64B
05-neg: cbor=163B sig=64B
06-cid-neg: cbor=228B sig=64B
07-exp-neg: cbor=193B sig=64B
08-cid-exp-neg: cbor=258B sig=64B
09-val-128byte: cbor=283B sig=64B
10-val-unicode: cbor=176B sig=64B

Wrote 10 fixtures to .../tests/fixtures/signature-corpus
Public key (multibase): zQ3shwPCvpBTKrDwtwYtJfrBD1nCBHbwwp4PRtyhDGA98s3oN
```

The byte counts are stable: any drift means either the schema changed,
the reference implementation changed, or the generator itself was edited.
A genuinely intentional regeneration will line up against one of those
three; an accidental one won't.

### Commit etiquette

After regeneration, all four files per fixture **must** be committed
together with any source change that motivated the refresh. A fixture
update in isolation is suspicious. `package-lock.json` is tracked so
reproductions pin transitive deps; `node_modules/` is gitignored.

### When to regenerate

1. The ATProto label-record schema changes (new/removed fields in §6.1).
2. `@atproto/crypto` or `@ipld/dag-cbor` publishes a change that alters
   canonical byte output or signature format. Bump the pinned versions
   in `package.json`, rerun, and document the delta in this README
   (update the "Reference versions" section and the date heading).

Regenerating without a schema or reference-lib change is a red flag: it
almost certainly means the fixtures drifted under an accidental
modification to the generator or the encoder. Investigate before
committing.

## Fixture matrix

| #  | cid | exp | neg | val                          | Purpose                                  |
|----|-----|-----|-----|------------------------------|------------------------------------------|
| 01 | –   | –   | –   | `spam`                       | Minimal — all optional fields absent.    |
| 02 | ✓   | –   | –   | `spam`                       | `cid` only.                              |
| 03 | –   | ✓   | –   | `spam`                       | `exp` only.                              |
| 04 | ✓   | ✓   | –   | `spam`                       | `cid` + `exp`.                           |
| 05 | –   | –   | ✓   | `spam`                       | Negation, no optionals.                  |
| 06 | ✓   | –   | ✓   | `spam`                       | Negation + `cid`.                        |
| 07 | –   | ✓   | ✓   | `spam`                       | Negation + `exp`.                        |
| 08 | ✓   | ✓   | ✓   | `spam`                       | Negation + all optionals.                |
| 09 | –   | –   | –   | 128-char ASCII string        | Text-string length-prefix boundary.      |
| 10 | –   | –   | –   | Mixed ASCII + 4-byte emoji   | UTF-8 multi-byte codepoint handling.     |

`neg` column "–" means the field is absent (schema default `false`); "✓"
means `neg: true` is present. Per §6.2, `neg: false` is omitted from
canonical form — this is pinned by fixture 01, whose `.cbor` contains no
`neg` key.

## Per-fixture files

Each fixture `NN-<descr>` produces four files:

- `.json` — the label record as a plain object (no `sig`, absent-fields
  truly absent). This is the input to Cairn's encoder in the parity test.
- `.cbor` — canonical DAG-CBOR bytes. Compared byte-for-byte against
  `canonical_bytes(label)`.
- `.sha256` — hex SHA-256 of the CBOR bytes. Not load-bearing for the
  test; included as an audit aid when debugging a parity divergence.
- `.sig` — raw 64-byte compact `(r, s)` signature. Compared byte-for-byte
  against `sign_label(key, label)`.

## Signing key

Pinned hex private key (generator + Rust tests share this exact value):

    b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a

`KEY.json` captures the derived `did:key` and `publicKeyMultibase` for
use by [`tests/signature_parity.rs`](../../signature_parity.rs) when
verifying signatures.

**This is a test key. Do not use it in production.** It is committed
deliberately: without a pinned key, the `.sig` bytes would not be
reproducible and the parity guarantee would collapse to "our encoder
agrees with whatever key we happened to generate this run."
