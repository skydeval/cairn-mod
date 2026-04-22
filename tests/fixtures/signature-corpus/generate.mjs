// Generate the Cairn <-> @atproto parity corpus.
//
// For each fixture the script writes four files:
//   NN-<descr>.json     — the label record as a plain object (no `sig`).
//   NN-<descr>.cbor     — canonical DAG-CBOR bytes of the label, `sig` absent,
//                          `ver` present. This is the exact byte sequence
//                          SHA-256'd before signing (§6.2 step 5 input).
//   NN-<descr>.sha256   — hex of sha256(cbor). Audit aid; not load-bearing.
//   NN-<descr>.sig      — raw 64-byte compact (r || s) ECDSA signature.
//
// Parity claim: proto-blue's `lex_cbor::encode` + `K256Keypair::sign`
// produce byte-identical `.cbor` and `.sig` from the same `.json` inputs.
// The Rust test at tests/signature_parity.rs asserts this.
//
// Regenerate:   npm install && npm run generate
// The regenerated files must be committed. README.md captures the exact
// resolved patch versions from the lockfile.

import { Secp256k1Keypair } from '@atproto/crypto';
import { encode as dagCborEncode } from '@ipld/dag-cbor';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// Pinned test private key — NEVER use in production. Chosen arbitrary 32-byte
// hex, clearly < curve order n. Both the generator and the Rust KAT/parity
// tests use this exact key; changing it regenerates the entire corpus.
const PRIV_HEX = 'b7e3f1c9a2d84ef50712436589bc1d8f023147b68cafed94a8b603c7159d4e2a';

// Stable baseline values used across fixtures so the matrix isolates the
// combinatorics of optional fields. The DRISL edge-case fixtures (09, 10)
// deliberately vary `val`.
const BASE = {
  ver: 1,
  src: 'did:plc:3jzfcijpj2z2a4pdagfkktq6',
  uri: 'at://did:plc:3jzfcijpj2z2a4pdagfkktq6/app.bsky.feed.post/3k5jy6qyfh22',
  val: 'spam',
  cts: '2026-04-22T12:00:00.000Z',
};

const CID = 'bafyreihvwplzihwmxejjxkc3olh6mouc2oduycgfhigs5lmxz2q2zmjg4a';
const EXP = '2027-04-22T12:00:00.000Z';

// 128-byte val — exercises the CBOR text-string length-prefix boundary at
// the 1-byte / 2-byte boundary (strings >=24 bytes use a 1-byte length,
// >=256 use 2-byte; 128 puts us firmly in the 1-byte-length region but
// close enough to validate correct boundary handling in the encoder).
const VAL_128 = 's'.repeat(128);

// Unicode val — BCP-47-valid grapheme cluster sequence including a 4-byte
// UTF-8 codepoint (the emoji) to exercise multi-byte text handling.
const VAL_UNICODE = 'porn-🔞-違規內容';

// Fixtures. Field ordering here is for readability only; canonical encoding
// sorts map keys length-first then byte-order, so the insertion order of
// object keys is irrelevant to the output bytes.
const FIXTURES = [
  ['01-minimal', { ...BASE }],
  ['02-cid', { ...BASE, cid: CID }],
  ['03-exp', { ...BASE, exp: EXP }],
  ['04-cid-exp', { ...BASE, cid: CID, exp: EXP }],
  ['05-neg', { ...BASE, neg: true }],
  ['06-cid-neg', { ...BASE, cid: CID, neg: true }],
  ['07-exp-neg', { ...BASE, exp: EXP, neg: true }],
  ['08-cid-exp-neg', { ...BASE, cid: CID, exp: EXP, neg: true }],
  ['09-val-128byte', { ...BASE, val: VAL_128 }],
  ['10-val-unicode', { ...BASE, val: VAL_UNICODE }],
];

// Canonical construction per §6.2: strip `sig`, keep `ver`, omit optional
// fields that are absent (DAG-CBOR distinguishes absent from null), omit
// `neg` when false (schema default — matches @atproto/api `omitFalse`).
function canonicalize(record) {
  const out = {
    ver: record.ver,
    src: record.src,
    uri: record.uri,
  };
  if (record.cid !== undefined) out.cid = record.cid;
  out.val = record.val;
  if (record.neg === true) out.neg = true;
  out.cts = record.cts;
  if (record.exp !== undefined) out.exp = record.exp;
  return out;
}

async function main() {
  const privBytes = Buffer.from(PRIV_HEX, 'hex');
  const keypair = await Secp256k1Keypair.import(privBytes, { exportable: true });

  // Capture the public key in multibase form so the Rust parity test knows
  // which key verified. Written once as KEY.json; shared across fixtures.
  const keyMeta = {
    jwtAlg: 'ES256K',
    did: keypair.did(),                       // did:key:zQ3s...
    publicKeyMultibase: keypair.did().replace('did:key:', ''), // z...
    privateKeyHex: PRIV_HEX,                  // for KAT + parity tests
  };
  writeFileSync(join(HERE, 'KEY.json'), JSON.stringify(keyMeta, null, 2) + '\n');

  mkdirSync(HERE, { recursive: true });
  for (const [name, record] of FIXTURES) {
    const canonical = canonicalize(record);
    const cbor = dagCborEncode(canonical);
    const hash = createHash('sha256').update(cbor).digest();
    const sig = await keypair.sign(cbor);

    if (sig.length !== 64) {
      throw new Error(`fixture ${name}: expected 64-byte sig, got ${sig.length}`);
    }

    writeFileSync(join(HERE, `${name}.json`), JSON.stringify(canonical, null, 2) + '\n');
    writeFileSync(join(HERE, `${name}.cbor`), cbor);
    writeFileSync(join(HERE, `${name}.sha256`), hash.toString('hex') + '\n');
    writeFileSync(join(HERE, `${name}.sig`), sig);

    console.log(`${name}: cbor=${cbor.length}B sig=${sig.length}B`);
  }

  console.log(`\nWrote ${FIXTURES.length} fixtures to ${HERE}`);
  console.log(`Public key (multibase): ${keyMeta.publicKeyMultibase}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
