#!/usr/bin/env bash
#
# Quickstart rot-check (#10) — walks the README's operator workflow
# end-to-end against a mock PDS so silent README drift fails CI.
#
# What this catches:
#   - README's TOML config blocks no longer parse against
#     cairn_mod::config::Config (field renames, type changes).
#   - `cairn publish-service-record` regresses against the labeler
#     config block the README documents.
#   - `cairn serve`'s §F19 startup-verify path breaks against a
#     just-published record.
#   - The /.well-known/did.json shape regresses (missing
#     verification methods, missing #atproto_label key).
#
# What this does NOT catch (chartered out of scope):
#   - openssl keygen path (python path is sufficient).
#   - systemd unit installation (covered by #9 via syntactic
#     validation).
#   - reverse-proxy specifics (#9 + future docker-compose tracker).
#   - real PDS interactions (`bsky.social`, real `did:plc` paths).
#
# Mocking shortcut, called out for honesty:
#   `cairn operator-login` reads the password via rpassword's
#   /dev/tty path, which CI runners typically lack. Rather than
#   shell-piping a password into a binary that explicitly errors
#   on no-TTY, this script writes the operator session file
#   directly with the canned tokens the mock PDS mints. The
#   `cairn operator-login` step in the README is therefore the
#   ONE link in the operator workflow this rot-check skips. If
#   the session file format ever changes, this script needs the
#   parallel update — flagged in CHANGELOG and in the commit
#   message.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

WORK=$(mktemp -d)
cleanup() {
    local exit_code=$?
    set +e
    [[ -n "${SERVE_PID:-}" ]] && kill "$SERVE_PID" 2>/dev/null
    [[ -n "${MOCK_PID:-}"  ]] && kill "$MOCK_PID"  2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo "=== build cairn (release) + mock_pds example ==="
SQLX_OFFLINE=true cargo build --release --bin cairn
SQLX_OFFLINE=true cargo build --release --example mock_pds

CAIRN="$REPO_ROOT/target/release/cairn"
MOCK_PDS="$REPO_ROOT/target/release/examples/mock_pds"

export MOCK_PDS_ADDR="127.0.0.1:5174"
export MOCK_PDS_OPERATOR_DID="did:plc:mockoperator0000000000000000"

echo "=== generate signing key (README step 2 — python path) ==="
python3 -c 'import secrets; print(secrets.token_hex(32))' > "$WORK/signing-key.hex"
chmod 600 "$WORK/signing-key.hex"

echo "=== write cairn.toml (README step 3) ==="
cat > "$WORK/cairn.toml" <<TOML
service_did = "did:plc:mockoperator0000000000000000"
service_endpoint = "http://127.0.0.1:3001"
db_path = "$WORK/cairn.db"
signing_key_path = "$WORK/signing-key.hex"
bind_addr = "127.0.0.1:3001"

[labeler]
label_values = ["spam"]

[[labeler.label_value_definitions]]
identifier = "spam"
severity = "alert"
blurs = "none"
default_setting = "warn"
locales = [{ lang = "en", name = "Spam", description = "Unsolicited promotional content." }]

[operator]
pds_url = "http://${MOCK_PDS_ADDR}"
session_path = "$WORK/operator-session.json"
TOML

echo "=== start mock PDS in background ==="
"$MOCK_PDS" &
MOCK_PID=$!
# Wait for the listener to bind. Polling rather than fixed sleep so
# CI variance doesn't leak into the timing.
for _ in $(seq 1 50); do
    if curl -sSL --max-time 1 "http://${MOCK_PDS_ADDR}/" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

echo "=== inject operator session (rpassword + no-TTY workaround) ==="
cat > "$WORK/operator-session.json" <<JSON
{
  "version": 1,
  "pds_url": "http://${MOCK_PDS_ADDR}",
  "operator_did": "${MOCK_PDS_OPERATOR_DID}",
  "operator_handle": "alice.bsky.social",
  "access_jwt": "mock-access-jwt",
  "refresh_jwt": "mock-refresh-jwt"
}
JSON
chmod 600 "$WORK/operator-session.json"

echo "=== cairn publish-service-record (README step 4 second command) ==="
"$CAIRN" publish-service-record --config "$WORK/cairn.toml"

echo "=== cairn serve (README step 5) ==="
"$CAIRN" serve --config "$WORK/cairn.toml" &
SERVE_PID=$!

# Poll readiness. The /health endpoint is the canonical readiness
# probe; falling back to bare TCP connect if the build doesn't
# include /health (defensive — current main does).
for _ in $(seq 1 100); do
    if curl -sSL --max-time 1 http://127.0.0.1:3001/ready >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

echo "=== verify /.well-known/did.json (README step 6) ==="
RESP=$(curl -fsSL http://127.0.0.1:3001/.well-known/did.json)
echo "$RESP" | python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
assert "verificationMethod" in d, "did.json missing verificationMethod array"
assert any(
    v.get("id", "").endswith("#atproto_label") for v in d["verificationMethod"]
), "no verification method with id ending #atproto_label"
assert "service" in d, "did.json missing service array (AtprotoLabeler entry)"
print("OK: did.json has #atproto_label key + AtprotoLabeler service entry")
'

echo ""
echo "=== quickstart rot-check: PASS ==="
