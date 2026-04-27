# Operations

Day-2 operator content for cairn-mod: production checklist, secrets
hygiene, monitoring, health probes, dependency scanning. Walk through
this before pointing real subscribers at the instance.

For first-deployment setup (install, configure, bootstrap), see
[SETUP.md](SETUP.md). For moderator-CLI workflows (managing
moderators, reports, audit log queries), see
[docs/moderator-cli.md](docs/moderator-cli.md). For trust-chain
disclosures and architecture overview, see [README.md](README.md).

## Production Checklist

Walk through this before pointing real subscribers at the instance.
Each item links the relevant design-doc section for deeper context.

### Transport ([§F13](cairn-design.md#f13-single-binary--sqlite-deployment))

- [ ] **TLS terminates at the reverse proxy**, not cairn-mod. `cairn
  serve` binds HTTP only (default `127.0.0.1:3000`) and assumes a
  TLS-terminating proxy fronts it. See
  [`contrib/`](contrib/) for Caddy and nginx templates.
- [ ] **HSTS header** on responses (`Strict-Transport-Security:
  max-age=31536000; includeSubDomains`). Set at the proxy; the
  contrib templates ship it.

### Rate limits ([§F13](cairn-design.md#f13-single-binary--sqlite-deployment) numbers, enforced at reverse proxy)

- [ ] **`createReport`** per-IP: example rate-limit
  configurations ship as commented operator-add stanzas in
  [`contrib/nginx/cairn.conf`](contrib/nginx/cairn.conf) and
  [`contrib/caddy/Caddyfile`](contrib/caddy/Caddyfile). Operators
  uncomment and tune rate values based on expected traffic and
  abuse posture. The §F13 reference values (burst 3, rate
  10/hour) are the design-doc baseline; the contrib examples
  mirror those numbers but ship commented by default to avoid
  version-specific syntax in shipped templates (the `r/h` rate
  unit landed in nginx 1.27, post-Ubuntu-LTS).
- [ ] **`subscribeLabels`** per-IP: 8 concurrent connections.
  Enforced active-by-default in `contrib/nginx/cairn.conf` —
  connection caps (`limit_conn_*`) are version-stable across
  nginx 1.18+, so the conn-cap stanza ships uncommented unlike
  its rate-limit sibling. The Caddy template ships without
  (Caddy core lacks connection-cap primitives;
  `caddy-ratelimit` provides them but is a third-party module).

### Secrets ([§5.1](cairn-design.md#51-labeler-service-identity), [§5.3](cairn-design.md#53-cli-ergonomics))

- [ ] **Signing key file** at mode `0600`, owned by the running
  user. cairn-mod's `credential_file::check_mode_and_owner` refuses
  wider permissions or foreign ownership at startup.
- [ ] **Signing key file NEVER committed to version control.** A
  signing key in git history is a compromise even after deletion.
- [ ] **Signing key material NOT delivered via env var.** The
  `CAIRN_SIGNING_KEY` env var is explicitly rejected by the
  loader (`SIGNING_KEY_ENV_REJECTED` constant) — the guardrail
  exists to prevent an "ergonomics" PR later adding a parallel
  unsafe path.
- [ ] **Operator session file** (written by `cairn operator-login`)
  at `0600` owned by the running user. Treat it as equivalent to
  your PDS app password — anyone with read access can push records
  to the labeler's PDS repo until the session expires.

### Key lifecycle ([§4.1.6](cairn-design.md#41-out-of-scope-threats), [§12](cairn-design.md#12-security-considerations))

- [ ] **Signing key is permanent for v1.** Rotation is v1.1
  scope. Plan the host, permissions, and backup accordingly — a
  v1 key lives as long as the labeler identity.
- [ ] **Do NOT remove the labeler signing key from the DID
  document.** Every historical label cairn-mod has signed stops
  verifying at consumers. Catastrophic and not undoable.

### Backup

- [ ] **SQLite database** (`db_path`) — contains labels, reports,
  audit log, moderators, single-instance lease state. Regular
  backups via `sqlite3 .backup` or filesystem snapshot.
- [ ] **Signing key file** (`signing_key_path`) — losing it means
  losing the labeler identity. Back up encrypted, store offline.
- [ ] **Session files are NOT backup-worthy.** Operator and
  moderator sessions are re-created by running `cairn
  operator-login` / `cairn login`.

### Single instance per DID ([§F5](cairn-design.md#f5-label-persistence-with-monotonic-sequence))

- [ ] **Only one `cairn serve` against a given DID at a time.**
  cairn-mod enforces this with a SQLite-backed lease; the loser of a
  startup race exits with `LEASE_CONFLICT` (exit code 11). The
  contrib systemd unit sets `RestartPreventExitStatus=11` so
  systemd doesn't restart-loop.
- [ ] **Even with the lease disabled, two instances against the
  same DB would corrupt the sequence space.** Don't attempt it.

### Monitoring (v1 surface is minimal)

- [ ] **systemd status + journalctl** — errors and panics land
  here. The contrib unit sets `StandardOutput=journal`.
- [ ] **Disk usage on the `db_path` partition** — cairn-mod has an
  app-level disk guard for the report path, but OS-level
  monitoring catches everything.
- [ ] **TLS certificate expiry at the reverse proxy** — Caddy
  auto-renews via ACME; nginx + certbot needs its own cron check.

### Health probes ([§F14](cairn-design.md#f14-health-and-readiness-probe-endpoints-v11))

cairn-mod exposes two unauthenticated endpoints for orchestrators:

- [ ] **`GET /health`** — liveness probe. Always returns 200 with
  `{"status": "ok", "version": "..."}` while the process can
  answer a request. No dependencies checked. Failure = restart
  the pod.
- [ ] **`GET /ready`** — readiness probe. Returns 200 on all-ok,
  503 on any check failure. Body is identical in both cases and
  names the individual checks (`database`, `signing_key`,
  `label_stream`). Failure = stop routing new traffic.
- [ ] **Verify both endpoints respond correctly against a running
  instance** before first release. `curl -s http://127.0.0.1:3000/health`
  should return 200; `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/ready`
  should return 200 when healthy and 503 when any check is
  intentionally failed (e.g., stop the writer, or point at an
  unreachable DB).

### Dependency security scanning ([§F15](cairn-design.md#f15-dependency-security-scanning-in-ci-v11))

- [ ] **Most recent CI security scan on `main` is green.** `cargo-audit`
  and `cargo-deny` both run on push to `main` and every PR; a scheduled
  daily `cargo-audit` opens a tracking issue when advisories land
  out-of-band. Before pointing real subscribers at the instance, verify
  the latest run on the version you're deploying passed.
- [ ] **No advisories ignored without dated rationale and review date.**
  Open `deny.toml` and inspect `[[advisories.ignore]]`. Each entry must
  carry a `reason` naming why the risk is accepted, and a
  `Review: YYYY-MM-DD` comment ≤ 180 days out. `grep -n 'Review:' deny.toml`
  is the one-command audit. Entries without a review date, or with
  dates in the past, are a hygiene failure — either renew the review
  or remove the ignore.
