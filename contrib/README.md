# contrib/

Operator-ready deployment templates for running cairn-mod behind a
TLS-terminating reverse proxy on a standard Linux host.

These files are not hand-verified on a live instance before every
release. Adapt them to your environment — the shapes are correct;
specific paths, hostnames, and user names will differ.

## What's in here

- **`systemd/cairn.service`** — systemd service unit for running
  `cairn serve`. Hardened defaults (sandboxing + capability drop +
  syscall filter). The `RestartPreventExitStatus=11` line is the
  operational payoff for cairn-mod's distinct `LEASE_CONFLICT` exit
  code (see `src/cli/error.rs`): if another instance already holds
  the §F5 single-instance lease, systemd stops instead of
  crash-looping.

- **`caddy/Caddyfile`** — Caddy reverse-proxy + TLS. Auto-ACME
  certificates, HSTS, no-cache on admin endpoints, transparent
  WebSocket upgrade for subscribeLabels.

- **`nginx/cairn.conf`** — equivalent posture in nginx. Manual TLS
  cert paths (operator provides via certbot or similar), explicit
  `Upgrade`/`Connection` headers for WebSocket.

## Caddy vs nginx

Both work. Pick the one you already operate — the two files are
functionally equivalent for cairn-mod's surface, just syntactically
different.

One substantive asymmetry between them: **rate limits** (§F13
targets — createReport per-IP burst 3 / rate 10 per hour;
subscribeLabels per-IP 8 concurrent). nginx has rate-limiting in
core, so `nginx/cairn.conf` ships with both limits **active by
default**. Caddy's core does not — the §F13 limits require the
third-party [`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit)
module — so `Caddyfile` ships with rate-limit stanzas **commented
out** and a pointer to the module install. This is a platform
capability difference, not an oversight.

## Install (systemd + nginx)

```
# 1. Dedicated service user.
sudo useradd --system --home-dir /var/lib/cairn --shell /usr/sbin/nologin cairn

# 2. Binary.
sudo install -m 0755 -o root -g root target/release/cairn /usr/local/bin/cairn

# 3. Config directory + file.
sudo install -dm 0750 -o root -g cairn /etc/cairn
sudo install -m 0640 -o root -g cairn cairn.toml /etc/cairn/cairn.toml

# 4. State directory + signing key (see "File permissions" below for
# why the signing key does NOT live in /etc/cairn/).
sudo install -dm 0700 -o cairn -g cairn /var/lib/cairn
sudo install -m 0600 -o cairn -g cairn signing-key.hex /var/lib/cairn/signing-key.hex

# 5. systemd service.
sudo install -Dm 0644 contrib/systemd/cairn.service /etc/systemd/system/cairn.service
sudo systemctl daemon-reload
sudo systemctl enable --now cairn

# 6. Reverse proxy (nginx path shown; see contrib/caddy/Caddyfile
# for the Caddy equivalent).
sudo install -m 0644 contrib/nginx/cairn.conf /etc/nginx/sites-available/cairn.conf
sudo ln -s /etc/nginx/sites-available/cairn.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 7. Verify.
sudo systemctl status cairn
curl -sSL https://labeler.example.com/.well-known/did.json
```

## File permissions

cairn-mod is strict about credential-file permissions per §5.1 /
§5.3 (see `src/credential_file.rs` for the enforcement). The
relevant split is not obvious at first glance:

| File | Owner | Mode | Notes |
|---|---|---|---|
| `/etc/cairn/cairn.toml` | `root:cairn` | `0640` | Ops hygiene. Not enforced by cairn-mod; readable by service user via group. |
| `/var/lib/cairn/signing-key.hex` | `cairn:cairn` | `0600` | **Enforced**. cairn-mod's `credential_file::check_mode_and_owner` rejects anything else. |
| `/var/lib/cairn/cairn.db` | `cairn:cairn` | `0600` | Created automatically by `storage::open` under systemd's `StateDirectory`. |

**Subtle caveat on the signing key's location:** the key file lives
under `/var/lib/cairn/` (systemd's `StateDirectory`), **not under
`/etc/cairn/`**. If you put it in `/etc/cairn/signing-key.hex`,
systemd's `ConfigurationDirectory` defaults give you a parent dir
owned by `root:cairn` with the file typically ending up owned by
root. cairn-mod's owner check — `file UID == running effective UID` —
then fails with `CredentialFileError::ForeignOwner`, and `cairn
serve` exits before binding the port.

`StateDirectory=cairn` in the unit file gives `/var/lib/cairn`
owned by `cairn:cairn` automatically, so a file placed there by
the `cairn` user has the right ownership for the check to pass.

## Cross-references

- Broader operator story (production checklist covering TLS +
  rate limits + key rotation + backup + monitoring + trust-chain
  disclosures) lives in the root README under "Production
  Checklist." See tracker issues #20 / #21.
- Security disclosure: [`../SECURITY.md`](../SECURITY.md).
- Upstream threat model: [`../cairn-design.md`](../cairn-design.md)
  §4 and §12.
