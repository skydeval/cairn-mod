# ---- builder ----
FROM rust:1.91-bookworm AS builder
WORKDIR /build
# kryphocron-lexicons' build script shells out to the proto-blue-codegen
# binary (its §5.2 subprocess-fallback integration path) and fails the
# build if it's not on PATH. Installed as its own layer so it caches
# across source changes.
RUN cargo install proto-blue-codegen --version "~0.3.1"
# Build context is trimmed by .dockerignore; everything the compile
# needs and nothing else:
#   Cargo.toml Cargo.lock  — manifest + locked deps (bin crate: the
#                            lockfile is the reproducibility contract)
#   .sqlx/                 — sqlx offline query cache; compile-time
#                            macros resolve against it, no
#                            DATABASE_URL in the build
#   migrations/            — embedded at compile time by
#                            sqlx::migrate!("./migrations")
#   lexicons/              — embedded at compile time by include_dir!
#                            (served at /.well-known/lexicons/)
#   src/
COPY Cargo.toml Cargo.lock ./
COPY .sqlx .sqlx
COPY migrations migrations
COPY lexicons lexicons
COPY src src
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked

# ---- runtime ----
FROM debian:bookworm-slim
# ca-certificates: rustls needs a root store (TLS is pure rustls — no
# libssl). curl: the compose healthcheck execs it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# Fixed UID 1000 is image API: the signing-key loader requires the key
# file to be owned by the effective UID (credential_file §5.1), so the
# documented host-side `chown 1000 signing-key.hex` must stay valid
# across image releases. Never change this UID.
RUN useradd --system --uid 1000 --create-home \
      --home-dir /var/lib/cairn --shell /usr/sbin/nologin cairn \
    && chmod 0750 /var/lib/cairn
COPY --from=builder /build/target/release/cairn /usr/local/bin/cairn
# Container-correct bind + path defaults. The env layer OVERRIDES any
# mounted cairn.toml for these three (figment precedence) — deliberate:
# they are container-topology facts, not operator policy. Override via
# compose environment:/.env/-e if you must.
ENV CAIRN_BIND_ADDR=0.0.0.0:3000 \
    CAIRN_DB_PATH=/var/lib/cairn/cairn.db \
    CAIRN_SIGNING_KEY_PATH=/var/lib/cairn/signing-key.hex
USER cairn
EXPOSE 3000
# ENTRYPOINT/CMD split: `docker compose run --rm cairn operator-login …`
# invokes the operator CLI in the same image/user/volume context, which
# the bootstrap flow requires (session file must be written in-container).
ENTRYPOINT ["cairn"]
CMD ["serve"]
