//! `cairn` — ATProto labeler binary entry point.
//!
//! Exposes the CLI subcommands (login/logout/report) and
//! `cairn serve` — the long-running labeler process.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cairn_mod::cli::{
    audit, audit_rebuild, audit_verify,
    error::{CliError, code},
    login::{self, post_login_warning},
    logout::{self, LogoutOutcome},
    moderator, moderator_action, moderator_events, moderator_pending, operator_login,
    pds_admin as cli_pds_admin, pds_admin_actions as cli_pds_admin_actions,
    pds_admin_reads as cli_pds_admin_reads,
    publish_service_record::{self, PublishOutcome},
    report::{self, ReportCreateInput},
    retention, session, trust_chain,
    unpublish_service_record::{self, UnpublishOutcome},
};
use cairn_mod::config::Config;
use cairn_mod::moderators::Role;
use cairn_mod::{serve, storage};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "cairn", version, about = "Cairn labeler CLI")]
struct Cli {
    /// Increase log verbosity. Default: warn. `-v` → info, `-vv` → debug.
    #[arg(short = 'v', action = ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Authenticate to a PDS, resolve Cairn's service DID, and
    /// cache a session file. Prompts for the PDS app password
    /// interactively — there is no `--app-password` flag (§5.3).
    /// For CI use, pre-bake a session file on a secure machine and
    /// point `CAIRN_SESSION_FILE` at it.
    Login(LoginArgs),

    /// Remove the local session file and revoke the token at the
    /// PDS. Local cleanup proceeds even if the PDS call fails
    /// (network down, server error) — the user's intent is to
    /// sever access.
    Logout,

    /// Report management.
    Report {
        #[command(subcommand)]
        sub: ReportSub,
    },

    /// Run the Cairn labeler as a long-running server. Loads config,
    /// runs migrations, acquires the single-instance lease, and
    /// serves HTTP until SIGINT/SIGTERM.
    Serve(ServeArgs),

    /// Authenticate as the operator (the DID that owns the labeler's
    /// PDS account) so `cairn publish-service-record` can write
    /// records to that repo. Prompts for the PDS app password
    /// interactively; writes a 0600 session file at the path in
    /// config's `[operator]` section.
    OperatorLogin(OperatorLoginArgs),

    /// Render `app.bsky.labeler.service` from the `[labeler]` config
    /// section and publish it to the operator's PDS at rkey=self
    /// (§F1). Idempotent — no PDS write if the content hash matches
    /// the last-published value.
    PublishServiceRecord(ServeArgs),

    /// Remove the published `app.bsky.labeler.service` record from
    /// the operator's PDS (#34). Idempotent — running when nothing
    /// is published is a no-op success, not an error. Clears the
    /// local `labeler_config` state on a real delete; the next
    /// `cairn serve` startup verify (§F19) will then exit 13
    /// SERVICE_RECORD_ABSENT until a fresh
    /// `cairn publish-service-record` runs.
    UnpublishServiceRecord(ServeArgs),

    /// Moderator management. Direct manipulation of the
    /// `moderators` SQLite table — bypasses the HTTP admin
    /// surface, so adds + removes via this command leave
    /// `moderators.added_by` NULL (no attested CLI-caller DID).
    Moderator {
        #[command(subcommand)]
        sub: ModeratorSub,
    },

    /// Audit log queries (`tools.cairn.admin.listAuditLog` /
    /// `getAuditLog`). **Admin role required** — the server's auth
    /// check uses `verify_and_authorize_admin_only`, so moderator-
    /// role sessions receive 403.
    Audit {
        #[command(subcommand)]
        sub: AuditSub,
    },

    /// Retention management — operator-initiated sweeps of the
    /// labels table (§F4). **Admin role required.**
    Retention {
        #[command(subcommand)]
        sub: RetentionSub,
    },

    /// Trust-chain transparency surface
    /// (`tools.cairn.admin.getTrustChain`). Returns declared
    /// signing keys, maintainer roster, service-record summary,
    /// and instance metadata. **Admin role required.**
    #[command(name = "trust-chain")]
    TrustChain {
        #[command(subcommand)]
        sub: TrustChainSub,
    },

    /// Backfill prev_hash + row_hash for pre-v1.3 audit_log rows
    /// (#40). One-shot operator command — direct DB, no HTTP, no
    /// moderator session. Acquires the writer lease for the
    /// duration of the rebuild; refuses to run while `cairn serve`
    /// is up. Idempotent — re-running on an already-rebuilt log
    /// is a no-op success.
    #[command(name = "audit-rebuild")]
    AuditRebuild(AuditRebuildArgs),

    /// Manual escape hatch for the PDS-admin bridge (#87, §F23 /
    /// §A13). Routes through the canonical recordAction pipeline
    /// (HTTP-routed; daemon must be up); the writer's post-commit
    /// dispatch fires the configured backend's takedown_account /
    /// suspend_account / restore_account call automatically.
    /// **Does not bypass strike accounting** — manual takedowns
    /// update strike state the same as policy-driven ones. For a
    /// no-strike test path, use a dedicated test subject DID.
    #[command(name = "pds-admin")]
    PdsAdmin {
        #[command(subcommand)]
        sub: PdsAdminSub,
    },

    /// Manage the inbound XRPC gateway's `xrpc_known_callers`
    /// table — moderator DIDs whose proxied
    /// `tools.ozone.moderation.*` calls cairn-mod accepts (#94).
    /// Direct DB; no HTTP. CLI-only management per §A12.
    #[command(name = "xrpc-callers")]
    XrpcCallers {
        #[command(subcommand)]
        sub: XrpcMembershipSub,
    },

    /// Manage the inbound XRPC gateway's `xrpc_trusted_pdses`
    /// table — PDS DIDs whose forwarded
    /// `com.atproto.moderation.createReport` calls cairn-mod
    /// accepts (#94).
    #[command(name = "xrpc-pdses")]
    XrpcPdses {
        #[command(subcommand)]
        sub: XrpcMembershipSub,
    },
}

/// `cairn pds-admin {takedown, suspend, restore}` (#99).
#[derive(Debug, Subcommand)]
enum PdsAdminSub {
    /// Record a Takedown action and let the writer's post-commit
    /// dispatch fire the backend's `takedown_account`.
    Takedown(PdsAdminTakedownArgs),
    /// Record a temp_suspension (when `--duration` is set) or
    /// indef_suspension (otherwise) and dispatch
    /// `suspend_account`.
    Suspend(PdsAdminSuspendArgs),
    /// Revoke the most-recent unrevoked takedown / suspension for
    /// the subject and dispatch `restore_account`. cairn-mod has
    /// no first-class "restore" action_type — this resolves to a
    /// `revoke_action` of the most-recent suspension row.
    Restore(PdsAdminRestoreArgs),
    /// Query the configured PDS-admin backend's moderation event
    /// stream (v1.8.3; RustBackend via
    /// tools.aurora.moderator.queryEvents — Unsupported on Ozone).
    Events {
        #[command(subcommand)]
        sub: PdsAdminEventsSub,
    },
    /// Query the configured PDS-admin backend's per-DID moderation
    /// statuses (v1.8.3; RustBackend via
    /// tools.aurora.moderator.queryStatuses — Unsupported on Ozone).
    Statuses {
        #[command(subcommand)]
        sub: PdsAdminStatusesSub,
    },
    /// Subject-scoped moderation reads (v1.8.4; RustBackend via
    /// tools.aurora.moderator.getSubjectContext /
    /// getSubjectHistory — Unsupported on Ozone).
    Subjects {
        #[command(subcommand)]
        sub: PdsAdminSubjectsSub,
    },
    /// Appeal reads (v1.8.4) and appeal actions (v1.8.5:
    /// resolve/escalate via the recordAction writer).
    Appeals {
        #[command(subcommand)]
        sub: PdsAdminAppealsSub,
    },
    /// Account-level destructive actions (v1.8.5; Admin+ role
    /// upstream; via the recordAction writer).
    Accounts {
        #[command(subcommand)]
        sub: PdsAdminAccountsSub,
    },
    /// Blob moderation actions (v1.8.5; via the recordAction
    /// writer).
    Blobs {
        #[command(subcommand)]
        sub: PdsAdminBlobsSub,
    },
    /// Record-level batch takedowns (v1.8.7; via the recordAction
    /// writer).
    Records {
        #[command(subcommand)]
        sub: PdsAdminRecordsSub,
    },
    /// Upstream report resolution actions (v1.8.5; via the
    /// recordAction writer).
    Reports {
        #[command(subcommand)]
        sub: PdsAdminReportsSub,
    },
    /// Moderation email actions (v1.8.5; Admin+ role upstream;
    /// via the recordAction writer).
    Emails {
        #[command(subcommand)]
        sub: PdsAdminEmailsSub,
    },
}

#[derive(Debug, Subcommand)]
enum PdsAdminEventsSub {
    /// Fetch a page of moderation events from the upstream PDS.
    Query(PdsAdminEventsQueryArgs),
    /// Fetch a single moderation event by id (v1.8.4).
    Get(PdsAdminEventsGetArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminSubjectsSub {
    /// Fetch contextual metadata for a subject DID: current
    /// status, recent actions, related reports and appeals.
    Context(PdsAdminSubjectsContextArgs),
    /// Fetch a subject DID's moderation-action history (action
    /// rows — same element shape as `statuses query`).
    History(PdsAdminSubjectsHistoryArgs),
    /// Set the account's upstream moderation status (v1.8.5;
    /// tri-state takedown | deactivated | active).
    UpdateStatus(PdsAdminSubjectsUpdateStatusArgs),
    /// Set one status on up to 50 accounts via one multi-subject
    /// emitEvent (v1.8.7).
    UpdateStatusMany(PdsAdminBatchStatusArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminAppealsSub {
    /// List appeals with filters and pagination.
    List(PdsAdminAppealsListArgs),
    /// Fetch a single appeal (with lifecycle timeline) by id.
    Get(PdsAdminAppealsGetArgs),
    /// Resolve an appeal (v1.8.5; approve cascades a reversal of
    /// the original action upstream).
    Resolve(PdsAdminAppealsResolveArgs),
    /// Escalate an appeal (v1.8.5).
    Escalate(PdsAdminAppealsEscalateArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminAccountsSub {
    /// Permanently delete an account at the PDS (Admin+ role
    /// upstream).
    Delete(PdsAdminAccountsDeleteArgs),
    /// Atomically take down up to 50 accounts in one upstream
    /// batch (v1.8.7; requires the operator opt-in pin
    /// `batch-takedown = "v1"` under
    /// `[pds_admin.rust.pinned_versions]`).
    BatchTakedown(PdsAdminBatchDidsArgs),
    /// Atomically suspend up to 50 accounts (v1.8.7;
    /// indefinite-only — the batch wire has no duration).
    BatchSuspend(PdsAdminBatchDidsArgs),
    /// Delete up to 10 accounts via one multi-subject emitEvent
    /// (v1.8.7; Admin+ role upstream).
    DeleteMany(PdsAdminBatchDidsArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminBlobsSub {
    /// Quarantine a blob.
    Quarantine(PdsAdminBlobsQuarantineArgs),
    /// Restore a quarantined blob.
    Restore(PdsAdminBlobsRestoreArgs),
    /// Permanently delete a blob.
    Delete(PdsAdminBlobsDeleteArgs),
    /// Quarantine up to 50 blobs via one multi-subject emitEvent
    /// (v1.8.7; blob refs as `<did>@<cid>`).
    QuarantineMany(PdsAdminBatchBlobsArgs),
    /// Restore up to 50 quarantined blobs (v1.8.7).
    RestoreMany(PdsAdminBatchBlobsRestoreArgs),
    /// Permanently delete up to 25 blobs (v1.8.7).
    DeleteMany(PdsAdminBatchBlobsArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminRecordsSub {
    /// Atomically take down up to 50 records **URI-level** in one
    /// upstream batch (v1.8.7): bare AT-URIs, all versions at
    /// each URI.
    BatchTakedown(PdsAdminBatchUrisArgs),
    /// Take down up to 50 records **CID-level** via one
    /// multi-subject emitEvent (v1.8.7): subjects as
    /// `<at-uri>#<cid>` — the CID fragment is required; bare
    /// URIs belong to `batch-takedown`.
    TakedownMany(PdsAdminBatchRecordSubjectsArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminReportsSub {
    /// Resolve an upstream report.
    Resolve(PdsAdminReportsResolveArgs),
    /// Dismiss an upstream report.
    Dismiss(PdsAdminReportsDismissArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminEmailsSub {
    /// Send a moderation email to an account (Admin+ role
    /// upstream).
    Send(PdsAdminEmailsSendArgs),
}

#[derive(Debug, Subcommand)]
enum PdsAdminStatusesSub {
    /// Fetch a page of per-DID moderation statuses from the
    /// upstream PDS.
    Query(PdsAdminStatusesQueryArgs),
}

/// Flags map 1:1 onto Aurora's `QueryEventsParams`
/// (aurora_moderator.rs:188-206); values pass through verbatim.
#[derive(Debug, Args)]
struct PdsAdminEventsQueryArgs {
    /// Filter by event type (snake_case value, e.g. `account_takedown`).
    #[arg(long = "event-type")]
    event_type: Option<String>,
    /// Filter by actor DID.
    #[arg(long)]
    actor: Option<String>,
    /// Filter by subject DID.
    #[arg(long = "subject-did")]
    subject_did: Option<String>,
    /// Lower bound on created_at (inclusive), RFC3339.
    #[arg(long)]
    after: Option<String>,
    /// Upper bound on created_at (inclusive), RFC3339.
    #[arg(long)]
    before: Option<String>,
    /// Opaque pagination cursor from a previous page.
    #[arg(long)]
    cursor: Option<String>,
    /// Page size (upstream default 50, capped at 100).
    #[arg(long)]
    limit: Option<u32>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// Flags map 1:1 onto Aurora's `QueryStatusesParams`
/// (aurora_moderator.rs:480-499).
#[derive(Debug, Args)]
struct PdsAdminStatusesQueryArgs {
    /// Filter by subject DID.
    #[arg(long)]
    did: Option<String>,
    /// Subject category: account | record | blob (lowercase wire
    /// values; record/blob currently yield empty results upstream).
    #[arg(long = "subject-type")]
    subject_type: Option<String>,
    /// Filter by action type (e.g. `takedown`, `suspend`).
    #[arg(long)]
    action: Option<String>,
    /// Include reversed actions (upstream default: true).
    #[arg(long = "include-reversed")]
    include_reversed: Option<bool>,
    /// Opaque pagination cursor from a previous page.
    #[arg(long)]
    cursor: Option<String>,
    /// Page size (upstream default 50, capped at 100).
    #[arg(long)]
    limit: Option<u32>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// Maps onto Aurora's `GetEventParams { id }`
/// (aurora_moderator.rs:415-418).
#[derive(Debug, Args)]
struct PdsAdminEventsGetArgs {
    /// Event id (from `events query` output).
    id: i64,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// Maps onto Aurora's `GetSubjectContextParams { did }`
/// (aurora_moderator.rs:649-652) — account-scoped, plain DID.
#[derive(Debug, Args)]
struct PdsAdminSubjectsContextArgs {
    /// Subject DID.
    did: String,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// Flags map 1:1 onto Aurora's `GetSubjectHistoryParams`
/// (aurora_moderator.rs:839-850).
#[derive(Debug, Args)]
struct PdsAdminSubjectsHistoryArgs {
    /// Subject DID.
    did: String,
    /// Filter by action type (e.g. `takedown`, `suspend`).
    #[arg(long)]
    action: Option<String>,
    /// Sort direction: asc | desc (upstream default desc).
    #[arg(long)]
    direction: Option<String>,
    /// Opaque pagination cursor from a previous page.
    #[arg(long)]
    cursor: Option<String>,
    /// Page size (upstream default 50, capped at 100).
    #[arg(long)]
    limit: Option<u32>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// Flags map 1:1 onto Aurora's `ListAppealsParams`
/// (aurora_moderator.rs:1226-1244).
#[derive(Debug, Args)]
struct PdsAdminAppealsListArgs {
    /// Filter by appeal status (snake_case wire value: pending,
    /// under_review, approved, denied, escalated).
    #[arg(long)]
    status: Option<String>,
    /// Filter by appellant DID.
    #[arg(long)]
    appellant: Option<String>,
    /// Filter by reviewer DID (matches reviewedBy).
    #[arg(long)]
    reviewer: Option<String>,
    /// Lower bound on submitted_at (inclusive), RFC3339.
    #[arg(long = "submitted-after")]
    submitted_after: Option<String>,
    /// Upper bound on submitted_at (inclusive), RFC3339.
    #[arg(long = "submitted-before")]
    submitted_before: Option<String>,
    /// Opaque pagination cursor from a previous page.
    #[arg(long)]
    cursor: Option<String>,
    /// Page size (upstream default 50, capped at 100).
    #[arg(long)]
    limit: Option<u32>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// Maps onto Aurora's `GetAppealParams { id }`
/// (aurora_moderator.rs:1469-1472).
#[derive(Debug, Args)]
struct PdsAdminAppealsGetArgs {
    /// Appeal id (from `appeals list` output).
    id: i64,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

/// v1.8.5 action subcommand args. All verbs route through the
/// recordAction writer; there is deliberately no
/// `--precipitating-action-id` flag (the writer derives the local
/// row id itself).
#[derive(Debug, Args)]
struct PdsAdminAccountsDeleteArgs {
    /// Subject DID.
    did: String,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminBlobsQuarantineArgs {
    /// Owning account DID.
    did: String,
    /// Blob CID.
    #[arg(long)]
    cid: String,
    /// Referencing record URI, when known.
    #[arg(long = "record-uri")]
    record_uri: Option<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminBlobsRestoreArgs {
    /// Owning account DID.
    did: String,
    /// Blob CID.
    #[arg(long)]
    cid: String,
    /// Backend action id of the prior quarantine (from the audit
    /// row's backendActionId).
    #[arg(long = "prior-action-id")]
    prior_action_id: String,
    /// Referencing record URI, when known.
    #[arg(long = "record-uri")]
    record_uri: Option<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminBlobsDeleteArgs {
    /// Owning account DID.
    did: String,
    /// Blob CID.
    #[arg(long)]
    cid: String,
    /// Referencing record URI, when known.
    #[arg(long = "record-uri")]
    record_uri: Option<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// v1.8.7 batch subcommand args over a DID list. One recordAction
/// intent row per invocation (first-subject-primary; the full
/// list rides `action_detail`); caps validated client-side before
/// the POST (fail fast, exit 7) and again at the trait boundary.
#[derive(Debug, Args)]
struct PdsAdminBatchDidsArgs {
    /// Subject DIDs (repeated positionals).
    #[arg(required = true)]
    dids: Vec<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// v1.8.7 batch blob args: blob refs as `<did>@<cid>` (the `@`
/// delimiter avoids DID-colon ambiguity; `@` appears in neither
/// DIDs nor CIDs). Per-blob record-URI attachment is deferred
/// (v2 §6.3).
#[derive(Debug, Args)]
struct PdsAdminBatchBlobsArgs {
    /// Blob references as `<did>@<cid>` (repeated positionals).
    #[arg(required = true)]
    blobs: Vec<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// `blobs restore-many` args — [`PdsAdminBatchBlobsArgs`] plus
/// the prior-quarantine backend action id (one shared reference
/// for the batch, mirroring the singular restore's trait shape).
#[derive(Debug, Args)]
struct PdsAdminBatchBlobsRestoreArgs {
    /// Blob references as `<did>@<cid>` (repeated positionals).
    #[arg(required = true)]
    blobs: Vec<String>,
    /// Backend action id of the prior quarantine (from the audit
    /// row's backendActionId).
    #[arg(long = "prior-action-id")]
    prior_action_id: String,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// `records batch-takedown` args: bare AT-URIs — URI-level
/// takedown of all versions at each URI (Aurora's empty-CID
/// cascade convention, scoped to this endpoint).
#[derive(Debug, Args)]
struct PdsAdminBatchUrisArgs {
    /// Record AT-URIs (repeated positionals; bare — no CID).
    #[arg(required = true)]
    uris: Vec<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// `records takedown-many` args: CID-level subjects as
/// `<at-uri>#<cid>` — the fragment is required (S-2: multi-subject
/// record takedowns are CID-required; URI-level belongs to
/// `records batch-takedown`).
#[derive(Debug, Args)]
struct PdsAdminBatchRecordSubjectsArgs {
    /// Record subjects as `<at-uri>#<cid>` (repeated positionals).
    #[arg(required = true)]
    subjects: Vec<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// `subjects update-status-many` args — DID list plus the shared
/// tri-state status.
#[derive(Debug, Args)]
struct PdsAdminBatchStatusArgs {
    /// Subject DIDs (repeated positionals).
    #[arg(required = true)]
    dids: Vec<String>,
    /// Status applied to every subject:
    /// takedown | deactivated | active.
    #[arg(long)]
    status: String,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

/// Report/appeal subjects are full subject references: pass the
/// account DID, add `--uri`/`--cid` for record-targeted rows or
/// `--cid` alone for blob-targeted ones — the coordinates must
/// match the report/appeal's stored subject exactly (Aurora
/// validates variant AND identifier).
#[derive(Debug, Args)]
struct PdsAdminReportsResolveArgs {
    /// Subject account DID (the report's subject).
    did: String,
    /// Upstream report id.
    report_id: i64,
    /// Record URI for record-targeted reports.
    #[arg(long)]
    uri: Option<String>,
    /// Record/blob CID.
    #[arg(long)]
    cid: Option<String>,
    /// Resolution: resolved | acknowledged | escalated.
    #[arg(long)]
    resolution: String,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminReportsDismissArgs {
    /// Subject account DID (the report's subject).
    did: String,
    /// Upstream report id.
    report_id: i64,
    /// Record URI for record-targeted reports.
    #[arg(long)]
    uri: Option<String>,
    /// Record/blob CID.
    #[arg(long)]
    cid: Option<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminAppealsResolveArgs {
    /// Appeal target subject DID (appellant account for
    /// moderation-appeals; the reported subject for
    /// report-appeals).
    did: String,
    /// Upstream appeal id.
    appeal_id: i64,
    /// Record URI when the appeal targets a record.
    #[arg(long)]
    uri: Option<String>,
    /// Record/blob CID when the appeal targets a record or blob.
    #[arg(long)]
    cid: Option<String>,
    /// Decision: approve | deny (approve cascades a reversal).
    #[arg(long)]
    decision: String,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminAppealsEscalateArgs {
    /// Appeal target subject DID.
    did: String,
    /// Upstream appeal id.
    appeal_id: i64,
    /// Record URI when the appeal targets a record.
    #[arg(long)]
    uri: Option<String>,
    /// Record/blob CID when the appeal targets a record or blob.
    #[arg(long)]
    cid: Option<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminEmailsSendArgs {
    /// Recipient account DID.
    did: String,
    /// Email subject line (Aurora wire field `subject`).
    #[arg(long)]
    subject: String,
    /// Email body.
    #[arg(long)]
    body: String,
    /// Optional upstream template identifier.
    #[arg(long)]
    template: Option<String>,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminSubjectsUpdateStatusArgs {
    /// Subject account DID.
    did: String,
    /// Status: takedown | deactivated | active.
    #[arg(long)]
    status: String,
    /// Reason identifier from `[moderation_reasons]` (defaults to
    /// the reserved pds-admin-cli code).
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator note (local-only; not transmitted).
    #[arg(long)]
    notes: Option<String>,
    /// Path to cairn.toml (defaults to ./cairn.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// One-line summary instead of the full JSON outcome.
    #[arg(long)]
    summary: bool,
}

#[derive(Debug, Args)]
struct PdsAdminTakedownArgs {
    /// Subject DID.
    did: String,
    /// Reason identifier from the operator's `[moderation_reasons]`
    /// vocabulary. Defaults to the reserved
    /// `pds-admin-cli` reason code if unset; operators must
    /// declare that code in `[moderation_reasons]` for the
    /// default to work.
    #[arg(long)]
    reason: Option<String>,
    /// Optional moderator-facing notes recorded on the
    /// subject_actions row.
    #[arg(long)]
    notes: Option<String>,
    /// Path to the TOML config file (used for the
    /// `[pds_admin].enabled` pre-flight check + the DB path for
    /// the post-call `pds_admin_audit` lookup). Must point at the
    /// same config the running `cairn serve` is using.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human one-liner.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PdsAdminSuspendArgs {
    did: String,
    #[arg(long)]
    reason: Option<String>,
    /// ISO-8601 duration (e.g. `PT72H`, `P7D`). Required for a
    /// finite-duration suspension (`temp_suspension`); absent
    /// produces an indefinite suspension (`indef_suspension`).
    #[arg(long)]
    duration: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PdsAdminRestoreArgs {
    did: String,
    /// Optional rationale recorded on the
    /// `subject_actions.revoked_reason` field.
    #[arg(long)]
    reason: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

/// Subcommand surface shared by `xrpc-callers` and `xrpc-pdses`.
#[derive(Debug, Subcommand)]
enum XrpcMembershipSub {
    Add(XrpcMembershipAddArgs),
    Revoke(XrpcMembershipRevokeArgs),
    List(XrpcMembershipListArgs),
}

#[derive(Debug, Args)]
struct XrpcMembershipAddArgs {
    did: String,
    #[arg(long)]
    note: Option<String>,
    /// DID of the moderator running the command (recorded as
    /// `added_by_moderator`).
    #[arg(long)]
    by: String,
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct XrpcMembershipRevokeArgs {
    did: String,
    /// DID of the moderator running the command (recorded as
    /// `revoked_by_moderator`).
    #[arg(long)]
    by: String,
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct XrpcMembershipListArgs {
    #[arg(long)]
    include_revoked: bool,
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct AuditRebuildArgs {
    /// Path to the TOML config file (same semantics as `cairn serve
    /// --config`). The DB path comes from this config.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Emit a JSON outcome line instead of the human one-liner.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum TrustChainSub {
    /// Fetch the trust-chain envelope. Read-only; no audit_log
    /// entry on the server.
    Show(TrustChainShowArgs),
}

#[derive(Debug, Args)]
struct TrustChainShowArgs {
    /// Per-invocation override of the session's stored Cairn
    /// server URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable sectioned output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum RetentionSub {
    /// Trigger a one-shot retention sweep through the running
    /// labeler's admin endpoint. The cutoff (`retention_days`) is
    /// configured at server startup; this command does NOT pass a
    /// per-call override. Writes one audit_log row per invocation.
    Sweep(RetentionSweepArgs),
}

#[derive(Debug, Args)]
struct RetentionSweepArgs {
    /// Per-invocation override of the session's stored Cairn
    /// server URL.
    #[arg(long)]
    cairn_server: Option<String>,
    /// JSON output instead of the human-readable single-line summary.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum AuditSub {
    /// List audit entries, optionally filtered by actor/action/
    /// outcome/time-window. Newest first; pagination via
    /// `--cursor`.
    List(AuditListArgs),
    /// Fetch a single audit entry by id. Returns
    /// `AuditEntryNotFound` 404 (surfaced as a non-zero exit) when
    /// the id does not exist.
    Show(AuditShowArgs),
    /// Verify the audit-log hash chain (#41). Read-only — safe to
    /// run while `cairn serve` is live. Direct-DB (no HTTP, no
    /// moderator session); `--config` points at the labeler's
    /// SQLite. Reports the first divergence and stops; returns a
    /// dedicated exit code (15 `AUDIT_DIVERGENCE`) so monitoring
    /// can branch on chain failure.
    Verify(AuditVerifyArgs),
    /// Cross-verify cairn-mod's dispatch ledger against the
    /// upstream PDS's hash-chained audit trail (v1.8.6): local
    /// 4-table chain verify, independent Path A re-verification
    /// of the upstream chain, and join-key comparison. Exits 15
    /// on any divergence; `--json` carries the outcome
    /// discriminator.
    CrossVerify(AuditCrossVerifyArgs),
}

#[derive(Debug, Args)]
struct AuditShowArgs {
    /// Audit row primary key.
    id: i64,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable multi-line output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AuditVerifyArgs {
    /// Path to the TOML config file (same semantics as `cairn serve
    /// --config`). The DB path comes from this config. Note: unlike
    /// sibling `audit list` / `audit show` (which use the moderator
    /// session and HTTP), `audit verify` is direct-DB and operator-
    /// tier — same model as `cairn audit-rebuild`.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Emit a JSON outcome line instead of the human multi-line
    /// summary. Stable `outcome` discriminator (`empty` /
    /// `verified` / `divergence`) for downstream tooling.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AuditCrossVerifyArgs {
    /// Restrict the independent upstream walk + join window to
    /// sequences >= this value.
    #[arg(long = "start-sequence")]
    start_sequence: Option<i64>,
    /// Restrict to sequences <= this value.
    #[arg(long = "end-sequence")]
    end_sequence: Option<i64>,
    /// List past cross-verify outcomes instead of running one.
    #[arg(long)]
    history: bool,
    /// Max history rows to list (with --history).
    #[arg(long, default_value_t = 20)]
    limit: i64,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    json: bool,
    /// Path to the TOML config file (same semantics as
    /// `cairn audit verify` — direct-DB plus the outbound
    /// backend from `[pds_admin]`).
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct AuditListArgs {
    /// Filter by actor DID.
    #[arg(long)]
    actor: Option<String>,
    /// Filter by action discriminator (e.g. `label_applied`,
    /// `report_resolved`).
    #[arg(long)]
    action: Option<String>,
    /// Filter by outcome (`success` or `failure`).
    #[arg(long)]
    outcome: Option<String>,
    /// RFC-3339 inclusive lower bound on `created_at`.
    #[arg(long)]
    since: Option<String>,
    /// RFC-3339 inclusive upper bound on `created_at`.
    #[arg(long)]
    until: Option<String>,
    /// Max rows to return. Server clamps to [1, 250]; default 50.
    #[arg(long)]
    limit: Option<i64>,
    /// Opaque pagination cursor from a prior response.
    #[arg(long)]
    cursor: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable table.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Path to the TOML config file. Defaults to
    /// `/etc/cairn/cairn.toml` (same as `Config::load`). Set
    /// `CAIRN_CONFIG` instead to reuse that path.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct OperatorLoginArgs {
    /// PDS base URL. Overrides `operator.pds_url` from config if
    /// both are set; one of the two must resolve to a usable value.
    #[arg(long)]
    pds: Option<String>,
    /// Operator handle or DID — the identifier passed to
    /// `com.atproto.server.createSession`.
    #[arg(long)]
    handle: String,
    /// Path to the TOML config file (same semantics as `cairn serve
    /// --config`).
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Base URL of the Cairn labeler (e.g. <https://labeler.example>).
    #[arg(long)]
    cairn_server: String,
    /// Moderator's PDS base URL (e.g. <https://bsky.social>).
    #[arg(long)]
    pds: String,
    /// Moderator handle or DID — the PDS identifier.
    #[arg(long)]
    handle: String,
    /// Override Cairn service DID instead of fetching from
    /// `<cairn-server>/.well-known/did.json`. Useful while #18's
    /// endpoint is pending or when the did.json is unreachable.
    #[arg(long)]
    cairn_did: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ReportSub {
    /// Submit a new report (com.atproto.moderation.createReport).
    Create(ReportCreateArgs),
    /// List reports (tools.cairn.admin.listReports). Admin OR
    /// moderator role on the session file. Returns the reason-less
    /// list projection per §F11.
    List(ReportListArgs),
    /// Fetch one report with full body (tools.cairn.admin.getReport).
    /// Admin OR moderator role. Reason body included per §F11
    /// admin-authenticated access.
    View(ReportViewArgs),
    /// Resolve a report (tools.cairn.admin.resolveReport). Admin
    /// OR moderator role. Optional `--apply-label-*` group resolves
    /// AND applies a label in one server transaction; omitting it
    /// resolves without a label (the "dismiss" workflow).
    Resolve(ReportResolveArgs),
    /// Flag a reporter (tools.cairn.admin.flagReporter with
    /// `suppressed: true`). Suppresses future reports from this
    /// DID. Admin OR moderator role.
    Flag(ReportFlagArgs),
    /// Unflag a reporter (tools.cairn.admin.flagReporter with
    /// `suppressed: false`). Removes suppression. Admin OR
    /// moderator role.
    Unflag(ReportFlagArgs),
}

#[derive(Debug, Args)]
struct ReportListArgs {
    /// Filter by status (`pending` or `resolved`).
    #[arg(long)]
    status: Option<String>,
    /// Filter by reporter DID.
    #[arg(long = "reported-by")]
    reported_by: Option<String>,
    /// Max rows to return. Server clamps to [1, 250]; default 50.
    #[arg(long)]
    limit: Option<i64>,
    /// Opaque pagination cursor from a prior response.
    #[arg(long)]
    cursor: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable table.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReportViewArgs {
    /// Report row primary key.
    id: i64,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable multi-line output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReportFlagArgs {
    /// Reporter DID to flag (`flag` subcommand) or unflag
    /// (`unflag` subcommand). Server requires `did:` prefix.
    did: String,
    /// Optional moderator rationale stored in the audit row's
    /// reason payload.
    #[arg(long)]
    reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable one-liner.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReportResolveArgs {
    /// Report row primary key to resolve.
    id: i64,
    /// Operator-facing resolution rationale.
    #[arg(long)]
    reason: Option<String>,
    /// Label value to apply on resolve. Both `--apply-label-val`
    /// and `--apply-label-uri` are required together; the other
    /// `--apply-label-*` flags are optional within that group.
    /// Omitting the entire group resolves without applying a label.
    #[arg(long = "apply-label-val", requires = "apply_label_uri")]
    apply_label_val: Option<String>,
    /// Subject URI (`at://...` or `did:...`) the label targets.
    #[arg(long = "apply-label-uri", requires = "apply_label_val")]
    apply_label_uri: Option<String>,
    /// Optional CID pin for `at://` subjects.
    #[arg(long = "apply-label-cid", requires = "apply_label_val")]
    apply_label_cid: Option<String>,
    /// Optional RFC-3339 expiration for the applied label.
    #[arg(long = "apply-label-exp", requires = "apply_label_val")]
    apply_label_exp: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human-readable one-liner.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ModeratorSub {
    /// Add a moderator. Errors on a duplicate DID unless
    /// `--update-role` is passed.
    Add(ModeratorAddArgs),
    /// Remove a moderator. Errors if the DID is not a moderator.
    /// Refuses to remove the last admin unless `--force` is set.
    Remove(ModeratorRemoveArgs),
    /// List moderators, optionally filtered by `--role`.
    List(ModeratorListArgs),
    /// Record a graduated-action moderation event (warning, note,
    /// temp_suspension, indef_suspension, takedown). HTTP-routed
    /// — talks to the running `cairn serve` admin XRPC. Requires
    /// a moderator session.
    Action(ModeratorActionArgs),
    /// Shorthand for `cairn moderator action --type warning`.
    Warn(ModeratorWarnArgs),
    /// Shorthand for `cairn moderator action --type note` (no
    /// reason required; the positional `<text>` becomes the note).
    Note(ModeratorNoteArgs),
    /// Revoke a previously-recorded action. Sets revoked_at on the
    /// row and removes its strikes from the subject's count.
    Revoke(ModeratorRevokeArgs),
    /// Show the moderation history for a subject. Read-only; safe
    /// to run while `cairn serve` is up. HTTP-routed via
    /// `tools.cairn.admin.getSubjectHistory`.
    History(ModeratorHistoryArgs),
    /// Show the current strike state for a subject — current count,
    /// good-standing flag, active suspension (if any), and a
    /// decay-trajectory hint. HTTP-routed via
    /// `tools.cairn.admin.getSubjectStrikes`.
    Strikes(ModeratorStrikesArgs),
    /// Show the ATProto labels cairn-mod is currently emitting
    /// against a subject — one row per emitted label (the action
    /// label plus one per reason code). HTTP-routed via the same
    /// `tools.cairn.admin.getSubjectStrikes` envelope used by
    /// `strikes`, but renders only the `activeLabels` field.
    Labels(ModeratorLabelsArgs),
    /// Manage policy-engine pending actions awaiting moderator
    /// review (§F22 / #74-#77). HTTP-routed via the
    /// `tools.cairn.admin.{listPendingActions, getPendingAction,
    /// confirmPendingAction, dismissPendingAction}` admin XRPC
    /// endpoints. Requires a moderator session.
    Pending(ModeratorPendingArgs),
    /// Operator-tier audit-events view (#99). Direct-DB scan of
    /// `audit_log` (joined with `subject_actions` for the
    /// recordAction surface). By default surfaces ALL audit
    /// actions including cairn-mod-internal events
    /// (`pending_*`, `retention_sweep`, `xrpc_*` collaboration
    /// changes, etc.). Pass `--ozone-only` to apply the same
    /// filter-out policy as
    /// `tools.ozone.moderation.queryEvents` (#98).
    Events(ModeratorEventsArgs),
}

#[derive(Debug, Args)]
struct ModeratorEventsArgs {
    /// Filter to events about a specific subject (DID for
    /// account-level, AT-URI for record-level).
    #[arg(long)]
    subject: Option<String>,
    /// Filter to events by this actor / moderator DID
    /// (`audit_log.actor_did`).
    #[arg(long)]
    actor: Option<String>,
    /// Filter to a specific `audit_log.action` string
    /// (e.g. `subject_action_recorded`, `retention_sweep`).
    #[arg(long = "type")]
    action_type: Option<String>,
    /// RFC-3339 lower bound on `audit_log.created_at`.
    #[arg(long)]
    from: Option<String>,
    /// RFC-3339 upper bound.
    #[arg(long)]
    to: Option<String>,
    /// Page size. Capped at 250; default 50.
    #[arg(long)]
    limit: Option<u32>,
    /// Opaque pagination cursor from a prior response.
    #[arg(long)]
    cursor: Option<String>,
    /// Apply the gateway endpoint's filter-out policy (#98). When
    /// passed, the output is identical to what
    /// `tools.ozone.moderation.queryEvents` would return for the
    /// same filters.
    #[arg(long = "ozone-only")]
    ozone_only: bool,
    /// Path to the TOML config file (same semantics as `cairn
    /// serve --config`).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Emit JSON instead of the tabular renderer.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorPendingArgs {
    #[command(subcommand)]
    sub: ModeratorPendingSub,
}

#[derive(Debug, Subcommand)]
enum ModeratorPendingSub {
    /// List unresolved pending policy actions awaiting review.
    /// Default newest-first, all subjects; `--subject` narrows.
    List(ModeratorPendingListArgs),
    /// Show full context for a single pending action.
    View(ModeratorPendingViewArgs),
    /// Confirm a pending: promote it to a real subject_actions
    /// row (#74). The moderator takes responsibility; the
    /// originating rule is preserved as forensic provenance.
    Confirm(ModeratorPendingConfirmArgs),
    /// Dismiss a pending: mark it resolved without creating a
    /// subject_actions row (#75). No emission, no strike change.
    Dismiss(ModeratorPendingDismissArgs),
}

#[derive(Debug, Args)]
struct ModeratorPendingListArgs {
    /// Filter to one subject. Server returns SubjectNotFound when
    /// the subject has never had a pending row.
    #[arg(long)]
    subject: Option<String>,
    /// Per-page row limit (server caps at 250; default 50).
    #[arg(long)]
    limit: Option<i64>,
    /// Opaque pagination cursor from a prior page.
    #[arg(long)]
    cursor: Option<String>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the tabular renderer.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorPendingViewArgs {
    /// pending_policy_actions row id.
    pending_id: i64,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorPendingConfirmArgs {
    /// pending_policy_actions row id.
    pending_id: i64,
    /// Optional moderator-facing rationale. Stored on the
    /// resulting subject_actions row's `notes` column and echoed
    /// in the audit row's `moderator_note` field.
    #[arg(long)]
    reason: Option<String>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorPendingDismissArgs {
    /// pending_policy_actions row id.
    pending_id: i64,
    /// Optional moderator-facing rationale. Echoed in the audit
    /// row's `moderator_reason` field (the pending table itself
    /// has no resolved_reason column).
    #[arg(long)]
    reason: Option<String>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorHistoryArgs {
    /// Subject DID.
    subject: String,
    /// Optional AT-URI filter — narrows to record-level actions
    /// on that specific URI.
    #[arg(long = "subject-uri")]
    subject_uri: Option<String>,
    /// Hide revoked actions (default: included).
    #[arg(long = "no-include-revoked")]
    no_include_revoked: bool,
    /// RFC-3339 lower bound on `effective_at`.
    #[arg(long)]
    since: Option<String>,
    /// Per-page row limit (server caps at 250).
    #[arg(long)]
    limit: Option<i64>,
    /// Opaque pagination cursor from a prior page.
    #[arg(long)]
    cursor: Option<String>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorStrikesArgs {
    /// Subject DID.
    subject: String,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorLabelsArgs {
    /// Subject DID.
    subject: String,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorActionArgs {
    /// Subject — `did:*` for an account, `at://...` for a record.
    subject: String,
    /// Graduated-action category.
    #[arg(long = "type", value_enum)]
    action_type: ActionTypeArg,
    /// Reason identifier from the operator's `[moderation_reasons]`
    /// vocabulary. Repeat for multi-reason actions.
    #[arg(long = "reason", action = ArgAction::Append, num_args = 1)]
    reason: Vec<String>,
    /// ISO-8601 duration (e.g. `P7D`). Required for
    /// `--type temp_suspension`; rejected for other types.
    #[arg(long)]
    duration: Option<String>,
    /// Optional moderator-facing note.
    #[arg(long)]
    note: Option<String>,
    /// Report row id that motivated this action. Repeat for
    /// multiple reports.
    #[arg(long = "report", action = ArgAction::Append, num_args = 1)]
    report: Vec<i64>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of the human one-liner.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorWarnArgs {
    /// Subject DID or AT-URI.
    subject: String,
    /// Reason identifier (repeat for multi-reason).
    #[arg(long = "reason", action = ArgAction::Append, num_args = 1)]
    reason: Vec<String>,
    /// Optional moderator-facing note.
    #[arg(long)]
    note: Option<String>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorNoteArgs {
    /// Subject DID or AT-URI.
    subject: String,
    /// Note body. Stored verbatim on the subject_actions row.
    text: String,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ModeratorRevokeArgs {
    /// subject_actions row id to revoke.
    action_id: i64,
    /// Optional moderator-facing rationale.
    #[arg(long)]
    reason: Option<String>,
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    #[arg(long)]
    json: bool,
}

/// Clap-side wrapper over [`cairn_mod::moderation::types::ActionType`].
/// Same posture as [`RoleArg`]: keeps `clap::ValueEnum` out of the
/// non-CLI module while staying 1:1 with the runtime enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ActionTypeArg {
    Warning,
    Note,
    TempSuspension,
    IndefSuspension,
    Takedown,
}

impl ActionTypeArg {
    fn as_db_str(self) -> &'static str {
        match self {
            ActionTypeArg::Warning => "warning",
            ActionTypeArg::Note => "note",
            ActionTypeArg::TempSuspension => "temp_suspension",
            ActionTypeArg::IndefSuspension => "indef_suspension",
            ActionTypeArg::Takedown => "takedown",
        }
    }
}

#[derive(Debug, Args)]
struct ModeratorAddArgs {
    /// DID of the moderator (e.g. `did:plc:...`, `did:web:...`).
    did: String,
    /// Role to assign.
    #[arg(long, value_enum)]
    role: RoleArg,
    /// Allow updating the role of an existing moderator. Without
    /// this flag, an attempt to add a DID that's already a
    /// moderator with a different role errors.
    #[arg(long)]
    update_role: bool,
    /// Also add this DID to `xrpc_known_callers` so the moderator
    /// can call cairn-mod via proxied XRPC (#94 / §A12). When
    /// passed, `--by` is required (it's recorded as the
    /// `added_by_moderator` audit field on the new
    /// xrpc_known_callers row).
    #[arg(long, requires = "by")]
    with_xrpc_callers: bool,
    /// DID of the operator running this command, recorded as the
    /// `added_by_moderator` audit field on the
    /// `xrpc_known_callers` row when `--with-xrpc-callers` is
    /// passed. Has no effect without `--with-xrpc-callers`.
    #[arg(long)]
    by: Option<String>,
    /// Emit JSON instead of a human one-liner.
    #[arg(long)]
    json: bool,
    /// Path to the TOML config file (same semantics as
    /// `cairn serve --config`).
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ModeratorRemoveArgs {
    /// DID of the moderator to remove.
    did: String,
    /// Skip the last-admin guard.
    #[arg(long)]
    force: bool,
    /// Emit JSON instead of a human one-liner.
    #[arg(long)]
    json: bool,
    /// Path to the TOML config file.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ModeratorListArgs {
    /// Filter to a specific role. If omitted, list everyone.
    #[arg(long, value_enum)]
    role: Option<RoleArg>,
    /// Emit JSON instead of the human-readable table.
    #[arg(long)]
    json: bool,
    /// Path to the TOML config file.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Clap-side wrapper over [`Role`]. Kept distinct from the shared
/// [`Role`] type so `clap::ValueEnum` doesn't leak into non-CLI
/// modules; the variants are by-construction 1:1 with `Role`, so
/// adding a role would require touching both — surfaced as a diff
/// in any future PR.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    Mod,
    Admin,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Role {
        match r {
            RoleArg::Mod => Role::Mod,
            RoleArg::Admin => Role::Admin,
        }
    }
}

#[derive(Debug, Args)]
struct ReportCreateArgs {
    /// Subject — `did:*` for an account, `at://...` for a record.
    #[arg(long)]
    subject: String,
    /// Required when subject is `at://...`.
    #[arg(long)]
    cid: Option<String>,
    /// Short reason-type (spam, violation, misleading, sexual,
    /// rude, other). Expanded to the lexicon-spec full value.
    #[arg(long = "reason-type", value_enum)]
    reason_type: ReasonTypeArg,
    /// Optional free-text body (≤2KB, enforced server-side).
    #[arg(long)]
    reason: Option<String>,
    /// Per-invocation override of the session's stored Cairn URL.
    #[arg(long = "cairn-server")]
    cairn_server: Option<String>,
    /// Emit JSON instead of a human one-liner.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReasonTypeArg {
    Spam,
    Violation,
    Misleading,
    Sexual,
    Rude,
    Other,
}

impl ReasonTypeArg {
    fn as_lexicon(self) -> &'static str {
        match self {
            ReasonTypeArg::Spam => "com.atproto.moderation.defs#reasonSpam",
            ReasonTypeArg::Violation => "com.atproto.moderation.defs#reasonViolation",
            ReasonTypeArg::Misleading => "com.atproto.moderation.defs#reasonMisleading",
            ReasonTypeArg::Sexual => "com.atproto.moderation.defs#reasonSexual",
            ReasonTypeArg::Rude => "com.atproto.moderation.defs#reasonRude",
            ReasonTypeArg::Other => "com.atproto.moderation.defs#reasonOther",
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = runtime.block_on(dispatch(cli.command));

    match result {
        Ok(()) => ExitCode::from(code::SUCCESS as u8),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

async fn dispatch(cmd: Command) -> Result<(), CliError> {
    match cmd {
        Command::Login(args) => run_login(args).await,
        Command::Logout => run_logout().await,
        Command::Report {
            sub: ReportSub::Create(args),
        } => run_report_create(args).await,
        Command::Report {
            sub: ReportSub::List(args),
        } => run_report_list(args).await,
        Command::Report {
            sub: ReportSub::View(args),
        } => run_report_view(args).await,
        Command::Report {
            sub: ReportSub::Resolve(args),
        } => run_report_resolve(args).await,
        Command::Report {
            sub: ReportSub::Flag(args),
        } => run_report_flag(args, true).await,
        Command::Report {
            sub: ReportSub::Unflag(args),
        } => run_report_flag(args, false).await,
        Command::Serve(args) => run_serve(args).await,
        Command::OperatorLogin(args) => run_operator_login(args).await,
        Command::PublishServiceRecord(args) => run_publish_service_record(args).await,
        Command::UnpublishServiceRecord(args) => run_unpublish_service_record(args).await,
        Command::Moderator {
            sub: ModeratorSub::Add(args),
        } => run_moderator_add(args).await,
        Command::Moderator {
            sub: ModeratorSub::Remove(args),
        } => run_moderator_remove(args).await,
        Command::Moderator {
            sub: ModeratorSub::List(args),
        } => run_moderator_list(args).await,
        Command::Moderator {
            sub: ModeratorSub::Action(args),
        } => run_moderator_action(args).await,
        Command::Moderator {
            sub: ModeratorSub::Warn(args),
        } => run_moderator_warn(args).await,
        Command::Moderator {
            sub: ModeratorSub::Note(args),
        } => run_moderator_note(args).await,
        Command::Moderator {
            sub: ModeratorSub::Revoke(args),
        } => run_moderator_revoke(args).await,
        Command::Moderator {
            sub: ModeratorSub::History(args),
        } => run_moderator_history(args).await,
        Command::Moderator {
            sub: ModeratorSub::Strikes(args),
        } => run_moderator_strikes(args).await,
        Command::Moderator {
            sub: ModeratorSub::Labels(args),
        } => run_moderator_labels(args).await,
        Command::Moderator {
            sub:
                ModeratorSub::Pending(ModeratorPendingArgs {
                    sub: ModeratorPendingSub::List(args),
                }),
        } => run_moderator_pending_list(args).await,
        Command::Moderator {
            sub:
                ModeratorSub::Pending(ModeratorPendingArgs {
                    sub: ModeratorPendingSub::View(args),
                }),
        } => run_moderator_pending_view(args).await,
        Command::Moderator {
            sub:
                ModeratorSub::Pending(ModeratorPendingArgs {
                    sub: ModeratorPendingSub::Confirm(args),
                }),
        } => run_moderator_pending_confirm(args).await,
        Command::Moderator {
            sub:
                ModeratorSub::Pending(ModeratorPendingArgs {
                    sub: ModeratorPendingSub::Dismiss(args),
                }),
        } => run_moderator_pending_dismiss(args).await,
        Command::Moderator {
            sub: ModeratorSub::Events(args),
        } => run_moderator_events(args).await,
        Command::Audit {
            sub: AuditSub::List(args),
        } => run_audit_list(args).await,
        Command::Audit {
            sub: AuditSub::Show(args),
        } => run_audit_show(args).await,
        Command::Audit {
            sub: AuditSub::Verify(args),
        } => run_audit_verify(args).await,
        Command::Audit {
            sub: AuditSub::CrossVerify(args),
        } => run_audit_cross_verify(args).await,
        Command::Retention {
            sub: RetentionSub::Sweep(args),
        } => run_retention_sweep(args).await,
        Command::TrustChain {
            sub: TrustChainSub::Show(args),
        } => run_trust_chain_show(args).await,
        Command::AuditRebuild(args) => run_audit_rebuild(args).await,
        Command::PdsAdmin {
            sub: PdsAdminSub::Takedown(args),
        } => run_pds_admin_takedown(args).await,
        Command::PdsAdmin {
            sub: PdsAdminSub::Suspend(args),
        } => run_pds_admin_suspend(args).await,
        Command::PdsAdmin {
            sub: PdsAdminSub::Restore(args),
        } => run_pds_admin_restore(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Events {
                    sub: PdsAdminEventsSub::Query(args),
                },
        } => run_pds_admin_events_query(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Statuses {
                    sub: PdsAdminStatusesSub::Query(args),
                },
        } => run_pds_admin_statuses_query(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Events {
                    sub: PdsAdminEventsSub::Get(args),
                },
        } => run_pds_admin_events_get(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Subjects {
                    sub: PdsAdminSubjectsSub::Context(args),
                },
        } => run_pds_admin_subjects_context(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Subjects {
                    sub: PdsAdminSubjectsSub::History(args),
                },
        } => run_pds_admin_subjects_history(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Appeals {
                    sub: PdsAdminAppealsSub::List(args),
                },
        } => run_pds_admin_appeals_list(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Appeals {
                    sub: PdsAdminAppealsSub::Get(args),
                },
        } => run_pds_admin_appeals_get(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Accounts {
                    sub: PdsAdminAccountsSub::Delete(args),
                },
        } => run_pds_admin_accounts_delete(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Accounts {
                    sub: PdsAdminAccountsSub::BatchTakedown(args),
                },
        } => run_pds_admin_accounts_batch_takedown(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Accounts {
                    sub: PdsAdminAccountsSub::BatchSuspend(args),
                },
        } => run_pds_admin_accounts_batch_suspend(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Accounts {
                    sub: PdsAdminAccountsSub::DeleteMany(args),
                },
        } => run_pds_admin_accounts_delete_many(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Blobs {
                    sub: PdsAdminBlobsSub::Quarantine(args),
                },
        } => run_pds_admin_blobs_quarantine(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Blobs {
                    sub: PdsAdminBlobsSub::Restore(args),
                },
        } => run_pds_admin_blobs_restore(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Blobs {
                    sub: PdsAdminBlobsSub::Delete(args),
                },
        } => run_pds_admin_blobs_delete(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Blobs {
                    sub: PdsAdminBlobsSub::QuarantineMany(args),
                },
        } => run_pds_admin_blobs_quarantine_many(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Blobs {
                    sub: PdsAdminBlobsSub::RestoreMany(args),
                },
        } => run_pds_admin_blobs_restore_many(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Blobs {
                    sub: PdsAdminBlobsSub::DeleteMany(args),
                },
        } => run_pds_admin_blobs_delete_many(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Records {
                    sub: PdsAdminRecordsSub::BatchTakedown(args),
                },
        } => run_pds_admin_records_batch_takedown(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Records {
                    sub: PdsAdminRecordsSub::TakedownMany(args),
                },
        } => run_pds_admin_records_takedown_many(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Reports {
                    sub: PdsAdminReportsSub::Resolve(args),
                },
        } => run_pds_admin_reports_resolve(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Reports {
                    sub: PdsAdminReportsSub::Dismiss(args),
                },
        } => run_pds_admin_reports_dismiss(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Appeals {
                    sub: PdsAdminAppealsSub::Resolve(args),
                },
        } => run_pds_admin_appeals_resolve(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Appeals {
                    sub: PdsAdminAppealsSub::Escalate(args),
                },
        } => run_pds_admin_appeals_escalate(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Emails {
                    sub: PdsAdminEmailsSub::Send(args),
                },
        } => run_pds_admin_emails_send(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Subjects {
                    sub: PdsAdminSubjectsSub::UpdateStatus(args),
                },
        } => run_pds_admin_subjects_update_status(args).await,
        Command::PdsAdmin {
            sub:
                PdsAdminSub::Subjects {
                    sub: PdsAdminSubjectsSub::UpdateStatusMany(args),
                },
        } => run_pds_admin_subjects_update_status_many(args).await,
        Command::XrpcCallers {
            sub: XrpcMembershipSub::Add(args),
        } => run_xrpc_callers_add(args).await,
        Command::XrpcCallers {
            sub: XrpcMembershipSub::Revoke(args),
        } => run_xrpc_callers_revoke(args).await,
        Command::XrpcCallers {
            sub: XrpcMembershipSub::List(args),
        } => run_xrpc_callers_list(args).await,
        Command::XrpcPdses {
            sub: XrpcMembershipSub::Add(args),
        } => run_xrpc_pdses_add(args).await,
        Command::XrpcPdses {
            sub: XrpcMembershipSub::Revoke(args),
        } => run_xrpc_pdses_revoke(args).await,
        Command::XrpcPdses {
            sub: XrpcMembershipSub::List(args),
        } => run_xrpc_pdses_list(args).await,
    }
}

async fn run_pds_admin_events_query(args: PdsAdminEventsQueryArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let filter = cairn_mod::pds_admin::rust::read_types::QueryEventsFilter {
        event_type: args.event_type,
        actor: args.actor,
        subject_did: args.subject_did,
        after: args.after,
        before: args.before,
    };
    let rendered =
        cli_pds_admin_reads::events_query(&config, filter, args.cursor.as_deref(), args.limit)
            .await?;
    println!("{rendered}");
    Ok(())
}

async fn run_pds_admin_statuses_query(args: PdsAdminStatusesQueryArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let filter = cairn_mod::pds_admin::rust::read_types::QueryStatusesFilter {
        did: args.did,
        subject_type: args.subject_type,
        action: args.action,
        include_reversed: args.include_reversed,
    };
    let rendered =
        cli_pds_admin_reads::statuses_query(&config, filter, args.cursor.as_deref(), args.limit)
            .await?;
    println!("{rendered}");
    Ok(())
}

async fn run_pds_admin_events_get(args: PdsAdminEventsGetArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let rendered = cli_pds_admin_reads::events_get(&config, args.id).await?;
    println!("{rendered}");
    Ok(())
}

async fn run_pds_admin_subjects_context(args: PdsAdminSubjectsContextArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let rendered = cli_pds_admin_reads::subjects_context(&config, &args.did).await?;
    println!("{rendered}");
    Ok(())
}

async fn run_pds_admin_subjects_history(args: PdsAdminSubjectsHistoryArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let filter = cairn_mod::pds_admin::rust::read_types::SubjectHistoryFilter {
        action: args.action,
        direction: args.direction,
    };
    let rendered = cli_pds_admin_reads::subjects_history(
        &config,
        &args.did,
        filter,
        args.cursor.as_deref(),
        args.limit,
    )
    .await?;
    println!("{rendered}");
    Ok(())
}

async fn run_pds_admin_appeals_list(args: PdsAdminAppealsListArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let filter = cairn_mod::pds_admin::rust::read_types::ListAppealsFilter {
        status: args.status,
        appellant: args.appellant,
        reviewer: args.reviewer,
        submitted_after: args.submitted_after,
        submitted_before: args.submitted_before,
    };
    let rendered =
        cli_pds_admin_reads::appeals_list(&config, filter, args.cursor.as_deref(), args.limit)
            .await?;
    println!("{rendered}");
    Ok(())
}

async fn run_pds_admin_appeals_get(args: PdsAdminAppealsGetArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let rendered = cli_pds_admin_reads::appeals_get(&config, args.id).await?;
    println!("{rendered}");
    Ok(())
}

/// Shared v1.8.5 action-runner scaffolding: config + policy gate +
/// pool + session, then submit + print.
async fn run_v185_action(
    config_path: Option<&Path>,
    cairn_server: Option<String>,
    summary: bool,
    reason: Option<String>,
    build: impl FnOnce(String) -> cli_pds_admin_actions::ActionSubmission,
) -> Result<(), CliError> {
    let config = load_config(config_path)?;
    cli_pds_admin::verify_pds_admin_enabled(&config)?;
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;
    let session_path = session_path()?;
    let mut session = session::SessionFile::load(&session_path)?.ok_or(CliError::NotLoggedIn)?;

    let reason = reason.unwrap_or_else(|| cli_pds_admin::PDS_ADMIN_DEFAULT_REASON_CODE.to_string());
    let mut submission = build(reason);
    submission.cairn_server_override = cairn_server;

    let outcome =
        cli_pds_admin_actions::submit(&pool, &mut session, &session_path, submission).await?;
    if summary {
        println!("{}", cli_pds_admin_actions::format_action_summary(&outcome));
    } else {
        println!("{}", cli_pds_admin_actions::format_action_json(&outcome));
    }
    Ok(())
}

/// Subject string for report/appeal verbs: at-URI when the target
/// is a record (writer routes `at://` to subject_uri and extracts
/// the parent DID), bare DID otherwise. Blob-targeted rows pass
/// the DID plus `--cid`.
fn subject_ref_string(did: &str, uri: Option<&str>) -> String {
    uri.map(str::to_string).unwrap_or_else(|| did.to_string())
}

async fn run_pds_admin_accounts_delete(args: PdsAdminAccountsDeleteArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "delete_account",
            subject: args.did,
            cid: None,
            detail: None,
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_blobs_quarantine(args: PdsAdminBlobsQuarantineArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "quarantine_blob",
            subject: subject_ref_string(&args.did, args.record_uri.as_deref()),
            cid: Some(args.cid),
            detail: None,
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_blobs_restore(args: PdsAdminBlobsRestoreArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "restore_blob",
            subject: subject_ref_string(&args.did, args.record_uri.as_deref()),
            cid: Some(args.cid),
            detail: Some(serde_json::json!({ "priorActionId": args.prior_action_id })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_blobs_delete(args: PdsAdminBlobsDeleteArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "delete_blob",
            subject: subject_ref_string(&args.did, args.record_uri.as_deref()),
            cid: Some(args.cid),
            detail: None,
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_reports_resolve(args: PdsAdminReportsResolveArgs) -> Result<(), CliError> {
    if cairn_mod::pds_admin::rust::action_types::ReportResolution::from_wire_str(&args.resolution)
        .is_none()
    {
        return Err(CliError::Config(format!(
            "--resolution must be one of resolved/acknowledged/escalated; got {:?}",
            args.resolution
        )));
    }
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "resolve_report",
            subject: subject_ref_string(&args.did, args.uri.as_deref()),
            cid: args.cid,
            detail: Some(serde_json::json!({
                "reportId": args.report_id,
                "resolution": args.resolution,
            })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_reports_dismiss(args: PdsAdminReportsDismissArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "dismiss_report",
            subject: subject_ref_string(&args.did, args.uri.as_deref()),
            cid: args.cid,
            detail: Some(serde_json::json!({ "reportId": args.report_id })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_appeals_resolve(args: PdsAdminAppealsResolveArgs) -> Result<(), CliError> {
    if cairn_mod::pds_admin::rust::action_types::AppealDecision::from_wire_str(&args.decision)
        .is_none()
    {
        return Err(CliError::Config(format!(
            "--decision must be approve or deny; got {:?}",
            args.decision
        )));
    }
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "resolve_appeal",
            subject: subject_ref_string(&args.did, args.uri.as_deref()),
            cid: args.cid,
            detail: Some(serde_json::json!({
                "appealId": args.appeal_id,
                "decision": args.decision,
            })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_appeals_escalate(args: PdsAdminAppealsEscalateArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "escalate_appeal",
            subject: subject_ref_string(&args.did, args.uri.as_deref()),
            cid: args.cid,
            detail: Some(serde_json::json!({ "appealId": args.appeal_id })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_emails_send(args: PdsAdminEmailsSendArgs) -> Result<(), CliError> {
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "send_email",
            subject: args.did,
            cid: None,
            detail: Some(serde_json::json!({
                "template": args.template,
                "subject": args.subject,
                "body": args.body,
            })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_subjects_update_status(
    args: PdsAdminSubjectsUpdateStatusArgs,
) -> Result<(), CliError> {
    if cairn_mod::pds_admin::rust::action_types::SubjectStatus::from_wire_str(&args.status)
        .is_none()
    {
        return Err(CliError::Config(format!(
            "--status must be one of takedown/deactivated/active; got {:?}",
            args.status
        )));
    }
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "update_subject_status",
            subject: args.did,
            cid: None,
            detail: Some(serde_json::json!({ "status": args.status })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

// ===========================================================================
// v1.8.7 batch subcommands (v2 §6, chainlink #143)
// ===========================================================================

/// Client-side batch cap check (v2 §6.3/§7): fail fast before the
/// recordAction POST with the same message shape and exit code (7,
/// `SERVER_4XX` via `BackendError::Validation`) the trait boundary
/// produces. The trait re-checks, and Aurora is the authority.
fn cli_batch_len_check(len: usize, cap: usize, label: &str) -> Result<(), CliError> {
    if len == 0 {
        return Err(CliError::Backend(
            cairn_mod::pds_admin::BackendError::Validation(format!(
                "{label} must contain at least one entry"
            )),
        ));
    }
    if len > cap {
        return Err(CliError::Backend(
            cairn_mod::pds_admin::BackendError::Validation(format!(
                "{label} length {len} exceeds limit of {cap}"
            )),
        ));
    }
    Ok(())
}

/// Authority (DID) segment of an `at://` URI — the batch intent
/// row's first-subject-primary `subject_did` for record batches
/// (the writer must see a bare DID so `subject_uri` stays NULL on
/// the one-row-per-batch shape).
fn batch_did_from_at_uri(uri: &str) -> Result<String, CliError> {
    let authority = uri
        .strip_prefix("at://")
        .map(|rest| rest.split('/').next().unwrap_or(rest));
    match authority {
        Some(a) if a.starts_with("did:") => Ok(a.to_string()),
        _ => Err(CliError::Config(format!(
            "record URI {uri:?} is not an at:// URI with a DID authority"
        ))),
    }
}

/// Split a `<did>@<cid>` blob reference (v2 §6.3: `@` appears in
/// neither DIDs nor CIDs, avoiding DID-colon ambiguity).
fn parse_blob_ref(s: &str) -> Result<(String, String), CliError> {
    match s.split_once('@') {
        Some((did, cid)) if did.starts_with("did:") && !cid.is_empty() => {
            Ok((did.to_string(), cid.to_string()))
        }
        _ => Err(CliError::Config(format!(
            "blob reference {s:?} must be <did>@<cid>"
        ))),
    }
}

/// Split an `<at-uri>#<cid>` record subject for `records
/// takedown-many`. The CID fragment is required (S-2) — bare URIs
/// (URI-level takedowns) belong to `records batch-takedown`.
fn parse_record_subject(s: &str) -> Result<(String, String), CliError> {
    match s.split_once('#') {
        Some((uri, cid)) if !uri.is_empty() && !cid.is_empty() => {
            Ok((uri.to_string(), cid.to_string()))
        }
        _ => Err(CliError::Config(format!(
            "record subject {s:?} must be <at-uri>#<cid> (CID-level); bare URIs \
             (URI-level takedowns) belong to `records batch-takedown`"
        ))),
    }
}

async fn run_pds_admin_accounts_batch_takedown(
    args: PdsAdminBatchDidsArgs,
) -> Result<(), CliError> {
    cli_batch_len_check(
        args.dids.len(),
        cairn_mod::pds_admin::rust::batch_types::MAX_BATCH_SIZE,
        "batch",
    )?;
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "takedown",
            subject: args.dids[0].clone(),
            cid: None,
            detail: Some(serde_json::json!({ "batch": true, "dids": args.dids })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_accounts_batch_suspend(args: PdsAdminBatchDidsArgs) -> Result<(), CliError> {
    cli_batch_len_check(
        args.dids.len(),
        cairn_mod::pds_admin::rust::batch_types::MAX_BATCH_SIZE,
        "batch",
    )?;
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            // Batch suspension is indefinite-only by wire
            // contract; the duration-less indef_suspension verb
            // is the matching intent row.
            action_type: "indef_suspension",
            subject: args.dids[0].clone(),
            cid: None,
            detail: Some(serde_json::json!({ "batch": true, "dids": args.dids })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_accounts_delete_many(args: PdsAdminBatchDidsArgs) -> Result<(), CliError> {
    cli_batch_len_check(
        args.dids.len(),
        cairn_mod::pds_admin::rust::batch_types::MAX_SUBJECTS_DELETE_ACCOUNT,
        "subjects",
    )?;
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "delete_account",
            subject: args.dids[0].clone(),
            cid: None,
            detail: Some(serde_json::json!({ "batch": true, "dids": args.dids })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

/// Shared body for the three blob `_many` subcommands: parse
/// `<did>@<cid>` refs, cap-check, and submit one batch intent row
/// (first blob's DID as primary; `subject_cid` deliberately NULL —
/// the authoritative blob list rides `action_detail.blobs`).
// The parameter list is the two arg structs' shared field set
// (restore adds prior_action_id via extra_detail); a bundling
// struct would only restate them.
#[allow(clippy::too_many_arguments)]
async fn run_pds_admin_blobs_many(
    action_type: &'static str,
    cap: usize,
    blobs: Vec<String>,
    extra_detail: Option<(&'static str, serde_json::Value)>,
    reason: Option<String>,
    notes: Option<String>,
    config: Option<PathBuf>,
    cairn_server: Option<String>,
    summary: bool,
) -> Result<(), CliError> {
    cli_batch_len_check(blobs.len(), cap, "subjects")?;
    let parsed: Vec<(String, String)> = blobs
        .iter()
        .map(|s| parse_blob_ref(s))
        .collect::<Result<_, _>>()?;
    let blob_entries: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(did, cid)| serde_json::json!({ "did": did, "cid": cid }))
        .collect();
    let mut detail = serde_json::json!({ "batch": true, "blobs": blob_entries });
    if let Some((key, value)) = extra_detail {
        detail[key] = value;
    }
    let first_did = parsed[0].0.clone();
    run_v185_action(config.as_deref(), cairn_server, summary, reason, |reason| {
        cli_pds_admin_actions::ActionSubmission {
            action_type,
            subject: first_did,
            cid: None,
            detail: Some(detail),
            reason,
            notes,
            cairn_server_override: None,
        }
    })
    .await
}

async fn run_pds_admin_blobs_quarantine_many(args: PdsAdminBatchBlobsArgs) -> Result<(), CliError> {
    run_pds_admin_blobs_many(
        "quarantine_blob",
        cairn_mod::pds_admin::rust::batch_types::MAX_SUBJECTS_DEFAULT,
        args.blobs,
        None,
        args.reason,
        args.notes,
        args.config,
        args.cairn_server,
        args.summary,
    )
    .await
}

async fn run_pds_admin_blobs_restore_many(
    args: PdsAdminBatchBlobsRestoreArgs,
) -> Result<(), CliError> {
    run_pds_admin_blobs_many(
        "restore_blob",
        cairn_mod::pds_admin::rust::batch_types::MAX_SUBJECTS_DEFAULT,
        args.blobs,
        Some((
            "priorActionId",
            serde_json::Value::String(args.prior_action_id),
        )),
        args.reason,
        args.notes,
        args.config,
        args.cairn_server,
        args.summary,
    )
    .await
}

async fn run_pds_admin_blobs_delete_many(args: PdsAdminBatchBlobsArgs) -> Result<(), CliError> {
    run_pds_admin_blobs_many(
        "delete_blob",
        cairn_mod::pds_admin::rust::batch_types::MAX_SUBJECTS_DELETE_BLOB,
        args.blobs,
        None,
        args.reason,
        args.notes,
        args.config,
        args.cairn_server,
        args.summary,
    )
    .await
}

async fn run_pds_admin_records_batch_takedown(args: PdsAdminBatchUrisArgs) -> Result<(), CliError> {
    cli_batch_len_check(
        args.uris.len(),
        cairn_mod::pds_admin::rust::batch_types::MAX_BATCH_SIZE,
        "batch",
    )?;
    let first_did = batch_did_from_at_uri(&args.uris[0])?;
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "takedown",
            subject: first_did,
            cid: None,
            detail: Some(serde_json::json!({ "batch": true, "uris": args.uris })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_records_takedown_many(
    args: PdsAdminBatchRecordSubjectsArgs,
) -> Result<(), CliError> {
    cli_batch_len_check(
        args.subjects.len(),
        cairn_mod::pds_admin::rust::batch_types::MAX_SUBJECTS_DEFAULT,
        "subjects",
    )?;
    let parsed: Vec<(String, String)> = args
        .subjects
        .iter()
        .map(|s| parse_record_subject(s))
        .collect::<Result<_, _>>()?;
    let first_did = batch_did_from_at_uri(&parsed[0].0)?;
    let subject_entries: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(uri, cid)| serde_json::json!({ "uri": uri, "cid": cid }))
        .collect();
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "takedown",
            subject: first_did,
            cid: None,
            detail: Some(serde_json::json!({ "batch": true, "subjects": subject_entries })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

async fn run_pds_admin_subjects_update_status_many(
    args: PdsAdminBatchStatusArgs,
) -> Result<(), CliError> {
    if cairn_mod::pds_admin::rust::action_types::SubjectStatus::from_wire_str(&args.status)
        .is_none()
    {
        return Err(CliError::Config(format!(
            "--status must be one of takedown/deactivated/active; got {:?}",
            args.status
        )));
    }
    cli_batch_len_check(
        args.dids.len(),
        cairn_mod::pds_admin::rust::batch_types::MAX_SUBJECTS_DEFAULT,
        "subjects",
    )?;
    run_v185_action(
        args.config.as_deref(),
        args.cairn_server,
        args.summary,
        args.reason,
        |reason| cli_pds_admin_actions::ActionSubmission {
            action_type: "update_subject_status",
            subject: args.dids[0].clone(),
            cid: None,
            detail: Some(serde_json::json!({
                "batch": true,
                "dids": args.dids,
                "status": args.status,
            })),
            reason,
            notes: args.notes,
            cairn_server_override: None,
        },
    )
    .await
}

// ===========================================================================
// XRPC gateway membership CLI dispatch (#94 / §A12)
// ===========================================================================

// ===========================================================================
// pds-admin CLI dispatch (#99 / §F23 manual escape hatch)
// ===========================================================================

async fn run_pds_admin_takedown(args: PdsAdminTakedownArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    cli_pds_admin::verify_pds_admin_enabled(&config)?;
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;
    let session_path = session_path()?;
    let mut session = session::SessionFile::load(&session_path)?.ok_or(CliError::NotLoggedIn)?;

    let reason = args
        .reason
        .unwrap_or_else(|| cli_pds_admin::PDS_ADMIN_DEFAULT_REASON_CODE.to_string());

    let outcome = cli_pds_admin::takedown(
        &pool,
        &mut session,
        &session_path,
        &args.did,
        &reason,
        args.notes,
        args.cairn_server,
    )
    .await?;

    if args.json {
        println!("{}", cli_pds_admin::format_takedown_json(&outcome));
    } else {
        println!("{}", cli_pds_admin::format_takedown_human(&outcome));
    }
    Ok(())
}

async fn run_pds_admin_suspend(args: PdsAdminSuspendArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    cli_pds_admin::verify_pds_admin_enabled(&config)?;
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;
    let session_path = session_path()?;
    let mut session = session::SessionFile::load(&session_path)?.ok_or(CliError::NotLoggedIn)?;

    let reason = args
        .reason
        .unwrap_or_else(|| cli_pds_admin::PDS_ADMIN_DEFAULT_REASON_CODE.to_string());

    let outcome = cli_pds_admin::suspend(
        &pool,
        &mut session,
        &session_path,
        &args.did,
        &reason,
        args.duration,
        args.notes,
        args.cairn_server,
    )
    .await?;

    if args.json {
        println!("{}", cli_pds_admin::format_takedown_json(&outcome));
    } else {
        println!("{}", cli_pds_admin::format_takedown_human(&outcome));
    }
    Ok(())
}

async fn run_pds_admin_restore(args: PdsAdminRestoreArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    cli_pds_admin::verify_pds_admin_enabled(&config)?;
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;
    let session_path = session_path()?;
    let mut session = session::SessionFile::load(&session_path)?.ok_or(CliError::NotLoggedIn)?;

    let outcome = cli_pds_admin::restore(
        &pool,
        &mut session,
        &session_path,
        &args.did,
        args.reason,
        args.cairn_server,
    )
    .await?;

    if args.json {
        println!("{}", cli_pds_admin::format_restore_json(&outcome));
    } else {
        println!("{}", cli_pds_admin::format_restore_human(&outcome));
    }
    Ok(())
}

async fn run_moderator_events(args: ModeratorEventsArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let resp = moderator_events::list(
        &pool,
        moderator_events::EventsInput {
            subject: args.subject,
            actor: args.actor,
            action_type: args.action_type,
            from: args.from,
            to: args.to,
            limit: args.limit,
            cursor: args.cursor,
            ozone_only: args.ozone_only,
        },
    )
    .await?;
    if args.json {
        println!("{}", moderator_events::format_json(&resp));
    } else {
        println!("{}", moderator_events::format_human(&resp));
    }
    Ok(())
}

async fn run_xrpc_callers_add(args: XrpcMembershipAddArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    cairn_mod::xrpc_gateway::add_known_caller(&pool, &args.did, args.note.as_deref(), &args.by)
        .await
        .map_err(|e| CliError::Startup(e.to_string()))?;
    println!("added xrpc_known_caller: {} (by {})", args.did, args.by);
    Ok(())
}

async fn run_xrpc_callers_revoke(args: XrpcMembershipRevokeArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    cairn_mod::xrpc_gateway::revoke_known_caller(&pool, &args.did, &args.by)
        .await
        .map_err(|e| CliError::Startup(e.to_string()))?;
    println!("revoked xrpc_known_caller: {} (by {})", args.did, args.by);
    Ok(())
}

async fn run_xrpc_callers_list(args: XrpcMembershipListArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let rows = cairn_mod::xrpc_gateway::list_known_callers(&pool, args.include_revoked)
        .await
        .map_err(|e| CliError::Startup(e.to_string()))?;
    print_membership_rows(&rows);
    Ok(())
}

async fn run_xrpc_pdses_add(args: XrpcMembershipAddArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    cairn_mod::xrpc_gateway::add_trusted_pds(&pool, &args.did, args.note.as_deref(), &args.by)
        .await
        .map_err(|e| CliError::Startup(e.to_string()))?;
    println!("added xrpc_trusted_pds: {} (by {})", args.did, args.by);
    Ok(())
}

async fn run_xrpc_pdses_revoke(args: XrpcMembershipRevokeArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    cairn_mod::xrpc_gateway::revoke_trusted_pds(&pool, &args.did, &args.by)
        .await
        .map_err(|e| CliError::Startup(e.to_string()))?;
    println!("revoked xrpc_trusted_pds: {} (by {})", args.did, args.by);
    Ok(())
}

async fn run_xrpc_pdses_list(args: XrpcMembershipListArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let rows = cairn_mod::xrpc_gateway::list_trusted_pdses(&pool, args.include_revoked)
        .await
        .map_err(|e| CliError::Startup(e.to_string()))?;
    print_membership_rows(&rows);
    Ok(())
}

fn print_membership_rows(rows: &[cairn_mod::xrpc_gateway::MembershipRow]) {
    if rows.is_empty() {
        println!("(no rows)");
        return;
    }
    for r in rows {
        let status = match r.revoked_at {
            None => "active".to_string(),
            Some(t) => format!("revoked@{t}"),
        };
        let note = r.note.as_deref().unwrap_or("-");
        println!(
            "{} {status} added@{} by {} note={note}",
            r.did, r.added_at, r.added_by_moderator
        );
    }
}

async fn run_audit_rebuild(args: AuditRebuildArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let outcome = audit_rebuild::rebuild(&pool).await?;
    if args.json {
        println!("{}", audit_rebuild::format_json(&outcome));
    } else {
        println!("{}", audit_rebuild::format_human(&outcome));
    }
    Ok(())
}

async fn run_audit_cross_verify(args: AuditCrossVerifyArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;

    if args.history {
        let rows = cairn_mod::cli::audit_cross_verify::history(&pool, args.limit).await?;
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).unwrap_or_default()
            );
        } else {
            println!(
                "{}",
                cairn_mod::cli::audit_cross_verify::format_history_human(&rows)
            );
        }
        return Ok(());
    }

    cli_pds_admin::verify_pds_admin_enabled(&config)?;
    // The verification_persist gate (first consumer of the field
    // since its v1.8.1 parse+store landing).
    let policy = cairn_mod::pds_admin::PdsAdminPolicy::from_config(&config)
        .map_err(|e| CliError::Config(format!("pds_admin policy: {e}")))?;
    let verification_persist = match &policy.backend {
        Some(cairn_mod::pds_admin::PdsAdminBackendConfig::Rust(r)) => r.verification_persist,
        _ => true,
    };
    let backend = cli_pds_admin_reads::backend_for_reads(&config).await?;

    let report = cairn_mod::cli::audit_cross_verify::run(
        &pool,
        backend.as_ref(),
        verification_persist,
        (args.start_sequence, args.end_sequence),
    )
    .await?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!(
            "{}",
            cairn_mod::cli::audit_cross_verify::format_report_human(&report)
        );
    }

    match report.outcome {
        cairn_mod::cli::audit_cross_verify::CrossVerifyOutcome::Verified
        | cairn_mod::cli::audit_cross_verify::CrossVerifyOutcome::Empty => Ok(()),
        divergent => Err(CliError::CrossVerifyDivergence {
            outcome: divergent.as_str(),
        }),
    }
}

async fn run_audit_verify(args: AuditVerifyArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let outcome = audit_verify::verify(&pool).await?;
    // Always print structured outcome to stdout — both --human and
    // --json consumers expect the report on stdout. Divergence
    // exits non-zero via the CliError mapping below; the stderr
    // "error: ..." line main.rs prints from CliError's Display
    // duplicates a portion of the human report (acceptable for
    // operators) and gives JSON consumers a quick human signal.
    if args.json {
        println!("{}", audit_verify::format_json(&outcome));
    } else {
        println!("{}", audit_verify::format_human(&outcome));
    }
    match outcome {
        audit_verify::VerifyOutcome::Divergence {
            table,
            row_id,
            expected_hash,
            actual_hash,
            attested_rows_before_divergence,
        } => Err(CliError::AuditDivergence {
            table: table.as_str(),
            row_id,
            expected_hash,
            actual_hash,
            attested_rows_before_divergence,
        }),
        _ => Ok(()),
    }
}

async fn run_retention_sweep(args: RetentionSweepArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = retention::SweepInput {
        cairn_server_override: args.cairn_server,
    };
    let resp = retention::sweep(&mut session, &path, input).await?;
    if args.json {
        println!("{}", retention::format_sweep_json(&resp));
    } else {
        println!("{}", retention::format_sweep_human(&resp));
    }
    Ok(())
}

async fn run_trust_chain_show(args: TrustChainShowArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = trust_chain::TrustChainShowInput {
        cairn_server_override: args.cairn_server,
    };
    let resp = trust_chain::show(&mut session, &path, input).await?;
    if args.json {
        println!("{}", trust_chain::format_show_json(&resp));
    } else {
        println!("{}", trust_chain::format_show_human(&resp));
    }
    Ok(())
}

async fn run_audit_show(args: AuditShowArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = audit::AuditShowInput {
        id: args.id,
        cairn_server_override: args.cairn_server,
    };
    let entry = audit::show(&mut session, &path, input).await?;
    if args.json {
        println!("{}", audit::format_show_json(&entry));
    } else {
        println!("{}", audit::format_show_human(&entry));
    }
    Ok(())
}

async fn run_audit_list(args: AuditListArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = audit::AuditListInput {
        actor: args.actor,
        action: args.action,
        outcome: args.outcome,
        since: args.since,
        until: args.until,
        limit: args.limit,
        cursor: args.cursor,
        cairn_server_override: args.cairn_server,
    };
    let resp = audit::list(&mut session, &path, input).await?;
    if args.json {
        println!("{}", audit::format_list_json(&resp));
    } else {
        println!("{}", audit::format_list_human(&resp));
    }
    Ok(())
}

async fn run_login(args: LoginArgs) -> Result<(), CliError> {
    let password = rpassword::prompt_password(format!(
        "App password for {} at {}: ",
        args.handle, args.pds
    ))
    .map_err(|e| CliError::Config(format!("could not read app password (no TTY?): {e}")))?;
    if password.is_empty() {
        return Err(CliError::Config("app password was empty".into()));
    }
    let path = session_path()?;
    let session = login::login(
        &args.cairn_server,
        &args.pds,
        &args.handle,
        &password,
        args.cairn_did.as_deref(),
        &path,
    )
    .await?;
    println!("{}", post_login_warning(&session, &path));
    Ok(())
}

async fn run_logout() -> Result<(), CliError> {
    let path = session_path()?;
    match logout::logout(&path).await? {
        LogoutOutcome::NotLoggedIn => println!("not logged in"),
        LogoutOutcome::RevokedAndRemoved => println!("Logged out. Session file removed."),
        LogoutOutcome::RemovedLocalOnlyPdsFailed => println!(
            "Session file removed. PDS deleteSession failed — re-check with your PDS; rerun logout is harmless.",
        ),
    }
    Ok(())
}

async fn run_report_create(args: ReportCreateArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = ReportCreateInput {
        subject: args.subject,
        cid: args.cid,
        reason_type: args.reason_type.as_lexicon().to_string(),
        reason: args.reason,
        cairn_server_override: args.cairn_server,
    };
    let resp = report::create(&mut session, &path, input).await?;

    if args.json {
        println!("{}", report::format_create_json(&resp));
    } else {
        println!("{}", report::format_create_human(&resp));
    }
    Ok(())
}

async fn run_report_list(args: ReportListArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = report::ReportListInput {
        status: args.status,
        reported_by: args.reported_by,
        limit: args.limit,
        cursor: args.cursor,
        cairn_server_override: args.cairn_server,
    };
    let resp = report::list(&mut session, &path, input).await?;
    if args.json {
        println!("{}", report::format_list_json(&resp));
    } else {
        println!("{}", report::format_list_human(&resp));
    }
    Ok(())
}

async fn run_report_view(args: ReportViewArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = report::ReportViewInput {
        id: args.id,
        cairn_server_override: args.cairn_server,
    };
    let resp = report::view(&mut session, &path, input).await?;
    if args.json {
        println!("{}", report::format_view_json(&resp));
    } else {
        println!("{}", report::format_view_human(&resp));
    }
    Ok(())
}

async fn run_report_flag(args: ReportFlagArgs, suppressed: bool) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    let input = report::ReportFlagInput {
        did: args.did,
        suppressed,
        reason: args.reason,
        cairn_server_override: args.cairn_server,
    };
    let resp = report::flag(&mut session, &path, input).await?;
    if args.json {
        println!("{}", report::format_flag_json(&resp));
    } else {
        println!("{}", report::format_flag_human(&resp));
    }
    Ok(())
}

async fn run_report_resolve(args: ReportResolveArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;

    // Build the optional ApplyLabelArg group. Clap's `requires`
    // attributes already enforce val + uri together; we only need
    // to compose the struct here.
    let apply_label = match (args.apply_label_val, args.apply_label_uri) {
        (Some(val), Some(uri)) => Some(report::ApplyLabelArg {
            uri,
            cid: args.apply_label_cid,
            val,
            exp: args.apply_label_exp,
        }),
        (None, None) => None,
        // Unreachable: clap's `requires` constraint pairs val + uri.
        _ => unreachable!("clap requires should pair --apply-label-val and --apply-label-uri"),
    };

    let input = report::ReportResolveInput {
        id: args.id,
        apply_label,
        reason: args.reason,
        cairn_server_override: args.cairn_server,
    };
    let resp = report::resolve(&mut session, &path, input).await?;
    if args.json {
        println!("{}", report::format_resolve_json(&resp));
    } else {
        println!("{}", report::format_resolve_human(&resp));
    }
    Ok(())
}

fn session_path() -> Result<PathBuf, CliError> {
    Ok(session::default_path()?)
}

async fn run_operator_login(args: OperatorLoginArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let operator_cfg = config
        .operator
        .as_ref()
        .ok_or_else(|| CliError::Config("missing [operator] section in config".into()))?;
    let pds_url = args.pds.as_deref().unwrap_or(&operator_cfg.pds_url);

    let password = rpassword::prompt_password(format!(
        "Operator app password for {} at {}: ",
        args.handle, pds_url
    ))
    .map_err(|e| CliError::Config(format!("could not read app password (no TTY?): {e}")))?;
    if password.is_empty() {
        return Err(CliError::Config("app password was empty".into()));
    }

    let session =
        operator_login::login(pds_url, &args.handle, &password, &operator_cfg.session_path).await?;
    println!(
        "{}",
        operator_login::post_login_warning(&session, &operator_cfg.session_path)
    );
    Ok(())
}

async fn run_publish_service_record(args: ServeArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let operator_cfg = config
        .operator
        .as_ref()
        .ok_or_else(|| CliError::Config("missing [operator] section in config".into()))?
        .clone();
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;

    let outcome =
        publish_service_record::publish(&pool, &config, &operator_cfg.session_path).await?;
    match outcome {
        PublishOutcome::NoChange => {
            println!("service record already up to date; no publish needed");
        }
        PublishOutcome::Published { cid, created_at } => {
            println!("published service record: cid={cid}, createdAt={created_at}");
        }
    }
    Ok(())
}

async fn run_unpublish_service_record(args: ServeArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    let operator_cfg = config
        .operator
        .as_ref()
        .ok_or_else(|| CliError::Config("missing [operator] section in config".into()))?
        .clone();
    let pool = storage::open(&config.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))?;

    let outcome =
        unpublish_service_record::unpublish(&pool, &config, &operator_cfg.session_path).await?;
    match outcome {
        UnpublishOutcome::NoChange => {
            println!("no service record published; nothing to unpublish");
        }
        UnpublishOutcome::Unpublished { cid } => {
            println!("unpublished service record: cid={cid}");
        }
    }
    Ok(())
}

async fn open_pool_from_config(
    config: Option<&PathBuf>,
) -> Result<sqlx::Pool<sqlx::Sqlite>, CliError> {
    let cfg = load_config(config.map(PathBuf::as_path))?;
    storage::open(&cfg.db_path)
        .await
        .map_err(|e| CliError::MigrationFailed(e.to_string()))
}

async fn run_moderator_add(args: ModeratorAddArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let json = args.json;
    let did = args.did.clone();
    let result = moderator::add(
        &pool,
        moderator::AddInput {
            did: args.did,
            role: args.role.into(),
            update_role: args.update_role,
        },
    )
    .await?;

    // --with-xrpc-callers: also add to xrpc_known_callers. The two
    // adds aren't transactional (the moderators table and
    // xrpc_known_callers are independent surfaces), but the
    // composite operation is idempotent at the application layer:
    // we pre-check `is_known_caller` and skip the second add when
    // the DID is already an active caller. (Without the pre-check
    // the second add would fail with a UNIQUE-constraint error.)
    let xrpc_caller_added = if args.with_xrpc_callers {
        let by = args
            .by
            .as_deref()
            .expect("clap requires --by when --with-xrpc-callers is set");
        let already = cairn_mod::xrpc_gateway::is_known_caller(&pool, &did)
            .await
            .map_err(|e| CliError::Startup(format!("xrpc_known_callers lookup: {e}")))?;
        if !already {
            cairn_mod::xrpc_gateway::add_known_caller(&pool, &did, None, by)
                .await
                .map_err(|e| CliError::Startup(format!("xrpc_known_callers add: {e}")))?;
            true
        } else {
            // Already-active caller; treat as success but flag in
            // the output so operators know nothing changed.
            false
        }
    } else {
        false
    };

    if json {
        println!(
            "{}",
            moderator::format_add_json_with_xrpc(&result, xrpc_caller_added)
        );
    } else {
        println!("{}", moderator::format_add_human(&result));
        if xrpc_caller_added {
            println!("also added to xrpc_known_callers");
        }
    }
    Ok(())
}

async fn run_moderator_remove(args: ModeratorRemoveArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let json = args.json;
    let result = moderator::remove(
        &pool,
        moderator::RemoveInput {
            did: args.did,
            force: args.force,
        },
    )
    .await?;
    if json {
        println!("{}", moderator::format_remove_json(&result));
    } else {
        println!("{}", moderator::format_remove_human(&result));
    }
    Ok(())
}

async fn run_moderator_list(args: ModeratorListArgs) -> Result<(), CliError> {
    let pool = open_pool_from_config(args.config.as_ref()).await?;
    let mods = moderator::list(
        &pool,
        moderator::ListInput {
            role: args.role.map(Into::into),
        },
    )
    .await?;
    if args.json {
        println!("{}", moderator::format_list_json(&mods));
    } else {
        println!("{}", moderator::format_list_human(&mods));
    }
    Ok(())
}

async fn run_moderator_action(args: ModeratorActionArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_action::record(
        &mut session,
        &path,
        moderator_action::RecordActionInput {
            subject: args.subject,
            action_type: args.action_type.as_db_str().to_string(),
            reasons: args.reason,
            duration: args.duration,
            note: args.note,
            report_ids: args.report,
            cid: None,
            detail: None,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_record_json(&resp));
    } else {
        println!("{}", moderator_action::format_record_human(&resp));
    }
    Ok(())
}

async fn run_moderator_warn(args: ModeratorWarnArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_action::record(
        &mut session,
        &path,
        moderator_action::RecordActionInput {
            subject: args.subject,
            action_type: "warning".to_string(),
            reasons: args.reason,
            duration: None,
            note: args.note,
            report_ids: vec![],
            cid: None,
            detail: None,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_record_json(&resp));
    } else {
        println!("{}", moderator_action::format_record_human(&resp));
    }
    Ok(())
}

async fn run_moderator_note(args: ModeratorNoteArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    // Notes carry no strikes and need no reasons in v1.4 design,
    // but the recorder validates reason_codes non-empty. Synthesize
    // a sentinel `note` reason — the operator's vocabulary
    // typically declares one (`other` is the default fallback).
    // If the operator removed the default vocabulary, they'll get
    // an InvalidReason from the server with a clear hint.
    let resp = moderator_action::record(
        &mut session,
        &path,
        moderator_action::RecordActionInput {
            subject: args.subject,
            action_type: "note".to_string(),
            reasons: vec!["other".to_string()],
            duration: None,
            note: Some(args.text),
            report_ids: vec![],
            cid: None,
            detail: None,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_record_json(&resp));
    } else {
        println!("{}", moderator_action::format_record_human(&resp));
    }
    Ok(())
}

async fn run_moderator_revoke(args: ModeratorRevokeArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_action::revoke(
        &mut session,
        &path,
        moderator_action::RevokeActionInput {
            action_id: args.action_id,
            reason: args.reason,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_revoke_json(&resp));
    } else {
        println!("{}", moderator_action::format_revoke_human(&resp));
    }
    Ok(())
}

async fn run_moderator_history(args: ModeratorHistoryArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let subject_for_msg = args.subject.clone();
    let resp = moderator_action::history(
        &mut session,
        &path,
        moderator_action::HistoryInput {
            subject: args.subject,
            subject_uri: args.subject_uri,
            include_revoked: !args.no_include_revoked,
            since: args.since,
            limit: args.limit,
            cursor: args.cursor,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_history_json(&resp));
    } else {
        println!(
            "{}",
            moderator_action::format_history_human(&resp, &subject_for_msg)
        );
    }
    Ok(())
}

async fn run_moderator_strikes(args: ModeratorStrikesArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let subject_for_msg = args.subject.clone();
    let resp = moderator_action::strikes(
        &mut session,
        &path,
        moderator_action::StrikesInput {
            subject: args.subject,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_strikes_json(&resp));
    } else {
        println!(
            "{}",
            moderator_action::format_strikes_human(&resp, &subject_for_msg)
        );
    }
    Ok(())
}

async fn run_moderator_labels(args: ModeratorLabelsArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let subject_for_msg = args.subject.clone();
    let resp = moderator_action::labels(
        &mut session,
        &path,
        moderator_action::LabelsInput {
            subject: args.subject,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_action::format_labels_json(&resp));
    } else {
        println!(
            "{}",
            moderator_action::format_labels_human(&resp, &subject_for_msg)
        );
    }
    Ok(())
}

async fn run_moderator_pending_list(args: ModeratorPendingListArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_pending::list(
        &mut session,
        &path,
        moderator_pending::ListPendingInput {
            subject: args.subject,
            limit: args.limit,
            cursor: args.cursor,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_pending::format_list_json(&resp));
    } else {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        println!("{}", moderator_pending::format_list_human(&resp, &now));
    }
    Ok(())
}

async fn run_moderator_pending_view(args: ModeratorPendingViewArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_pending::view(
        &mut session,
        &path,
        moderator_pending::ViewPendingInput {
            pending_id: args.pending_id,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_pending::format_view_json(&resp));
    } else {
        println!("{}", moderator_pending::format_view_human(&resp));
    }
    Ok(())
}

async fn run_moderator_pending_confirm(args: ModeratorPendingConfirmArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_pending::confirm(
        &mut session,
        &path,
        moderator_pending::ConfirmPendingInput {
            pending_id: args.pending_id,
            reason: args.reason,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_pending::format_confirm_json(&resp));
    } else {
        println!("{}", moderator_pending::format_confirm_human(&resp));
    }
    Ok(())
}

async fn run_moderator_pending_dismiss(args: ModeratorPendingDismissArgs) -> Result<(), CliError> {
    let path = session_path()?;
    let mut session = session::SessionFile::load(&path)?.ok_or(CliError::NotLoggedIn)?;
    let json = args.json;
    let resp = moderator_pending::dismiss(
        &mut session,
        &path,
        moderator_pending::DismissPendingInput {
            pending_id: args.pending_id,
            reason: args.reason,
            cairn_server_override: args.cairn_server,
        },
    )
    .await?;
    if json {
        println!("{}", moderator_pending::format_dismiss_json(&resp));
    } else {
        println!("{}", moderator_pending::format_dismiss_human(&resp));
    }
    Ok(())
}

fn load_config(explicit_path: Option<&std::path::Path>) -> Result<Config, CliError> {
    match explicit_path {
        Some(p) => Config::load_from(Some(p)),
        None => Config::load(),
    }
    .map_err(|e| CliError::Config(e.to_string()))
}

async fn run_serve(args: ServeArgs) -> Result<(), CliError> {
    let config = load_config(args.config.as_deref())?;
    serve::run(config, shutdown_signal()).await
}

/// Future that resolves on the first SIGINT (Ctrl-C) or SIGTERM. Both
/// signals land the same way — request graceful shutdown. SIGTERM is
/// what `systemctl stop` sends; SIGINT is interactive Ctrl-C.
async fn shutdown_signal() {
    // Tracing kept at debug! so future signal-handling bugs can be
    // diagnosed via `-vv` without cluttering the info-level log stream
    // on every start/stop.
    tracing::debug!("shutdown_signal: entered, awaiting SIGINT or SIGTERM");
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::debug!("shutdown_signal: SIGINT (ctrl_c) fired");
            }
            _ = term.recv() => {
                tracing::debug!("shutdown_signal: SIGTERM (term.recv()) fired");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::debug!("shutdown_signal: ctrl_c fired (non-unix path)");
    }
}

#[cfg(test)]
mod batch_cli_tests {
    use super::*;

    #[test]
    fn blob_ref_shorthand_parses_and_rejects() {
        // v2 §6.3: `@` delimiter sidesteps DID-colon ambiguity.
        let (did, cid) = parse_blob_ref("did:plc:abc123@bafyblobcid").unwrap();
        assert_eq!(did, "did:plc:abc123");
        assert_eq!(cid, "bafyblobcid");
        // DIDs containing colons stay intact.
        let (did, _) = parse_blob_ref("did:web:pds.example.com@bafy2").unwrap();
        assert_eq!(did, "did:web:pds.example.com");
        assert!(parse_blob_ref("did:plc:abc123").is_err());
        assert!(parse_blob_ref("not-a-did@bafy").is_err());
        assert!(parse_blob_ref("did:plc:abc123@").is_err());
    }

    #[test]
    fn record_subject_fragment_required() {
        let (uri, cid) =
            parse_record_subject("at://did:plc:a/app.bsky.feed.post/r1#bafy1").unwrap();
        assert_eq!(uri, "at://did:plc:a/app.bsky.feed.post/r1");
        assert_eq!(cid, "bafy1");
        // Bare URI (URI-level) is records batch-takedown territory.
        let err = parse_record_subject("at://did:plc:a/app.bsky.feed.post/r1").unwrap_err();
        assert!(err.to_string().contains("batch-takedown"), "{err}");
    }

    #[test]
    fn batch_did_extraction_from_at_uri() {
        assert_eq!(
            batch_did_from_at_uri("at://did:plc:a/app.bsky.feed.post/r1").unwrap(),
            "did:plc:a"
        );
        assert!(batch_did_from_at_uri("https://example.com/x").is_err());
        assert!(batch_did_from_at_uri("at://handle.example.com/c/r").is_err());
    }

    #[test]
    fn cli_batch_len_check_matches_aurora_shapes() {
        assert!(cli_batch_len_check(49, 50, "batch").is_ok());
        assert!(cli_batch_len_check(50, 50, "batch").is_ok());
        let err = cli_batch_len_check(51, 50, "batch").unwrap_err();
        assert_eq!(err.exit_code(), 7, "cap violation exits 7 (SERVER_4XX)");
        assert!(
            err.to_string()
                .contains("batch length 51 exceeds limit of 50"),
            "{err}"
        );
        assert!(cli_batch_len_check(0, 50, "batch").is_err());
    }

    #[test]
    fn nine_batch_subcommands_parse_and_batch_restore_is_absent() {
        use clap::Parser as _;
        // The nine v1.8.7 subcommands round-trip through clap.
        for argv in [
            vec![
                "cairn",
                "pds-admin",
                "accounts",
                "batch-takedown",
                "did:plc:a",
                "did:plc:b",
            ],
            vec![
                "cairn",
                "pds-admin",
                "accounts",
                "batch-suspend",
                "did:plc:a",
            ],
            vec!["cairn", "pds-admin", "accounts", "delete-many", "did:plc:a"],
            vec![
                "cairn",
                "pds-admin",
                "blobs",
                "quarantine-many",
                "did:plc:a@bafy1",
            ],
            vec![
                "cairn",
                "pds-admin",
                "blobs",
                "restore-many",
                "did:plc:a@bafy1",
                "--prior-action-id",
                "evt-1",
            ],
            vec![
                "cairn",
                "pds-admin",
                "blobs",
                "delete-many",
                "did:plc:a@bafy1",
            ],
            vec![
                "cairn",
                "pds-admin",
                "records",
                "batch-takedown",
                "at://did:plc:a/c/r",
            ],
            vec![
                "cairn",
                "pds-admin",
                "records",
                "takedown-many",
                "at://did:plc:a/c/r#bafy1",
            ],
            vec![
                "cairn",
                "pds-admin",
                "subjects",
                "update-status-many",
                "did:plc:a",
                "--status",
                "active",
            ],
        ] {
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?} should parse: {e}"));
        }
        // Positional lists are required.
        assert!(Cli::try_parse_from(["cairn", "pds-admin", "accounts", "batch-takedown"]).is_err());
        // LB-A: batch-restore intentionally has no CLI surface.
        assert!(
            Cli::try_parse_from([
                "cairn",
                "pds-admin",
                "accounts",
                "batch-restore",
                "did:plc:a"
            ])
            .is_err()
        );
    }
}
