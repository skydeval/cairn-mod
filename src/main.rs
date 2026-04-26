//! `cairn` — ATProto labeler binary entry point.
//!
//! Exposes the CLI subcommands (login/logout/report) and
//! `cairn serve` — the long-running labeler process.

use std::path::PathBuf;
use std::process::ExitCode;

use cairn_mod::cli::{
    audit,
    error::{CliError, code},
    login::{self, post_login_warning},
    logout::{self, LogoutOutcome},
    moderator, operator_login,
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
        Command::Audit {
            sub: AuditSub::List(args),
        } => run_audit_list(args).await,
        Command::Audit {
            sub: AuditSub::Show(args),
        } => run_audit_show(args).await,
        Command::Retention {
            sub: RetentionSub::Sweep(args),
        } => run_retention_sweep(args).await,
        Command::TrustChain {
            sub: TrustChainSub::Show(args),
        } => run_trust_chain_show(args).await,
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
    let result = moderator::add(
        &pool,
        moderator::AddInput {
            did: args.did,
            role: args.role.into(),
            update_role: args.update_role,
        },
    )
    .await?;
    if json {
        println!("{}", moderator::format_add_json(&result));
    } else {
        println!("{}", moderator::format_add_human(&result));
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
