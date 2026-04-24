//! `cairn` — ATProto labeler binary entry point.
//!
//! Exposes the CLI subcommands (login/logout/report) and
//! `cairn serve` — the long-running labeler process.

use std::path::PathBuf;
use std::process::ExitCode;

use cairn_mod::cli::{
    error::{CliError, code},
    login::{self, post_login_warning},
    logout::{self, LogoutOutcome},
    operator_login,
    publish_service_record::{self, PublishOutcome},
    report::{self, ReportCreateInput},
    session,
};
use cairn_mod::config::Config;
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
        Command::Serve(args) => run_serve(args).await,
        Command::OperatorLogin(args) => run_operator_login(args).await,
        Command::PublishServiceRecord(args) => run_publish_service_record(args).await,
    }
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
        println!("{}", report::format_json(&resp));
    } else {
        println!("{}", report::format_human(&resp));
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
