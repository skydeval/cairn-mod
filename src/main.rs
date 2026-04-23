//! `cairn` — ATProto labeler binary entry point.
//!
//! v1 surface is CLI-only here. The `cairn serve` subcommand (to
//! launch the labeler HTTP/WebSocket process) is deferred to #18.

use std::path::PathBuf;
use std::process::ExitCode;

use cairn_mod::cli::{
    error::{CliError, code},
    login::{self, post_login_warning},
    logout::{self, LogoutOutcome},
    report::{self, ReportCreateInput},
    session,
};
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
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Base URL of the Cairn labeler (e.g. https://labeler.example).
    #[arg(long)]
    cairn_server: String,
    /// Moderator's PDS base URL (e.g. https://bsky.social).
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
