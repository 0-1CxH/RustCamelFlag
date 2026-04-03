//! CamelFlagProtocol (CFP) – entry point.
//!
//! Usage:
//!   cfp server --passkey <KEY> [--listen 0.0.0.0:8080] [--output-dir ./received]
//!   cfp client --file <FILE> --server http://host:port --passkey <KEY>

mod chunker;
mod client;
mod config;
mod crypto;
mod protocol;
mod server;

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::{Router, routing::get};
use clap::Parser;
use tracing::{info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use config::{Cli, Commands};
use server::handler::{AppState, SessionState};

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server(args) => run_server(args).await,
        Commands::Client(args) => {
            // The client uses reqwest::blocking which must NOT run inside an
            // async Tokio context.  Dispatch it to a dedicated OS thread.
            tokio::task::spawn_blocking(move || run_client(args))
                .await
                .context("Client thread panicked")??;
            Ok(())
        }
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

async fn run_server(args: config::ServerArgs) -> Result<()> {
    let passkey = resolve_passkey(args.passkey.as_deref(), "Server passkey")?;

    // ── Logging: to disk ─────────────────────────────────────────────────
    let _guard = init_server_logging(&args.log_dir)?;

    info!("CamelFlagProtocol Server starting …");
    info!(listen = %args.listen, output_dir = %args.output_dir, "Config");

    // ── Derive keys ───────────────────────────────────────────────────────
    info!("Deriving cryptographic keys from passkey …");
    let keys = crypto::derive_keys(&passkey).context("Key derivation failed")?;
    info!("RSA-2048 key pair ready");

    // ── Build app state ───────────────────────────────────────────────────
    let state = AppState {
        keys: Arc::new(keys),
        sessions: Arc::new(Mutex::new(HashMap::<String, SessionState>::new())),
        output_dir: PathBuf::from(&args.output_dir),
        padding_min: args.padding_min,
        padding_max: args.padding_max,
    };

    // ── Router ────────────────────────────────────────────────────────────
    // GET  /complete/:session_id → completion poll
    // Any other request (POST from client) → chunk receiver
    // The client uses random URL paths for obfuscation; we catch all with fallback.
    let app = Router::new()
        .route("/complete/:session_id", get(server::handler::poll_complete))
        .fallback(server::handler::receive_chunk)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .context(format!("Failed to bind to {}", args.listen))?;

    info!("Listening on http://{}", args.listen);
    println!("CFP Server listening on http://{}", args.listen);

    axum::serve(listener, app)
        .await
        .context("Server error")?;

    Ok(())
}

// ── Client ────────────────────────────────────────────────────────────────────

fn run_client(args: config::ClientArgs) -> Result<()> {
    let passkey = resolve_passkey(args.passkey.as_deref(), "Client passkey")?;

    // ── Logging: stdout only ──────────────────────────────────────────────
    init_client_logging();

    info!(file = %args.file, server = %args.server, "CamelFlagProtocol Client starting …");

    // ── Read file ─────────────────────────────────────────────────────────
    let file_path = PathBuf::from(&args.file);
    let file_bytes = std::fs::read(&file_path)
        .with_context(|| format!("Cannot read file: {}", args.file))?;

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    info!(
        file = %file_name,
        bytes = file_bytes.len(),
        chunk_min = args.chunk_min,
        chunk_max = args.chunk_max,
        "File loaded"
    );

    println!(
        "Sending '{}' ({} bytes) to {} …",
        file_name,
        file_bytes.len(),
        args.server
    );

    // ── Split into chunks ─────────────────────────────────────────────────
    let chunks =
        chunker::split(&file_bytes, &file_name, args.chunk_min, args.chunk_max)
            .context("Chunking failed")?;

    info!(
        chunks = chunks.len(),
        chunk_min_bytes = args.chunk_min,
        chunk_max_bytes = args.chunk_max,
        threads = args.threads,
        "Ready to transmit"
    );

    println!(
        "Split into {} chunk(s), using {} sender threads",
        chunks.len(),
        args.threads
    );

    // ── Send ──────────────────────────────────────────────────────────────
    client::sender::run(chunks, &args, &passkey)?;

    Ok(())
}

// ── Logging setup ─────────────────────────────────────────────────────────────

fn init_server_logging(log_dir: &str) -> Result<WorkerGuard> {
    std::fs::create_dir_all(log_dir)
        .with_context(|| format!("Cannot create log directory: {}", log_dir))?;

    let file_appender = tracing_appender::rolling::daily(log_dir, "server.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true),
        )
        .init();

    Ok(guard)
}

fn init_client_logging() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_ansi(true)
                .with_target(false),
        )
        .init();
}

// ── Passkey resolution ────────────────────────────────────────────────────────

fn resolve_passkey(supplied: Option<&str>, prompt_label: &str) -> Result<String> {
    if let Some(pk) = supplied {
        return Ok(pk.to_string());
    }

    // Interactive prompt (no echo)
    print!("{}: ", prompt_label);
    io::stdout().flush()?;

    // Read without echo using rpassword-like approach
    // We use a simple stdin read here for portability
    let mut passkey = String::new();
    io::stdin()
        .read_line(&mut passkey)
        .context("Failed to read passkey")?;
    let passkey = passkey.trim().to_string();

    if passkey.is_empty() {
        anyhow::bail!("Passkey cannot be empty");
    }

    Ok(passkey)
}
