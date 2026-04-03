//! Default configuration values and CLI structures.

use clap::{Parser, Subcommand};

// ── Defaults ─────────────────────────────────────────────────────────────────

pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
pub const DEFAULT_OUTPUT_DIR: &str = "./received";
pub const DEFAULT_CHUNK_MIN: u64 = 1 * 1024 * 1024; // 1 MB
pub const DEFAULT_CHUNK_MAX: u64 = 4 * 1024 * 1024; // 4 MB
pub const DEFAULT_SENDER_THREADS: usize = 64;
pub const DEFAULT_INTERVAL_MIN_MS: u64 = 200; // 0.2 s
pub const DEFAULT_INTERVAL_MAX_MS: u64 = 800; // 0.8 s
pub const DEFAULT_RESPONSE_PADDING_MIN: usize = 20;
pub const DEFAULT_RESPONSE_PADDING_MAX: usize = 200;
pub const PBKDF2_ITERATIONS: u32 = 100_000;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "cfp",
    version,
    about = "CamelFlagProtocol – encrypted covert file transfer over HTTP"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the CFP server
    Server(ServerArgs),
    /// Run the CFP client (send a file)
    Client(ClientArgs),
}

#[derive(Parser, Debug)]
pub struct ServerArgs {
    /// Address to listen on
    #[arg(long, default_value = DEFAULT_LISTEN_ADDR)]
    pub listen: String,

    /// Directory where received files are saved
    #[arg(long, default_value = DEFAULT_OUTPUT_DIR)]
    pub output_dir: String,

    /// Passkey (if not supplied, will prompt interactively)
    #[arg(long)]
    pub passkey: Option<String>,

    /// Minimum padding bytes added to each ACK response
    #[arg(long, default_value_t = DEFAULT_RESPONSE_PADDING_MIN)]
    pub padding_min: usize,

    /// Maximum padding bytes added to each ACK response
    #[arg(long, default_value_t = DEFAULT_RESPONSE_PADDING_MAX)]
    pub padding_max: usize,

    /// Log directory
    #[arg(long, default_value = "./logs")]
    pub log_dir: String,
}

#[derive(Parser, Debug)]
pub struct ClientArgs {
    /// File to transfer
    #[arg(short, long)]
    pub file: String,

    /// Server URL (e.g. http://127.0.0.1:8080)
    #[arg(short, long)]
    pub server: String,

    /// Passkey (if not supplied, will prompt interactively)
    #[arg(long)]
    pub passkey: Option<String>,

    /// Minimum chunk size in bytes
    #[arg(long, default_value_t = DEFAULT_CHUNK_MIN)]
    pub chunk_min: u64,

    /// Maximum chunk size in bytes
    #[arg(long, default_value_t = DEFAULT_CHUNK_MAX)]
    pub chunk_max: u64,

    /// Number of parallel sender threads
    #[arg(long, default_value_t = DEFAULT_SENDER_THREADS)]
    pub threads: usize,

    /// Minimum inter-packet delay per thread (milliseconds)
    #[arg(long, default_value_t = DEFAULT_INTERVAL_MIN_MS)]
    pub interval_min_ms: u64,

    /// Maximum inter-packet delay per thread (milliseconds)
    #[arg(long, default_value_t = DEFAULT_INTERVAL_MAX_MS)]
    pub interval_max_ms: u64,
}
