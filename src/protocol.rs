//! Wire types for CamelFlagProtocol (serialised as JSON over HTTP).

use serde::{Deserialize, Serialize};

// ── Chunk envelope (client → server) ─────────────────────────────────────────

/// The JSON body sent in each HTTP POST for a single file chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkEnvelope {
    /// Protocol version
    pub version: u8,

    /// Transfer session identifier (UUIDv4); ties all chunks to one file
    pub session_id: String,

    /// Original file name (no path component)
    pub file_name: String,

    /// Total number of chunks in this session
    pub total_chunks: usize,

    /// Zero-based position of this chunk in the original file
    pub chunk_index: usize,

    /// SHA-256 hex digest of the *plaintext* chunk bytes
    pub chunk_hash: String,

    /// RSA-2048 / OAEP encrypted 32-byte AES session key (base64)
    pub encrypted_key: String,

    /// AES-256-CTR ciphertext of the chunk bytes (base64)
    pub payload: String,
}

// ── ACK response (server → client, per chunk) ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckResponse {
    /// "ok" or "error"
    pub status: String,

    pub session_id: String,

    pub chunk_index: usize,

    /// SHA-256 hex of the plaintext chunk; client uses this to verify the
    /// server decrypted correctly
    pub chunk_hash: String,

    /// Optional error message (only when status == "error")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Random padding bytes (base64); client must ignore this field
    pub padding: String,
}

// ── Completion response (server → client, after last chunk) ──────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteResponse {
    pub status: String, // "complete"

    pub session_id: String,

    /// SHA-256 hex of the entire reassembled file
    pub file_hash: String,

    pub file_name: String,

    /// Random padding bytes (base64); client must ignore this field
    pub padding: String,
}
