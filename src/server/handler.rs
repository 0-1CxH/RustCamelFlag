//! Axum HTTP handlers for the CFP server.
//!
//! Routes:
//!   POST  /*path          – receive a ChunkEnvelope, decrypt, ACK
//!   GET   /complete/:sid  – poll for session completion; 202 = still assembling

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::Rng;
use serde_json::json;
use tracing::{error, info, warn};

use crate::crypto::{self, CfpKeys};
use crate::protocol::{AckResponse, ChunkEnvelope, CompleteResponse};

// ── Session state ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SessionState {
    /// chunk_index → plaintext bytes
    pub received: HashMap<usize, Vec<u8>>,
    pub total_chunks: Option<usize>,
    pub file_name: Option<String>,
    /// Set once the file has been written to disk
    pub file_hash: Option<String>,
}

// ── AppState ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<CfpKeys>,
    pub sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    pub output_dir: PathBuf,
    pub padding_min: usize,
    pub padding_max: usize,
}

// ── Handler: receive chunk ────────────────────────────────────────────────────

/// Handles any POST to the server (path is ignored – obfuscation only).
pub async fn receive_chunk(
    State(state): State<AppState>,
    body: Bytes,
) -> Response {
    let text = match std::str::from_utf8(&body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            error!("Non-UTF8 body received");
            return error_response("Invalid request body", None, 0, StatusCode::BAD_REQUEST);
        }
    };

    let envelope: ChunkEnvelope = match serde_json::from_str(&text) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "Failed to parse ChunkEnvelope");
            return error_response("Malformed envelope", None, 0, StatusCode::BAD_REQUEST);
        }
    };

    let session_id = envelope.session_id.clone();
    let chunk_index = envelope.chunk_index;
    let total_chunks = envelope.total_chunks;
    let file_name = envelope.file_name.clone();
    let expected_hash = envelope.chunk_hash.clone();

    info!(
        session_id = %session_id,
        chunk = chunk_index,
        total = total_chunks,
        file = %file_name,
        "Receiving chunk"
    );

    // ── Decode base64 fields ──────────────────────────────────────────────
    let encrypted_key = match B64.decode(&envelope.encrypted_key) {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "Bad base64 in encrypted_key");
            return error_response("Bad base64", Some(&session_id), chunk_index, StatusCode::BAD_REQUEST);
        }
    };
    let ciphertext = match B64.decode(&envelope.payload) {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "Bad base64 in payload");
            return error_response("Bad base64", Some(&session_id), chunk_index, StatusCode::BAD_REQUEST);
        }
    };

    // ── Decrypt ───────────────────────────────────────────────────────────
    let plaintext =
        match crypto::decrypt_chunk(&state.keys.private_key, &encrypted_key, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                error!(session_id = %session_id, chunk = chunk_index, error = %e, "Decryption failed");
                return error_response("Decryption failed", Some(&session_id), chunk_index, StatusCode::UNPROCESSABLE_ENTITY);
            }
        };

    // ── Verify chunk hash ─────────────────────────────────────────────────
    let actual_hash = crypto::sha256_hex(&plaintext);
    if actual_hash != expected_hash {
        warn!(
            session_id = %session_id,
            chunk = chunk_index,
            expected = %expected_hash,
            actual = %actual_hash,
            "Chunk hash mismatch"
        );
        return error_response(
            "Hash mismatch",
            Some(&session_id),
            chunk_index,
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    }

    info!(
        session_id = %session_id,
        chunk = chunk_index,
        hash = %actual_hash,
        bytes = plaintext.len(),
        "Chunk decrypted and verified"
    );

    // ── Store chunk & check for completion ────────────────────────────────
    let maybe_complete = {
        let mut sessions = state.sessions.lock().unwrap();
        let session = sessions.entry(session_id.clone()).or_default();

        session.total_chunks.get_or_insert(total_chunks);
        session.file_name.get_or_insert(file_name.clone());

        // Ignore duplicate chunk_index
        session.received.entry(chunk_index).or_insert(plaintext);

        let received_count = session.received.len();
        let total = session.total_chunks.unwrap_or(total_chunks);

        if received_count == total && session.file_hash.is_none() {
            // All chunks received – assemble and write
            match assemble_and_write(session, &state.output_dir) {
                Ok(hash) => {
                    session.file_hash = Some(hash.clone());
                    Some((file_name.clone(), hash))
                }
                Err(e) => {
                    error!(session_id = %session_id, error = %e, "File assembly failed");
                    None
                }
            }
        } else {
            None
        }
    };

    if let Some((fname, file_hash)) = maybe_complete {
        info!(
            session_id = %session_id,
            file = %fname,
            hash = %file_hash,
            "✅ File fully assembled and saved"
        );
    }

    // ── Build ACK ─────────────────────────────────────────────────────────
    let padding = random_padding(state.padding_min, state.padding_max);
    let ack = AckResponse {
        status: "ok".into(),
        session_id,
        chunk_index,
        chunk_hash: actual_hash,
        error: None,
        padding: B64.encode(padding),
    };

    (StatusCode::OK, Json(ack)).into_response()
}

// ── Handler: poll completion ──────────────────────────────────────────────────

pub async fn poll_complete(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Response {
    let info_opt = {
        let sessions = state.sessions.lock().unwrap();
        sessions.get(&session_id).and_then(|s| {
            s.file_hash
                .as_ref()
                .zip(s.file_name.as_ref())
                .map(|(h, n)| (h.clone(), n.clone()))
        })
    };

    let padding = random_padding(state.padding_min, state.padding_max);

    if let Some((file_hash, file_name)) = info_opt {
        let resp = CompleteResponse {
            status: "complete".into(),
            session_id,
            file_hash,
            file_name,
            padding: B64.encode(padding),
        };
        (StatusCode::OK, Json(resp)).into_response()
    } else {
        // 202 Accepted – still assembling
        (
            StatusCode::ACCEPTED,
            Json(json!({ "status": "assembling", "session_id": session_id })),
        )
            .into_response()
    }
}

// ── File assembly ─────────────────────────────────────────────────────────────

fn assemble_and_write(
    session: &SessionState,
    output_dir: &PathBuf,
) -> anyhow::Result<String> {
    let total = session.total_chunks.unwrap();
    let mut data = Vec::new();

    for idx in 0..total {
        let chunk = session
            .received
            .get(&idx)
            .ok_or_else(|| anyhow::anyhow!("Missing chunk {}", idx))?;
        data.extend_from_slice(chunk);
    }

    let hash = crypto::sha256_hex(&data);
    let file_name = session.file_name.as_deref().unwrap_or("unknown");

    std::fs::create_dir_all(output_dir)?;
    let dest = output_dir.join(file_name);
    std::fs::write(&dest, &data)?;

    info!(path = %dest.display(), bytes = data.len(), hash = %hash, "File written");
    Ok(hash)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(min..=max);
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf[..]);
    buf
}

fn error_response(
    msg: &str,
    session_id: Option<&str>,
    chunk_index: usize,
    status: StatusCode,
) -> Response {
    let ack = AckResponse {
        status: "error".into(),
        session_id: session_id.unwrap_or("").to_string(),
        chunk_index,
        chunk_hash: String::new(),
        error: Some(msg.to_string()),
        padding: B64.encode(random_padding(20, 200)),
    };
    (status, Json(ack)).into_response()
}
