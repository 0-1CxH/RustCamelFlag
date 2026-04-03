# CamelFlagProtocol (CFP) — Design Document

## Overview

CamelFlagProtocol is a covert, encrypted file-transfer protocol that disguises data
as ordinary HTTP traffic. Files are split into variable-size encrypted chunks, sent
out of order across many parallel threads, and reassembled by the server after
decryption and integrity verification.

---

## Goals

| Goal | Details |
|---|---|
| **Confidentiality** | Every chunk is RSA-2048 / AES-CTR encrypted with a passkey-derived key pair |
| **Integrity** | SHA-256 hash per chunk + whole-file hash |
| **Traffic obfuscation** | HTTP/1.1 requests that look like normal web browsing |
| **Performance** | 64 parallel sender threads with random inter-packet delay |
| **Reliability** | Chunk index tracking, ACK-based progress, final file hash cross-check |

---

## Project Layout

```
CFP/
├── Cargo.toml
├── design.md
└── src/
    ├── main.rs              # CLI entry-point (subcommands: server / client)
    ├── config.rs            # Global defaults & CLI arg structs
    ├── crypto.rs            # Key derivation, RSA, AES-CTR
    ├── protocol.rs          # Wire types (ChunkEnvelope, AckResponse, …)
    ├── chunker.rs           # File → variable-size chunks + chunk_index
    ├── server/
    │   ├── mod.rs
    │   └── handler.rs       # Axum HTTP handler, file reassembly, disk logging
    └── client/
        ├── mod.rs
        └── sender.rs        # Thread pool, shuffle, HTTP dispatch
```

---

## Cryptographic Design

### Key Derivation Strategy

```
passkey (UTF-8 string)
        │
        ▼
PBKDF2-HMAC-SHA-256
  salt  = SHA-256("CamelFlagProtocol-salt-v1")   ← deterministic, no randomness
  iter  = 100_000
  out   = 32 bytes  (symmetric_key K)
        │
        ├──► K used as AES-CTR deterministic seed
        │      nonce = SHA-256("CFP-nonce-v1")[0..16]   ← fixed, deterministic
        │
        └──► K → seed ChaCha20 CSPRNG → RSA-2048 keygen
               (rsa crate accepts a deterministic RNG)
```

Both server and client call the **same** derivation function with the **same**
passkey → they independently arrive at identical RSA key pairs and AES-CTR
parameters.

### Per-Chunk Encryption

Each chunk payload is encrypted using RSA-2048 OAEP (PKCS1_v1_5 OAEP with
SHA-256 label).  Because RSA-2048 with OAEP-SHA256 can encrypt at most
~190 bytes directly, we use a **hybrid** scheme:

```
chunk_bytes  (1 MB – 4 MB)
     │
     ▼
1. Generate random 32-byte AES session key  Ks  (from thread-local OsRng)
2. Encrypt Ks with RSA public key → encrypted_key  (256 bytes)
3. Encrypt chunk_bytes with AES-256-CTR using Ks → ciphertext
4. Wire payload = encrypted_key ‖ ciphertext
```

> Note: The "deterministic RNG" for RSA key-gen is the PBKDF2-derived AES-CTR
> stream; per-chunk AES session keys still use OsRng for forward secrecy.

### Chunk Envelope (JSON over HTTP body)

```jsonc
{
  "version": 1,
  "session_id": "<uuid4>",        // identifies the file transfer session
  "file_name": "report.pdf",
  "total_chunks": 42,
  "chunk_index": 7,               // 0-based
  "chunk_hash": "<hex-sha256>",   // hash of plaintext chunk
  "encrypted_key": "<base64>",    // RSA-encrypted AES session key
  "payload": "<base64>"           // AES-CTR encrypted chunk data
}
```

### ACK Response (JSON)

```jsonc
{
  "status": "ok",                 // or "error"
  "session_id": "<uuid4>",
  "chunk_index": 7,
  "chunk_hash": "<hex-sha256>",   // echoed from envelope for client validation
  "padding": "<base64-random>"    // 20–200 random bytes, client ignores
}
```

### Final Completion Response

After all chunks are reassembled and file is written to disk, the server sends a
special response carrying the whole-file hash:

```jsonc
{
  "status": "complete",
  "session_id": "<uuid4>",
  "file_hash": "<hex-sha256>",
  "file_name": "report.pdf",
  "padding": "<base64-random>"
}
```

---

## HTTP Traffic Obfuscation

Requests are crafted to resemble ordinary browser page loads:

| Header | Strategy |
|---|---|
| `User-Agent` | Rotated list of real browser UA strings |
| `Accept` | `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` |
| `Accept-Language` | `en-US,en;q=0.5` |
| `Accept-Encoding` | `gzip, deflate, br` |
| `Connection` | `keep-alive` |
| `Content-Type` | `application/x-www-form-urlencoded` |
| URL path | Randomly chosen from a set of plausible paths (`/update`, `/api/data`, …) |
| Body | JSON envelope above |

---

## File Chunking

```
file_size = N bytes
chunk_size ~ Uniform(chunk_min, chunk_max)   e.g. [1 MB, 4 MB]

chunks[0]  → bytes [0,               chunk_size_0)
chunks[1]  → bytes [chunk_size_0,    chunk_size_0 + chunk_size_1)
…
```

Chunks are shuffled with a Fisher-Yates shuffle before being handed to the
thread pool.

---

## Sender Thread Pool

```
64 threads  (configurable)
Each thread owns a reqwest::blocking::Client (keep-alive pool)

Thread loop:
  while let Some(envelope) = rx.recv() {
      let delay = Uniform(interval_min, interval_max).sample(&mut rng);
      sleep(delay);
      post(envelope);
  }
```

A `crossbeam_channel` MPSC queue feeds all threads from the main client thread.

---

## Server: File Reassembly

```
State (per session, in Arc<Mutex<SessionState>>):
  received: HashMap<usize, Vec<u8>>   // chunk_index → plaintext bytes
  total_chunks: usize
  file_name: String

On last chunk received:
  1. Sort by chunk_index
  2. Concatenate → file_bytes
  3. Compute SHA-256(file_bytes) = file_hash
  4. Write to <output_dir>/<file_name>
  5. Return "complete" response with file_hash
```

---

## Logging

| Side | Destination | Library |
|---|---|---|
| Server | `logs/server.log` (rolling, append) | `tracing` + `tracing-appender` |
| Client | stdout only | `tracing` (console subscriber) |

---

## Configuration Defaults

| Parameter | Default |
|---|---|
| `listen_addr` | `0.0.0.0:8080` |
| `output_dir` | `./received/` |
| `chunk_min` | 1 MB (1_048_576 bytes) |
| `chunk_max` | 4 MB (4_194_304 bytes) |
| `sender_threads` | 64 |
| `interval_min` | 0.2 s |
| `interval_max` | 0.8 s |
| `response_padding_min` | 20 bytes |
| `response_padding_max` | 200 bytes |
| `pbkdf2_iterations` | 100_000 |

---

## Data-Flow Diagram

```
CLIENT                                         SERVER
──────                                         ──────
read_file()
  │
  ├─ chunk() → [C0, C1, … Cn]
  │
  ├─ for each Ci:
  │     derive_keys(passkey) → (rsa_pub, aes_key)
  │     gen_session_key() → Ks
  │     encrypted_key = rsa_pub.encrypt(Ks)
  │     ciphertext    = aes_ctr(Ks, Ci)
  │     envelope      = ChunkEnvelope { … }
  │
  ├─ shuffle(envelopes)
  │
  ├─ enqueue → channel ──────────────────────────►
  │                                               recv envelope
  │                                               rsa_priv.decrypt(encrypted_key) → Ks
  │                                               aes_ctr(Ks, ciphertext) → plaintext
  │                                               verify chunk_hash
  │                                               store chunk
  │                                               ◄── HTTP 200 AckResponse
  │
  ├─ verify ack.chunk_hash == sent chunk_hash
  ├─ update progress
  │
  │   (last chunk received)
  │                                               assemble_file()
  │                                               write to disk
  │                                               ◄── HTTP 200 { status:"complete", file_hash }
  └─ verify file_hash == local SHA-256(original)
     print "Transfer complete ✓"
```

---

## Security Considerations

1. **Replay protection**: `session_id` (UUIDv4) ties all chunks to one transfer.
   Duplicate `chunk_index` within a session is silently ignored by the server.
2. **No persistent secret storage**: Keys are derived on startup from the
   passkey and never written to disk.
3. **Padding oracle**: OAEP mode is selected specifically to prevent padding
   oracle attacks against RSA (vs PKCS#1 v1.5).
4. **Thread safety**: All shared server state is wrapped in `Arc<Mutex<_>>`.

---

## Crate Dependencies

```toml
[dependencies]
# Async runtime
tokio          = { version = "1", features = ["full"] }
# HTTP server
axum           = "0.7"
# HTTP client
reqwest        = { version = "0.12", features = ["blocking", "json"] }
# Crypto
rsa            = { version = "0.9", features = ["sha2"] }
sha2           = "0.10"
aes            = "0.8"
ctr            = "0.9"
pbkdf2         = { version = "0.12", features = ["hmac"] }
hmac           = "0.12"
rand           = "0.8"
rand_chacha    = "0.3"
# Serialization
serde          = { version = "1", features = ["derive"] }
serde_json     = "1"
base64         = "0.22"
hex            = "0.4"
# UUID
uuid           = { version = "1", features = ["v4"] }
# CLI
clap           = { version = "4", features = ["derive"] }
# Logging
tracing        = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-appender   = "0.2"
# Channels
crossbeam-channel  = "0.5"
# Misc
anyhow         = "1"
```
