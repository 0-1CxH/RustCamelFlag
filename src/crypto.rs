//! Cryptographic primitives for CamelFlagProtocol.
//!
//! Key-derivation strategy (fully deterministic from passkey):
//!
//!  passkey
//!    │
//!    ▼
//!  PBKDF2-HMAC-SHA256(salt = SHA256("CamelFlagProtocol-salt-v1"), iter = 100_000)
//!    │
//!    └─► 32-byte symmetric seed K
//!             │
//!             ├─► seed ChaCha20Rng → RSA-2048 key-pair derivation
//!             └─► AES-256-CTR key (nonce = SHA256("CFP-nonce-v1")[0..16])
//!
//! Per-chunk encryption uses a *hybrid* scheme:
//!   1. Generate a fresh 32-byte AES session key  Ks  via OsRng
//!   2. Encrypt Ks with the RSA-2048 public key (OAEP / SHA-256)
//!   3. Encrypt the chunk plaintext with AES-256-CTR keyed by Ks
//!
//! Result on the wire: encrypted_key (256 bytes, base64) || payload (base64)

use aes::Aes256;
use anyhow::{Context, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use rsa::{
    Oaep,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

// ── Exported key-pair bundle ──────────────────────────────────────────────────

pub struct CfpKeys {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Deterministically derive an RSA-2048 key pair and a 32-byte AES key from
/// `passkey`.  Both server and client call this with the same passkey and
/// obtain identical results.
pub fn derive_keys(passkey: &str) -> Result<CfpKeys> {
    // ── Step 1: PBKDF2 → 32-byte seed ────────────────────────────────────
    let salt_preimage = b"CamelFlagProtocol-salt-v1";
    let salt: [u8; 32] = Sha256::digest(salt_preimage).into();

    let mut seed = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        passkey.as_bytes(),
        &salt,
        crate::config::PBKDF2_ITERATIONS,
        &mut seed,
    )
    .context("PBKDF2 derivation failed")?;

    // ── Step 2: seed ChaCha20 → RSA-2048 key generation ──────────────────
    let mut chacha_rng = ChaCha20Rng::from_seed(seed);
    let private_key = RsaPrivateKey::new(&mut chacha_rng, 2048)
        .context("RSA key generation failed")?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok(CfpKeys {
        public_key,
        private_key,
    })
}

// ── Per-chunk encrypt / decrypt ───────────────────────────────────────────────

/// Encrypt `plaintext` using the hybrid RSA+AES scheme.
///
/// Returns `(encrypted_key_bytes, ciphertext_bytes)` where
/// `encrypted_key_bytes` is 256 bytes (RSA-2048 output).
pub fn encrypt_chunk(public_key: &RsaPublicKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // 1. Fresh 32-byte AES session key
    let mut ks = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ks);

    // 2. Encrypt Ks with RSA OAEP
    let padding = Oaep::new::<Sha256>();
    let encrypted_key = public_key
        .encrypt(&mut rand::thread_rng(), padding, &ks)
        .context("RSA encrypt failed")?;

    // 3. AES-256-CTR: nonce = SHA-256("CFP-chunk-nonce")[0..16]
    let nonce_full = Sha256::digest(b"CFP-chunk-nonce");
    let nonce: [u8; 16] = nonce_full[..16].try_into().unwrap();

    let mut cipher = Aes256Ctr::new(&ks.into(), &nonce.into());
    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    Ok((encrypted_key, ciphertext))
}

/// Decrypt a chunk that was encrypted with `encrypt_chunk`.
pub fn decrypt_chunk(
    private_key: &RsaPrivateKey,
    encrypted_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    // 1. Recover Ks
    let padding = Oaep::new::<Sha256>();
    let ks = private_key
        .decrypt(padding, encrypted_key)
        .context("RSA decrypt failed")?;

    if ks.len() != 32 {
        anyhow::bail!("Unexpected session key length: {}", ks.len());
    }

    // 2. AES-256-CTR decrypt (same nonce as encryption)
    let nonce_full = Sha256::digest(b"CFP-chunk-nonce");
    let nonce: [u8; 16] = nonce_full[..16].try_into().unwrap();
    let ks_arr: [u8; 32] = ks.try_into().unwrap();

    let mut cipher = Aes256Ctr::new(&ks_arr.into(), &nonce.into());
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

// ── Hash helpers ──────────────────────────────────────────────────────────────

/// SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}
