//! File-to-chunk splitting and chunk metadata.

use anyhow::Result;
use rand::Rng;

// ── Chunk ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Chunk {
    /// Zero-based position of this chunk in the original file
    pub index: usize,
    /// Total number of chunks
    pub total: usize,
    /// Original file name (basename only)
    pub file_name: String,
    /// Plaintext bytes
    pub data: Vec<u8>,
}

// ── Splitter ──────────────────────────────────────────────────────────────────

/// Split `file_bytes` into variable-size chunks in the range
/// `[chunk_min, chunk_max]` bytes chosen uniformly at random.
///
/// Returns chunks in *original order* (0, 1, 2, …).
/// The caller is responsible for shuffling before transmission.
pub fn split(
    file_bytes: &[u8],
    file_name: &str,
    chunk_min: u64,
    chunk_max: u64,
) -> Result<Vec<Chunk>> {
    if chunk_min == 0 || chunk_min > chunk_max {
        anyhow::bail!(
            "Invalid chunk range: chunk_min={} chunk_max={}",
            chunk_min,
            chunk_max
        );
    }

    let mut rng = rand::thread_rng();
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut offset = 0usize;
    let total_bytes = file_bytes.len();

    // First pass: collect all raw data slices
    let mut raw_slices: Vec<Vec<u8>> = Vec::new();
    while offset < total_bytes {
        let remaining = (total_bytes - offset) as u64;
        let size = if remaining <= chunk_min {
            remaining
        } else {
            rng.gen_range(chunk_min..=chunk_max.min(remaining))
        };
        let size = size as usize;
        raw_slices.push(file_bytes[offset..offset + size].to_vec());
        offset += size;
    }

    let total = raw_slices.len();
    for (index, data) in raw_slices.into_iter().enumerate() {
        chunks.push(Chunk {
            index,
            total,
            file_name: file_name.to_string(),
            data,
        });
    }

    Ok(chunks)
}
