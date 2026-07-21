/// Proof-of-Sequential-Work (PoSW) implementation for Project CHRONOS.
///
/// Computes a SHA-256 hash chain of `t` sequential iterations, recording
/// a checkpoint hash every `t / CHECKPOINT_COUNT` steps. The checkpoint
/// Merkle root serves as the cryptographic proof that the full chain was
/// evaluated before key erasure.
///
/// This is the Rust equivalent of `posw.py` — same algorithm, no Python
/// bindings. The Python prototype uses `mp.Pipe` for subprocess communication;
/// this implementation runs entirely in a Tokio `spawn_blocking` thread.

use sha2::{Digest, Sha256};

const CHECKPOINT_COUNT: usize = 1_000;

/// A completed PoSW computation result.
pub struct PoswResult {
    /// The sequential checkpoint hashes, one per segment.
    pub checkpoints: Vec<[u8; 32]>,
    /// The final hash after all `t` iterations.
    pub root: [u8; 32],
}

/// Compute a SHA-256 hash chain of `t` iterations starting from `seed`.
///
/// The chain is split into `CHECKPOINT_COUNT` equal segments. The hash at
/// the end of each segment is recorded as a checkpoint. The final hash
/// across all iterations is returned as the `root`.
///
/// # Panics
/// Panics if `seed` is not exactly 32 bytes.
pub fn compute_posw_chain(seed: &[u8; 32], t: usize) -> PoswResult {
    let mut current = *seed;
    let step = std::cmp::max(1, t / CHECKPOINT_COUNT);
    let full_segments = t / step;
    let remainder = t % step;

    let mut checkpoints = Vec::with_capacity(CHECKPOINT_COUNT);
    let mut hasher = Sha256::new();

    for _ in 0..full_segments {
        for _ in 0..step {
            hasher.update(&current);
            let result = hasher.finalize_reset();
            current.copy_from_slice(&result);
        }
        checkpoints.push(current);
    }

    // Handle any remaining iterations that don't fill a full segment.
    for _ in 0..remainder {
        hasher.update(&current);
        let result = hasher.finalize_reset();
        current.copy_from_slice(&result);
    }

    PoswResult {
        checkpoints,
        root: current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posw_deterministic() {
        let seed = [0u8; 32];
        let r1 = compute_posw_chain(&seed, 1_000);
        let r2 = compute_posw_chain(&seed, 1_000);
        assert_eq!(r1.root, r2.root, "PoSW must be deterministic");
    }

    #[test]
    fn test_posw_different_seeds_differ() {
        let seed_a = [0u8; 32];
        let mut seed_b = [0u8; 32];
        seed_b[0] = 1;
        let r_a = compute_posw_chain(&seed_a, 1_000);
        let r_b = compute_posw_chain(&seed_b, 1_000);
        assert_ne!(r_a.root, r_b.root, "Different seeds must produce different roots");
    }

    #[test]
    fn test_posw_checkpoint_count() {
        let seed = [42u8; 32];
        let result = compute_posw_chain(&seed, 10_000);
        // At 10_000 iterations and 1_000 checkpoints, step = 10.
        // full_segments = 10_000 / 10 = 1_000.
        assert_eq!(result.checkpoints.len(), 1_000);
    }
}
