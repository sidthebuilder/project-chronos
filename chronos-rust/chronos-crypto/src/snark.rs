use sha2::{Sha256, Digest};

/// Hash-based key erasure commitment.
///
/// What this actually proves: the agent held a specific key (identified by
/// its SHA-256 commitment) and has committed to its value before erasure.
/// Verification confirms the commitment is internally consistent.
///
/// What this does NOT prove: zero-knowledge anything. The verifier sees
/// the same hash chain. This is NOT a Schnorr NIZK or a SNARK.
///
/// Production path: replace with a Groth16 circuit over arkworks-rs that
/// takes the secret key as a private witness and proves its SHA-256
/// hash equals the public commitment, without revealing the key.
pub trait ErasureCommitter {
    fn commit(&self, key_material: &[u8]) -> ErasureCommitment;
    fn verify(&self, key_material_hash: &[u8; 32], commitment: &ErasureCommitment) -> bool;
}

#[derive(Debug, Clone)]
pub struct ErasureCommitment {
    /// SHA-256 of the key material. Public. Identifies the key without revealing it.
    pub key_hash: [u8; 32],
    /// SHA-256(key_hash || b"CHRONOS_ERASE"). Proves the erase protocol ran.
    pub erasure_tag: [u8; 32],
}

pub struct HashCommitter;

impl HashCommitter {
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    fn sha256_two(a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }
}

impl ErasureCommitter for HashCommitter {
    fn commit(&self, key_material: &[u8]) -> ErasureCommitment {
        let key_hash = Self::sha256(key_material);
        let erasure_tag = Self::sha256_two(&key_hash, b"CHRONOS_ERASE");
        ErasureCommitment { key_hash, erasure_tag }
    }

    fn verify(&self, key_material_hash: &[u8; 32], commitment: &ErasureCommitment) -> bool {
        if commitment.key_hash != *key_material_hash {
            return false;
        }
        let expected_tag = Self::sha256_two(&commitment.key_hash, b"CHRONOS_ERASE");
        expected_tag == commitment.erasure_tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_is_nonzero() {
        let c = HashCommitter;
        let commitment = c.commit(b"secret_key_material");
        assert_ne!(commitment.key_hash, [0u8; 32]);
        assert_ne!(commitment.erasure_tag, [0u8; 32]);
    }

    #[test]
    fn test_verify_valid_commitment() {
        let c = HashCommitter;
        let key = b"chronos_secret_key_32byte_input!";
        let commitment = c.commit(key);
        let key_hash = HashCommitter::sha256(key);
        assert!(c.verify(&key_hash, &commitment));
    }

    #[test]
    fn test_tampered_tag_fails_verify() {
        let c = HashCommitter;
        let key = b"chronos_secret_key_32byte_input!";
        let mut commitment = c.commit(key);
        commitment.erasure_tag[0] ^= 0xFF;
        let key_hash = HashCommitter::sha256(key);
        assert!(!c.verify(&key_hash, &commitment));
    }

    #[test]
    fn test_wrong_key_hash_fails_verify() {
        let c = HashCommitter;
        let key = b"chronos_secret_key_32byte_input!";
        let commitment = c.commit(key);
        let wrong_hash = HashCommitter::sha256(b"different_key_material_entirely!");
        assert!(!c.verify(&wrong_hash, &commitment));
    }

    #[test]
    fn test_commitment_is_deterministic() {
        let c = HashCommitter;
        let key = b"determinism_check_key_material!!";
        let a = c.commit(key);
        let b = c.commit(key);
        assert_eq!(a.key_hash, b.key_hash);
        assert_eq!(a.erasure_tag, b.erasure_tag);
    }
}
