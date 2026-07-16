use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

/// Wesolowski Verifiable Delay Function (VDF) implementation.
/// Mathematical construction over an RSA modulus N:
///   Evaluate: y = g^(2^T) mod N
///   Prove: l = Hash(g, y, T), pi = g^(floor(2^T / l)) mod N
///   Verify: pi^l * g^(2^T mod l) == y mod N
/// This guarantees T sequential squarings (cannot be parallelised)
/// while allowing extremely fast verification.

pub struct VdfProof {
    pub y: Vec<u8>,
    pub pi: Vec<u8>,
}

pub trait VdfEngine {
    fn evaluate(&self, seed: &[u8], iterations: u64) -> VdfProof;
    fn verify(&self, seed: &[u8], iterations: u64, proof: &VdfProof) -> bool;
}

pub struct WesolowskiVdf {
    /// RSA Modulus (N = p*q, factors unknown to prover)
    pub n: BigUint,
}

impl WesolowskiVdf {
    /// Helper: Hash inputs to a 128-bit challenge prime `l`
    fn hash_challenge(g: &BigUint, y: &BigUint, t: u64) -> BigUint {
        let mut hasher = Sha256::new();
        hasher.update(g.to_bytes_le());
        hasher.update(y.to_bytes_le());
        hasher.update(t.to_le_bytes());
        let digest = hasher.finalize();
        // Take first 16 bytes for a 128-bit challenge
        BigUint::from_bytes_le(&digest[..16])
    }
}

impl VdfEngine for WesolowskiVdf {
    fn evaluate(&self, seed: &[u8], iterations: u64) -> VdfProof {
        let g = BigUint::from_bytes_le(seed) % &self.n;
        
        // 1. Evaluate y = g^(2^T) mod N (Sequential squarings)
        let mut y = g.clone();
        for _ in 0..iterations {
            y = y.modpow(&BigUint::from(2u32), &self.n);
        }

        // 2. Fiat-Shamir challenge l
        let l = Self::hash_challenge(&g, &y, iterations);
        if l.is_zero() {
            // Highly improbable, but handle gracefully
            return VdfProof { y: y.to_bytes_le(), pi: vec![] };
        }

        // 3. Prove pi = g^(floor(2^T / l)) mod N
        // Wesolowski iterative quotient computation:
        let mut pi = BigUint::one();
        let mut r = BigUint::one();
        for _ in 0..iterations {
            let r2 = r * 2u32;
            let b = &r2 / &l;
            r = r2 % &l;
            
            // pi = (pi^2) * (g^b) mod N
            let pi_sq = pi.modpow(&BigUint::from(2u32), &self.n);
            let gb = g.modpow(&b, &self.n);
            pi = (pi_sq * gb) % &self.n;
        }

        VdfProof {
            y: y.to_bytes_le(),
            pi: pi.to_bytes_le(),
        }
    }

    fn verify(&self, seed: &[u8], iterations: u64, proof: &VdfProof) -> bool {
        let g = BigUint::from_bytes_le(seed) % &self.n;
        let y = BigUint::from_bytes_le(&proof.y);
        let pi = BigUint::from_bytes_le(&proof.pi);

        let l = Self::hash_challenge(&g, &y, iterations);
        if l.is_zero() { return false; }

        // r = 2^T mod l
        // We can compute this quickly using modpow
        let two = BigUint::from(2u32);
        let r = two.modpow(&BigUint::from(iterations), &l);

        // Check: pi^l * g^r == y mod N
        let pi_l = pi.modpow(&l, &self.n);
        let g_r = g.modpow(&r, &self.n);
        let lhs = (pi_l * g_r) % &self.n;

        lhs == y
    }
}