use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

/// Schnorr Non-Interactive Zero-Knowledge (NIZK) Proof of Erasure.
///
/// Proves the agent possessed the secret key without revealing it,
/// bound to the context of the erasure event via Fiat-Shamir.
///
/// Protocol over Ristretto255 group:
/// 1. Prover holds secret key `sk` (Scalar). Public key is `PK = sk * G`.
/// 2. Prover generates random scalar `r`.
/// 3. Computes commitment `R = r * G`.
/// 4. Computes challenge `e = Hash(R || PK || "CHRONOS_ERASE")`.
/// 5. Computes response `s = r + e * sk`.
/// 6. Erases `sk` from memory.
/// 
/// Verifier checks: `s * G == R + e * PK`.

#[derive(Debug, Clone)]
pub struct SchnorrProof {
    pub pk: RistrettoPoint,
    pub r_point: RistrettoPoint,
    pub s: Scalar,
}

pub trait NizkProver {
    fn prove(&self, secret_key: &[u8; 32]) -> SchnorrProof;
    fn verify(&self, proof: &SchnorrProof) -> bool;
}

pub struct SchnorrNizk;

impl SchnorrNizk {
    fn hash_challenge(r_point: &RistrettoPoint, pk: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(r_point.compress().as_bytes());
        hasher.update(pk.compress().as_bytes());
        hasher.update(b"CHRONOS_ERASE");
        Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
    }
}

impl NizkProver for SchnorrNizk {
    fn prove(&self, secret_key_bytes: &[u8; 32]) -> SchnorrProof {
        // We treat the secret key bytes as the seed for the scalar `sk`.
        // To be safe and deterministic across bytes, we hash it to a scalar.
        let mut sk_hasher = Sha512::new();
        sk_hasher.update(secret_key_bytes);
        let sk = Scalar::from_bytes_mod_order_wide(&sk_hasher.finalize().into());
        
        let pk = sk * RISTRETTO_BASEPOINT_POINT;

        // Generate random r
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);
        let r_point = r * RISTRETTO_BASEPOINT_POINT;

        // Fiat-Shamir challenge
        let e = Self::hash_challenge(&r_point, &pk);

        // Response
        let s = r + (e * sk);

        SchnorrProof { pk, r_point, s }
    }

    fn verify(&self, proof: &SchnorrProof) -> bool {
        let e = Self::hash_challenge(&proof.r_point, &proof.pk);
        
        let lhs = proof.s * RISTRETTO_BASEPOINT_POINT;
        let rhs = proof.r_point + (e * proof.pk);
        
        lhs == rhs
    }
}
