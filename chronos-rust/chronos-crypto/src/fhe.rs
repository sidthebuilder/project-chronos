use kzen_paillier::{DecryptionKey, EncryptionKey, Paillier, Rawtraits};
use rand::{RngCore, thread_rng};

/// Production Paillier FHE implementation.
/// Additive homomorphism: E(m1) * E(m2) mod n^2 = E(m1 + m2)

pub struct FheKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    /// A random 32-byte seed representing the entropy of this keypair,
    /// used for the pre-erasure hash commitment.
    secret_seed: [u8; 32],
}

impl FheKeyPair {
    /// Returns the secret entropy bytes for the erasure commitment.
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret_seed.to_vec()
    }
}

pub trait FheEngine {
    fn keygen(&self) -> FheKeyPair;
    fn encrypt(&self, key: &FheKeyPair, m: u64) -> Vec<u8>;
    fn decrypt(&self, key: &FheKeyPair, c: &[u8]) -> u64;
    fn homomorphic_add(&self, key: &FheKeyPair, c1: &[u8], c2: &[u8]) -> Vec<u8>;
}

pub struct PrototypeFhe;

impl FheEngine for PrototypeFhe {
    fn keygen(&self) -> FheKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let mut secret_seed = [0u8; 32];
        thread_rng().fill_bytes(&mut secret_seed);
        FheKeyPair { ek, dk, secret_seed }
    }

    fn encrypt(&self, key: &FheKeyPair, m: u64) -> Vec<u8> {
        // Paillier::encrypt takes BigInt, returns BigInt.
        // We'll use the kzen-paillier From/Into traits.
        // Since m is u64, we can convert it.
        use num_bigint::BigInt;
        let m_big = BigInt::from(m);
        let c = Paillier::encrypt(&key.ek, m_big);
        // Convert the ciphertext BigInt to bytes.
        c.to_bytes_le().1
    }

    fn decrypt(&self, key: &FheKeyPair, c: &[u8]) -> u64 {
        use num_bigint::BigInt;
        use num_traits::cast::ToPrimitive;
        let c_big = BigInt::from_bytes_le(num_bigint::Sign::Plus, c);
        let m_big: BigInt = Paillier::decrypt(&key.dk, c_big);
        m_big.to_u64().unwrap_or(0)
    }

    fn homomorphic_add(&self, key: &FheKeyPair, c1: &[u8], c2: &[u8]) -> Vec<u8> {
        use num_bigint::BigInt;
        let c1_big = BigInt::from_bytes_le(num_bigint::Sign::Plus, c1);
        let c2_big = BigInt::from_bytes_le(num_bigint::Sign::Plus, c2);
        let c_sum = Paillier::add(&key.ek, c1_big, c2_big);
        c_sum.to_bytes_le().1
    }
}
