use rand::{thread_rng, RngCore};
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint32, ServerKey};

/// Production TFHE-rs FHE implementation (CHRONOS v2 Paper).
/// Replaces the Paillier toy prototype with Zama's TFHE-rs for
/// production-grade machine learning inference on encrypted data.

pub struct FheKeyPair {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
    /// A random 32-byte seed representing the entropy of this keypair,
    /// used for the pre-erasure hash commitment.
    secret_seed: [u8; 32],
}

impl FheKeyPair {
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret_seed.to_vec()
    }
}

pub trait FheEngine {
    fn keygen(&self) -> FheKeyPair;
    fn encrypt(&self, key: &FheKeyPair, m: u32) -> FheUint32;
    fn decrypt(&self, key: &FheKeyPair, c: &FheUint32) -> u32;
    fn homomorphic_dot_product(
        &self,
        key: &FheKeyPair,
        encrypted_features: &[FheUint32],
        plaintext_weights: &[u32],
    ) -> FheUint32;
}

pub struct ProductionFhe;

impl FheEngine for ProductionFhe {
    fn keygen(&self) -> FheKeyPair {
        // TFHE-rs configuration (default securely chosen parameters)
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        let mut secret_seed = [0u8; 32];
        thread_rng().fill_bytes(&mut secret_seed);

        FheKeyPair {
            client_key,
            server_key,
            secret_seed,
        }
    }

    fn encrypt(&self, key: &FheKeyPair, m: u32) -> FheUint32 {
        FheUint32::encrypt(m, &key.client_key)
    }

    fn decrypt(&self, key: &FheKeyPair, c: &FheUint32) -> u32 {
        c.decrypt(&key.client_key)
    }

    /// Evaluates a machine learning linear model (dot product) completely under FHE
    fn homomorphic_dot_product(
        &self,
        key: &FheKeyPair,
        encrypted_features: &[FheUint32],
        plaintext_weights: &[u32],
    ) -> FheUint32 {
        // Must set the server key for the current thread to perform homomorphic ops
        set_server_key(key.server_key.clone());

        assert_eq!(encrypted_features.len(), plaintext_weights.len());

        let mut sum = self.encrypt(key, 0);

        for (feature, &weight) in encrypted_features.iter().zip(plaintext_weights.iter()) {
            // TFHE-rs supports scalar multiplication (FheUint * u32)
            let product = feature * weight;
            sum = sum + product;
        }

        sum
    }
}
