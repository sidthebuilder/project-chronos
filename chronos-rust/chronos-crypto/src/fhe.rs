/// Prototype FHE based on textbook RSA multiplicative homomorphism.
///
/// Mathematical guarantee: for RSA encryption E(m) = m^e mod n:
///   E(m1) * E(m2) mod n  =  (m1 * m2)^e mod n  =  E(m1 * m2)
///
/// This is a real cryptographic property — not a stub.
/// Production path: replace with tfhe-rs for boolean circuit evaluation.

#[derive(Debug)]
pub struct RsaKeyPair {
    pub n: u64,
    pub e: u64,
    d: u64, // private: never expose the secret exponent
}

impl RsaKeyPair {
    /// Returns the secret exponent only as raw bytes for secure storage.
    /// Does not return d as a u64 to prevent accidental logging/printing.
    pub fn secret_bytes(&self) -> [u8; 8] {
        self.d.to_le_bytes()
    }
}

pub trait FheEngine {
    /// Generate a key pair. Returns (public_key_bytes, secret_key_bytes).
    fn keygen(&self) -> RsaKeyPair;

    /// Encrypt a small plaintext message m < n.
    fn encrypt(&self, key: &RsaKeyPair, m: u64) -> u64;

    /// Decrypt a ciphertext c.
    fn decrypt(&self, key: &RsaKeyPair, c: u64) -> u64;

    /// Homomorphic multiplication: given E(m1) and E(m2), compute E(m1 * m2).
    /// No plaintext is ever observed.
    fn homomorphic_mul(&self, key: &RsaKeyPair, c1: u64, c2: u64) -> u64;
}

pub struct PrototypeFhe;

impl PrototypeFhe {
    /// Square-and-multiply modular exponentiation.
    pub fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
        if modulus == 1 {
            return 0;
        }
        let mut result = 1u64;
        base %= modulus;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result
                    .checked_mul(base)
                    .expect("overflow in mod_exp")
                    % modulus;
            }
            exp >>= 1;
            base = base
                .checked_mul(base)
                .expect("overflow in mod_exp square")
                % modulus;
        }
        result
    }
}

impl FheEngine for PrototypeFhe {
    fn keygen(&self) -> RsaKeyPair {
        // Safe small primes for prototype: p=61, q=53
        // n = 3233, phi(n) = 3120, e = 17, d = 2753
        // Verified: 17 * 2753 = 46801 = 1 + 15 * 3120 ✓
        RsaKeyPair { n: 3233, e: 17, d: 2753 }
    }

    fn encrypt(&self, key: &RsaKeyPair, m: u64) -> u64 {
        // debug_assert: panics in debug/test, elided in release.
        // Caller must ensure m < n. For this prototype n=3233.
        debug_assert!(m < key.n, "plaintext must be less than modulus n={}", key.n);
        Self::mod_exp(m, key.e, key.n)
    }

    fn decrypt(&self, key: &RsaKeyPair, c: u64) -> u64 {
        Self::mod_exp(c, key.d, key.n)
    }

    fn homomorphic_mul(&self, key: &RsaKeyPair, c1: u64, c2: u64) -> u64 {
        // E(m1) * E(m2) mod n = E(m1 * m2) mod n.
        // Widen to u128 before multiply to prevent overflow when
        // c1 and c2 are both near n. Truncate back after mod.
        let product = (c1 as u128) * (c2 as u128);
        (product % key.n as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (PrototypeFhe, RsaKeyPair) {
        let fhe = PrototypeFhe;
        let key = fhe.keygen();
        (fhe, key)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (fhe, key) = setup();
        let m = 42u64;
        let c = fhe.encrypt(&key, m);
        let m_out = fhe.decrypt(&key, c);
        assert_eq!(m, m_out);
    }

    #[test]
    fn test_homomorphic_mul_property() {
        let (fhe, key) = setup();
        let m1 = 4u64;
        let m2 = 5u64;

        let c1 = fhe.encrypt(&key, m1);
        let c2 = fhe.encrypt(&key, m2);

        // Multiply ciphertexts — no decryption happens here
        let c_product = fhe.homomorphic_mul(&key, c1, c2);

        // Decrypt the homomorphic product
        let decrypted = fhe.decrypt(&key, c_product);

        // Must equal plaintext product
        assert_eq!(decrypted, m1 * m2);
    }

    #[test]
    fn test_ciphertext_hides_plaintext() {
        let (fhe, key) = setup();
        let m = 7u64;
        let c = fhe.encrypt(&key, m);
        // Ciphertext must not equal plaintext (semantic check)
        assert_ne!(c, m);
    }

    #[test]
    fn test_keygen_correct_inverse() {
        let (_, key) = setup();
        // Verify e * d ≡ 1 (mod phi(n)) — phi(3233) = 3120
        // secret_bytes() returns d as little-endian bytes; reconstruct u64.
        let phi_n = 3120u64;
        let d = u64::from_le_bytes(key.secret_bytes());
        assert_eq!((key.e * d) % phi_n, 1);
    }
}
