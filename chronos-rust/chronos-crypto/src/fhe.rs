pub trait FheEngine {
    fn keygen(&self) -> (Vec<u8>, Vec<u8>);
    fn evaluate(&self, ciphertext: &[u8]) -> Vec<u8>;
}

/// A mathematical Prototype FHE based on unpadded textbook RSA.
/// Unpadded RSA is multiplicatively homomorphic: E(m1) * E(m2) = E(m1 * m2).
/// This replaces the DummyFhe with a real cryptographic mathematical property.
pub struct PrototypeFhe {
    pub n: u64,
    pub e: u64,
}

impl PrototypeFhe {
    pub fn new() -> Self {
        // Prototype small primes for demonstration: p = 61, q = 53
        // n = 3233, phi = 3120, e = 17, d = 2753
        Self {
            n: 3233,
            e: 17,
        }
    }

    /// Helper for modular exponentiation
    fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
        if modulus == 1 { return 0; }
        let mut result = 1;
        base = base % modulus;
        while exp > 0 {
            if exp % 2 == 1 {
                result = (result * base) % modulus;
            }
            exp = exp >> 1;
            base = (base * base) % modulus;
        }
        result
    }
}

impl FheEngine for PrototypeFhe {
    fn keygen(&self) -> (Vec<u8>, Vec<u8>) {
        // Public key (n, e), Secret key (n, d)
        // d = 2753
        let pk = vec![17, 0, 0, 0]; // stub byte rep
        let sk = vec![193, 10, 0, 0]; // 2753 in bytes
        (pk, sk)
    }

    fn evaluate(&self, ciphertext: &[u8]) -> Vec<u8> {
        // Homomorphic Evaluation: f(x) = x^2
        // Since E(m) = m^e mod n, E(m) * E(m) mod n = (m^2)^e mod n = E(m^2)
        // We take a small u64 ciphertext, square it modulo n.
        
        let mut c_val = 0u64;
        for (i, &b) in ciphertext.iter().enumerate().take(8) {
            c_val |= (b as u64) << (i * 8);
        }
        
        let homomorphic_result = (c_val * c_val) % self.n;
        
        homomorphic_result.to_le_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homomorphic_property() {
        let fhe = PrototypeFhe::new();
        // m = 4, E(4) = 4^17 mod 3233 = 1111
        let m = 4u64;
        let c = PrototypeFhe::mod_exp(m, fhe.e, fhe.n);
        assert_eq!(c, 1111);

        // Evaluate f(x) = x^2 over ciphertext
        let c_bytes = c.to_le_bytes().to_vec();
        let eval_bytes = fhe.evaluate(&c_bytes);
        
        let mut eval_val = 0u64;
        for (i, &b) in eval_bytes.iter().enumerate().take(8) {
            eval_val |= (b as u64) << (i * 8);
        }

        // Decrypt the evaluated ciphertext: eval_val^d mod n
        let d = 2753;
        let decrypted = PrototypeFhe::mod_exp(eval_val, d, fhe.n);
        
        // The decrypted result should be 4^2 = 16
        assert_eq!(decrypted, 16);
    }
}
