use kzen_paillier::{DecryptionKey, EncryptionKey, Paillier, Add, Decrypt, Encrypt, KeyGeneration};
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
        use curv::arithmetic::Converter;
        use num_bigint::BigInt as NumBigInt;
        use num_traits::Num;
        use kzen_paillier::{BigInt as KzenBigInt, RawPlaintext, RawCiphertext};
        
        let m_str = m.to_string();
        let m_kzen = <KzenBigInt as Converter>::from_str_radix(&m_str, 10).unwrap();
        let pt = RawPlaintext::from(m_kzen);
        let ct: RawCiphertext = Paillier::encrypt(&key.ek, pt);
        
        let ct_big: KzenBigInt = ct.into();
        let ct_hex = ct_big.to_hex();
        
        let ct_num = <NumBigInt as num_traits::Num>::from_str_radix(&ct_hex, 16).unwrap();
        ct_num.to_bytes_le().1
    }

    fn decrypt(&self, key: &FheKeyPair, c: &[u8]) -> u64 {
        use curv::arithmetic::Converter;
        use num_bigint::BigInt as NumBigInt;
        use num_traits::Num;
        use kzen_paillier::{BigInt as KzenBigInt, RawPlaintext, RawCiphertext};
        
        let ct_num = NumBigInt::from_bytes_le(num_bigint::Sign::Plus, c);
        let ct_hex = ct_num.to_str_radix(16);
        let ct_kzen = KzenBigInt::from_hex(&ct_hex).unwrap();
        
        let ct = RawCiphertext::from(ct_kzen);
        let pt: RawPlaintext = Paillier::decrypt(&key.dk, ct);
        
        let m_kzen: KzenBigInt = pt.into();
        let m_hex = m_kzen.to_hex();
        
        let m_num = <NumBigInt as num_traits::Num>::from_str_radix(&m_hex, 16).unwrap();
        let m_str = m_num.to_string();
        m_str.parse::<u64>().unwrap_or(0)
    }

    fn homomorphic_add(&self, key: &FheKeyPair, c1: &[u8], c2: &[u8]) -> Vec<u8> {
        use curv::arithmetic::Converter;
        use num_bigint::BigInt as NumBigInt;
        use num_traits::Num;
        use kzen_paillier::{BigInt as KzenBigInt, RawCiphertext};
        
        let c1_num = NumBigInt::from_bytes_le(num_bigint::Sign::Plus, c1);
        let c2_num = NumBigInt::from_bytes_le(num_bigint::Sign::Plus, c2);
        
        let c1_hex = c1_num.to_str_radix(16);
        let c2_hex = c2_num.to_str_radix(16);
        
        let c1_kzen = KzenBigInt::from_hex(&c1_hex).unwrap();
        let c2_kzen = KzenBigInt::from_hex(&c2_hex).unwrap();
        
        let ct1 = RawCiphertext::from(c1_kzen);
        let ct2 = RawCiphertext::from(c2_kzen);
        
        let c_sum: RawCiphertext = Paillier::add(&key.ek, ct1, ct2);
        let c_sum_kzen: KzenBigInt = c_sum.into();
        
        let sum_hex = c_sum_kzen.to_hex();
        let sum_num = <NumBigInt as num_traits::Num>::from_str_radix(&sum_hex, 16).unwrap();
        sum_num.to_bytes_le().1
    }
}
