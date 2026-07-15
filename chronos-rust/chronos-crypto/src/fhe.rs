pub trait FheEngine {
    fn keygen(&self) -> (Vec<u8>, Vec<u8>);
    fn evaluate(&self, ciphertext: &[u8]) -> Vec<u8>;
}

pub struct DummyFhe;

impl FheEngine for DummyFhe {
    fn keygen(&self) -> (Vec<u8>, Vec<u8>) {
        (vec![1, 2, 3], vec![4, 5, 6])
    }

    fn evaluate(&self, ciphertext: &[u8]) -> Vec<u8> {
        ciphertext.to_vec()
    }
}
