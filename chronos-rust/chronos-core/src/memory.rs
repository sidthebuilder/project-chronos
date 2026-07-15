pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new(data: Vec<u8>) -> Self {
        // Production: call libc::mlock() here to pin memory pages to RAM.
        // This prevents the OS from swapping the key to disk.
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Triple-pass zeroization using write_volatile.
        // write_volatile is mandatory here — without it, LLVM's Dead Store
        // Elimination (DSE) optimization will remove these writes entirely
        // at compile time, leaving the key intact in memory.
        unsafe {
            for byte in self.data.iter_mut() {
                std::ptr::write_volatile(byte, 0x00);
            }
            for byte in self.data.iter_mut() {
                std::ptr::write_volatile(byte, 0xFF);
            }
            for byte in self.data.iter_mut() {
                std::ptr::write_volatile(byte, 0x00);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_stores_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let s = SecureString::new(data.clone());
        assert_eq!(s.as_bytes(), data.as_slice());
    }

    #[test]
    fn test_secure_string_len() {
        let s = SecureString::new(vec![1u8; 64]);
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_secure_string_drops_without_panic() {
        // Verifies the Drop impl does not panic or segfault.
        let s = SecureString::new(vec![0xAB; 128]);
        drop(s); // explicit drop
    }
}
