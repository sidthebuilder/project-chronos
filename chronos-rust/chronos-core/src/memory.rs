pub struct SecureString {
    inner: Vec<u8>,
}

impl SecureString {
    pub fn new(data: Vec<u8>) -> Self {
        #[cfg(all(target_family = "unix", not(miri)))]
        unsafe {
            // Attempt to pin the memory to RAM so it's never paged out to disk swap
            libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
        }

        Self { inner: data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Triple-pass zeroization using write_volatile.
        // write_volatile is mandatory here — without it, LLVM's Dead Store
        // Elimination (DSE) optimization will remove these writes entirely
        // at compile time, leaving the key intact in memory.
        unsafe {
            for byte in self.inner.iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }

            // Additional passes for paranoia (simulating DoD 5220.22-M triple pass)
            for byte in self.inner.iter_mut() {
                core::ptr::write_volatile(byte, 0xFF);
            }
            for byte in self.inner.iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }

            #[cfg(all(target_family = "unix", not(miri)))]
            {
                // Unlock the memory so the OS can reclaim it
                libc::munlock(self.inner.as_ptr() as *const libc::c_void, self.inner.len());
            }

            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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
