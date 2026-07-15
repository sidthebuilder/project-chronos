pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new(data: Vec<u8>) -> Self {
        // In a real production system, this is where we would call libc::mlock
        // to pin the memory to RAM and prevent OS paging.
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zeroize memory on drop (triple pass)
        // Use write_volatile to prevent LLVM Dead Store Elimination (DSE)
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
        println!("[MEMORY SANITIZER] SecureString zeroized.");
    }
}
