"""
Memory Sanitization Module.
Uses ctypes for physical C-level RAM shredding.
"""

import ctypes
from typing import Any

from logger import get_chronos_logger


class MemorySanitizer:
    """
    Enterprise-grade Memory Sanitizer.
    Bypasses Python's garbage collector by invoking C-level memset to physically wipe RAM buffers.
    """

    @staticmethod
    def zeroize_buffer(buffer: Any) -> None:
        """
        Executes a secure, triple-pass physical memory overwrite on a mutable bytearray.
        """
        logger = get_chronos_logger("MemorySanitizer")

        if not isinstance(buffer, bytearray):
            logger.error("Target buffer must be a mutable bytearray.")
            raise TypeError("Cannot zeroize immutable objects. Pass a bytearray.")

        buffer_len: int = len(buffer)
        buffer_ptr: int = ctypes.addressof(
            (ctypes.c_char * buffer_len).from_buffer(buffer)
        )

        logger.info(
            f"Commencing C-level physical triple-pass overwrite on {buffer_len} bytes at RAM address {buffer_ptr}..."
        )

        # Pass 1: Zeros
        ctypes.memset(buffer_ptr, 0, buffer_len)
        # Pass 2: Ones
        ctypes.memset(buffer_ptr, 255, buffer_len)
        # Pass 3: Zeros again
        ctypes.memset(buffer_ptr, 0, buffer_len)

        logger.info("Physical memory buffer securely zeroized and shredded.")
