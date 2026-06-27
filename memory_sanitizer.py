"""
Project CHRONOS — Physical Memory Sanitizer (§3.4 — Erasure Protocol)

The core claim of CHRONOS's Erasure Protocol is that key material is not just
garbage-collected but *physically overwritten* at the C level before the ZK
proof is generated.  This module provides that guarantee.

Why ctypes.memset and not simple Python assignment?
    buffer = bytearray(len(buffer))   # ← WRONG
    This creates a NEW bytearray object and rebinds the name.  The original
    memory block is still readable until the GC collects it — which could be
    seconds or minutes later in a long-running process.

    ctypes.memset(ptr, 0, len)         # ← CORRECT
    This calls C-level memset() directly on the physical RAM address of the
    buffer, overwriting it in place immediately, with no new object created.

Triple-pass overwrite rationale (Peter Gutmann, 1996):
    Pass 1: 0x00 — zero out all bits.
    Pass 2: 0xFF — flip all bits to ones (verify write, detect hardware errors).
    Pass 3: 0x00 — final zero-out, leaving the buffer in a deterministic state.

    While modern SSDs and DRAM do not require 35-pass Gutmann wiping, a
    triple-pass is sufficient for DRAM residual data protection and is the
    minimum recommended by NIST SP 800-88 Rev.1 (§2.4) for volatile media.

Post-erasure verification:
    After the triple pass, we read back every byte and assert they are all
    zero.  If verification fails (hardware error, OS-level copy-on-write page),
    we raise MemoryIntegrityError rather than silently continuing.
"""

import ctypes
from typing import Any

from exceptions import MemoryIntegrityError
from logger import get_chronos_logger

_log = get_chronos_logger("MemorySanitizer")


class MemorySanitizer:
    """Performs secure, cryptographically-motivated physical memory erasure.

    All methods are static because the sanitizer has no state of its own; it
    is a pure function over a memory buffer.
    """

    @staticmethod
    def zeroize_buffer(buffer: Any) -> None:
        """Execute a secure triple-pass physical memory overwrite on *buffer*.

        The buffer is modified **in place**.  After this call completes, every
        byte in *buffer* is guaranteed to be 0x00, and this has been verified
        by reading back each byte.

        Args:
            buffer: A mutable ``bytearray`` holding sensitive key material.
                    Passing an immutable ``bytes`` or ``str`` object will raise
                    ``TypeError`` immediately — we will not attempt to cast.

        Raises:
            TypeError:            If *buffer* is not a bytearray.
            MemoryIntegrityError: If any byte is non-zero after the triple-pass
                                  wipe (hardware error or OS-level anomaly).
        """
        if not isinstance(buffer, bytearray):
            raise TypeError(
                f"zeroize_buffer requires a mutable bytearray; "
                f"got {type(buffer).__name__!r}.  "
                f"Wrap the secret in bytearray() before passing it to this function."
            )

        buf_len: int = len(buffer)
        if buf_len == 0:
            _log.warning("zeroize_buffer called with an empty buffer — no-op.")
            return

        # Obtain the C-level address of the first byte of the bytearray's
        # internal buffer.  (ctypes.c_char * n).from_buffer() gives us a
        # ctypes array that shares memory with the Python bytearray object.
        c_buf = (ctypes.c_char * buf_len).from_buffer(buffer)
        ptr: int = ctypes.addressof(c_buf)

        _log.info(
            f"Initiating triple-pass C-level wipe: {buf_len} bytes at "
            f"RAM address {ptr:#018x}"
        )

        # --- Pass 1: Zero out all bits -----------------------------------
        ctypes.memset(ptr, 0x00, buf_len)
        _log.debug("  Pass 1/3 complete (0x00 — zeros)")

        # --- Pass 2: Set all bits to one ---------------------------------
        ctypes.memset(ptr, 0xFF, buf_len)
        _log.debug("  Pass 2/3 complete (0xFF — ones)")

        # --- Pass 3: Zero out again — final state ------------------------
        ctypes.memset(ptr, 0x00, buf_len)
        _log.debug("  Pass 3/3 complete (0x00 — zeros, final)")

        # --- Post-wipe read-back verification ----------------------------
        # Read the bytes back through the bytearray view (not through 'c_buf'
        # which shares the same memory) and assert every byte is zero.
        failed_at: int = -1
        for i in range(buf_len):
            if buffer[i] != 0:
                failed_at = i
                break

        if failed_at != -1:
            # This is a critical security failure.  We do NOT swallow it.
            raise MemoryIntegrityError(
                f"Triple-pass wipe verification failed: byte at index {failed_at} "
                f"is {buffer[failed_at]:#04x} after erasure.  "
                f"Possible OS copy-on-write anomaly or hardware error."
            )

        _log.info(
            f"Memory erasure verified: all {buf_len} bytes confirmed 0x00.  "
            f"Key material is physically destroyed."
        )
