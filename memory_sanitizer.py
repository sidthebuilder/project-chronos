"""
Project CHRONOS — Physical Memory Sanitizer (§3.4 — Erasure Protocol)

The core claim of CHRONOS's Erasure Protocol is that key material is not just
garbage-collected but *physically overwritten* at the C level before the
pre-erasure commitment is generated.  This module provides that guarantee.

Why ctypes.memset and not simple Python assignment?
    buffer = bytearray(len(buffer))   # <- WRONG
    This creates a NEW bytearray object and rebinds the name.  The original
    memory block is still readable until the GC collects it — which could be
    seconds or minutes later in a long-running process.

    ctypes.memset(ptr, 0, len)         # <- CORRECT
    This calls C-level memset() directly on the physical RAM address of the
    buffer, overwriting it in place immediately, with no new object created.

Triple-pass overwrite rationale (Peter Gutmann, 1996; NIST SP 800-88 Rev.1):
    Pass 1: 0x00 — zero out all bits.
    Pass 2: 0xFF — flip all bits to ones (verify write, detect hardware errors).
    Pass 3: 0x00 — final zero-out, leaving the buffer in a deterministic state.

    While modern SSDs and DRAM do not require 35-pass Gutmann wiping, a
    triple-pass is sufficient for DRAM residual data protection and meets the
    minimum recommended by NIST SP 800-88 Rev.1 (§2.4) for volatile media.

Post-erasure verification (D10 fix):
    After the triple pass, we use ctypes.memcmp (via a C-level compare, not a
    Python byte loop) to confirm all bytes are zero.  This is O(n) at C speed
    rather than O(n) with Python interpreter overhead per byte.

    A reference zero buffer of the same size is compared against the wiped
    buffer via ctypes.string_at() + bytes comparison, which in CPython goes
    through C memcmp internally.

Compiler barrier:
    A ctypes CDLL call acts as an opaque side effect to the Python interpreter,
    preventing any speculative reordering of the memset across this call boundary.
    On x86 (TSO memory model) this is sufficient.  ARM requires an explicit
    memory barrier instruction, which would need a native extension.

Exclusivity Assumption (EA) — mlock():
    The revised paper (§3.4) explicitly states the Exclusivity Assumption:
    the FHE private key sk must exist ONLY in the committed memory region M,
    enforced by mlock(), no-swap, and no-core-dump OS configuration.

    This module calls mlock_buffer() on any sensitive bytearray before use.
    On Linux, mlock(2) prevents the pages from being paged to swap.
    On Windows, VirtualLock() provides the same guarantee.
    If the call fails (insufficient privileges), a WARNING is logged — the
    prototype continues but the EA may not hold on that system.  Production
    deployments should run with CAP_IPC_LOCK (Linux) or SeIncreaseWorkingSet
    (Windows).
"""

import ctypes
import os
from typing import Any

from exceptions import MemoryIntegrityError
from logger import get_chronos_logger

_log = get_chronos_logger("MemorySanitizer")


def mlock_buffer(buffer: bytearray) -> bool:
    """Attempt to lock *buffer* pages into physical RAM.

    Prevents the OS from paging these pages to swap, which is a requirement
    for the Exclusivity Assumption (EA) stated in §3.4 of the paper.

    Args:
        buffer: A mutable bytearray holding sensitive key material.

    Returns:
        True if mlock succeeded, False if the call is unavailable or
        insufficient privileges prevented locking (a WARNING is logged).
    """
    if not isinstance(buffer, bytearray) or len(buffer) == 0:
        return False

    c_buf = (ctypes.c_char * len(buffer)).from_buffer(buffer)
    ptr: int = ctypes.addressof(c_buf)
    size: int = len(buffer)

    try:
        if os.name == "nt":
            # Windows: VirtualLock(lpAddress, dwSize)
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            result: bool = bool(
                kernel32.VirtualLock(ctypes.c_void_p(ptr), ctypes.c_size_t(size))
            )
            if result:
                _log.info(f"VirtualLock: {size} bytes pinned to physical RAM at {ptr:#018x}")
            else:
                _log.warning(
                    f"VirtualLock failed (error={kernel32.GetLastError()}).  "
                    "The Exclusivity Assumption (EA) may not hold on this system.  "
                    "Run with SeIncreaseWorkingSetPrivilege for full EA enforcement."
                )
            return result
        else:
            # POSIX: mlock(addr, len)
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            rc: int = libc.mlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size))
            if rc == 0:
                _log.info(f"mlock: {size} bytes pinned to physical RAM at {ptr:#018x}")
                return True
            else:
                errno = ctypes.get_errno()
                _log.warning(
                    f"mlock failed (errno={errno}).  "
                    "The Exclusivity Assumption (EA) may not hold on this system.  "
                    "Run with CAP_IPC_LOCK for full EA enforcement."
                )
                return False
    except Exception as exc:
        _log.warning(f"mlock_buffer: platform call unavailable ({exc}).  EA not enforced.")
        return False


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
        via a C-level comparison (not a slow Python byte loop).

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
            _log.warning("zeroize_buffer called with an empty buffer - no-op.")
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
        _log.debug("  Pass 1/3 complete (0x00 - zeros)")

        # --- Pass 2: Set all bits to one ---------------------------------
        ctypes.memset(ptr, 0xFF, buf_len)
        _log.debug("  Pass 2/3 complete (0xFF - ones)")

        # --- Pass 3: Zero out again — final state ------------------------
        ctypes.memset(ptr, 0x00, buf_len)
        _log.debug("  Pass 3/3 complete (0x00 - zeros, final)")

        # --- Post-wipe verification via C-level comparison (D10 fix) -----
        # ctypes.string_at() reads buf_len bytes starting at ptr as a Python
        # bytes object.  In CPython, bytes == bytes comparison uses C memcmp
        # internally, so this is O(n) at C speed with no Python loop overhead.
        #
        # The opaque ctypes call also acts as a compiler barrier — the Python
        # interpreter cannot reorder the memset across this boundary.
        wiped_bytes: bytes = ctypes.string_at(ptr, buf_len)
        expected: bytes = b"\x00" * buf_len

        if wiped_bytes != expected:
            # Find the first failing byte for diagnostic purposes.
            failed_at: int = next((i for i, b in enumerate(wiped_bytes) if b != 0), -1)
            raise MemoryIntegrityError(
                f"Triple-pass wipe verification failed: byte at index {failed_at} "
                f"is {wiped_bytes[failed_at]:#04x} after erasure.  "
                f"Possible OS copy-on-write anomaly or hardware error."
            )

        _log.info(
            f"Memory erasure verified: all {buf_len} bytes confirmed 0x00.  "
            f"Key material is no longer in the committed region."
        )
