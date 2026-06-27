# mypy: ignore-errors
"""Tests for the MemorySanitizer erasure module.

Verifies the physical memory wipe contract:
    - Triple-pass wipe executes exactly three ctypes.memset calls.
    - The buffer is all zeros after a successful wipe.
    - Immutable types are rejected with TypeError.
    - The MemoryIntegrityError is raised when a byte is non-zero post-wipe
      (simulated hardware failure scenario).
"""

import os
import sys
import unittest
from unittest.mock import call, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exceptions import MemoryIntegrityError  # noqa: E402
from memory_sanitizer import MemorySanitizer  # noqa: E402


class TestMemorySanitizer(unittest.TestCase):

    def test_triple_pass_wipe_calls_memset_three_times(self) -> None:
        """ctypes.memset must be called exactly three times with the correct arguments."""
        buf = bytearray(b"TOP_SECRET_KEY_MATERIAL_1234567890")
        buf_len = len(buf)

        def _fake_memset(ptr, val, size):
            # Simulate memset by actually writing into the bytearray so the
            # post-wipe read-back verification passes after the final pass (0x00).
            for i in range(len(buf)):
                buf[i] = val

        with patch("ctypes.addressof", return_value=0xDEADBEEF), patch(
            "ctypes.memset", side_effect=_fake_memset
        ) as mock_memset:
            MemorySanitizer.zeroize_buffer(buf)

        self.assertEqual(mock_memset.call_count, 3, "Expected exactly 3 memset calls.")
        mock_memset.assert_any_call(0xDEADBEEF, 0x00, buf_len)
        mock_memset.assert_any_call(0xDEADBEEF, 0xFF, buf_len)
        # Verify ordering: 0x00, 0xFF, 0x00
        self.assertEqual(
            mock_memset.call_args_list,
            [
                call(0xDEADBEEF, 0x00, buf_len),
                call(0xDEADBEEF, 0xFF, buf_len),
                call(0xDEADBEEF, 0x00, buf_len),
            ],
        )

    def test_real_wipe_zeroes_buffer(self) -> None:
        """The actual C-level wipe must leave every byte as 0x00."""
        buf = bytearray(os.urandom(256))
        self.assertTrue(
            any(b != 0 for b in buf), "Buffer was already all zeros before test."
        )

        MemorySanitizer.zeroize_buffer(buf)

        self.assertTrue(
            all(b == 0 for b in buf), "Buffer must be all zeros after wipe."
        )

    def test_rejects_immutable_bytes(self) -> None:
        """Passing immutable bytes must raise TypeError."""
        with self.assertRaises(TypeError):
            MemorySanitizer.zeroize_buffer(b"immutable")

    def test_rejects_string(self) -> None:
        """Passing a str must raise TypeError."""
        with self.assertRaises(TypeError):
            MemorySanitizer.zeroize_buffer("secret_string")  # type: ignore

    def test_rejects_none(self) -> None:
        """Passing None must raise TypeError."""
        with self.assertRaises(TypeError):
            MemorySanitizer.zeroize_buffer(None)  # type: ignore

    def test_empty_buffer_is_noop(self) -> None:
        """An empty bytearray is valid but a no-op — no memset calls."""
        buf = bytearray(0)
        with patch("ctypes.memset") as mock_memset:
            MemorySanitizer.zeroize_buffer(buf)
        mock_memset.assert_not_called()

    def test_memory_integrity_error_on_failed_wipe(self) -> None:
        """If any byte is non-zero after the wipe, MemoryIntegrityError must be raised.

        This simulates a hardware anomaly where memset does not fully zero the buffer.
        """
        buf = bytearray(b"SENSITIVE_KEY_DATA")

        # Patch memset to do nothing (simulating hardware failure),
        # and patch addressof to return a valid-looking address.
        with patch("ctypes.addressof", return_value=0x1234), patch("ctypes.memset"):
            # buf still contains original data after a no-op memset.
            with self.assertRaises(MemoryIntegrityError):
                MemorySanitizer.zeroize_buffer(buf)


if __name__ == "__main__":
    unittest.main()
