# mypy: ignore-errors
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memory_sanitizer import MemorySanitizer


class TestMemorySanitizer(unittest.TestCase):
    @patch("ctypes.memset")
    def test_zeroize_buffer_success(self, mock_memset) -> None:
        """Test that a bytearray is properly wiped using ctypes.memset."""
        # Create a mock private key buffer
        sensitive_data = bytearray(b"SUPER_SECRET_KEY_1234567890")
        original_length = len(sensitive_data)

        # We patch ctypes.addressof to return a fake pointer
        with patch("ctypes.addressof", return_value=123456):
            MemorySanitizer.zeroize_buffer(sensitive_data)

        # Ensure memset was called exactly 3 times (triple-pass wipe)
        self.assertEqual(mock_memset.call_count, 3)

        # Ensure the first pass was zeroing out (0)
        mock_memset.assert_any_call(123456, 0, original_length)
        # Ensure the second pass was ones (255)
        mock_memset.assert_any_call(123456, 255, original_length)

    def test_zeroize_immutable_buffer_fails(self) -> None:
        """Test that attempting to zeroize an immutable bytes object fails safely."""
        immutable_data = b"IMMUTABLE_KEY"
        with self.assertRaises(TypeError):
            MemorySanitizer.zeroize_buffer(immutable_data)

    def test_zeroize_string_fails(self) -> None:
        """Test that attempting to zeroize a string fails safely."""
        string_data = "STRING_KEY"
        with self.assertRaises(TypeError):
            MemorySanitizer.zeroize_buffer(string_data)


if __name__ == "__main__":
    unittest.main()
