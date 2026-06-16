# mypy: ignore-errors
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posw import PoSWManager


class TestPoSWManager(unittest.TestCase):
    def setUp(self) -> None:
        # Small duration for fast tests
        self.posw = PoSWManager(target_duration_seconds=1)

    @patch("posw.mp.Queue")
    @patch("posw.mp.Process")
    def test_compute_posw_multiprocessing(self, mock_process, mock_queue) -> None:
        """Test that PoSW spawns a background process safely."""
        # We don't want to actually wait for multiprocessing in unit tests,
        # we just want to ensure it gets dispatched correctly.
        mock_instance = MagicMock()
        mock_process.return_value = mock_instance

        mock_q_instance = MagicMock()
        mock_q_instance.get.return_value = "mocked_root_123"
        mock_queue.return_value = mock_q_instance

        self.posw.compute_posw()

        mock_process.assert_called_once()
        mock_instance.start.assert_called_once()
        mock_instance.join.assert_called_once()
        self.assertEqual(self.posw.published_root, "mocked_root_123")

    def test_derive_encryption_key_deterministic(self) -> None:
        """Test that the HKDF key derivation is deterministic."""
        # Inject a fake root
        self.posw.published_root = "deadbeef12345678"
        key1 = self.posw.derive_encryption_key()
        key2 = self.posw.derive_encryption_key()
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)  # Should be 256-bit AES key

    def test_derive_key_without_root_fails(self) -> None:
        """Test that deriving a key before PoSW finishes raises an exception."""
        self.posw.published_root = None
        with self.assertRaises(ValueError):
            self.posw.derive_encryption_key()


if __name__ == "__main__":
    unittest.main()
