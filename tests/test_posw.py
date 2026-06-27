# mypy: ignore-errors
"""Tests for the PoSW Time-Lock Manager.

Covers calibration, multiprocessing dispatch, HKDF key derivation
determinism, and error handling for missing proof state.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posw import PoSWManager, PoSWProof  # noqa: E402


class TestPoSWManager(unittest.TestCase):

    def setUp(self) -> None:
        # duration_sec=1 triggers a fast calibration in every test.
        self.posw = PoSWManager(target_duration_seconds=1)

    def test_calibration_produces_positive_hash_rate(self) -> None:
        """_hashes_per_second must be positive after calibration."""
        self.assertGreater(self.posw._hashes_per_second, 0)

    def test_t_equals_rate_times_duration(self) -> None:
        """T must equal hashes_per_second × target_duration_seconds."""
        expected_t = self.posw._hashes_per_second * self.posw.target_duration_seconds
        self.assertEqual(self.posw.t, expected_t)

    @patch("posw.mp.Queue")
    @patch("posw.mp.Process")
    def test_compute_posw_dispatches_subprocess(
        self, mock_process_cls, mock_queue_cls
    ) -> None:
        """compute_posw() must spawn exactly one subprocess and join it."""
        # Build a fake PoSWProof to put on the fake queue
        fake_proof = PoSWProof(
            merkle_root="deadbeef" * 8,
            checkpoints=[b"\x00" * 32],
            t=self.posw.t,
            seed=self.posw._seed,
            elapsed_sec=0.0,
        )
        mock_q = MagicMock()
        mock_q.get_nowait.return_value = fake_proof
        mock_queue_cls.return_value = mock_q

        mock_proc = MagicMock()
        mock_proc.exitcode = 0
        mock_process_cls.return_value = mock_proc

        self.posw.compute_posw()

        mock_process_cls.assert_called_once()
        mock_proc.start.assert_called_once()
        mock_proc.join.assert_called_once()
        self.assertIsNotNone(self.posw._proof)
        self.assertEqual(self.posw._proof.merkle_root, "deadbeef" * 8)

    def test_derive_key_before_compute_raises(self) -> None:
        """Calling derive_encryption_key() before compute_posw() must raise ValueError."""
        fresh_posw = PoSWManager(target_duration_seconds=1)
        self.assertIsNone(fresh_posw._proof)
        with self.assertRaises(ValueError):
            fresh_posw.derive_encryption_key()

    def test_derive_key_is_deterministic(self) -> None:
        """Two calls to derive_encryption_key() with the same proof must return the same key."""
        fake_proof = PoSWProof(
            merkle_root="aabbccdd" * 8,
            checkpoints=[],
            t=1,
            seed=b"\x01" * 32,
            elapsed_sec=1.0,
        )
        self.posw._proof = fake_proof
        # Override seed so HKDF salt is deterministic too
        self.posw._seed = b"\x01" * 32

        key1 = self.posw.derive_encryption_key()
        key2 = self.posw.derive_encryption_key()

        self.assertEqual(key1, key2)

    def test_derive_key_length_is_256_bits(self) -> None:
        """The derived key must be exactly 32 bytes (256 bits) for AES-256."""
        fake_proof = PoSWProof(
            merkle_root="cafebabe" * 8,
            checkpoints=[],
            t=1,
            seed=b"\x02" * 32,
            elapsed_sec=1.0,
        )
        self.posw._proof = fake_proof
        self.posw._seed = b"\x02" * 32

        key = self.posw.derive_encryption_key()
        self.assertEqual(len(key), 32, "HKDF key must be 32 bytes (256-bit).")

    def test_different_roots_produce_different_keys(self) -> None:
        """Different Merkle roots must produce different derived keys (HKDF isolation)."""
        root_a = PoSWProof("aa" * 32, [], 1, b"\x03" * 32, 0.0)
        root_b = PoSWProof("bb" * 32, [], 1, b"\x03" * 32, 0.0)

        self.posw._seed = b"\x03" * 32

        self.posw._proof = root_a
        key_a = self.posw.derive_encryption_key()

        self.posw._proof = root_b
        key_b = self.posw.derive_encryption_key()

        self.assertNotEqual(
            key_a, key_b, "Different Merkle roots must produce different keys."
        )


if __name__ == "__main__":
    unittest.main()
