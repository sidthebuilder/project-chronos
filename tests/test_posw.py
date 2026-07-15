# mypy: ignore-errors
"""Tests for the PoSW Time-Lock Manager.

Covers calibration, multiprocessing dispatch, HKDF key derivation
determinism, and error handling for missing proof state.

Updated to reflect the mp.Pipe (not mp.Queue) implementation used to
avoid pipe buffer deadlock when the checkpoint list is large (D4 fix).
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, call, patch

from posw import MerkleTree, PoSWManager, PoSWProof, _posw_worker


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

    @patch("posw.mp.Pipe")
    @patch("posw.mp.Process")
    def test_compute_posw_dispatches_subprocess(
        self, mock_process_cls, mock_pipe
    ) -> None:
        """compute_posw() must spawn exactly one subprocess and join it.

        The implementation uses mp.Pipe (not mp.Queue) to avoid deadlock.
        We mock both ends of the pipe: parent_conn.recv() returns checkpoints,
        child_conn is closed after the worker starts.
        """
        # Set up a mock pipe with two connection ends.
        mock_parent_conn = MagicMock()
        mock_child_conn = MagicMock()
        mock_parent_conn.recv.return_value = [b"\x00" * 32]
        mock_pipe.return_value = (mock_parent_conn, mock_child_conn)

        mock_proc = MagicMock()
        mock_proc.exitcode = 0
        mock_process_cls.return_value = mock_proc

        self.posw.compute_posw()

        mock_process_cls.assert_called_once()
        mock_proc.start.assert_called_once()
        mock_proc.join.assert_called_once()
        # parent_conn.recv() must have been called to get checkpoints
        mock_parent_conn.recv.assert_called_once()
        self.assertIsNotNone(self.posw._proof)
        self.assertEqual(self.posw._proof.merkle_root, "00" * 32)

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
            target_sec=1,
            drift_fraction=0.0,
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
            target_sec=1,
            drift_fraction=0.0,
        )
        self.posw._proof = fake_proof
        self.posw._seed = b"\x02" * 32

        key = self.posw.derive_encryption_key()
        self.assertEqual(len(key), 32, "HKDF key must be 32 bytes (256-bit).")

    def test_different_roots_produce_different_keys(self) -> None:
        """Different Merkle roots must produce different derived keys (HKDF isolation)."""
        root_a = PoSWProof("aa" * 32, [], 1, b"\x03" * 32, 0.0, 1, 0.0)
        root_b = PoSWProof("bb" * 32, [], 1, b"\x03" * 32, 0.0, 1, 0.0)

        self.posw._seed = b"\x03" * 32

        self.posw._proof = root_a
        key_a = self.posw.derive_encryption_key()

        self.posw._proof = root_b
        key_b = self.posw.derive_encryption_key()

        self.assertNotEqual(
            key_a, key_b, "Different Merkle roots must produce different keys."
        )

    @patch("posw.mp.Pipe")
    @patch("posw.mp.Process")
    @patch("posw.time.time")
    def test_compute_posw_drift_warning(
        self, mock_time, mock_process_cls, mock_pipe
    ) -> None:
        """compute_posw() must emit a warning if drift exceeds threshold."""
        mock_time.side_effect = [100.0, 101.5]

        mock_parent_conn = MagicMock()
        mock_child_conn = MagicMock()
        mock_parent_conn.recv.return_value = [b"\x00" * 32]
        mock_pipe.return_value = (mock_parent_conn, mock_child_conn)

        mock_proc = MagicMock()
        mock_proc.exitcode = 0
        mock_process_cls.return_value = mock_proc

        with patch.object(self.posw, "_log") as mock_log:
            self.posw.compute_posw()
            mock_log.warning.assert_called_once()
            self.assertIn("[POSW DRIFT]", mock_log.warning.call_args[0][0])

    @patch("posw.mp.Pipe")
    @patch("posw.mp.Process")
    def test_worker_exitcode_failure(self, mock_process_cls, mock_pipe) -> None:
        """compute_posw() must raise RuntimeError on non-zero subprocess exit."""
        mock_parent_conn = MagicMock()
        mock_child_conn = MagicMock()
        # Simulate EOFError (worker died before sending)
        mock_parent_conn.recv.side_effect = EOFError
        mock_pipe.return_value = (mock_parent_conn, mock_child_conn)

        mock_proc = MagicMock()
        mock_proc.exitcode = 1
        mock_process_cls.return_value = mock_proc

        with self.assertRaises(RuntimeError):
            self.posw.compute_posw()

    def test_verify_checkpoint(self) -> None:
        self.posw._proof = PoSWProof(
            merkle_root="00" * 32,
            checkpoints=[b"\x00" * 32],
            t=1,
            seed=b"a",
            elapsed_sec=1,
            target_sec=1,
            drift_fraction=0.0,
        )
        with patch("posw.MerkleTree") as mock_mt:
            mock_mt.verify.return_value = True
            res = self.posw.verify_checkpoint(0)
            self.assertTrue(res)

    def test_proof_property(self) -> None:
        self.assertIsNone(self.posw.proof)
        self.posw._proof = PoSWProof(
            merkle_root="00" * 32,
            checkpoints=[b"\x00" * 32],
            t=1,
            seed=b"a",
            elapsed_sec=1,
            target_sec=1,
            drift_fraction=0.0,
        )
        self.assertIsNotNone(self.posw.proof)


class TestMerkleTree(unittest.TestCase):
    def test_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            MerkleTree([])

    def test_build_prove_verify(self) -> None:
        leaves = [bytes([i] * 32) for i in range(3)]
        tree = MerkleTree(leaves)
        proof = tree.prove(1)
        self.assertTrue(MerkleTree.verify(proof))
        self.assertEqual(proof.leaf_index, 1)


class TestPoSWWorker(unittest.TestCase):
    def test_posw_worker(self) -> None:
        """_posw_worker sends checkpoint list via connection.send()."""
        mock_conn = MagicMock()
        with patch("posw._CHECKPOINT_COUNT", 2):
            _posw_worker(b"seed", 3, mock_conn)
            mock_conn.send.assert_called_once()
            mock_conn.close.assert_called_once()
        # Verify checkpoints are a list of bytes
        sent_checkpoints = mock_conn.send.call_args[0][0]
        self.assertIsInstance(sent_checkpoints, list)
        for cp in sent_checkpoints:
            self.assertIsInstance(cp, bytes)
            self.assertEqual(len(cp), 32)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    unittest.main()
