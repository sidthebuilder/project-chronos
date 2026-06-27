# mypy: ignore-errors
"""Tests for the Paillier FHE Engine.

Verifies the core mathematical property of the scheme:
    Decrypt(E(A) ⊕ E(B)) = A + B

This is the foundational claim of plaintext blindness — if this property
holds, the engine can perform inference on ciphertexts without ever seeing
the plaintexts.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fhe_engine import FHEEngineMock, PaillierCryptosystem  # noqa: E402


class TestPaillierCryptosystem(unittest.TestCase):
    """Unit tests for the raw PaillierCryptosystem class."""

    @classmethod
    def setUpClass(cls) -> None:
        # Use minimum 1024-bit keys (cryptography library enforces this lower bound).
        # Tests are slower than 512-bit would be, but correctness is the priority.
        cls.paillier = PaillierCryptosystem(key_size=1024)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Encrypt then decrypt a plaintext should return the original value."""
        for m in [0, 1, 42, 999, 65535]:
            with self.subTest(plaintext=m):
                ct = self.paillier.encrypt(m)
                recovered = self.paillier.decrypt(ct)
                self.assertEqual(recovered, m, f"Roundtrip failed for m={m}")

    def test_homomorphic_addition(self) -> None:
        """Decrypt(E(A) ⊕ E(B)) must equal A + B for arbitrary A, B."""
        test_cases = [(100, 50), (0, 0), (1, 1), (255, 1), (1000, 2000)]
        for a, b in test_cases:
            with self.subTest(a=a, b=b):
                ct_a = self.paillier.encrypt(a)
                ct_b = self.paillier.encrypt(b)
                ct_sum = self.paillier.homomorphic_add(ct_a, ct_b)
                result = self.paillier.decrypt(ct_sum)
                self.assertEqual(result, a + b, f"Homomorphic add failed: {a}+{b}")

    def test_ciphertext_randomisation(self) -> None:
        """Two encryptions of the same plaintext must produce different ciphertexts
        (semantic security — IND-CPA)."""
        m = 42
        ct1 = self.paillier.encrypt(m)
        ct2 = self.paillier.encrypt(m)
        self.assertNotEqual(
            ct1,
            ct2,
            "Two encryptions of the same plaintext returned identical ciphertexts. "
            "The random blinding factor r may not be working.",
        )

    def test_public_key_structure(self) -> None:
        """The public key must satisfy the Paillier structural constraints."""
        pk = self.paillier.pub_key
        self.assertEqual(pk.n_sq, pk.n * pk.n)
        self.assertEqual(pk.g, pk.n + 1)  # simplified Paillier generator


class TestFHEEngineMock(unittest.TestCase):
    """Integration tests for the ICryptographicEngine-compatible wrapper."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fhe = FHEEngineMock()

    def test_homomorphic_demo_payload(self) -> None:
        """The demo payload E(100) ⊕ E(50) should decrypt to exactly 150."""
        ct1, ct2 = self.fhe.encrypt_data(b"")
        ct_out = self.fhe.evaluate_inference((ct1, ct2))
        result = self.fhe.crypto.decrypt(ct_out)
        self.assertEqual(
            result,
            150,
            f"Demo payload homomorphic addition returned {result}, expected 150.",
        )

    def test_get_private_key_bytes_returns_bytearray(self) -> None:
        """get_private_key_bytes() must return a mutable bytearray, not bytes."""
        key_bytes = self.fhe.get_private_key_bytes()
        self.assertIsInstance(key_bytes, bytearray)
        self.assertGreater(len(key_bytes), 0)

    def test_private_key_bytes_are_mutable(self) -> None:
        """The returned buffer must be mutable so MemorySanitizer can wipe it."""
        key_bytes = self.fhe.get_private_key_bytes()
        # If it were immutable bytes, this assignment would raise TypeError.
        key_bytes[0] = 0xFF
        self.assertEqual(key_bytes[0], 0xFF)


if __name__ == "__main__":
    unittest.main()
