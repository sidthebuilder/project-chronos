# mypy: ignore-errors
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fhe_engine import FHEEngineMock


class TestFHEEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.fhe = FHEEngineMock()

    def test_homomorphic_addition(self) -> None:
        """
        Tests that E(A) + E(B) = E(A+B) using the True Paillier Engine.
        """
        ct1, ct2 = self.fhe.encrypt_data(b"")
        ct_out = self.fhe.evaluate_inference((ct1, ct2))

        # We decrypt using the inner crypto object for verification
        decrypted_result = self.fhe.crypto.decrypt(ct_out)
        self.assertEqual(
            decrypted_result, 150, "Homomorphic addition failed to produce 150!"
        )


if __name__ == "__main__":
    unittest.main()
