import os
import sys
import unittest

from security.secure_string import ObfuscatedString


class TestObfuscatedString(unittest.TestCase):
    def test_init_and_unmask(self) -> None:
        secret = "super_secret_api_key_123"
        obs = ObfuscatedString(secret)
        self.assertEqual(obs.unmask(), secret)
        self.assertNotEqual(obs._masked, secret.encode())

    def test_invalid_init(self) -> None:
        with self.assertRaises(TypeError):
            ObfuscatedString(123)  # type: ignore

    def test_repr_and_str(self) -> None:
        obs = ObfuscatedString("secret")
        self.assertNotIn("secret", repr(obs))
        self.assertNotIn("secret", str(obs))
        self.assertEqual(str(obs), "<ObfuscatedString [REDACTED]>")

    def test_format_raises(self) -> None:
        obs = ObfuscatedString("secret")
        with self.assertRaises(TypeError):
            f"{obs}"

    def test_equality(self) -> None:
        obs1 = ObfuscatedString("secret")
        obs2 = ObfuscatedString("secret")
        obs3 = ObfuscatedString("different")

        self.assertEqual(obs1, obs2)
        self.assertNotEqual(obs1, obs3)
        self.assertNotEqual(obs1, "secret")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    unittest.main()
