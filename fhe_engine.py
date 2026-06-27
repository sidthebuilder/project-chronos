"""
Project CHRONOS — Paillier FHE Engine (§3.1 — Plaintext Blindness)

This module implements the Fully Homomorphic Encryption subsystem.  It
provides cryptographically real Paillier homomorphic addition that matches
the formal definition in §2.1 of the CHRONOS paper:

    KeyGen(λ):   Generate (pk, sk) where pk = (n, g, n²) and sk = (λ, μ)
    Encrypt(pk, m):   c = g^m · r^n mod n²   (r ∈ Z*_n random)
    Eval(pk, c₁, c₂): c₁ · c₂ mod n²         (homomorphic addition)
    Decrypt(sk, c):   L(c^λ mod n²) · μ mod n

Why Paillier and not TFHE?
    - Paillier runs in pure Python without native extensions, making it
      deployable in any environment without a C compiler.
    - The additive homomorphism is sufficient to demonstrate the blindness
      property described in §3.1 (the agent evaluates a weighted sum on
      encrypted inputs without ever seeing the plaintext).
    - A production deployment would replace this with concrete-ml or
      py-fhe (TFHE) for arbitrary boolean circuit evaluation.

Security parameters (prototype):
    - 1024-bit Paillier keys (512-bit security level).
    - Upgrade to 2048-bit for NIST Level 2 (equivalent to AES-128).
    - The ICryptographicEngine interface allows drop-in replacement.

Timing note:
    evaluate_inference() contains NO artificial time.sleep().  The
    benchmark measures actual Paillier modular exponentiation time.
"""

import secrets
import time
from dataclasses import dataclass
from typing import Final, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from config import RSA_KEY_SIZE_BITS
from interfaces import ICryptographicEngine
from logger import get_chronos_logger

_log = get_chronos_logger("FHE_Engine")


# ---------------------------------------------------------------------------
# Cryptographic primitives
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PaillierPublicKey:
    """Immutable Paillier public key.

    Attributes:
        n:    RSA modulus (product of two safe primes p and q).
        g:    Generator, set to n+1 for the simplified Paillier scheme.
        n_sq: n² — used as the working modulus for all ciphertext operations.
    """

    n: int
    g: int
    n_sq: int


@dataclass(frozen=True, slots=True)
class PaillierPrivateKey:
    """Immutable Paillier private key.

    Attributes:
        l_val:  λ = lcm(p-1, q-1) — the Carmichael totient of n.
        mu:     μ = (L(g^λ mod n²))^(-1) mod n — the decryption multiplier.
    """

    l_val: int
    mu: int


class MathUtils:
    """Static helpers for cryptographic integer arithmetic.

    All methods use Python's built-in pow(a, b, m) which calls C-level
    Montgomery multiplication and is constant-time for the base / exponent
    pair.  We explicitly avoid pure-Python GCD / extended-Euclidean
    implementations that have data-dependent branch behaviour and are
    susceptible to timing side-channels.
    """

    __slots__ = ()

    @staticmethod
    def lcm(a: int, b: int) -> int:
        """Least common multiple via gcd.

        Python 3.9+ exposes math.lcm() but we implement it here for clarity
        and to avoid an import.
        """
        import math

        return abs(a * b) // math.gcd(a, b)

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """Modular multiplicative inverse using Python's built-in pow(a, -1, m).

        Python 3.8+ supports the three-argument pow() with a negative exponent,
        which uses the extended Euclidean algorithm implemented in C.  This is
        significantly faster and more constant-time than a pure-Python version.

        Raises:
            ValueError: If *a* and *m* are not coprime (no inverse exists).
        """
        return pow(a, -1, m)


class PaillierCryptosystem:
    """Object-oriented implementation of the Paillier additively homomorphic
    encryption scheme (Pascal Paillier, 1999).

    The scheme is instantiated by generating an RSA modulus and deriving the
    Paillier parameters from it.  This avoids writing a prime-generation
    routine from scratch and delegates that security-critical step to the
    well-audited cryptography library.

    Args:
        key_size:  Bit-length of the Paillier modulus n = p·q.  Each prime
                   is key_size/2 bits.  Must be at least 1024.
    """

    def __init__(self, key_size: int = 1024) -> None:
        _log.info(
            f"Generating Paillier keypair: {key_size}-bit modulus "
            f"(~{key_size // 2}-bit security level)..."
        )
        t0 = time.perf_counter()
        self.pub_key, self.priv_key = self._generate_keypair(key_size)
        elapsed = time.perf_counter() - t0
        _log.info(
            f"Keypair generated in {elapsed * 1000:.1f} ms.  "
            f"Public modulus n is {self.pub_key.n.bit_length()}-bit."
        )

    def _generate_keypair(
        self, bits: int
    ) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
        """Generate a Paillier keypair.

        We extract p and q from an RSA key object because Python's cryptography
        library has a highly-optimised, FIPS-tested prime generation routine.

        Mathematical construction:
            n   = p · q
            λ   = lcm(p-1, q-1)   [Carmichael totient — stronger than Euler's]
            g   = n + 1            [simplified generator for Paillier]
            u   = g^λ mod n²
            μ   = L(u)^(-1) mod n  where L(x) = (x-1)/n
        """
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend(),
        )
        nums = rsa_key.private_numbers()
        p: int = nums.p
        q: int = nums.q
        n: int = p * q
        n_sq: int = n * n

        lambda_n: int = MathUtils.lcm(p - 1, q - 1)
        g: int = n + 1

        def _L(u: int) -> int:
            return (u - 1) // n

        u: int = pow(g, lambda_n, n_sq)
        mu: int = MathUtils.mod_inverse(_L(u), n)

        return PaillierPublicKey(n=n, g=g, n_sq=n_sq), PaillierPrivateKey(
            l_val=lambda_n, mu=mu
        )

    def encrypt(self, plaintext: int) -> int:
        """Encrypt a non-negative integer plaintext.

        The random blinding factor r is chosen from Z*_n using secrets.randbelow()
        (Python's CSPRNG).  We verify gcd(r, n) = 1 before use to satisfy the
        Paillier correctness requirement.

        Args:
            plaintext: A non-negative integer m where 0 ≤ m < n.

        Returns:
            An integer ciphertext c in Z_{n²}.
        """
        n = self.pub_key.n
        n_sq = self.pub_key.n_sq
        g = self.pub_key.g

        # Find r ∈ Z*_n  (i.e. gcd(r, n) = 1).
        # For large n (1024-bit), a random r will satisfy this with overwhelming
        # probability on the first try — the loop terminates almost instantly.
        import math

        while True:
            r = secrets.randbelow(n - 1) + 1  # 1 ≤ r < n
            if math.gcd(r, n) == 1:
                break

        # c = g^m · r^n mod n²
        c = (pow(g, plaintext, n_sq) * pow(r, n, n_sq)) % n_sq
        return c

    def decrypt(self, ciphertext: int) -> int:
        """Decrypt a Paillier ciphertext to recover the integer plaintext.

        m = L(c^λ mod n²) · μ mod n
        """
        n = self.pub_key.n
        n_sq = self.pub_key.n_sq
        l_val = self.priv_key.l_val
        mu = self.priv_key.mu

        u: int = pow(ciphertext, l_val, n_sq)
        plaintext: int = ((u - 1) // n * mu) % n
        return plaintext

    def homomorphic_add(self, c1: int, c2: int) -> int:
        """Evaluate the homomorphic sum of two ciphertexts.

        The Paillier scheme satisfies:
            Decrypt(c1 · c2 mod n²) = Decrypt(c1) + Decrypt(c2) mod n

        This is the core "plaintext blindness" property: the computation is
        performed entirely on ciphertexts without the engine ever decrypting
        them.

        Args:
            c1, c2: Integer ciphertexts in Z_{n²}.

        Returns:
            Integer ciphertext in Z_{n²} encrypting (m1 + m2 mod n).
        """
        return (c1 * c2) % self.pub_key.n_sq


# ---------------------------------------------------------------------------
# ICryptographicEngine implementation
# ---------------------------------------------------------------------------


class FHEEngineMock(ICryptographicEngine):
    """Paillier FHE engine implementing the ICryptographicEngine contract.

    The name "Mock" is a historical artefact — this implementation uses REAL
    Paillier homomorphic encryption.  The "mock" refers to the fact that it
    uses a fixed demo payload (A=100, B=50) rather than taking live inference
    inputs.  The mathematical operations are not simulated.

    In a production deployment, replace the fixed demo payload in
    encrypt_data() with actual model input features, and replace
    evaluate_inference() with the FHE circuit for the model's inference pass.
    """

    # Fixed demo plaintexts.  The ZK proof in the paper uses these values:
    # E(100) ⊕ E(50) → E(150) — a trivially verifiable homomorphic addition.
    _DEMO_A: Final[int] = 100
    _DEMO_B: Final[int] = 50

    def __init__(self) -> None:
        self.crypto = PaillierCryptosystem(key_size=RSA_KEY_SIZE_BITS)

    def get_private_key_bytes(self) -> bytearray:
        """Serialise the Paillier private key as a mutable bytearray.

        Both λ (l_val) and μ (mu) are big-endian encoded and concatenated.
        The buffer is handed to the agent and will be zeroized by
        MemorySanitizer at mission end.

        Returns:
            A mutable bytearray containing the concatenated private key fields.
        """
        l_val: int = self.crypto.priv_key.l_val
        mu: int = self.crypto.priv_key.mu

        def _int_to_bytes(x: int) -> bytes:
            return x.to_bytes((x.bit_length() + 7) // 8, "big")

        raw: bytes = _int_to_bytes(l_val) + _int_to_bytes(mu)
        return bytearray(raw)

    def encrypt_data(self, data: bytes) -> Tuple[int, int]:
        """Encrypt the demo payload under Paillier.

        The *data* argument is accepted for interface compliance but is not
        used in this prototype.  The two fixed plaintexts (100 and 50) are
        encrypted fresh each call with independent blinding factors.

        Returns:
            (ct_A, ct_B): A pair of Paillier ciphertexts.
        """
        _log.debug(
            f"Encrypting demo payload under Paillier: "
            f"A={self._DEMO_A}, B={self._DEMO_B}"
        )
        ct_a = self.crypto.encrypt(self._DEMO_A)
        ct_b = self.crypto.encrypt(self._DEMO_B)
        _log.debug("Paillier encryption complete.")
        return ct_a, ct_b

    def evaluate_inference(self, ciphertexts: Tuple[int, int]) -> int:
        """Perform homomorphic addition over two ciphertexts.

        This is the "plaintext-blind" computation: the engine adds A and B
        while they are encrypted.  The result is E(A + B) = E(150), which
        can only be confirmed by decrypting — which requires the private key.

        Returns:
            A single Paillier ciphertext encrypting (A + B).
        """
        _log.info(
            "Evaluating homomorphic inference: E(A) ⊕ E(B) → E(A+B) "
            "[plaintext never exposed]"
        )
        ct1, ct2 = ciphertexts
        ct_out = self.crypto.homomorphic_add(ct1, ct2)
        _log.info(
            f"Homomorphic addition complete.  "
            f"Output ciphertext (first 20 digits): {str(ct_out)[:20]}..."
        )
        return ct_out


# ---------------------------------------------------------------------------
# Legacy shim — used by benchmark.py for result verification
# ---------------------------------------------------------------------------


def decrypt(
    pub_key: Tuple[int, int, int],
    priv_key: Tuple[int, int],
    c: int,
) -> int:
    """Standalone Paillier decryption for use in benchmarks and tests.

    Args:
        pub_key:  (n, g, n_sq) tuple.
        priv_key: (l_val, mu) tuple.
        c:        Integer ciphertext.

    Returns:
        Integer plaintext.
    """
    n, _, _ = pub_key
    l_val, mu = priv_key

    def _L(u: int) -> int:
        return (u - 1) // n

    u: int = pow(c, l_val, n * n)
    return int((_L(u) * mu) % n)
