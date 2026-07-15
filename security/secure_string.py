"""
Project CHRONOS — In-Memory String Obfuscation

Secrets like API endpoints must never sit in plaintext in heap memory, where
a cold-boot attack or /proc/self/mem dump would expose them immediately.

This module implements XOR-mask obfuscation with a per-instance 256-bit
nonce.  It is NOT encryption — the nonce lives alongside the ciphertext in the
same process — but it defeats pattern-matching on raw memory dumps and forces
an attacker to understand the object layout before extraction.

Security properties:
    - Plaintext is never stored; only XOR(plaintext, nonce) is kept.
    - __repr__ and __str__ are overridden so that accidental logging or
      f-string interpolation never leaks the secret.
    - unmask() returns a fresh str each time; callers should bind it to a
      short-lived local variable and avoid storing it in long-lived structures.

Limitations (acknowledged in §4.4 of the CHRONOS paper):
    - Python's reference-counted GC does not guarantee when the str returned
      by unmask() will be collected.  In production use Cython extensions or
      cffi with explicit free() for sub-millisecond secret lifetimes.
"""

import os


class ObfuscatedString:
    """XOR-mask obfuscated in-memory string.

    The plaintext is never stored; only the XOR product against a fresh
    32-byte random nonce is kept in the object.

    Usage::

        url = ObfuscatedString("https://api.drand.sh/public/latest")
        # ... store the object, pass it around, log it safely ...
        raw_url = url.unmask()   # short-lived str, use immediately
        response = await client.get(raw_url)
        # raw_url goes out of scope; GC will eventually collect it
    """

    __slots__ = ("_nonce", "_masked")

    def __init__(self, plaintext: str) -> None:
        if not isinstance(plaintext, str):
            raise TypeError(
                f"ObfuscatedString requires a str, got {type(plaintext).__name__}"
            )

        # One 32-byte nonce per instance.  os.urandom() uses the OS CSPRNG
        # (CryptGenRandom on Windows, getrandom() on Linux ≥ 3.17).
        self._nonce: bytes = os.urandom(32)

        raw: bytes = plaintext.encode("utf-8")
        nonce_len: int = len(self._nonce)

        # XOR each byte against the cycling nonce.
        self._masked: bytearray = bytearray(
            b ^ self._nonce[i % nonce_len] for i, b in enumerate(raw)
        )

    def unmask(self) -> str:
        """Return the original plaintext string.

        The returned str is a new Python object each time.  Callers must not
        assign the result to a module-level or class-level attribute, as that
        would defeat the purpose of obfuscation.
        """
        nonce_len: int = len(self._nonce)
        raw: bytearray = bytearray(
            b ^ self._nonce[i % nonce_len] for i, b in enumerate(self._masked)
        )
        return raw.decode("utf-8")

    # ------------------------------------------------------------------
    # Prevent accidental leakage through logging, repr(), str(), format()
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<ObfuscatedString len={len(self._masked)} nonce_id={id(self._nonce):#x}>"
        )

    def __str__(self) -> str:
        return "<ObfuscatedString [REDACTED]>"

    def __format__(self, format_spec: str) -> str:
        # Raise explicitly so that f"{secret_url}" fails loudly rather than
        # silently leaking a REDACTED placeholder into log output.
        raise TypeError(
            "ObfuscatedString cannot be interpolated directly.  "
            "Call .unmask() explicitly and bind the result to a local variable."
        )

    def __eq__(self, other: object) -> bool:
        """Constant-time equality check against another ObfuscatedString."""
        if not isinstance(other, ObfuscatedString):
            return NotImplemented
        # Compare unmasked values in constant time using hmac.compare_digest.
        import hmac

        return hmac.compare_digest(self.unmask().encode(), other.unmask().encode())
