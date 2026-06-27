"""
Project CHRONOS — Interface Contracts (Structural Subtyping)

Using typing.Protocol instead of abc.ABC gives us structural subtyping:
any class that implements the required methods satisfies the interface without
inheriting from it.  This keeps test doubles and production implementations
fully decoupled — no base class import needed.

The four contracts map directly to the four subsystems described in §3 of the
CHRONOS paper:
    ICryptographicEngine  →  §3.1  Plaintext Blindness (FHE)
    ITimeLock             →  §3.2  Cryptographic Fuse (PoSW)
    IOracleClient         →  §3.3  Dead Man's Switch (drand)
    IMemorySanitizer      →  §3.4  Erasure Protocol (memory wipe)
"""

from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable


@runtime_checkable
class ICryptographicEngine(Protocol):
    """Contract for the Fully Homomorphic Encryption subsystem (§3.1).

    Implementations must provide:
    - Key material extraction as a mutable bytearray (so it can be shredded).
    - Encryption of an arbitrary byte payload.
    - Homomorphic inference evaluation over ciphertexts without decrypting them.
    """

    def get_private_key_bytes(self) -> bytearray:
        """Return the private key as a mutable bytearray.

        The caller owns the buffer and is responsible for zeroizing it via
        MemorySanitizer.zeroize_buffer() after use.
        """
        ...

    def encrypt_data(self, data: bytes) -> Tuple[int, int]:
        """Encrypt a byte payload and return a pair of ciphertexts.

        Returns a tuple of two integer ciphertexts suitable for
        evaluate_inference().
        """
        ...

    def evaluate_inference(self, ciphertexts: Tuple[int, int]) -> int:
        """Perform homomorphic computation over ciphertexts without decrypting.

        Returns a single integer ciphertext representing the encrypted result.
        """
        ...


@runtime_checkable
class ITimeLock(Protocol):
    """Contract for the Proof of Sequential Work time-lock (§3.2).

    Implementations must enforce that no shortcut exists to compute the result
    faster than real elapsed wall-clock time (sequential, non-parallelisable).
    """

    def compute_posw(self) -> None:
        """Execute the sequential hash chain.

        This is a blocking, CPU-bound call.  The caller is responsible for
        running it in a thread or subprocess so it does not block the event loop.
        After this returns, derive_encryption_key() may be called.
        """
        ...

    def derive_encryption_key(self) -> bytes:
        """Derive a 256-bit AES key from the PoSW Merkle root via HKDF-SHA256.

        Raises:
            ValueError: If compute_posw() has not been called yet.

        Returns:
            32 raw bytes suitable for use as an AES-256 key.
        """
        ...


@runtime_checkable
class IOracleClient(Protocol):
    """Contract for the decentralised randomness beacon (§3.3).

    drand provides a publicly verifiable, BLS-threshold-signed random beacon
    that the agent uses as an unforgeable external clock.
    """

    async def fetch_latest_round(self) -> Optional[Dict[str, Any]]:
        """Fetch the most recent round from the drand network.

        Returns:
            A dict with at minimum ``round`` (int), ``signature`` (hex str),
            and ``randomness`` (hex str) keys, or None on failure.

        Raises:
            OracleUnreachableError: On any network or HTTP error.
        """
        ...

    async def wait_for_round(
        self, target_round: int, polling_interval: int = 3
    ) -> Dict[str, Any]:
        """Poll the beacon until *target_round* is reached or exceeded.

        This is the Dead Man's Switch trigger.  It must not block the event loop.

        Args:
            target_round:       The drand round number to wait for.
            polling_interval:   Seconds between successive API calls.

        Returns:
            The full drand round data dict for the first round >= *target_round*.

        Raises:
            CryptographicSanityError: If the beacon's BLS signature fails.
        """
        ...


@runtime_checkable
class IMemorySanitizer(Protocol):
    """Contract for the physical memory erasure protocol (§3.4)."""

    @staticmethod
    def zeroize_buffer(buffer: bytearray) -> None:
        """Perform a secure, multi-pass overwrite of *buffer* in place.

        Args:
            buffer: A mutable bytearray containing sensitive key material.

        Raises:
            TypeError:           If *buffer* is not a bytearray.
            MemoryIntegrityError: If any byte remains non-zero after erasure.
        """
        ...
