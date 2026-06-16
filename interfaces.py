"""
Project Interfaces Module.
Uses modern Structural Subtyping (typing.Protocol) instead of legacy abc.ABC.
"""

from typing import Any, Dict, Optional, Protocol, Tuple


class ICryptographicEngine(Protocol):
    """
    Structural interface for the underlying encryption engine.
    """

    def get_private_key_bytes(self) -> bytearray: ...

    def encrypt_data(self, data: bytes) -> Tuple[int, int]: ...

    def evaluate_inference(self, ciphertexts: Tuple[int, int]) -> int: ...


class ITimeLock(Protocol):
    """
    Structural interface for the PoSW time-lock manager.
    """

    def compute_posw(self) -> None: ...

    def derive_encryption_key(self) -> bytes: ...


class IOracleClient(Protocol):
    """
    Structural interface for the Decentralized Randomness Beacon.
    Now operates asynchronously for modern event-loop compatibility.
    """

    async def fetch_latest_round(self) -> Optional[Dict[str, Any]]: ...

    async def wait_for_round(
        self, target_round: int, polling_interval: int = 3
    ) -> Dict[str, Any]: ...


class IMemorySanitizer(Protocol):
    """
    Structural interface for the physical memory shredder.
    """

    @staticmethod
    def zeroize_buffer(buffer: bytearray) -> None: ...
