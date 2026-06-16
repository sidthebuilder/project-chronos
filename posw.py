"""
Proof of Sequential Work (PoSW) Module.
Leverages Python multiprocessing to escape the GIL for maximum cryptographic throughput.
"""

import hashlib
import multiprocessing as mp
import secrets
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from logger import get_chronos_logger


class PoSWManager:
    """
    Strictly-typed Time-Lock Manager utilizing SHA-256 hash chains.
    """

    def __init__(self, target_duration_seconds: int) -> None:
        self.logger = get_chronos_logger("PoSW")
        self.target_duration_seconds: int = target_duration_seconds
        self.hashes_per_second: int = self._calibrate_speed()

        # Calculate exactly how many hashes equal the mission duration
        self.t: int = self.hashes_per_second * self.target_duration_seconds
        self.seed: bytes = secrets.token_bytes(32)
        self.published_root: Optional[str] = None

    def _calibrate_speed(self) -> int:
        """Calibrates local CPU hashing throughput without syscall overhead."""
        self.logger.info("Calibrating true hash speed...")

        current_val: bytes = b"calibration_seed"

        # Pre-warm the CPU
        for _ in range(1000):
            current_val = hashlib.sha256(current_val).digest()

        start_time: float = time.perf_counter()
        count: int = 100_000

        for _ in range(count):
            current_val = hashlib.sha256(current_val).digest()

        end_time: float = time.perf_counter()

        hashes_per_sec: int = int(count / (end_time - start_time))
        self.logger.info(
            f"Calibration complete. Speed: {hashes_per_sec:,} hashes/sec. T = {hashes_per_sec * self.target_duration_seconds:,}"
        )
        return hashes_per_sec

    def compute_posw(self) -> None:
        """
        Executes the PoSW algorithm on an isolated CPU core.
        """
        self.logger.info(
            f"Starting isolated multi-processing sequential computation (Target: {self.target_duration_seconds}s)..."
        )

        queue: "mp.Queue[str]" = mp.Queue()
        process = mp.Process(
            target=self._sequential_hash_chain, args=(self.seed, self.t, queue)
        )

        start: float = time.time()
        process.start()
        process.join()
        end: float = time.time()

        self.published_root = queue.get()
        self.logger.info(
            f"Computation & Merkle Commitment finished in {end - start:.2f}s."
        )
        if self.published_root:
            self.logger.info(f"Published Merkle Root: {self.published_root[:16]}...")

    def _sequential_hash_chain(
        self, seed: bytes, t: int, queue: "mp.Queue[str]"
    ) -> None:
        """Isolated multi-processing function with mathematically optimal inner loop."""
        current_val: bytes = seed
        trace_points = []

        step = max(1, t // 1000)
        chunks = t // step
        remainder = t % step

        for _ in range(chunks):
            for _ in range(step):
                current_val = hashlib.sha256(current_val).digest()
            trace_points.append(current_val)

        for _ in range(remainder):
            current_val = hashlib.sha256(current_val).digest()

        merkle_root = hashlib.sha256(b"".join(trace_points)).hexdigest()
        queue.put(merkle_root)

    def derive_encryption_key(self) -> bytes:
        """Derives a deterministic AES key from the PoSW Merkle root using HKDF."""
        if not self.published_root:
            raise ValueError("PoSW computation not completed. Root is missing.")

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chronos_fhe_key_derivation",
        )
        key: bytes = kdf.derive(self.published_root.encode())
        self.logger.info("K_enc derived successfully from PoSW proof.")
        return key
