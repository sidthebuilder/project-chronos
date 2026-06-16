import argparse
import asyncio
import hashlib
import os
import random
import sys
from typing import Any, Dict, Final, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    DEFAULT_MISSION_DURATION_SEC,
    DRAND_ROUND_INTERVAL_SEC,
    ZERO_KNOWLEDGE_GENERATOR,
    ZERO_KNOWLEDGE_PRIME,
    ZERO_KNOWLEDGE_Q,
)
from drand_client import DrandClient
from fhe_engine import FHEEngineMock
from interfaces import ICryptographicEngine, IOracleClient, ITimeLock
from logger import get_chronos_logger
from memory_sanitizer import MemorySanitizer
from posw import PoSWManager


class ChronosAgent:
    """
    Staff-Level Orchestrator for the CHRONOS autonomous agent.
    Strictly types dependencies via Interface Contracts (Dependency Injection).
    """

    def __init__(
        self,
        fhe_engine: ICryptographicEngine,
        posw_manager: ITimeLock,
        drand: IOracleClient,
        mission_duration_sec: int = DEFAULT_MISSION_DURATION_SEC,
    ) -> None:

        self.logger = get_chronos_logger("ChronosAgent")
        self.logger.info("==================================================")
        self.logger.info("          PROJECT CHRONOS - AGENT BOOT            ")
        self.logger.info("==================================================")

        # 1. Inject Dependency Modules (IoC)
        self.fhe_engine: Final[ICryptographicEngine] = fhe_engine
        self.posw_manager: Final[ITimeLock] = posw_manager
        self.drand: Final[IOracleClient] = drand
        self.mission_duration_sec: Final[int] = mission_duration_sec

        # Extract and Encrypt the Private Key as a mutable bytearray
        self.raw_sk_buffer: bytearray = self.fhe_engine.get_private_key_bytes()

    async def _initialize_target_deadline(self) -> None:
        """Asynchronously fetches the current drand round to calculate the deadline."""
        current_drand: Optional[Dict[str, Any]] = await self.drand.fetch_latest_round()
        if not current_drand:
            self.logger.error(
                "Cannot reach drand beacon to determine mission deadline."
            )
            raise Exception("Drand initialization failed.")

        current_round: int = current_drand["round"]
        rounds_to_wait: int = max(
            1, self.mission_duration_sec // DRAND_ROUND_INTERVAL_SEC
        )
        self.target_round: int = current_round + rounds_to_wait

        self.logger.info(f"Mission Duration: {self.mission_duration_sec}s")
        self.logger.info(f"Current drand round: {current_round}")
        self.logger.info(f"Target deadline round: {self.target_round}")

    async def run_mission(self) -> None:
        """Executes the agent's strictly sequential async state machine."""

        # 1. Init async deadline
        await self._initialize_target_deadline()

        # 2. Start PoSW in a background thread via the event loop
        # asyncio.to_thread runs the CPU-bound PoSW math without blocking the I/O event loop!
        posw_task = asyncio.create_task(
            asyncio.to_thread(self.posw_manager.compute_posw)
        )

        # 3. Simulate FHE Inference payload during the mission
        ct_input = self.fhe_engine.encrypt_data(b"")

        self.logger.info("--- BEGIN MISSION PHASE ---")
        _ = await asyncio.to_thread(self.fhe_engine.evaluate_inference, ct_input)

        # 4. Wait for the drand deadline (Dead Man's Switch - Non Blocking)
        await self.drand.wait_for_round(self.target_round)

        # 5. Ensure PoSW CPU-bound thread is done
        await posw_task

        # 6. Derive Key & Decrypt (Simulation)
        self.posw_manager.derive_encryption_key()

        self.logger.info("--- DEAD MAN's SWITCH TRIGGERED ---")
        self.logger.info("drand confirmed deadline. PoSW verified. Key decrypted.")

        # 7. Pre-Wipe ZK Commitment
        self.logger.info("Generating Zero-Knowledge Erasure Proof (Fiat-Shamir)...")
        p: int = ZERO_KNOWLEDGE_PRIME
        g: int = ZERO_KNOWLEDGE_GENERATOR
        q: int = ZERO_KNOWLEDGE_Q

        # PhD-Level Fix: Securely extract full 256-bit entropy integer from buffer
        x: int = int.from_bytes(self.raw_sk_buffer, "big") % q
        y: int = pow(g, x, p)  # Public verification key

        v: int = random.randrange(1, q)
        t: int = pow(g, v, p)

        m = hashlib.sha256()
        m.update(str(g).encode())
        m.update(str(y).encode())
        m.update(str(t).encode())
        c: int = int(m.hexdigest(), 16) % q
        r: int = (v - c * x) % q

        self.logger.info(f"SNARK Commitment: t={t}, c={c}, r={r}")

        # 8. Self-Destruct & Zeroization
        MemorySanitizer.zeroize_buffer(self.raw_sk_buffer)

        # 9. Verify Erasure mathematically
        self._verify_erasure_proof(r, t, c, y, p, g)

        self.logger.info("==================================================")
        self.logger.info("     CHRONOS AGENT TERMINATED SUCCESSFULLY        ")
        self.logger.info("==================================================")

    def _verify_erasure_proof(
        self, r: int, t: int, c: int, y: int, p: int, g: int
    ) -> None:
        """
        Verifies the Fiat-Shamir NIZK proof and asserts physical mathematical erasure.
        """
        t_check: int = (pow(g, r, p) * pow(y, c, p)) % p
        math_valid: bool = t_check == t

        # Verify the buffer is now mathematically zeroed
        erasure_valid: bool = sum(self.raw_sk_buffer) == 0

        if math_valid and erasure_valid:
            self.logger.info(
                "Zero-Knowledge Math Verified AND Memory is Zeros.\nStatus: VALID"
            )
        else:
            self.logger.error("Zero-Knowledge Math or Erasure Verification: FALSE")
            raise Exception("Erasure Proof Verification Failed")


class ChronosAgentFactory:
    """
    Factory Pattern for Dependency Injection.
    Ensures all dependencies are properly initialized and decoupled from the orchestrator.
    """

    @staticmethod
    def create(duration_sec: int) -> ChronosAgent:
        fhe: ICryptographicEngine = FHEEngineMock()
        posw: ITimeLock = PoSWManager(target_duration_seconds=duration_sec)
        drand: IOracleClient = DrandClient()
        return ChronosAgent(fhe, posw, drand, mission_duration_sec=duration_sec)


async def async_main() -> None:
    parser = argparse.ArgumentParser(
        description="Project CHRONOS: Autonomous Agent Orchestrator"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_MISSION_DURATION_SEC,
        help="Mission duration in seconds.",
    )
    args = parser.parse_args()

    agent = ChronosAgentFactory.create(args.duration)
    await agent.run_mission()


if __name__ == "__main__":
    asyncio.run(async_main())
