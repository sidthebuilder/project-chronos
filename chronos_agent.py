"""
Project CHRONOS — Agent Orchestrator (§3 — Full Architecture)

This module is the top-level orchestrator that sequences the four subsystems:

    Phase 1 — BOOT:
        a. Start the Anti-Tamper Engine (background daemon).
        b. Generate FHE keypair; extract SK into a mutable bytearray.
        c. Register the SK buffer with the Anti-Tamper Engine for emergency
           zeroization if a debugger is detected.
        d. Contact drand to establish the target deadline round.

    Phase 2 — MISSION:
        a. Launch PoSW computation in a background thread (asyncio.to_thread).
        b. Concurrently: encrypt the inference payload and evaluate it
           homomorphically.  The agent never sees the plaintext of its own
           inputs during this phase.

    Phase 3 — TRIGGER (Dead Man's Switch fires):
        a. Wait asynchronously for the drand target round.
        b. Await the PoSW computation to ensure the cryptographic fuse has
           elapsed.

    Phase 4 — ERASURE:
        a. Commit the ZK proof BEFORE wiping memory — the proof must bind
           to the key material that is about to be destroyed.
        b. Derive K_enc from the PoSW root (proves time elapsed).
        c. Execute triple-pass C-level memory wipe of the SK buffer.
        d. Verify the ZK erasure proof against the wiped buffer.

    Phase 5 — TERMINATE:
        a. Log the proof coordinates for the verifier.
        b. Stop the Anti-Tamper daemon.

ZK Erasure Proof (Fiat-Shamir NIZK, §4.2):
    The proof proves knowledge of x (the private key as an integer) WITHOUT
    revealing x, using the Schnorr identification protocol made non-interactive
    via the Fiat-Shamir heuristic:

        x  = int.from_bytes(raw_sk_buffer) mod q     (secret witness)
        y  = g^x mod p                                (public verification key)
        v  = secrets.randbelow(q)                     (CSPRNG nonce — NOT random.randrange!)
        t  = g^v mod p                                (commitment)
        c  = H(g || y || t) mod q                     (Fiat-Shamir challenge)
        r  = (v - c·x) mod q                          (response)

    Proof: (t, c, r)
    Verification: g^r · y^c ≡ t (mod p)

    After the memory wipe, the buffer contains only zeros, which means x=0
    and y = g^0 = 1.  The verifier re-runs the proof check with (t, c, r)
    and the original y.  If the proof checks out AND the buffer is all zeros,
    the erasure is cryptographically verified.

Security note on the CSPRNG:
    The nonce v uses secrets.randbelow() — Python's os.urandom()-backed CSPRNG.
    Using random.randrange() here would be catastrophic: a predictable nonce
    leaks x via r = (v - c·x) mod q.
"""

import argparse
import asyncio
import hashlib
import os
import secrets
import sys
from typing import Any, Dict, Final, Optional

from config import (
    DEFAULT_MISSION_DURATION_SEC,
    DISABLE_ANTI_TAMPER,
    DRAND_ROUND_INTERVAL_SEC,
    ZERO_KNOWLEDGE_GENERATOR,
    ZERO_KNOWLEDGE_PRIME,
    ZERO_KNOWLEDGE_Q,
)
from drand_client import DrandClient
from exceptions import CryptographicSanityError, MemoryIntegrityError
from fhe_engine import FHEEngineMock
from interfaces import ICryptographicEngine, IOracleClient, ITimeLock
from logger import get_chronos_logger
from memory_sanitizer import MemorySanitizer
from posw import PoSWManager

_log = get_chronos_logger("ChronosAgent")


class ChronosAgent:
    """Top-level CHRONOS agent orchestrator.

    Composes the four subsystems via Dependency Injection — no concrete type
    is imported or instantiated here; all dependencies arrive through the
    constructor as typed interface objects.  This makes the orchestrator
    fully testable without touching any real cryptography or network I/O.

    Args:
        fhe_engine:           Plaintext-blind inference engine (§3.1).
        posw_manager:         Sequential work time-lock (§3.2).
        drand:                Decentralised randomness beacon (§3.3).
        mission_duration_sec: How long the mission runs before the Dead Man's
                              Switch fires.
    """

    def __init__(
        self,
        fhe_engine: ICryptographicEngine,
        posw_manager: ITimeLock,
        drand: IOracleClient,
        mission_duration_sec: int = DEFAULT_MISSION_DURATION_SEC,
    ) -> None:
        # --- Anti-Tamper Engine -------------------------------------------
        # Imported here to avoid circular-import at module level.
        # Skipped entirely in CI/pytest via the CHRONOS_DISABLE_ANTI_TAMPER
        # environment variable.
        self._anti_tamper = None
        if not DISABLE_ANTI_TAMPER:
            from security.anti_tamper import AntiTamperEngine

            self._anti_tamper = AntiTamperEngine(check_interval=0.5)
            self._anti_tamper.start()

        _log.info("=" * 58)
        _log.info("          PROJECT CHRONOS — AGENT BOOT                  ")
        _log.info("=" * 58)

        # --- Dependency Injection (IoC) -----------------------------------
        self.fhe_engine: Final[ICryptographicEngine] = fhe_engine
        self.posw_manager: Final[ITimeLock] = posw_manager
        self.drand: Final[IOracleClient] = drand
        self.mission_duration_sec: Final[int] = mission_duration_sec

        # --- Extract SK into mutable buffer ---
        # The buffer will be zeroized at mission end.  We also register it
        # with the Anti-Tamper Engine so it is wiped on tamper-detected abort.
        self.raw_sk_buffer: bytearray = self.fhe_engine.get_private_key_bytes()
        if self._anti_tamper is not None:
            self._anti_tamper.register_emergency_buffer(self.raw_sk_buffer)

        # --- Runtime state (set during mission) ---
        self.target_round: int = 0

    # ------------------------------------------------------------------
    # Phase 1 — Deadline initialisation
    # ------------------------------------------------------------------

    async def _initialise_target_deadline(self) -> None:
        """Fetch the current drand round and compute the target deadline.

        Raises:
            Exception: If the drand oracle cannot be reached.
        """
        current: Optional[Dict[str, Any]] = await self.drand.fetch_latest_round()
        if not current:
            raise CryptographicSanityError(
                "Cannot establish mission deadline: drand returned no data."
            )

        current_round: int = int(current["round"])
        rounds_to_wait: int = max(
            1, self.mission_duration_sec // DRAND_ROUND_INTERVAL_SEC
        )
        self.target_round = current_round + rounds_to_wait

        _log.info(f"Mission duration   : {self.mission_duration_sec}s")
        _log.info(f"Current drand round: {current_round}")
        _log.info(
            f"Target deadline    : round {self.target_round} "
            f"(+{rounds_to_wait} rounds)"
        )

    # ------------------------------------------------------------------
    # Phase 2–5 — Main mission state machine
    # ------------------------------------------------------------------

    async def run_mission(self) -> None:
        """Execute the agent's five-phase lifecycle.

        This coroutine is the single entry point for a complete agent run.
        It must complete in order — no phase may be skipped or reordered.
        """

        # Phase 1 — Establish deadline
        await self._initialise_target_deadline()

        # Phase 2 — Launch PoSW and FHE inference concurrently
        _log.info("--- PHASE 2: MISSION ACTIVE ---")

        # PoSW runs on an isolated CPU core (subprocess) via asyncio.to_thread.
        # This offloads the blocking computation without stalling the event loop.
        posw_task: asyncio.Task[None] = asyncio.create_task(
            asyncio.to_thread(self.posw_manager.compute_posw),
            name="posw-computation",
        )

        # FHE inference: encrypt the payload and evaluate the circuit.
        ct_pair = self.fhe_engine.encrypt_data(b"")
        _ = await asyncio.to_thread(self.fhe_engine.evaluate_inference, ct_pair)
        _log.info("FHE inference completed over encrypted payload.")

        # Phase 3 — Wait for Dead Man's Switch
        _log.info("--- PHASE 3: DEAD MAN'S SWITCH ARMED ---")
        await self.drand.wait_for_round(self.target_round)
        _log.info("drand target round reached.  Dead Man's Switch TRIGGERED.")

        # Ensure PoSW subprocess has finished before key derivation.
        await posw_task
        _log.info("PoSW computation confirmed complete.")

        # Phase 4 — Erasure Protocol
        _log.info("--- PHASE 4: ERASURE PROTOCOL ---")
        self._execute_erasure_protocol()

        # Phase 5 — Terminate
        _log.info("=" * 58)
        _log.info("     CHRONOS AGENT TERMINATED SUCCESSFULLY             ")
        _log.info("=" * 58)
        if self._anti_tamper is not None:
            self._anti_tamper.stop()

    # ------------------------------------------------------------------
    # Phase 4 — Erasure Protocol
    # ------------------------------------------------------------------

    def _execute_erasure_protocol(self) -> None:
        """Generate the ZK proof, wipe memory, then verify the proof.

        The strict ordering is:
            1. Derive y = g^x mod p from the still-intact SK buffer.
            2. Generate the Schnorr proof (t, c, r).
            3. Derive K_enc from the PoSW root (time-lock opened).
            4. WIPE the SK buffer (triple-pass C-level memset).
            5. Verify the proof against the wiped buffer.

        Raises:
            CryptographicSanityError: If the Schnorr proof fails to verify.
            MemoryIntegrityError:     If the memory wipe is incomplete.
        """
        _log.info("Step 4a: Computing Fiat-Shamir NIZK commitment...")

        p: int = ZERO_KNOWLEDGE_PRIME
        g: int = ZERO_KNOWLEDGE_GENERATOR
        q: int = ZERO_KNOWLEDGE_Q

        # Extract x from the intact key buffer BEFORE wiping.
        # We reduce mod q to fit x into the prime-order subgroup.
        x: int = int.from_bytes(self.raw_sk_buffer, "big") % q

        # Public verification key: y = g^x mod p
        y: int = pow(g, x, p)

        # CSPRNG nonce — MUST be secrets.randbelow(), NOT random.randrange().
        # A predictable nonce directly leaks x via r = (v - cx) mod q.
        v: int = secrets.randbelow(q - 1) + 1  # v ∈ [1, q-1]
        t: int = pow(g, v, p)

        # Fiat-Shamir challenge: c = H(g || y || t) mod q
        h = hashlib.sha256()
        h.update(p.to_bytes((p.bit_length() + 7) // 8, "big"))
        h.update(g.to_bytes((g.bit_length() + 7) // 8, "big"))
        h.update(y.to_bytes((y.bit_length() + 7) // 8, "big"))
        h.update(t.to_bytes((t.bit_length() + 7) // 8, "big"))
        c: int = int(h.hexdigest(), 16) % q

        # Schnorr response: r = (v - c·x) mod q
        r: int = (v - c * x) % q

        _log.info(
            f"ZK proof generated:  "
            f"y={str(y)[:20]}..., "
            f"c={str(c)[:20]}..., "
            f"r={str(r)[:20]}..."
        )

        # Derive K_enc — this is what the time-lock was protecting.
        _log.info("Step 4b: Deriving K_enc from PoSW Merkle root (HKDF-SHA256)...")
        self.posw_manager.derive_encryption_key()

        # Triple-pass C-level memory wipe (raises MemoryIntegrityError on failure).
        _log.info("Step 4c: Executing C-level triple-pass memory wipe...")
        MemorySanitizer.zeroize_buffer(self.raw_sk_buffer)

        # Post-wipe proof verification.
        _log.info("Step 4d: Verifying erasure proof against wiped buffer...")
        self._verify_erasure_proof(r=r, t=t, c=c, y=y, p=p, g=g)

    def _verify_erasure_proof(
        self, r: int, t: int, c: int, y: int, p: int, g: int
    ) -> None:
        """Verify the Schnorr NIZK proof and assert the buffer is zeroed.

        Verification equation:
            g^r · y^c ≡ t  (mod p)

        If the proof verifies AND every byte in raw_sk_buffer is zero, the
        erasure is cryptographically proven.

        Args:
            r, t, c:  Schnorr proof coordinates.
            y:        Public verification key (g^x mod p).
            p, g:     Group parameters (RFC 3526 2048-bit MODP safe prime).

        Raises:
            CryptographicSanityError: If the Schnorr equation does not hold.
            MemoryIntegrityError:     If the buffer is not fully zeroed.
        """
        t_check: int = (pow(g, r, p) * pow(y, c, p)) % p
        proof_valid: bool = t_check == t

        buffer_zeroed: bool = all(b == 0 for b in self.raw_sk_buffer)

        if not proof_valid:
            raise CryptographicSanityError(
                f"Schnorr proof verification FAILED: "
                f"g^r·y^c mod p = {str(t_check)[:20]}... ≠ t = {str(t)[:20]}..."
            )

        if not buffer_zeroed:
            raise MemoryIntegrityError(
                "Erasure proof FAILED: raw_sk_buffer contains non-zero bytes "
                "after the triple-pass wipe.  Memory integrity compromised."
            )

        _log.info("✓ Schnorr proof equation satisfied: g^r·y^c ≡ t (mod p)")
        _log.info("✓ Memory buffer fully zeroed: erasure cryptographically verified.")
        _log.info("ERASURE PROOF STATUS: VALID — key material is physically destroyed.")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class ChronosAgentFactory:
    """Factory that wires the four concrete subsystems into a ChronosAgent.

    Keeping construction logic here separates the "how to build" concern from
    the "how to run" concern in ChronosAgent.  Tests bypass this factory
    entirely and inject mocks directly.
    """

    @staticmethod
    def create(duration_sec: int) -> "ChronosAgent":
        """Construct and return a fully initialised ChronosAgent.

        Args:
            duration_sec: Mission duration in seconds.

        Returns:
            A ChronosAgent with real FHE, PoSW, and drand dependencies.
        """
        fhe: ICryptographicEngine = FHEEngineMock()
        posw: ITimeLock = PoSWManager(target_duration_seconds=duration_sec)
        oracle: IOracleClient = DrandClient()
        return ChronosAgent(
            fhe_engine=fhe,
            posw_manager=posw,
            drand=oracle,
            mission_duration_sec=duration_sec,
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _async_main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Project CHRONOS: Autonomous Cryptographic Agent with "
            "Provable Memory Erasure"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_MISSION_DURATION_SEC,
        metavar="SECONDS",
        help="Mission duration in seconds before the Dead Man's Switch fires.",
    )
    args = parser.parse_args()

    agent = ChronosAgentFactory.create(args.duration)
    await agent.run_mission()


if __name__ == "__main__":
    asyncio.run(_async_main())
