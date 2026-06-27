# mypy: ignore-errors
"""Integration tests for the ChronosAgent orchestrator.

All real subsystems (FHE, PoSW, drand) are replaced with precise mocks so
these tests run in milliseconds with no network I/O or CPU-bound computation.

Tests verify:
    - Correct deadline calculation from drand round data.
    - The full async state machine executes all five phases in sequence.
    - The ZK proof is generated and verified correctly.
    - Memory wipe is called exactly once.
    - The correct round number is awaited from the drand oracle.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Suppress the anti-tamper engine in all tests — it would fire on pytest's trace hook.
os.environ["CHRONOS_DISABLE_ANTI_TAMPER"] = "true"

from chronos_agent import ChronosAgent  # noqa: E402


def _make_agent(duration_sec: int = 3) -> ChronosAgent:
    """Build a ChronosAgent with fully mocked subsystem dependencies."""
    mock_fhe = MagicMock()
    mock_posw = MagicMock()
    mock_drand = AsyncMock()

    # FHE mock — provides a zeroisable key buffer
    mock_fhe.get_private_key_bytes.return_value = bytearray(
        b"MOCK_SECRET_KEY_32BYTES_PADDING!"
    )
    mock_fhe.encrypt_data.return_value = (111, 222)
    mock_fhe.evaluate_inference.return_value = 333

    # drand mock — reports current round as 1000
    mock_drand.fetch_latest_round.return_value = {"round": 1000, "signature": "a" * 96}
    mock_drand.wait_for_round.return_value = {"round": 1001, "signature": "a" * 96}

    # PoSW mock — compute_posw is synchronous void, derive_encryption_key returns bytes
    mock_posw.compute_posw.return_value = None
    mock_posw.derive_encryption_key.return_value = b"\x00" * 32

    return ChronosAgent(
        fhe_engine=mock_fhe,
        posw_manager=mock_posw,
        drand=mock_drand,
        mission_duration_sec=duration_sec,
    )


@pytest.mark.asyncio
class TestChronosAgentDeadline(unittest.IsolatedAsyncioTestCase):

    async def test_deadline_calculation(self) -> None:
        """Target round = current_round + ceil(duration / interval)."""
        agent = _make_agent(duration_sec=3)
        await agent._initialise_target_deadline()
        # duration=3s, interval=3s → 1 additional round → 1000 + 1 = 1001
        self.assertEqual(agent.target_round, 1001)

    async def test_deadline_rounds_up_short_duration(self) -> None:
        """Even a 1-second duration must wait at least 1 round (max(1, ...))."""
        agent = _make_agent(duration_sec=1)
        await agent._initialise_target_deadline()
        self.assertGreaterEqual(agent.target_round, 1001)


@pytest.mark.asyncio
class TestChronosAgentMission(unittest.IsolatedAsyncioTestCase):

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_full_mission_state_machine(self, mock_wipe: MagicMock) -> None:
        """The five-phase state machine must execute all steps in sequence."""

        # We need zeroize_buffer to actually zero the buffer or the proof will fail.
        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent(duration_sec=3)
        await agent.run_mission()

        # Phase 2 — FHE inference ran
        agent.fhe_engine.encrypt_data.assert_called_once()
        agent.fhe_engine.evaluate_inference.assert_called_once_with((111, 222))

        # Phase 3 — Waited for the correct drand round
        agent.drand.wait_for_round.assert_called_once_with(1001)

        # Phase 4a — PoSW key derived
        agent.posw_manager.derive_encryption_key.assert_called_once()

        # Phase 4c — Memory wipe executed exactly once
        mock_wipe.assert_called_once_with(agent.raw_sk_buffer)

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_buffer_is_zeroed_after_mission(self, mock_wipe: MagicMock) -> None:
        """raw_sk_buffer must be all zeros after the mission completes."""

        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent(duration_sec=3)
        await agent.run_mission()

        self.assertTrue(
            all(b == 0 for b in agent.raw_sk_buffer),
            "SK buffer still contains non-zero bytes after mission completion.",
        )

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_wipe_called_exactly_once(self, mock_wipe: MagicMock) -> None:
        """The memory wipe must be called exactly once, not zero or multiple times."""

        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent(duration_sec=3)
        await agent.run_mission()

        self.assertEqual(
            mock_wipe.call_count,
            1,
            f"zeroize_buffer was called {mock_wipe.call_count} times; expected exactly 1.",
        )


if __name__ == "__main__":
    unittest.main()
