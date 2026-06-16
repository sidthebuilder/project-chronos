# mypy: ignore-errors
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chronos_agent import ChronosAgent


@pytest.mark.asyncio
class TestChronosAgent(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.mock_fhe = MagicMock()
        self.mock_posw = MagicMock()

        # Async mock for drand
        self.mock_drand = AsyncMock()

        # Setup FHE Mock
        self.mock_fhe.get_private_key_bytes.return_value = bytearray(b"MOCK_KEY_123")
        self.mock_fhe.encrypt_data.return_value = ("mock_ct1", "mock_ct2")
        self.mock_fhe.evaluate_inference.return_value = "mock_ct_out"

        # Setup Drand Mock
        self.mock_drand.fetch_latest_round.return_value = {"round": 100}

        # Initialize Agent
        self.agent = ChronosAgent(
            fhe_engine=self.mock_fhe,
            posw_manager=self.mock_posw,
            drand=self.mock_drand,
            mission_duration_sec=3,
        )

    async def test_initialization_calculates_target_round(self) -> None:
        """Test that the agent correctly calculates the async drand deadline."""
        await self.agent._initialize_target_deadline()
        self.assertEqual(self.agent.target_round, 101)  # 100 + max(1, 3 // 3)

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_run_mission_executes_state_machine(self, mock_zeroize) -> None:
        """Test the overarching async state machine executes in the correct order."""
        # Mock derive encryption key
        self.mock_posw.derive_encryption_key.return_value = b"k_enc_mock"

        # Mock CPU-bound compute
        self.mock_posw.compute_posw.return_value = None

        # Simulate the physical memory wipe since we are mocking it
        def mock_zeroize_side_effect(buffer):
            for i in range(len(buffer)):
                buffer[i] = 0

        mock_zeroize.side_effect = mock_zeroize_side_effect

        await self.agent.run_mission()

        # Assert FHE Inference was called
        self.mock_fhe.encrypt_data.assert_called_once()
        self.mock_fhe.evaluate_inference.assert_called()

        # Assert we waited for Drand
        self.mock_drand.wait_for_round.assert_called_with(101)

        # Assert Key Derived
        self.mock_posw.derive_encryption_key.assert_called_once()

        # Assert Memory Wiped
        mock_zeroize.assert_called_once()


if __name__ == "__main__":
    unittest.main()
