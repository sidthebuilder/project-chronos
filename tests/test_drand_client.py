# mypy: ignore-errors
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import RequestError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drand_client import DrandClient
from exceptions import CryptographicSanityError, OracleUnreachableError


@pytest.mark.asyncio
class TestDrandClient(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.client = DrandClient()

    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_fetch_latest_round_success(self, mock_get) -> None:
        """Test valid drand response parsing via async httpx."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "round": 6206626,
            "randomness": "test_randomness",
            "signature": "test_signature",
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        data = await self.client.fetch_latest_round()
        self.assertIsNotNone(data)
        self.assertEqual(data["round"], 6206626)

    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_fetch_latest_round_failure(self, mock_get) -> None:
        """Test drand fallback gracefully on network failure."""
        mock_get.side_effect = RequestError("Network offline", request=MagicMock())
        with self.assertRaises(OracleUnreachableError):
            await self.client.fetch_latest_round()

    async def test_ssrf_vulnerability_blocked(self) -> None:
        """Test that injecting a local file scheme is mathematically blocked."""
        self.client.api_url = "file:///etc/shadow"
        with self.assertRaises(CryptographicSanityError) as context:
            await self.client.fetch_latest_round()
        self.assertIn("Invalid Drand API URL scheme", str(context.exception))

    async def test_ssrf_vulnerability_blocked_ftp(self) -> None:
        """Test that injecting ftp scheme is blocked."""
        self.client.api_url = "ftp://internal.server/data"
        with self.assertRaises(CryptographicSanityError):
            await self.client.fetch_latest_round()

    @patch("drand_client.DrandClient.fetch_latest_round", new_callable=AsyncMock)
    @patch("drand_client.DrandClient._verify_bls_signature", return_value=True)
    async def test_wait_for_round(self, mock_verify, mock_fetch) -> None:
        """Test waiting logic correctly loops until target round is hit using async sleep."""
        # Simulating time passing by mocking drand to return increasing rounds
        mock_fetch.side_effect = [
            {"round": 100, "signature": "sig1"},
            {"round": 101, "signature": "sig2"},
            {"round": 102, "signature": "sig_target"},
        ]

        # Patch sleep to not actually sleep during unit tests
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await self.client.wait_for_round(102)

        self.assertEqual(mock_fetch.call_count, 3)


if __name__ == "__main__":
    unittest.main()
