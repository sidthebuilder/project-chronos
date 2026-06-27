# mypy: ignore-errors
"""Tests for the drand Oracle Client.

Covers the asynchronous fetch, SSRF protection, wait-for-round polling
logic, network error handling, and BLS signature validation.

All tests use AsyncMock and patch() to avoid any real network calls.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import RequestError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drand_client import DrandClient  # noqa: E402
from exceptions import CryptographicSanityError, OracleUnreachableError  # noqa: E402

# A well-formed BLS12-381 G1 signature in hex (96 hex chars = 48 bytes)
_VALID_SIG = "a" * 96

# A well-formed drand round dict
_VALID_ROUND = {
    "round": 1_000_000,
    "randomness": "bb" * 32,
    "signature": _VALID_SIG,
    "previous_signature": "cc" * 48,
}


@pytest.mark.asyncio
class TestDrandClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        # Disable anti-tamper in tests
        os.environ["CHRONOS_DISABLE_ANTI_TAMPER"] = "true"
        self.client = DrandClient()

    def tearDown(self) -> None:
        os.environ.pop("CHRONOS_DISABLE_ANTI_TAMPER", None)

    # --- fetch_latest_round -----------------------------------------------

    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_fetch_latest_round_success(self, mock_get: AsyncMock) -> None:
        """Valid API response is parsed and returned as a dict."""
        mock_response = MagicMock()
        mock_response.json.return_value = _VALID_ROUND.copy()
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        data = await self.client.fetch_latest_round()

        self.assertIsNotNone(data)
        self.assertEqual(data["round"], 1_000_000)

    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_fetch_raises_on_network_error(self, mock_get: AsyncMock) -> None:
        """A network error must raise OracleUnreachableError, not propagate raw httpx."""
        mock_get.side_effect = RequestError("Connection refused", request=MagicMock())

        with self.assertRaises(OracleUnreachableError):
            await self.client.fetch_latest_round()

    # --- SSRF protection --------------------------------------------------

    async def test_ssrf_http_scheme_blocked(self) -> None:
        """HTTP URLs must be rejected with CryptographicSanityError."""
        from security.secure_string import ObfuscatedString

        self.client._obfuscated_url = ObfuscatedString("http://evil.internal/data")

        with self.assertRaises(CryptographicSanityError):
            await self.client.fetch_latest_round()

    async def test_ssrf_ftp_scheme_blocked(self) -> None:
        """FTP URLs must be rejected with CryptographicSanityError."""
        from security.secure_string import ObfuscatedString

        self.client._obfuscated_url = ObfuscatedString("ftp://192.168.1.1/secret")

        with self.assertRaises(CryptographicSanityError):
            await self.client.fetch_latest_round()

    # --- BLS signature verification ---------------------------------------

    def test_valid_bls_signature_passes_format_check(self) -> None:
        """A correctly-formatted 96-char hex signature must pass the format check."""
        self.client._verify_bls_signature(_VALID_ROUND)  # Should not raise.

    def test_short_signature_raises(self) -> None:
        """A signature shorter than 96 hex chars must raise CryptographicSanityError."""
        bad_round = {**_VALID_ROUND, "signature": "aa" * 10}
        with self.assertRaises(CryptographicSanityError):
            self.client._verify_bls_signature(bad_round)

    def test_non_hex_signature_raises(self) -> None:
        """A signature containing non-hex characters must raise CryptographicSanityError."""
        bad_round = {**_VALID_ROUND, "signature": "z" * 96}
        with self.assertRaises(CryptographicSanityError):
            self.client._verify_bls_signature(bad_round)

    def test_empty_signature_raises(self) -> None:
        """An empty signature field must raise CryptographicSanityError."""
        bad_round = {**_VALID_ROUND, "signature": ""}
        with self.assertRaises(CryptographicSanityError):
            self.client._verify_bls_signature(bad_round)

    # --- wait_for_round ---------------------------------------------------

    @patch("drand_client.DrandClient.fetch_latest_round", new_callable=AsyncMock)
    @patch("drand_client.DrandClient._verify_bls_signature")
    async def test_wait_for_round_polls_until_target(
        self, mock_verify: MagicMock, mock_fetch: AsyncMock
    ) -> None:
        """wait_for_round() must poll until the target round is >= requested."""
        mock_fetch.side_effect = [
            {"round": 100, "signature": _VALID_SIG},
            {"round": 101, "signature": _VALID_SIG},
            {"round": 102, "signature": _VALID_SIG},  # target
        ]
        mock_verify.return_value = None  # No-op (format check pass)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await self.client.wait_for_round(102, polling_interval=1)

        self.assertEqual(mock_fetch.call_count, 3)
        self.assertEqual(result["round"], 102)

    @patch("drand_client.DrandClient.fetch_latest_round", new_callable=AsyncMock)
    @patch("drand_client.DrandClient._verify_bls_signature")
    async def test_wait_for_round_accepts_higher_round(
        self, mock_verify: MagicMock, mock_fetch: AsyncMock
    ) -> None:
        """wait_for_round() must accept a round number GREATER than the target too."""
        mock_fetch.return_value = {"round": 150, "signature": _VALID_SIG}
        mock_verify.return_value = None

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await self.client.wait_for_round(100, polling_interval=1)

        self.assertGreaterEqual(result["round"], 100)

    @patch("drand_client.DrandClient.fetch_latest_round", new_callable=AsyncMock)
    async def test_wait_for_round_retries_on_oracle_error(
        self, mock_fetch: AsyncMock
    ) -> None:
        """wait_for_round() must retry (not raise) when OracleUnreachableError is thrown."""
        mock_fetch.side_effect = [
            OracleUnreachableError("timeout"),
            OracleUnreachableError("timeout"),
            {"round": 200, "signature": _VALID_SIG},
        ]

        with patch("asyncio.sleep", new_callable=AsyncMock), patch.object(
            self.client, "_verify_bls_signature"
        ):
            result = await self.client.wait_for_round(200, polling_interval=1)

        self.assertEqual(result["round"], 200)
        self.assertEqual(mock_fetch.call_count, 3)


if __name__ == "__main__":
    unittest.main()
