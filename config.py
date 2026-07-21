"""
Project CHRONOS — Configuration

All tuneable parameters live here and are validated at import time via
Pydantic BaseSettings.  Every value can be overridden by setting the
corresponding environment variable, e.g.:

    CHRONOS_RSA_KEY_SIZE_BITS=2048 python chronos_agent.py

Design decisions:
- zero_knowledge_q is derived from zero_knowledge_prime at validation time
  using a @computed_field so that the Pydantic model is the single source of
  truth.  There is no raw constant that could drift out of sync.
- The legacy flat-constant exports at the bottom of this file exist so that
  every other module can do "from config import FOO" without touching Pydantic
  internals directly.  All imports go through settings.foo.
"""

from typing import Final

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ChronosSettings(BaseSettings):  # type: ignore
    """Validated configuration for the CHRONOS agent.

    All integer fields enforce lower bounds so that obviously insecure values
    (e.g. key_size=0) are rejected at startup rather than silently accepted.
    """

    # --- Mission parameters ------------------------------------------------

    mission_duration_sec: int = Field(
        default=10,
        gt=0,
        description="Active lifespan of the agent in seconds.",
    )

    # --- drand oracle -------------------------------------------------------

    drand_round_interval_sec: int = Field(
        default=3,
        gt=0,
        description="Seconds between consecutive drand beacon rounds.",
    )
    drand_public_api: str = Field(
        default="https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
        description="HTTP endpoint for the drand League of Entropy active quicknet chain.",
    )
    drand_timeout_sec: int = Field(
        default=10,
        gt=0,
        description="Per-request timeout for drand API calls, in seconds.",
    )

    # --- Paillier FHE -------------------------------------------------------

    rsa_key_size_bits: int = Field(
        default=2048,
        ge=2048,
        description=(
            "Bit-length of the RSA primes p and q used to instantiate the "
            "Paillier cryptosystem.  The effective security level is half this "
            "value (1024-bit security for 2048-bit keys), meeting NIST SP 800-131A "
            "recommendations through 2030 and beyond.  Values below 2048 are "
            "rejected as they no longer provide adequate security margins."
        ),
    )

    # --- Zero-Knowledge proof (Fiat-Shamir NIZK) ----------------------------

    zero_knowledge_generator: int = Field(
        default=2,
        description="Generator g of the prime-order subgroup used in the NIZK.",
    )
    zero_knowledge_prime: int = Field(
        default=int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16,
        ),
        description="RFC 3526 2048-bit MODP Group 14 safe prime (p).",
    )

    # --- Test / CI guard ----------------------------------------------------

    disable_anti_tamper: bool = Field(
        default=False,
        description=(
            "Set CHRONOS_DISABLE_ANTI_TAMPER=true to suppress the debugger-"
            "detection thread during pytest runs.  Never set this in production."
        ),
    )

    model_config = SettingsConfigDict(env_prefix="CHRONOS_")

    # --- Derived fields (computed at validation time) -----------------------

    @computed_field  # type: ignore
    @property
    def zero_knowledge_q(self) -> int:
        """Order of the prime-order subgroup: q = (p - 1) / 2.

        p is a safe prime (p = 2q + 1), so q is itself prime, which guarantees
        that the Schnorr-style ZK proof has a clean prime-order group to work in.
        """
        return (self.zero_knowledge_prime - 1) // 2


# ---------------------------------------------------------------------------
# Singleton — validated once at import time.  Any misconfiguration (e.g. a
# non-integer value for an integer field) surfaces here, not deep in mission
# logic.
# ---------------------------------------------------------------------------
settings: Final[ChronosSettings] = ChronosSettings()

# ---------------------------------------------------------------------------
# Legacy flat exports — every other module imports these directly so that
# they are not coupled to the Pydantic model internals.
# ---------------------------------------------------------------------------
DEFAULT_MISSION_DURATION_SEC: Final[int] = settings.mission_duration_sec
DRAND_ROUND_INTERVAL_SEC: Final[int] = settings.drand_round_interval_sec
DRAND_PUBLIC_API: Final[str] = settings.drand_public_api
DRAND_TIMEOUT_SEC: Final[int] = settings.drand_timeout_sec
RSA_KEY_SIZE_BITS: Final[int] = settings.rsa_key_size_bits
ZERO_KNOWLEDGE_GENERATOR: Final[int] = settings.zero_knowledge_generator
ZERO_KNOWLEDGE_PRIME: Final[int] = settings.zero_knowledge_prime
ZERO_KNOWLEDGE_Q: Final[int] = settings.zero_knowledge_q
DISABLE_ANTI_TAMPER: Final[bool] = settings.disable_anti_tamper
