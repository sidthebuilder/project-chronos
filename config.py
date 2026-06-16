"""
Configuration module for Project CHRONOS.
Uses Pydantic BaseSettings for strict runtime type checking and environment validation.
"""

from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ChronosSettings(BaseSettings):  # type: ignore
    """
    Strictly typed configuration object defining all cryptographic parameters.
    Values can be overridden securely via Environment Variables.
    """

    mission_duration_sec: int = Field(
        10, gt=0, description="Default active lifespan of the agent."
    )
    drand_round_interval_sec: int = Field(
        3, gt=0, description="Drand network round interval."
    )
    drand_public_api: str = Field(
        "https://api.drand.sh/public/latest", description="Drand HTTP Endpoint."
    )
    drand_timeout_sec: int = Field(5, gt=0, description="Timeout for Drand API calls.")
    rsa_key_size_bits: int = Field(
        1024, ge=1024, description="Key size for the underlying Paillier cryptosystem."
    )
    zero_knowledge_generator: int = Field(
        2, description="Generator g for the ZK prime-order subgroup."
    )
    zero_knowledge_prime: int = Field(
        int(
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
        description="RFC 3526 2048-bit MODP Group Safe Prime (p).",
    )
    zero_knowledge_q: int = Field(
        0, description="The order of the prime subgroup (q = (p-1)/2)."
    )

    model_config = SettingsConfigDict(env_prefix="CHRONOS_")


# Singleton instance
settings: Final[ChronosSettings] = ChronosSettings()

# Legacy exports for backwards compatibility with existing modules
DEFAULT_MISSION_DURATION_SEC = settings.mission_duration_sec
DRAND_ROUND_INTERVAL_SEC = settings.drand_round_interval_sec
DRAND_PUBLIC_API = settings.drand_public_api
DRAND_TIMEOUT_SEC = settings.drand_timeout_sec
RSA_KEY_SIZE_BITS = settings.rsa_key_size_bits
ZERO_KNOWLEDGE_GENERATOR = settings.zero_knowledge_generator
ZERO_KNOWLEDGE_PRIME = settings.zero_knowledge_prime
ZERO_KNOWLEDGE_Q = (ZERO_KNOWLEDGE_PRIME - 1) // 2
