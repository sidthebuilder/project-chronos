"""
Project CHRONOS — Custom Exception Hierarchy

All security-related failures propagate through this typed exception tree,
giving callers the ability to catch at any granularity they need:

    ChronosSecurityException               (catch-all)
    ├── TimeLockViolationError             (PoSW / key-access failures)
    ├── OracleUnreachableError             (drand network failures)
    ├── CryptographicSanityError           (signature / proof failures)
    └── MemoryIntegrityError               (buffer / erasure failures)
"""


class ChronosSecurityException(Exception):
    """Base class for all CHRONOS security violations.

    Every exception in this module inherits from here so that callers can
    set a single broad except clause in top-level handlers while still
    letting specific handlers catch narrower types in subsystems.
    """


class TimeLockViolationError(ChronosSecurityException):
    """Raised when the agent attempts to access keys before PoSW unlocks.

    This represents a premature key-extraction attack (Game TR-1 in the
    security model).  Any code that catches this must NOT retry — the
    agent must be treated as compromised and terminated.
    """


class OracleUnreachableError(ChronosSecurityException):
    """Raised when the drand randomness beacon cannot be reached.

    The agent uses drand as an external time-reference (Dead Man's Switch).
    If the oracle is unreachable for longer than the configured retry window,
    the agent cannot verify its deadline and must abort.
    """


class CryptographicSanityError(ChronosSecurityException):
    """Raised when internal cryptographic invariants are violated.

    Examples:
    - BLS12-381 signature verification fails on a drand response
    - The Fiat-Shamir NIZK erasure proof does not verify
    - A URL scheme other than HTTPS is detected (SSRF guard)
    """


class MemoryIntegrityError(ChronosSecurityException):
    """Raised when the physical memory erasure protocol fails or is detected
    to be incomplete.

    After a zeroize call, if any byte in the buffer is non-zero the agent
    must raise this exception rather than silently continuing — leaving
    key material in RAM is a critical security failure.
    """
