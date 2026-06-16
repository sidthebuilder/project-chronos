"""
Custom exception definitions for CHRONOS security bounds.
"""


class ChronosSecurityException(Exception):
    """Base exception for all CHRONOS security violations."""

    pass


class TimeLockViolationError(ChronosSecurityException):
    """Raised when the agent attempts to access keys before PoSW unlocks."""

    pass


class OracleUnreachableError(ChronosSecurityException):
    """Raised when the drand oracle cannot be reached to verify constraints."""

    pass


class CryptographicSanityError(ChronosSecurityException):
    """Raised when internal cryptographic checks fail."""

    pass
