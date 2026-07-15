"""
Project CHRONOS — Structured Logging

Provides a single factory function that returns a consistently-configured
logger for every subsystem.  Key design decisions:

- One handler per logger: calling get_chronos_logger() multiple times for
  the same name is safe — the guard prevents duplicate handlers.
- Log level is driven by the CHRONOS_LOG_LEVEL environment variable so that
  production deployments can suppress DEBUG output without touching code.
- The format includes the Unix timestamp in milliseconds so that log lines
  can be correlated with the PoSW timeline in post-incident analysis.
"""

import logging
import os
import sys


def get_chronos_logger(name: str) -> logging.Logger:
    """Return a configured logger for a CHRONOS subsystem.

    Args:
        name: Subsystem identifier that appears in every log line,
              e.g. "ChronosAgent", "PoSW", "FHE_Engine".

    Returns:
        A ``logging.Logger`` instance.  The first call for a given *name*
        attaches a StreamHandler; subsequent calls return the cached logger
        untouched.
    """
    logger = logging.getLogger(f"chronos.{name}")

    if logger.handlers:
        # Already configured — return immediately to prevent duplicate output.
        return logger

    raw_level = os.environ.get("CHRONOS_LOG_LEVEL", "DEBUG").upper()
    level = getattr(logging, raw_level, logging.DEBUG)

    logger.setLevel(level)
    logger.propagate = False  # Do not pass records up to the root logger.

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Include milliseconds so log lines can be correlated with PoSW timing.
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d  [%(name)-28s]  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
