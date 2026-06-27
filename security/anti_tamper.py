"""
Project CHRONOS — Anti-Tamper and Anti-Debugging Engine (§4.4)

This module implements the enterprise defence layer described in §4.4 of the
CHRONOS security model.  It runs as a background daemon thread that executes
heuristic checks every *check_interval* seconds.  On detection, it calls
os._exit(1) — bypassing all atexit handlers, signal handlers, and Python
finalizers that could be hooked by an attacker's instrumentation framework.

Heuristics implemented:
    1. sys.gettrace()          — catches pdb, pydevd, coverage.py, trace.py
    2. sys.getprofile()        — catches cProfile, yappi, line_profiler
    3. IsDebuggerPresent()     — Windows kernel32 API (WinDbg, x64dbg, OllyDbg)
    4. /proc/self/status       — Linux TracerPid field (strace, gdb, ptrace)
    5. Timing anomaly          — detects single-step execution via clock drift

Security design notes:
    - The daemon thread is marked daemon=True so it does not prevent the
      process from exiting normally.
    - _abort_process() calls MemorySanitizer to zero the key buffer BEFORE
      calling os._exit() — this is the critical path for the Dead Man's Switch
      in a tamper-detected scenario.
    - In a pytest / CI environment, set CHRONOS_DISABLE_ANTI_TAMPER=true to
      skip engine startup.  Never set this flag in production.
"""

import ctypes
import os
import sys
import threading
import time
from typing import List, Optional


class AntiTamperEngine:
    """Background daemon that continuously monitors for debugger attachment.

    The engine is started once and runs until the process exits or stop() is
    called explicitly.  Detection triggers an immediate, unconditional process
    abort with no error recovery.

    Args:
        check_interval:  Seconds between consecutive heuristic sweeps.
                         Lower values increase detection speed at the cost of
                         a marginal CPU overhead (~0.01% on modern hardware).
    """

    def __init__(self, check_interval: float = 0.5) -> None:
        self._check_interval: float = check_interval
        self._running: bool = False
        self._monitor_thread: Optional[threading.Thread] = None

        # Pre-initialize emergency buffer list here so register_emergency_buffer()
        # never needs to reach for object.__setattr__().
        self._emergency_buffers: List[bytearray] = []

        # Timing baseline — used for step-execution anomaly detection.
        # We record how long 10_000 tight arithmetic ops take; a debugger
        # single-stepping through that loop will inflate the measurement by
        # several orders of magnitude.
        self._timing_baseline_ns: int = self._measure_timing_baseline()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background monitor daemon thread.

        Idempotent — calling start() a second time has no effect.
        """
        if self._running:
            return
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="chronos-anti-tamper",
            daemon=True,
        )
        self._monitor_thread.start()

    def stop(self) -> None:
        """Signal the monitor thread to stop after its next sleep cycle.

        This is provided for clean shutdown in tests.  In production the thread
        terminates automatically when the process exits.
        """
        self._running = False

    # ------------------------------------------------------------------
    # Internal monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        while self._running:
            self._run_heuristics()
            time.sleep(self._check_interval)

    def _run_heuristics(self) -> None:
        """Execute all detection heuristics sequentially."""

        if self._detect_python_trace():
            self._abort_process("DEBUGGER_HOOK: sys.gettrace() returned non-None")

        if self._detect_python_profile():
            self._abort_process("PROFILER_HOOK: sys.getprofile() returned non-None")

        if self._detect_windows_debugger():
            self._abort_process("WINDOWS_DEBUGGER: IsDebuggerPresent() == TRUE")

        if self._detect_linux_tracer():
            self._abort_process("LINUX_PTRACE: TracerPid != 0 in /proc/self/status")

        if self._detect_timing_anomaly():
            self._abort_process(
                "TIMING_ANOMALY: execution rate inconsistent with hardware"
            )

    # ------------------------------------------------------------------
    # Heuristic implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_python_trace() -> bool:
        """Return True if a Python trace function is registered.

        Both pdb and most IDE debuggers (PyCharm, VS Code debugpy) install a
        trace function via sys.settrace().
        """
        return sys.gettrace() is not None

    @staticmethod
    def _detect_python_profile() -> bool:
        """Return True if a Python profile function is registered."""
        return sys.getprofile() is not None

    @staticmethod
    def _detect_windows_debugger() -> bool:
        """Query the Windows kernel for an attached debugger.

        kernel32.IsDebuggerPresent() returns 1 if the process was launched
        under a debugger or if a remote debugger has attached since startup.
        CheckRemoteDebuggerPresent() provides additional coverage for
        late-attach scenarios.
        """
        if os.name != "nt":
            return False
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined, unused-ignore]
            if kernel32.IsDebuggerPresent():
                return True
            # CheckRemoteDebuggerPresent covers WinDbg -pn late-attach
            is_remote = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(),
                ctypes.byref(is_remote),
            )
            return bool(is_remote.value)
        except Exception:
            return False

    @staticmethod
    def _detect_linux_tracer() -> bool:
        """Parse /proc/self/status for a non-zero TracerPid.

        A non-zero TracerPid means that another process (gdb, strace, ltrace)
        has attached via ptrace(2).  This is the standard anti-debug check on
        Linux used by commercial DRM and anti-cheat systems.
        """
        if os.name != "posix":
            return False
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split(":", 1)[1].strip())
                        return tracer_pid != 0
        except (OSError, ValueError):
            pass
        return False

    def _detect_timing_anomaly(self) -> bool:
        """Detect single-step execution via clock-cycle timing.

        We measure how long 10_000 tight arithmetic operations take and compare
        it against the baseline captured at init time.  If the ratio exceeds a
        threshold (e.g. 100×), the process is almost certainly being
        single-stepped by a debugger.
        """
        t0 = time.perf_counter_ns()
        x = 0
        for i in range(10_000):
            x ^= i * 31
        elapsed = time.perf_counter_ns() - t0

        # Guard against a zero baseline (should not happen, but be safe)
        if self._timing_baseline_ns == 0:
            return False

        ratio = elapsed / self._timing_baseline_ns
        # A factor of 50× or more indicates step-through execution.
        return ratio > 50.0

    @staticmethod
    def _measure_timing_baseline() -> int:
        """Measure how long 10_000 tight arithmetic ops take at init time.

        Returns:
            Elapsed time in nanoseconds.  Returns 0 if perf_counter_ns is
            unavailable (Python < 3.7, should never happen for this project).
        """
        t0 = time.perf_counter_ns()
        x = 0
        for i in range(10_000):
            x ^= i * 31
        _ = x  # prevent optimiser from eliding the loop
        return time.perf_counter_ns() - t0

    # ------------------------------------------------------------------
    # Abort
    # ------------------------------------------------------------------

    def _abort_process(self, reason: str) -> None:
        """Unconditional secure process abort.

        Steps (in order):
          1. Print a brief notice to stderr.
          2. Attempt emergency memory sanitization of any tracked buffers.
          3. Call os._exit(1) — this bypasses all Python cleanup so that
             hooked atexit handlers, finalizers, and except hooks cannot
             prevent termination.

        This method must NEVER raise an exception.
        """
        try:
            print(f"\n[CHRONOS] FATAL: {reason}", file=sys.stderr, flush=True)
            print(
                "[CHRONOS] Initiating emergency erasure and process abort.",
                file=sys.stderr,
                flush=True,
            )
        except Exception:
            pass

        # Best-effort: try to zeroize any sensitive memory before exiting.
        # We import here to avoid circular deps at module load time.
        try:
            from memory_sanitizer import MemorySanitizer  # noqa: PLC0415

            for buf in self._emergency_buffers:
                try:
                    MemorySanitizer.zeroize_buffer(buf)
                except Exception:
                    pass
        except Exception:
            pass

        os._exit(1)

    def register_emergency_buffer(self, buf: bytearray) -> None:
        """Register a key buffer to be zeroized on tamper-detection abort.

        Call this immediately after allocating the raw_sk_buffer in the agent
        so that even in a tamper-detected abort path the key material is wiped.

        Args:
            buf: A mutable bytearray containing sensitive key material.

        Raises:
            TypeError: If buf is not a bytearray.
        """
        if not isinstance(buf, bytearray):
            raise TypeError(
                f"register_emergency_buffer requires a bytearray; "
                f"got {type(buf).__name__!r}."
            )
        self._emergency_buffers.append(buf)
