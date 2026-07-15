"""
Project CHRONOS — Benchmark Runner

Measures and reports real performance metrics for all four CHRONOS subsystems
over multiple runs with proper statistical analysis (mean, std, 95% CI).

Run from the project directory:
    python benchmark.py [--runs N]

What is measured (N runs each, default N=10):
    1. SHA-256 hash rate (PoSW calibration throughput)
    2. Paillier key generation time
    3. Paillier encryption time per operation
    4. Paillier homomorphic evaluation time (no artificial sleep)
    5. Paillier decryption verification (confirms E(A)+E(B)=E(150))
    6. drand network latency (async, measured with asyncio.run)
    7. Triple-pass memory wipe time (64 KB buffer)

Statistical reporting:
    - All multi-run metrics are reported as mean ± 1σ (standard deviation).
    - 95% confidence interval uses Student's t-distribution with (N-1) d.o.f.
    - drand is measured once (network I/O makes repeated measures noisy and
      potentially rate-limited).

Important notes on what is NOT measured:
    - Wesolowski VDF squarings: not implemented in pure Python at production
      speed; the SHA-256 chain timing is reported as the PoSW substitute.
    - GPU/FPGA acceleration: requires specialised hardware; only CPU is measured.
    - MPC modulus generation: the Diogenes protocol requires a live network;
      timing here would represent a local single-machine simulation.
    - Groth16 SNARK proving: requires a native Rust/C++ backend; not measured.
"""

import argparse
import asyncio
import math
import os
import platform
import statistics
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from drand_client import DrandClient  # noqa: E402
from fhe_engine import PaillierFHEEngine, decrypt  # noqa: E402
from memory_sanitizer import MemorySanitizer  # noqa: E402
from posw import PoSWManager  # noqa: E402

# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: List[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _t_critical_95(df: int) -> float:
    """Approximate two-tailed t-critical value for 95% CI.

    Uses a lookup table for common degrees of freedom (df = n-1).
    For df >= 120 the value converges to 1.96 (normal approximation).
    """
    _table = {
        1: 12.706,
        2: 4.303,
        3: 3.182,
        4: 2.776,
        5: 2.571,
        6: 2.447,
        7: 2.365,
        8: 2.306,
        9: 2.262,
        10: 2.228,
        15: 2.131,
        20: 2.086,
        25: 2.060,
        30: 2.042,
        40: 2.021,
        60: 2.000,
        120: 1.980,
    }
    for threshold in sorted(_table.keys(), reverse=True):
        if df >= threshold:
            return _table[threshold]
    return _table[1]


def _ci95(values: List[float]) -> float:
    """Half-width of the 95% confidence interval for the mean."""
    n = len(values)
    if n < 2:
        return 0.0
    t = _t_critical_95(n - 1)
    return t * _stdev(values) / math.sqrt(n)


def _fmt_ms(seconds: float) -> str:
    return f"{seconds * 1000:.3f} ms"


def _fmt_s(seconds: float) -> str:
    return f"{seconds:.4f} s"


# ---------------------------------------------------------------------------
# Measurement functions
# ---------------------------------------------------------------------------


def _measure_posw(duration_sec: int = 1) -> Dict[str, Any]:
    """Calibrate SHA-256 hash rate (single measurement — deterministic)."""
    posw = PoSWManager(target_duration_seconds=duration_sec)
    return {
        "hash_rate": posw._hashes_per_second,
        "t_for_1h": posw._hashes_per_second * 3600,
        "t_for_1s": posw._hashes_per_second,
    }


def _measure_fhe(runs: int = 10) -> Dict[str, Any]:
    """Measure Paillier key generation, encryption, and evaluation."""
    keygen_times: List[float] = []
    enc_times: List[float] = []
    eval_times: List[float] = []
    key_bits: int = 0
    math_correct: bool = True
    decrypted_result: int = 0

    for run_idx in range(runs):
        t0 = time.perf_counter()
        fhe = PaillierFHEEngine()
        keygen_times.append(time.perf_counter() - t0)
        key_bits = fhe.crypto.pub_key.n.bit_length()

        t0 = time.perf_counter()
        ct1, ct2 = fhe.encrypt_data(b"")
        enc_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct_out = fhe.evaluate_inference((ct1, ct2))
        eval_times.append(time.perf_counter() - t0)

        # Correctness check on first run only (keygen is the expensive part).
        if run_idx == 0:
            n = fhe.crypto.pub_key.n
            g = fhe.crypto.pub_key.g
            n_sq = fhe.crypto.pub_key.n_sq
            l_val = fhe.crypto.priv_key.l_val
            mu = fhe.crypto.priv_key.mu
            decrypted_result = decrypt((n, g, n_sq), (l_val, mu), ct_out)
            math_correct = decrypted_result == 150

    return {
        "key_bits": key_bits,
        "runs": runs,
        "keygen_mean": _mean(keygen_times),
        "keygen_std": _stdev(keygen_times),
        "keygen_ci95": _ci95(keygen_times),
        "enc_mean": _mean(enc_times),
        "enc_std": _stdev(enc_times),
        "enc_ci95": _ci95(enc_times),
        "eval_mean": _mean(eval_times),
        "eval_std": _stdev(eval_times),
        "eval_ci95": _ci95(eval_times),
        "decrypted_result": decrypted_result,
        "math_correct": math_correct,
    }


async def _measure_drand_async() -> Dict[str, Any]:
    """Measure drand round fetch latency (single call — network I/O)."""
    client = DrandClient()
    t0 = time.perf_counter()
    data = await client.fetch_latest_round()
    elapsed = time.perf_counter() - t0
    return {
        "latency_sec": elapsed,
        "round": data.get("round", "?") if data else "FAILED",
        "reachable": data is not None,
    }


def _measure_drand() -> Dict[str, Any]:
    try:
        return asyncio.run(_measure_drand_async())
    except Exception as exc:
        return {
            "latency_sec": 0.0,
            "round": "FAILED",
            "reachable": False,
            "error": str(exc),
        }


def _measure_memory_wipe(size_kb: int = 64, runs: int = 10) -> Dict[str, Any]:
    """Measure triple-pass memory wipe over multiple runs."""
    times: List[float] = []
    for _ in range(runs):
        buf = bytearray(os.urandom(size_kb * 1024))
        t0 = time.perf_counter()
        MemorySanitizer.zeroize_buffer(buf)
        times.append(time.perf_counter() - t0)
    return {
        "size_kb": size_kb,
        "runs": runs,
        "mean": _mean(times),
        "std": _stdev(times),
        "ci95": _ci95(times),
    }


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------


def run_benchmark(runs: int = 10) -> None:
    print("=" * 65)
    print("  PROJECT CHRONOS — Performance Benchmark")
    print(f"  ({runs} runs per metric, 95% CI reported)")
    print("=" * 65)

    print(f"\n[1/4] Measuring PoSW SHA-256 hash rate (calibration)...")
    posw_metrics = _measure_posw(duration_sec=1)
    print(f"      Hash rate : {posw_metrics['hash_rate']:,} SHA-256/s")
    print(f"      T for 1h  : {posw_metrics['t_for_1h']:,} hashes")

    print(f"[2/4] Measuring Paillier FHE ({runs} runs)...")
    fhe_metrics = _measure_fhe(runs=runs)
    kg_m, kg_ci = fhe_metrics["keygen_mean"], fhe_metrics["keygen_ci95"]
    en_m, en_ci = fhe_metrics["enc_mean"], fhe_metrics["enc_ci95"]
    ev_m, ev_ci = fhe_metrics["eval_mean"], fhe_metrics["eval_ci95"]
    print(
        f"      Key gen   : {_fmt_ms(kg_m)} ± {_fmt_ms(fhe_metrics['keygen_std'])} "
        f"[95% CI ±{_fmt_ms(kg_ci)}]"
    )
    print(
        f"      Encrypt   : {_fmt_ms(en_m)} ± {_fmt_ms(fhe_metrics['enc_std'])} "
        f"[95% CI ±{_fmt_ms(en_ci)}]"
    )
    print(
        f"      HE eval   : {_fmt_ms(ev_m)} ± {_fmt_ms(fhe_metrics['eval_std'])} "
        f"[95% CI ±{_fmt_ms(ev_ci)}]"
    )
    print(
        f"      E(100)+E(50)=E({fhe_metrics['decrypted_result']})  "
        f"{'SUCCESS' if fhe_metrics['math_correct'] else 'FAILED'}"
    )

    print("[3/4] Measuring drand network latency (1 call)...")
    drand_metrics = _measure_drand()
    if drand_metrics["reachable"]:
        print(f"      Latency   : {_fmt_ms(drand_metrics['latency_sec'])}")
        print(f"      Round     : {drand_metrics['round']}")
    else:
        print(f"      OFFLINE - drand unreachable: {drand_metrics.get('error', 'unknown')}")

    print(f"[4/4] Measuring memory wipe (64 KB, {runs} runs)...")
    wipe_metrics = _measure_memory_wipe(size_kb=64, runs=runs)
    print(
        f"      Wipe time : {_fmt_ms(wipe_metrics['mean'])} ± "
        f"{_fmt_ms(wipe_metrics['std'])} "
        f"[95% CI ±{_fmt_ms(wipe_metrics['ci95'])}]"
    )

    # --- Write markdown report ---
    if drand_metrics["reachable"]:
        drand_section = (
            f"- **Latency**: `{_fmt_ms(drand_metrics['latency_sec'])}`\n"
            f"- **Current Round**: `{drand_metrics['round']}`\n"
            f"- **Oracle Status**: ✓ Online"
        )
    else:
        drand_section = (
            f"- **Oracle Status**: ✗ Offline " f"(`{drand_metrics.get('error', 'unknown')}`)"
        )

    report = f"""# CHRONOS — Real-World Performance Metrics

> Generated by `benchmark.py` on {platform.node()} | {runs} runs per metric

## Hardware Profile

| Field | Value |
|-------|-------|
| Architecture | `{platform.machine()}` |
| Processor | `{platform.processor() or "N/A"}` |
| System | `{platform.system()} {platform.release()}` |
| Python | `{platform.python_version()}` |

---

## Methodology

- All timed operations are run {runs} times.
- Statistics: mean ± 1σ (standard deviation), 95% CI computed via
  Student's t-distribution with ({runs}-1) = {runs-1} degrees of freedom.
- drand is measured once (network I/O; repeated measures are noisy and
  potentially rate-limited by the League of Entropy API).
- No GPU, FPGA, or multi-party operations are measured in this run.

---

## 1. Cryptographic Fuse (PoSW — SHA-256 Hash Chain)

> **Note**: This measures the SHA-256 hash chain PoSW (Cohen 2018), not the
> Wesolowski VDF specified in the paper. The Wesolowski VDF requires a GMP-
> accelerated native backend. See `interfaces.IVDFEngine` for the production API.

- **Algorithm**: SHA-256 iterated sequential chain
- **Measured Throughput**: `{posw_metrics['hash_rate']:,} hashes/second`
- **1-Hour Mission Difficulty**: `{posw_metrics['t_for_1h']:,} hashes`
- **Parallelism Resistance**: Sequential by construction

---

## 2. Plaintext Blindness (Paillier Homomorphic Encryption)

> **Note**: This uses the Paillier additive HE scheme (1999) as a prototype
> substitute for TFHE-rs. Paillier provides the same plaintext-blindness property
> but supports only addition, not arbitrary boolean circuits.

| Operation | Mean | Std | 95% CI |
|-----------|------|-----|--------|
| Key Generation ({fhe_metrics['key_bits']}-bit modulus) | `{_fmt_ms(kg_m)}` | `{_fmt_ms(fhe_metrics['keygen_std'])}` | `±{_fmt_ms(kg_ci)}` |
| Encrypt (one ciphertext) | `{_fmt_ms(en_m)}` | `{_fmt_ms(fhe_metrics['enc_std'])}` | `±{_fmt_ms(en_ci)}` |
| Homomorphic Addition E(A)+E(B) | `{_fmt_ms(ev_m)}` | `{_fmt_ms(fhe_metrics['eval_std'])}` | `±{_fmt_ms(ev_ci)}` |

**Mathematical Verification**: E(100) ⊕ E(50) → E(**{fhe_metrics['decrypted_result']}**) — {'**PASS ✓**' if fhe_metrics['math_correct'] else '**FAIL ✗**'}

---

## 3. Dead Man's Switch (drand Randomness Beacon)

{drand_section}
- **Round Interval**: 3 seconds
- **Chain**: quicknet (BLS12-381 threshold, G1 signatures, unchained)

---

## 4. Erasure Protocol (Triple-Pass C-Level Memory Wipe)

| Metric | Value |
|--------|-------|
| Buffer Size | {wipe_metrics['size_kb']} KB |
| Mean Wipe Time | `{_fmt_ms(wipe_metrics['mean'])}` |
| Standard Deviation | `{_fmt_ms(wipe_metrics['std'])}` |
| 95% CI Half-Width | `±{_fmt_ms(wipe_metrics['ci95'])}` |
| Method | `ctypes.memset()` — three passes (0x00, 0xFF, 0x00) |
| Verification | `ctypes.string_at()` C-level memcmp all-zeros check |

---

## Limitations of This Benchmark

The following are NOT measured and would require additional infrastructure:

| Component | Reason Not Measured |
|-----------|---------------------|
| Wesolowski VDF squarings | Requires GMP-backed Rust native extension |
| GPU FHE acceleration | Requires CUDA / Concrete-ML GPU build |
| FPGA FHE acceleration | Requires Xilinx Alveo / BASALISC bitstream |
| MPC modulus generation | Requires live multi-party Diogenes network |
| Groth16 SNARK proving | Requires bellman/arkworks Rust crate via cffi |
| SGX baseline | Requires Intel SGX2 hardware + OpenEnclave SDK |

*Run `python benchmark.py --runs N` to regenerate with a different run count.*
"""

    out_path = os.path.join(os.path.dirname(__file__), "real_results.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nBenchmark report written to: {out_path}")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Project CHRONOS performance benchmark",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        metavar="N",
        help="Number of measurement runs per metric (minimum 2 for statistics).",
    )
    args = parser.parse_args()
    if args.runs < 2:
        print("Error: --runs must be at least 2 for statistical analysis.")
        sys.exit(1)
    run_benchmark(runs=args.runs)
