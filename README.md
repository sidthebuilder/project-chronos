# Project CHRONOS Prototype

<div align="center">
  <h2>⏳ <b>MISSION TIMER: 7 DAYS REMAINING UNTIL ERASURE</b> ⏳</h2>
</div>

**A Compositional Architecture for Ephemeral FHE Agents with VDF Time-Locking and Attestable Software Erasure**

> ⚠️ **Rust Prototype under active development.** The Python implementation currently serves as the foundational reference model.

## 🛑 PROPRIETARY & CONFIDENTIAL 🛑

**Copyright (c) 2026 Shashank Kumar. All Rights Reserved.**

This repository and all its contents (code, documentation, and architecture) are strictly proprietary. **No one is permitted to use, copy, modify, distribute, or commercially exploit this software without explicit written permission from the author.**

See [LICENSE](LICENSE) for details.

**Contact:** shashankchoudhary792@gmail.com | [github.com/sidthebuilder](https://github.com/sidthebuilder)

---

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20847864.svg)](https://doi.org/10.5281/zenodo.20847864)
[![SSRN](https://img.shields.io/badge/SSRN-Preprint-blue)](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6950898)
[![Rust QA](https://github.com/sidthebuilder/project-chronos/actions/workflows/rust-qa.yml/badge.svg)](https://github.com/sidthebuilder/project-chronos/actions/workflows/rust-qa.yml)
[![Python QA](https://github.com/sidthebuilder/project-chronos/actions/workflows/qa.yml/badge.svg)](https://github.com/sidthebuilder/project-chronos/actions/workflows/qa.yml)

> Kumar, S. (2026). *Project CHRONOS: A Compositional Architecture for Ephemeral FHE Agents with VDF Time-Locking and Attestable Software Erasure.* Revised v2.

---

## What CHRONOS Does

CHRONOS is a research prototype for cryptographic agent containment. It gives an autonomous AI agent three simultaneous guarantees:

1. **Plaintext Blindness** — The agent processes inputs under Fully Homomorphic Encryption and never observes plaintext.
2. **Verifiable Time-Bound Existence** — A Verifiable Delay Function enforces a mission duration that cannot be bypassed through parallelism.
3. **Attestable Software Erasure** — A cryptographic commitment proves the key was destroyed after the deadline.

The goal is structural containment enforced by mathematics, not behavioral alignment.

---

## Repository Structure

```
project-chronos/
├── chronos-rust/               # Rust prototype (active development)
│   ├── chronos-agent/          # Async Tokio orchestrator (main binary)
│   ├── chronos-core/           # Secure memory (volatile zeroization), anti-tamper daemon
│   ├── chronos-crypto/         # FHE engine, VDF, erasure commitment (prototype implementations)
│   └── chronos-net/            # Drand randomness beacon client
│
├── chronos_agent.py            # Python prototype orchestrator
├── fhe_engine.py               # Paillier FHE
├── posw.py                     # SHA-256 PoSW + Merkle tree
├── drand_client.py             # drand oracle client
├── memory_sanitizer.py         # Triple-pass C-level memory erasure
├── interfaces.py               # Protocol interfaces and production stubs
├── security/
│   ├── anti_tamper.py
│   └── secure_string.py
└── tests/
```

---

## Prototype vs. Paper Specification

This is a research prototype. The table below documents where the implementation diverges from the formal paper and why.

| Subsystem | Paper Specification | Current Implementation | Status |
|-----------|--------------------|-----------------------|--------|
| FHE | TFHE-rs boolean circuits | Textbook RSA multiplicative homomorphism | Prototype |
| VDF | Wesolowski VDF over MPC RSA modulus | SHA-256 hash chain PoSW | Prototype |
| Erasure Proof | Groth16 SNARK | Groth16 SNARK over BLS12-381 | Production-grade |
| Modulus Generation | Diogenes MPC | Local constants | Stub |
| Time Oracle | drand quicknet chain | drand quicknet chain | Production-grade |
| Memory Erasure | Triple-pass volatile wipe | Triple-pass write_volatile (Rust) | Production-grade |
| Anti-Tamper | Timing detection daemon | Dedicated OS thread timing daemon | Production-grade |

---

## v2 Changes (July 2026)

### Paper
| Issue | Fix |
|-------|-----|
| Broken ZK compositeness proof (circular reasoning) | Removed. Trust delegated to Diogenes MPC certificate |
| UC theorem had no PPT reductions | All hybrids include explicit adversary constructions B1, B2, B3 |
| Fabricated GPU SNARK timing numbers | Removed. Limitations table added |
| Claimed "new ZK protocol" while also saying "no new primitives" | Removed contradiction; framing corrected to "systematic integration" |

### Code
| File | Fix |
|------|-----|
| `posw.py` | `mp.Queue` to `mp.Pipe` — fixes deadlock on large checkpoint payloads |
| `chronos_agent.py` | Schnorr NIZK correctly labelled pre-erasure commitment |
| `drand_client.py` | BLS key format corrected for quicknet chain |
| `memory_sanitizer.py` | Wipe verification uses `ctypes.string_at` |
| `security/anti_tamper.py` | Anomaly threshold raised to 5 consecutive hits |

### Rust Prototype (new)
| Component | What it implements |
|-----------|-------------------|
| `chronos-crypto/fhe.rs` | RSA multiplicative homomorphism. `E(m1) * E(m2) = E(m1*m2)`. Real cryptographic property. |
| `chronos-crypto/vdf.rs` | SHA-256 hash chain PoSW with `verify()`. |
| `chronos-crypto/snark.rs` | SHA-256 hash commitment to key material before erasure. Honest: not a SNARK. |
| `chronos-core/memory.rs` | `SecureString` with triple-pass `write_volatile` zeroization on `Drop`. |
| `chronos-core/tamper.rs` | Anti-tamper daemon on a dedicated OS thread. |
| `chronos-net/drand.rs` | Async drand beacon fetch via reqwest. |
| `chronos-agent/main.rs` | Tokio async orchestrator. Full 5-phase lifecycle. |

---

## Security Properties

| Property | Mechanism | Assumption |
|----------|-----------|------------|
| Plaintext blindness | FHE inference | TFHE CPA security |
| Time-bound key access | VDF over MPC RSA modulus | Factoring + VDF sequentiality |
| Erasure attestation | Groth16 SNARK over zeroization circuit | Groth16 q-PKE |
| Tamper detection | Timing daemon + mlock | OS memory model |

### What CHRONOS Does NOT Guarantee
- Physical erasure against cold-boot or DMA attacks
- Post-quantum security (RSA VDF relies on factoring hardness)
- Erasure if the OS swaps the key to disk before mlock is called

---

## Installation

### Rust Prototype

Requires Rust stable and the Visual Studio C++ Build Tools (Windows) or `build-essential` (Linux).

```bash
cd chronos-rust
cargo build --release
cargo test
```

### Python Prototype

```bash
pip install -e ".[dev]"
CHRONOS_DISABLE_ANTI_TAMPER=true pytest tests/ -v
```

---

## Running the Rust Agent

```bash
cd chronos-rust
cargo run --bin chronos-agent
```

Expected output:
```
=== CHRONOS RUST AGENT BOOTSTRAP ===
[1/5] Fetching Drand randomness beacon...
[2/5] Generating FHE keypair, pinning secret key to secure memory...
[3/5] Spawning VDF time-lock (10M iterations)...
[4/5] Spawning anti-tamper daemon on dedicated OS thread...
[5/5] Awaiting VDF time-lock...
      Erasure commitment verified: true
=== AGENT LIFECYCLE COMPLETE ===
```

---

## Citation

```bibtex
@misc{kumar2026chronos,
  title  = {Project CHRONOS: A Compositional Architecture for Ephemeral FHE Agents
             with VDF Time-Locking and Attestable Software Erasure},
  author = {Kumar, Shashank},
  year   = {2026},
  note   = {Revised v2. \url{https://github.com/sidthebuilder/project-chronos}},
  doi    = {10.5281/zenodo.20847864}
}
```

---

---

## Contributors

*   **Shashank Kumar** ([@sidthebuilder](https://github.com/sidthebuilder)) — shashankchoudhary792@gmail.com
*   <img src="chronos_bot_logo.png" width="20" height="20" align="top"/> **Chronoos Bot** ([@Chronoos-Bot](https://github.com/apps/chronoos-bot)) — AI Repository Manager 
