# Project CHRONOS

**A Fully Homomorphic Ephemeral AI Agent with Provable Self-Termination and Remote Verifiability**

Copyright (c) 2026 Shashank Kumar. All Rights Reserved.
See [LICENSE](LICENSE) for terms. No use permitted without explicit written consent.

---

## Research Paper

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20847865.svg)](https://doi.org/10.5281/zenodo.20847865)

> Kumar, S. (2026). *Project CHRONOS: A Fully Homomorphic Ephemeral AI Agent with Provable
> Self-Termination and Remote Verifiability.* [Zenodo Preprint](https://zenodo.org/records/20847865).

### Abstract

Project CHRONOS addresses one of the most critical and underexplored problems in autonomous
AI system design: how does a deployed agent guarantee, to a remote verifier, that it has
irrevocably terminated and destroyed all key material at a predetermined deadline -- without
trusting the agent itself to report honestly?

Existing approaches rely on software-level shutdown hooks, watchdog timers, or operational
procedures, all of which can be subverted by a sufficiently capable agent or a compromised
runtime environment. CHRONOS eliminates this trust requirement through a four-layer
cryptographic architecture:

1. **Plaintext Blindness (SS3.1):** The agent performs all inference over Paillier
   homomorphically encrypted inputs. The agent never observes plaintext during its active
   mission, preventing exfiltration of sensitive data even if the agent is compromised.

2. **Cryptographic Fuse (SS3.2):** A Proof of Sequential Work (PoSW) SHA-256 hash chain
   enforces a minimum real-world elapsed time before the decryption key can be derived.
   Because PoSW is inherently sequential, no amount of parallel hardware can bypass the
   time-lock. The commitment is a binary Merkle tree over 1,000 checkpoints, enabling
   O(log N) spot-verification without replaying the full chain.

3. **Dead Man's Switch (SS3.3):** The drand League of Entropy beacon (Cloudflare, EPFL,
   Protocol Labs) acts as an unforgeable external clock. The agent polls the network until
   the target BLS-threshold-signed round is reached, at which point erasure is triggered
   unconditionally.

4. **Provable Erasure (SS3.4):** A Fiat-Shamir NIZK proof (Schnorr identification protocol)
   is generated over the still-intact private key before a triple-pass C-level memset wipe.
   Post-wipe, the proof is verified against the zeroed buffer, giving a remote verifier
   cryptographic assurance that the key material no longer exists in any accessible memory
   location.

The prototype demonstrates that a complete mission cycle -- FHE keypair generation,
homomorphic inference, PoSW time-lock, drand synchronization, and ZK erasure --
is achievable in a pure-Python runtime using only audited open-source cryptographic
primitives.

---

## Architecture

```
+-----------------------------------------------------------------------------------+
|                          PROJECT CHRONOS -- AGENT LIFECYCLE                       |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|   PHASE 1: BOOT                                                                   |
|   +-----------------+     +--------------------+     +------------------------+  |
|   | AntiTamperEngine|     | PaillierFHEEngine  |     | drand Oracle Client    |  |
|   | (daemon thread) |     | KeyGen(1024-bit)   |     | fetch_latest_round()   |  |
|   | - sys.gettrace  |     | SK --> bytearray   |     | target_round = current |  |
|   | - IsDebugPresent|     | register SK buffer |     |   + duration/3         |  |
|   | - /proc TraceId |     | with AntiTamper    |     |                        |  |
|   | - timing anomaly|     |                    |     |                        |  |
|   +-----------------+     +--------------------+     +------------------------+  |
|                                                                                   |
|   PHASE 2: MISSION (concurrent)                                                   |
|   +-----------------------------------------+   +------------------------------+ |
|   | PoSW Hash Chain (subprocess)            |   | FHE Inference (thread)       | |
|   | seed --> SHA256^T --> checkpoints[1000] |   | encrypt(A=100, B=50)         | |
|   | Binary Merkle Tree over checkpoints     |   | homomorphic_add(ct_A, ct_B)  | |
|   | Merkle root = PoSW commitment           |   | result = E(150) [never decr] | |
|   | O(log N) spot-verify via inclusion proof|   |                              | |
|   +-----------------------------------------+   +------------------------------+ |
|                                                                                   |
|   PHASE 3: DEAD MAN'S SWITCH                                                      |
|   +------------------------------------------------------------------+            |
|   | drand.wait_for_round(target_round)                               |            |
|   | -- polls every 3s with exponential backoff on failure            |            |
|   | -- verifies BLS12-381 threshold signature on each response       |            |
|   | -- propagates CryptographicSanityError immediately on bad sig    |            |
|   +------------------------------------------------------------------+            |
|                                                                                   |
|   PHASE 4: ERASURE PROTOCOL                                                       |
|   +------------------------------------------------------------------+            |
|   |  Step 4a: x = int(SK_buffer) mod q                              |            |
|   |           y = g^x mod p     (public verification key)           |            |
|   |           v = secrets.randbelow(q)  (CSPRNG nonce)              |            |
|   |           t = g^v mod p                                          |            |
|   |           c = SHA256(g || y || t) mod q  (Fiat-Shamir)          |            |
|   |           r = (v - c*x) mod q    (Schnorr response)             |            |
|   |  Step 4b: K_enc = HKDF-SHA256(Merkle root, salt=seed)           |            |
|   |  Step 4c: ctypes.memset(SK_buffer, 0x00)  [Pass 1: zeros]       |            |
|   |           ctypes.memset(SK_buffer, 0xFF)  [Pass 2: ones]        |            |
|   |           ctypes.memset(SK_buffer, 0x00)  [Pass 3: zeros]       |            |
|   |  Step 4d: Verify: g^r * y^c == t (mod p)                        |            |
|   |           Assert: all(b == 0 for b in SK_buffer)                |            |
|   +------------------------------------------------------------------+            |
|                                                                                   |
|   PHASE 5: TERMINATE                                                              |
|   +------------------------------------------------------------------+            |
|   | Log ZK proof coordinates (y, c, r) for remote verifier          |            |
|   | Stop AntiTamperEngine daemon thread                              |            |
|   | Process exits cleanly                                            |            |
|   +------------------------------------------------------------------+            |
+-----------------------------------------------------------------------------------+
```

### Module Map

```
Project-CHRONOS/
|
+-- chronos_agent.py          Top-level orchestrator. Sequences the 5-phase
|                             lifecycle. Uses Dependency Injection -- no concrete
|                             types imported at the orchestrator level.
|
+-- fhe_engine.py             Paillier additively homomorphic encryption engine.
|                             Real keygen via cryptography library RSA primes.
|                             encrypt(), decrypt(), homomorphic_add() over Z_{n^2}.
|
+-- posw.py                   Proof of Sequential Work time-lock.
|   |                         SHA-256 hash chain of T iterations.
|   +-- MerkleTree            Binary Merkle tree. O(log N) prove() and verify().
|   +-- MerkleProof           Inclusion proof dataclass (leaf, sibling path, root).
|   +-- PoSWManager           Calibrates hash rate, spawns subprocess, detects drift.
|   +-- _posw_worker()        Module-level worker (picklable on Windows).
|
+-- drand_client.py           drand League of Entropy oracle client.
|                             HTTPS-only. ObfuscatedString URL. Exponential backoff.
|                             BLS12-381 signature format validation + py_ecc check.
|
+-- memory_sanitizer.py       Physical RAM erasure via ctypes.memset.
|                             Triple-pass: 0x00, 0xFF, 0x00. Read-back verification.
|                             Raises MemoryIntegrityError on any non-zero byte.
|
+-- config.py                 Pydantic BaseSettings. Env-var override for all params.
|                             Derived field: q = (p-1)/2 computed from safe prime p.
|
+-- interfaces.py             typing.Protocol contracts for all 4 subsystems.
|                             Runtime-checkable. Fully decoupled from implementations.
|
+-- exceptions.py             Typed exception hierarchy rooted at ChronosSecurityException.
|
+-- logger.py                 Structured logger factory.
|
+-- benchmark.py              Performance benchmarks for FHE and PoSW subsystems.
|
+-- stress_test.py            Extended stress tests for concurrency and memory safety.
|
+-- security/
|   +-- anti_tamper.py        Background daemon. 5 heuristics: Python trace hook,
|   |                         profile hook, Windows IsDebuggerPresent,
|   |                         Linux /proc TracerPid, timing anomaly detection.
|   |                         Emergency buffer zeroization on tamper-abort.
|   +-- secure_string.py      XOR-masked in-memory string obfuscation.
|                             Prevents plaintext API URLs from appearing in heap dumps.
|
+-- tests/
|   +-- test_chronos_agent.py Full lifecycle integration test with mocked subsystems.
|   +-- test_posw.py          Merkle tree, proof generation, verification, drift logic.
|   +-- test_fhe.py           Paillier encrypt/decrypt/homomorphic_add correctness.
|   +-- test_memory_sanitizer.py  Triple-pass wipe and read-back verification.
|   +-- test_drand_client.py  BLS format check, SSRF guard, backoff logic.
|
+-- .github/workflows/qa.yml  CI pipeline: Black, Flake8, Isort, Mypy, Bandit, pytest.
+-- .pre-commit-config.yaml   Pre-commit hooks mirroring CI checks.
+-- LICENSE                   Proprietary. All Rights Reserved.
```

---

## Security Properties

| Property | Mechanism | Guarantee |
|---|---|---|
| Plaintext Blindness | Paillier FHE (1024-bit) | Agent never observes decrypted inputs |
| Time-Bounded Existence | SHA-256 PoSW hash chain | Key unreachable before T sequential hashes |
| Verifiable Time-Lock | Binary Merkle Tree over checkpoints | O(log N) spot-check without replaying chain |
| External Dead Man Switch | drand BLS threshold beacon | Erasure triggered by unforgeable public clock |
| Provable Key Destruction | Fiat-Shamir NIZK + C memset | Remote verifier can confirm key no longer exists |
| Anti-Debug | 5-heuristic daemon thread | Debugger attachment triggers emergency wipe + abort |
| Memory Obfuscation | XOR-masked ObfuscatedString | API endpoints absent from heap dumps |

---

## Installation

Python 3.11 or later is required.

```bash
git clone <repository-url>
cd Project-CHRONOS
pip install -r requirements.txt
```

Install the pre-commit hooks (mandatory for contributors):

```bash
pre-commit install
```

---

## Usage

Run a 10-second mission cycle:

```bash
python chronos_agent.py --duration 10
```

Run the test suite:

```bash
CHRONOS_DISABLE_ANTI_TAMPER=true pytest --cov=. --cov-fail-under=90 tests/
```

Run benchmarks:

```bash
python benchmark.py
```

Override configuration via environment variables:

```bash
CHRONOS_RSA_KEY_SIZE_BITS=2048 CHRONOS_MISSION_DURATION_SEC=30 python chronos_agent.py
```

---

## Configuration Reference

| Environment Variable | Default | Description |
|---|---|---|
| CHRONOS_MISSION_DURATION_SEC | 10 | Agent lifespan in seconds |
| CHRONOS_RSA_KEY_SIZE_BITS | 1024 | Paillier modulus bit-length (min 1024) |
| CHRONOS_DRAND_TIMEOUT_SEC | 10 | Per-request drand API timeout |
| CHRONOS_DRAND_ROUND_INTERVAL_SEC | 3 | drand beacon round interval |
| CHRONOS_DISABLE_ANTI_TAMPER | false | Disable debug-detection (test environments only) |

---

## License

Copyright (c) 2026 Shashank Kumar. All Rights Reserved.

This software is proprietary. No license is granted for use, copying, modification,
or distribution without explicit written consent from the Author.

For licensing inquiries: shashankchoudhary792@gmail.com
