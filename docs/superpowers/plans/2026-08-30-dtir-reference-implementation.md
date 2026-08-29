# DTI-R Reference Implementation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an independent, reproducible Python implementation of the DTI-R manuscript protocol and regenerate its deterministic state, recovery, communication, storage, and host-benchmark evidence.

**Architecture:** A small standard-library Python package implements canonical encoding, HMAC/HKDF operations, message records, device state, and server confirmed/pending state. A separate finite-state verifier models only authenticated delivery outcomes, while tests exercise the concrete protocol including retry, loss, restart, replay, and implicit commitment.

**Tech Stack:** Python 3.10+, standard library (`hashlib`, `hmac`, `dataclasses`, `secrets`, `json`, `statistics`, `time`), pytest for the test harness, GitHub Actions for reproducibility.

**Spec:** `DTI_R_Repository2_Design_Spec.md`

## Global Constraints

- Ratchet state, K_auth, and K_sess are 32 bytes.
- DTI, ND, NS, and all authentication tags are 16 bytes.
- HKDF output is exactly 96 bytes split as X_next || K_auth || K_sess.
- DTI/FAR/BAR/AKA equations and confirmed/pending transitions follow the manuscript.
- The real identifier and DTI_next are never transmitted online.
- Exactly one pending transition is permitted per device.
- Exact FAR retry returns the byte-identical stored BAR and derives no new values.
- The repository is limited to the reference implementation, state verification, cost analysis, tests, and benchmark evidence.
- Historical benchmark numbers are never hard-coded as generated results.

---

### Task 1: Cryptographic and encoding core
**Files:** Create `src/dtir/constants.py`, `src/dtir/encoding.py`, `src/dtir/crypto.py`; test with `tests/test_encoding.py`, `tests/test_crypto.py`.
**Produces:** `encode_fields`, `generate_dti`, `far_tag`, `derive_schedule`, `bar_tag`, `aka_tag`.
- [ ] Write failing tests for boundary-unambiguous length-prefix encoding, DTI determinism, 96-byte schedule split, and tag sizes.
- [ ] Run focused tests and confirm failure because implementation modules are absent.
- [ ] Implement the minimal standard-library functions.
- [ ] Run focused tests and confirm pass.

### Task 2: Messages, records, and normal protocol
**Files:** Create `src/dtir/messages.py`, `src/dtir/records.py`, `src/dtir/device.py`, `src/dtir/server.py`, `src/dtir/protocol.py`; test with `tests/test_protocol.py`.
**Produces:** FAR/BAR/AKA serialization; `Device`; `Server`; explicit FAR-BAR-AKA transaction.
- [ ] Write failing tests for 48/32/32-byte messages, one successful exchange, matching state/session keys, and 1,000 sequential rounds.
- [ ] Run focused tests and confirm failure.
- [ ] Implement message/record types and normal explicit-commit flow.
- [ ] Run focused tests and confirm pass.

### Task 3: Recovery, replay, and restart semantics
**Files:** Test `tests/test_recovery.py`, `tests/test_restart.py`; extend `device.py`, `server.py`, `records.py` only as required.
**Produces:** exact retry, Reject-Busy, implicit commit, retired replay rejection, late AKA rejection, persistence snapshots/restores.
- [ ] Write failing tests for all recovery/restart cases from the manuscript.
- [ ] Run focused tests and confirm failure.
- [ ] Implement minimal recovery/restart behavior.
- [ ] Run focused tests and confirm pass.

### Task 4: Independent finite-state verification
**Files:** Create `verification/state_model.py`, `verification/fixed_point_check.py`, `verification/enumerate_sequences.py`; test with `tests/test_state_verification.py`.
**Produces:** 3-state fixed point and exhaustive 4^7 enumeration with invariant checks.
- [ ] Write failing tests expecting reachable S0/S1/S2 and 5,462/5,461/5,461 final distribution.
- [ ] Run focused tests and confirm failure.
- [ ] Implement independent transition table, fixed-point search, and exhaustive enumeration.
- [ ] Run focused tests and confirm pass.

### Task 5: Cost accounting and benchmark
**Files:** Create `src/dtir/costs.py`, `tests/test_costs.py`, `benchmark/benchmark_dtir.py`.
**Produces:** deterministic communication/storage reports and machine-dependent timing output.
- [ ] Write failing cost tests for 48/32/32/112-byte communication and 32/48/80/128/160-byte protocol storage values.
- [ ] Run focused tests and confirm failure.
- [ ] Implement cost calculators and benchmark harness.
- [ ] Run cost tests and smoke benchmark.

### Task 6: Reproducibility package and CI
**Files:** Create `scripts/regenerate_results.py`, `README.md`, `CITATION.cff`, `LICENSE`, `pyproject.toml`, `.github/workflows/reproducibility.yml`.
**Produces:** generated result summaries, environment metadata, checksums, one-command regeneration, CI.
- [ ] Generate deterministic results from executed code.
- [ ] Execute benchmark and record its actual environment separately.
- [ ] Run the complete test suite from a clean Python environment.
- [ ] Verify result files correspond to executed commands and create release ZIP.
