# DTI-R Reference Implementation and State Verification
## Design Specification for Repository 2

**Status:** Proposed design for author approval before implementation  
**Target repository:** `DTI-R-Reference-Implementation-and-State-Verification`  
**Source of truth:** the current DTI-R manuscript specification. The implementation will not copy the previously reported Python code because that code is not available. It will be reconstructed independently from the protocol equations, algorithms, persistence rules, and stated validation cases.

## 1. Objective

The repository will provide a clean, reproducible Python reference implementation of DTI-R and an independent state-verification harness. Its purpose is to regenerate the implementation, synchronization, communication-cost, storage-cost, and host-side benchmark evidence used in the manuscript.

The repository is separate from the ProVerif repository and is limited to the reference implementation, state verification, tests, cost analysis, and benchmark evidence.

## 2. Scientific rule

No historical numerical result will be copied into the generated result files merely because it appears in the manuscript. Every result reported by this repository must be produced by executing the new implementation or by an exact deterministic calculation from the protocol constants.

If a regenerated result differs from the current manuscript, the manuscript will be updated to the regenerated result rather than tuning the code to reproduce the previous number.

## 3. Protocol constants

The implementation will use the protocol sizes stated in the manuscript:

- ratchet state: 32 bytes (256 bits)
- authentication key: 32 bytes
- application session key: 32 bytes
- DTI: 16 bytes (128 bits)
- device nonce ND: 16 bytes
- server nonce NS: 16 bytes
- FAR/BAR/AKA tag: 16 bytes
- HKDF output: 96 bytes, split as `X_next || K_auth || K_sess`

Cryptographic primitives:

- SHA-256
- HMAC-SHA-256
- HKDF-Extract using HMAC-SHA-256
- HKDF-Expand using HMAC-SHA-256

## 4. Domain separation and protocol equations

### 4.1 Dynamic Temporary Identifier

`DTI = Trunc128(HMAC_X(Encode("DTI-R/v1/DTI", ID)))`

The real identifier is never placed in an online protocol message.

### 4.2 Key schedule

`Salt = SHA256(Encode("SALT", DTI, ND, NS))`

`PRK = HKDF-Extract(Salt, X)`

`OKM = HKDF-Expand(PRK, Encode("KEY-SCHEDULE", DTI, ND, NS), 96)`

`X_next || K_auth || K_sess = OKM`

The next DTI is generated locally from `X_next` using the DTI equation above.

### 4.3 FAR

`Tau_D = Trunc128(HMAC_X(Encode("DTI-R/v1/FAR", DTI, ND)))`

Wire message:

`FAR = DTI || ND || Tau_D`

Expected size: 48 bytes.

### 4.4 BAR

`Tau_S = Trunc128(HMAC_Kauth(Encode("DTI-R/v1/BAR", DTI_current, DTI_next, ND, NS)))`

Wire message:

`BAR = NS || Tau_S`

Expected size: 32 bytes.

`DTI_next` is not transmitted.

### 4.5 AKA

`Tau_A = Trunc128(HMAC_Kauth(Encode("DTI-R/v1/AKA", DTI_current, DTI_next, ND, NS)))`

Wire message:

`AKA = DTI_current || Tau_A`

Expected size: 32 bytes.

Total normal wire cost: 112 bytes.

## 5. Canonical encoding

All HMAC and hash inputs will pass through one explicit canonical encoder. The implementation will not use ambiguous raw concatenation of variable-length fields.

Initial design: each field is encoded as a 4-byte unsigned big-endian length followed by the exact field bytes. ASCII protocol labels are encoded as UTF-8 bytes before length-prefixing.

The encoder will have dedicated tests proving that different field boundaries cannot produce the same encoded byte sequence.

If the manuscript specifies a different exact canonical representation during later review, this single module can be replaced without changing the state machine.

## 6. State model

### 6.1 Device

Persistent fields:

- real identifier `ID`
- current ratchet state `X`
- unresolved device nonce `ND`, when a FAR is in flight

The device must persist `ND` before transmitting a newly created FAR.

### 6.2 Server confirmed record

- current state `X`
- current DTI

### 6.3 Server pending record

The executable reference implementation will store:

- next state
- next DTI
- device nonce
- server nonce
- authentication key
- session key
- exact BAR bytes

The scientific storage-cost calculator will separately compute the manuscript's minimum re-derivable representation and the cached-BAR representation. Python object overhead will not be presented as protocol storage cost.

## 7. Server FAR decision rules

The implementation will return explicit decisions equivalent to Algorithm 1:

- `NEW_CURRENT`
- `EXACT_RETRY`
- `REJECT_BUSY`
- `IMPLICIT_COMMIT`
- `REJECT`
- `REJECT_UNKNOWN`

Rules:

1. A DTI match alone never changes state; the FAR tag is verified first.
2. Valid current-state FAR with no pending record prepares one pending transition while retaining the confirmed record.
3. Same current-state FAR with the same ND while pending exists returns exactly the stored BAR and derives no new values.
4. A different-ND current-state FAR while pending exists is rejected and cannot replace the pending transition.
5. A valid FAR under the pending state first promotes the previous pending state, then uses the same FAR to prepare the next pending transition.
6. Unknown or invalid messages change no state.

The server will maintain a DTI index and reject/re-derive a pending DTI if it collides with an active DTI.

## 8. Commit and recovery rules

### Explicit commitment

After the device verifies BAR, it durably replaces its local state with `X_next` before sending AKA. A valid AKA causes the server to promote pending to confirmed and clear pending.

### Implicit commitment

If AKA is lost, the device is already on `X_next`. Its next FAR therefore selects and authenticates under the pending server record. The server promotes that record and processes the same FAR as the next transaction.

### Exact retry

Loss of FAR or BAR does not cause a fresh ND. The device reuses the unresolved FAR context. The server returns the exact stored BAR for the same FAR.

## 9. Independent synchronization abstraction

The finite-state verifier will be kept independent from the cryptographic implementation. It will model only authenticated transition outcomes after invalid forgeries have already been rejected.

Abstract states:

- `S0`: device and server confirmed on the same state; no pending record
- `S1`: pending transition prepared; device still on confirmed state
- `S2`: device advanced; server retains confirmed and pending records

Invariant:

- if pending is absent, device state equals confirmed state
- if pending exists, device state equals either confirmed state or pending state

The fixed-point exploration must compute the complete reachable abstract state set without a manually selected depth bound.

## 10. Test-first implementation requirements

Tests will be written before production code for each behavior.

Required deterministic tests:

1. DTI generation is deterministic for equal `(ID, X)` and changes when state changes.
2. HKDF schedule produces exactly 96 bytes and three 32-byte fields.
3. FAR/BAR/AKA serialization sizes are 48/32/32 bytes.
4. One complete authentication derives identical `X_next`, `K_auth`, `K_sess`, and `DTI_next` at both endpoints.
5. 1,000 sequential complete rounds produce equal device/server final states and matching session keys; server pending is empty after each normal explicit commit.
6. Exact FAR retry returns byte-for-byte identical BAR and creates no additional transition.
7. Competing current-state FAR with a different ND is rejected while pending exists.
8. BAR loss is recoverable by exact FAR retry.
9. AKA loss is recoverable by the next pending-state FAR through implicit commitment.
10. Retired-DTI replay changes no active state.
11. Late duplicate AKA after implicit commitment changes no active state.
12. Restart before BAR reuses the persisted FAR/ND.
13. Server restart with pending preserves the exact stored BAR.
14. Device restart after BAR preserves the advanced state and permits implicit recovery.
15. Server restart after durable promotion retains the new confirmed state and no pending record.
16. Invalid FAR/BAR/AKA tags change no committed state.
17. Canonical encoding is boundary-unambiguous for tested inputs.
18. Active DTI collision handling regenerates NS and derives another candidate without overwriting another active record.

## 11. State-verification tests

### Fixed point

Starting from `S0`, apply every abstract delivery/loss transition until no new state is generated. The expected manuscript claim is exactly three reachable states. This expected value is treated as a test hypothesis; the executable checker decides the actual result.

### Exhaustive length-seven enumeration

The independent enumeration will evaluate four outcomes at each position for seven positions:

`4^7 = 16,384` sequences.

The invariant is checked after every transition, not only at the final state.

The current manuscript reports the final-state distribution:

- confirmed: 5,462
- pending prepared: 5,461
- device advanced: 5,461

These numbers will be treated as values to verify. They will not be hard-coded as generated output. If the new abstract transition definition produces different values, the trace difference will be investigated before the manuscript is changed.

## 12. Communication and storage calculators

The repository will generate protocol costs from constants used by the implementation rather than duplicate values manually.

Expected communication values to verify:

- FAR: 48 bytes
- BAR: 32 bytes
- AKA: 32 bytes
- total: 112 bytes

Expected storage calculations to verify:

- device minimum state: 32 bytes
- unresolved device state plus ND: 48 bytes
- confirmed server record: 48 bytes
- minimum pending re-derivable record: 80 bytes
- confirmed + minimum pending: 128 bytes
- confirmed + minimum pending + cached BAR: 160 bytes

Any larger Python in-memory representation will be reported separately from protocol storage.

## 13. Host benchmark policy

The previous manuscript timings will not be copied as results of this implementation.

The benchmark will measure, at minimum:

- DTI generation
- FAR tag generation
- HKDF-SHA-256 96-byte schedule
- BAR tag generation/verification
- AKA tag generation/verification
- complete successful FAR-BAR-AKA transaction

Method:

- warm-up phase
- 21 measured batches by default
- median and IQR reported
- garbage collection disabled during the timed region where appropriate
- platform, Python version, OpenSSL version, CPU, OS, and timestamp recorded

GitHub Actions will execute a functional smoke benchmark but will not fail based on timing thresholds. Performance numbers used in the paper should come from a recorded release environment, not from arbitrary CI runners.

## 14. Reproducibility outputs

Generated outputs will be stored under `results/`, including:

- implementation test summary
- state fixed-point result
- exhaustive enumeration summary
- communication cost JSON/text
- storage cost JSON/text
- benchmark CSV/JSON/text
- environment metadata
- SHA-256 checksums

Results will clearly distinguish deterministic PASS/FAIL evidence from machine-dependent timing measurements.

## 15. Proposed repository structure

```text
DTI-R-Reference-Implementation-and-State-Verification/
├── README.md
├── CITATION.cff
├── LICENSE
├── pyproject.toml
├── src/dtir/
│   ├── __init__.py
│   ├── constants.py
│   ├── encoding.py
│   ├── crypto.py
│   ├── messages.py
│   ├── records.py
│   ├── device.py
│   ├── server.py
│   └── protocol.py
├── tests/
│   ├── test_encoding.py
│   ├── test_crypto.py
│   ├── test_protocol.py
│   ├── test_recovery.py
│   ├── test_restart.py
│   └── test_costs.py
├── verification/
│   ├── state_model.py
│   ├── fixed_point_check.py
│   └── enumerate_sequences.py
├── benchmark/
│   └── benchmark_dtir.py
├── scripts/
│   └── regenerate_results.py
├── results/
└── .github/workflows/reproducibility.yml
```

## 16. Citation and authorship metadata

`CITATION.cff` will initially avoid assuming that the author list is identical to the previous manuscript. Author names will be finalized only after the manuscript authorship is confirmed. Until then, repository metadata will use a placeholder note that must be resolved before the public release/DOI.

## 17. Acceptance criteria before public release

The repository will not be declared ready until:

1. all deterministic tests pass from a clean environment;
2. the 1,000-round test is reproduced;
3. fixed-point reachability and the 16,384-sequence enumeration are executed from scratch;
4. no invariant violation is found, or any violation is fully investigated and reported;
5. communication/storage numbers are generated from code;
6. a new benchmark is executed and its environment recorded;
7. GitHub Actions reproduces the deterministic suite;
8. README instructions work from a clean checkout;
9. generated result files match the executed commands;
10. the manuscript is updated to agree with the newly generated evidence.

