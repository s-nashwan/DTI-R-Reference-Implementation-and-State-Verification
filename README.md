# DTI-R Reference Implementation and State Verification

This repository contains an **independent reconstruction** of the DTI-R reference implementation from the protocol equations, algorithms, persistence rules, and validation cases stated in the manuscript. It is separate from the DTI-R ProVerif repository and is intended to reproduce the implementation, synchronization, protocol-cost, storage-cost, and host-side benchmark evidence.

## Scope

The implementation covers:

- HMAC-SHA-256 DTI generation with 128-bit truncation;
- SHA-256 and HKDF-SHA-256 key derivation with a 96-byte output split into `X_next`, `K_auth`, and `K_sess`;
- FAR, BAR, and AKA message generation and verification;
- confirmed and single-pending server records;
- byte-identical exact FAR retry;
- rejection of a competing FAR while a pending transaction exists;
- explicit AKA commitment;
- implicit commitment after AKA loss using the next FAR under the pending state;
- crash/restart tests at the manuscript persistence boundaries;
- an independent three-state synchronization model;
- exhaustive enumeration of all `4^7 = 16,384` length-seven delivery/loss sequences;
- deterministic communication, storage, and operation-count calculations;
- a host-side benchmark that records its execution environment.

The repository does **not** contain ProVerif models. Those are maintained separately at:

`https://github.com/s-nashwan/DTI-R-ProVerif-Formal-Verification`

## Scientific reproducibility rule

No historical result is copied into `results/` simply because it appears in the manuscript. The files in `results/` are generated from the code in this repository. If regenerated evidence differs from a previous manuscript value, the manuscript should be updated to the regenerated evidence rather than tuning this implementation to reproduce the historical value.

## Protocol wire format

| Message | Fields | Bytes |
|---|---|---:|
| FAR | `DTI || ND || Tau_D` | 48 |
| BAR | `NS || Tau_S` | 32 |
| AKA | `DTI_current || Tau_A` | 32 |
| Total | FAR + BAR + AKA | 112 |

All cryptographic inputs use a canonical framing rule: each field is encoded as a 4-byte unsigned big-endian length followed by the exact field bytes. This makes field boundaries unambiguous. The real identifier and `DTI_next` are not transmitted online.

## Quick start

Python 3.10 or newer is required.

```bash
python -m pip install -e . pytest
pytest -q
python scripts/regenerate_results.py
```

The last command runs the full deterministic test suite, the independent state-verification scripts, cost calculations, and the host benchmark, then writes the evidence to `results/`.

To regenerate deterministic evidence without a timing benchmark:

```bash
python scripts/regenerate_results.py --skip-benchmark
```

## Expected deterministic checks

The repository treats the following manuscript values as hypotheses to reproduce, not hard-coded output:

- 1,000 sequential successful rounds with matching device/server states and session keys;
- exact retry returns the same stored BAR;
- competing FAR is rejected while pending exists;
- BAR-loss and AKA-loss recovery succeed;
- retired replay and late AKA do not alter active state;
- four restart-boundary tests succeed;
- fixed-point exploration reaches exactly `S0`, `S1`, and `S2`;
- length-seven enumeration examines 16,384 sequences with zero invariant violations;
- final-state counts are S0 = 5,462, S1 = 5,461, S2 = 5,461;
- communication cost is 112 bytes.

## Results

Generated artifacts are stored in `results/`:

- `implementation_test_summary.txt`
- `state_verification.json` and `.txt`
- `communication_costs.json`
- `storage_costs.json`
- `operation_counts.json`
- `benchmark.json`
- `environment.json`
- `SHA256SUMS.txt`

Timing results are machine-dependent and are not constrained-device measurements. The release benchmark pins the process to one available logical CPU when the operating system permits it, disables garbage collection during timed regions, uses a warm-up stage, and reports the median and IQR across 21 batches. GitHub Actions checks functional reproducibility but does not use a timing threshold as a pass/fail criterion.

## Repository status and authorship

This is a development release reconstructed from the manuscript specification. The final human author list for `CITATION.cff` must be confirmed before the public archival release and DOI minting. The current citation metadata therefore uses a neutral contributor entity and does not assume that the author list is identical to another manuscript.

## License

MIT License. See `LICENSE`.
