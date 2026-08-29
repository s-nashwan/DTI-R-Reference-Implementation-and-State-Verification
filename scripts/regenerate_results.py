from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from benchmark.benchmark_dtir import environment_metadata, run_benchmark
from dtir.costs import communication_costs, operation_counts, storage_costs
from dtir.crypto import far_tag
from dtir.device import Device
from dtir.messages import FAR
from dtir.protocol import complete_round
from dtir.server import Decision, Server
from verification.enumerate_sequences import enumerate_length
from verification.fixed_point_check import reachable_states
from verification.state_model import State


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _run_tests(results_dir: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SRC), str(ROOT), str(ROOT / "tests"), env.get("PYTHONPATH", "")]
    )
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    (results_dir / "implementation_test_summary.txt").write_text(
        output + f"\nexit_code={proc.returncode}\n"
    )
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)




class _CounterNonce:
    def __init__(self, start: int):
        self.value = start

    def __call__(self) -> bytes:
        value = self.value
        self.value += 1
        return value.to_bytes(16, "big")


def _validation_results(results_dir: Path) -> None:
    real_id = b"device-0001"
    x0 = bytes(range(32))
    scenarios: dict[str, object] = {}

    device = Device(real_id, x0, nonce_source=_CounterNonce(1))
    server = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    sequential_ok = True
    for _ in range(1000):
        result = complete_round(device, server)
        if not (
            result.committed
            and result.device_session_key == result.server_session_key
            and device.state == server.confirmed.state
            and device.current_dti == server.confirmed.dti
            and server.pending is None
        ):
            sequential_ok = False
            break
    scenarios["sequential_1000_rounds"] = {
        "rounds": 1000,
        "pass": sequential_ok,
    }

    device = Device(real_id, x0, nonce_source=_CounterNonce(1))
    server = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    far = device.prepare_far()
    first = server.process_far(far)
    retry = server.process_far(device.prepare_far())
    scenarios["exact_far_retry"] = {
        "pass": retry.decision is Decision.EXACT_RETRY and retry.bar.to_bytes() == first.bar.to_bytes()
    }

    other_nd = (999).to_bytes(16, "big")
    competing = FAR(far.dti, other_nd, far_tag(device.state, far.dti, other_nd))
    busy = server.process_far(competing)
    scenarios["competing_far_rejected"] = {"pass": busy.decision is Decision.REJECT_BUSY}

    accepted = device.accept_bar(retry.bar)
    scenarios["bar_loss_exact_retry_recovery"] = {
        "pass": server.process_aka(accepted.aka).accepted
    }

    device = Device(real_id, x0, nonce_source=_CounterNonce(1))
    server = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    far0 = device.prepare_far()
    r0 = server.process_far(far0)
    lost_aka = device.accept_bar(r0.bar).aka
    far1 = device.prepare_far()
    implicit = server.process_far(far1)
    late = server.process_aka(lost_aka)
    scenarios["aka_loss_implicit_commit"] = {
        "pass": implicit.decision is Decision.IMPLICIT_COMMIT
    }
    scenarios["late_aka_rejected_after_implicit_commit"] = {"pass": not late.accepted}

    device = Device(real_id, x0, nonce_source=_CounterNonce(1))
    server = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    old_far = device.prepare_far()
    r = server.process_far(old_far)
    accepted = device.accept_bar(r.bar)
    server.process_aka(accepted.aka)
    replay = server.process_far(old_far)
    scenarios["retired_dti_replay_rejected"] = {
        "pass": replay.decision is Decision.REJECT_UNKNOWN
    }

    # Four persistence boundaries from the manuscript.
    device = Device(real_id, x0, nonce_source=_CounterNonce(1))
    far = device.prepare_far()
    restored_device = Device.restore(device.snapshot(), nonce_source=_CounterNonce(500))
    restart_1 = restored_device.prepare_far().to_bytes() == far.to_bytes()

    server = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    first = server.process_far(far)
    restored_server = Server.restore(server.snapshot(), nonce_source=_CounterNonce(2000))
    retry = restored_server.process_far(far)
    restart_2 = retry.decision is Decision.EXACT_RETRY and retry.bar.to_bytes() == first.bar.to_bytes()

    device2 = Device(real_id, x0, nonce_source=_CounterNonce(1))
    server2 = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    f = device2.prepare_far()
    br = server2.process_far(f)
    device2.accept_bar(br.bar)
    restored2 = Device.restore(device2.snapshot(), nonce_source=_CounterNonce(500))
    implicit2 = server2.process_far(restored2.prepare_far())
    restart_3 = implicit2.decision is Decision.IMPLICIT_COMMIT

    device3 = Device(real_id, x0, nonce_source=_CounterNonce(1))
    server3 = Server(real_id, x0, nonce_source=_CounterNonce(1000))
    f3 = device3.prepare_far()
    b3 = server3.process_far(f3)
    a3 = device3.accept_bar(b3.bar)
    server3.process_aka(a3.aka)
    restored3 = Server.restore(server3.snapshot(), nonce_source=_CounterNonce(2000))
    restart_4 = restored3.pending is None and restored3.confirmed == server3.confirmed

    scenarios["restart_boundaries"] = {
        "pass": all((restart_1, restart_2, restart_3, restart_4)),
        "boundaries_passed": sum((restart_1, restart_2, restart_3, restart_4)),
        "boundaries_total": 4,
    }

    all_pass = all(bool(item["pass"]) for item in scenarios.values())
    data = {"all_pass": all_pass, "scenarios": scenarios}
    _write_json(results_dir / "deterministic_validation.json", data)
    lines = ["DTI-R deterministic validation", f"all_pass={str(all_pass).lower()}"]
    for name, item in scenarios.items():
        lines.append(f"{name}={'PASS' if item['pass'] else 'FAIL'}")
    (results_dir / "deterministic_validation.txt").write_text("\n".join(lines) + "\n")
    if not all_pass:
        raise SystemExit("one or more deterministic validation scenarios failed")


def _state_results(results_dir: Path) -> None:
    reached = sorted(reachable_states(), key=lambda s: s.name)
    enumeration = enumerate_length(7)
    data = {
        "fixed_point": {
            "reachable_state_count": len(reached),
            "reachable_states": [s.name for s in reached],
        },
        "length_seven_enumeration": {
            "sequence_length": enumeration.length,
            "total_sequences": enumeration.total_sequences,
            "invariant_violations": enumeration.invariant_violations,
            "final_state_counts": {
                state.name: enumeration.final_counts.get(state, 0)
                for state in State
            },
        },
    }
    _write_json(results_dir / "state_verification.json", data)
    (results_dir / "state_verification.txt").write_text(
        "DTI-R state verification\n"
        f"reachable_states={','.join(data['fixed_point']['reachable_states'])}\n"
        f"reachable_state_count={data['fixed_point']['reachable_state_count']}\n"
        f"sequence_length={enumeration.length}\n"
        f"total_sequences={enumeration.total_sequences}\n"
        f"invariant_violations={enumeration.invariant_violations}\n"
        f"S0={enumeration.final_counts.get(State.S0, 0)}\n"
        f"S1={enumeration.final_counts.get(State.S1, 0)}\n"
        f"S2={enumeration.final_counts.get(State.S2, 0)}\n"
    )


def _cost_results(results_dir: Path) -> None:
    _write_json(results_dir / "communication_costs.json", communication_costs())
    _write_json(results_dir / "storage_costs.json", storage_costs())
    _write_json(results_dir / "operation_counts.json", operation_counts())




def _write_results_markdown(results_dir: Path) -> None:
    state = json.loads((results_dir / "state_verification.json").read_text())
    comm = json.loads((results_dir / "communication_costs.json").read_text())
    storage = json.loads((results_dir / "storage_costs.json").read_text())
    ops = json.loads((results_dir / "operation_counts.json").read_text())
    validation = json.loads((results_dir / "deterministic_validation.json").read_text())
    benchmark_path = results_dir / "benchmark.json"
    lines = [
        "# Reproduced DTI-R Results",
        "",
        "This file is generated by `python scripts/regenerate_results.py` from the implementation in this repository.",
        "",
        "## Deterministic validation",
        "",
        f"- Overall deterministic validation: **{'PASS' if validation['all_pass'] else 'FAIL'}**",
    ]
    for name, item in validation["scenarios"].items():
        lines.append(f"- `{name}`: **{'PASS' if item['pass'] else 'FAIL'}**")
    fp = state["fixed_point"]
    enum = state["length_seven_enumeration"]
    counts = enum["final_state_counts"]
    lines += [
        "",
        "## State verification",
        "",
        f"- Reachable abstract states: {fp['reachable_state_count']} (`{', '.join(fp['reachable_states'])}`)",
        f"- Length-seven sequences: {enum['total_sequences']:,}",
        f"- Invariant violations: {enum['invariant_violations']}",
        f"- Final-state distribution: S0={counts['S0']:,}, S1={counts['S1']:,}, S2={counts['S2']:,}",
        "",
        "## Protocol costs",
        "",
        f"- FAR: {comm['far_bytes']} bytes",
        f"- BAR: {comm['bar_bytes']} bytes",
        f"- AKA: {comm['aka_bytes']} bytes",
        f"- Complete exchange: {comm['total_exchange_bytes']} bytes",
        f"- Device state: {storage['device_state_bytes']} bytes",
        f"- Confirmed + minimum pending + cached BAR: {storage['confirmed_plus_minimum_pending_plus_cached_bar_bytes']} bytes",
        f"- This reference implementation's confirmed + pending byte-string payload: {storage['reference_confirmed_plus_pending_payload_bytes']} bytes (Python object overhead excluded)",
        f"- Device operation accounting: {ops['device_hmac_sha256']} HMAC-SHA-256 + {ops['device_sha256']} SHA-256 + one 128-bit fresh nonce",
        f"- Server operation accounting: {ops['server_hmac_sha256']} HMAC-SHA-256 + {ops['server_sha256']} SHA-256 + one 128-bit fresh nonce",
    ]
    if benchmark_path.exists():
        b = json.loads(benchmark_path.read_text())
        lines += ["", "## Host-side benchmark", ""]
        for name, item in b["results"].items():
            lines.append(
                f"- `{name}`: median {item['median_us']:.3f} us (IQR {item['q1_us']:.3f}-{item['q3_us']:.3f} us)"
            )
        env = b["environment"]
        lines += [
            "",
            f"Environment: Python {env['python']}; {env['openssl']}; {env['cpu']}; kernel {env['kernel']}; pinned logical CPU {env.get('pinned_logical_cpu', 'unavailable')}.",
            "",
            "The timing values are host-side reproducibility measurements, not constrained-device performance claims.",
        ]
    else:
        lines += ["", "## Host-side benchmark", "", "Not generated in this deterministic-only run."]
    (ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")


def _checksums(results_dir: Path) -> None:
    lines = []
    for path in sorted(results_dir.iterdir()):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    (results_dir / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-benchmark", action="store_true")
    parser.add_argument("--benchmark-batches", type=int, default=21)
    parser.add_argument("--benchmark-repetitions", type=int, default=2000)
    parser.add_argument("--transaction-repetitions", type=int, default=500)
    args = parser.parse_args()

    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    for path in results_dir.iterdir():
        if path.is_file():
            path.unlink()

    _run_tests(results_dir)
    _validation_results(results_dir)
    _state_results(results_dir)
    _cost_results(results_dir)
    _write_json(results_dir / "environment.json", environment_metadata())

    if not args.skip_benchmark:
        benchmark = run_benchmark(
            batches=args.benchmark_batches,
            repetitions=args.benchmark_repetitions,
            transaction_repetitions=args.transaction_repetitions,
            warmup=200,
        )
        _write_json(results_dir / "benchmark.json", benchmark)

    _write_results_markdown(results_dir)
    _checksums(results_dir)
    print(f"Generated results in {results_dir}")


if __name__ == "__main__":
    main()
