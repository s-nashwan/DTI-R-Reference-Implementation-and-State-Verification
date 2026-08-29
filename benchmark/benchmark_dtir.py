from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
from pathlib import Path
import platform
import ssl
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dtir.crypto import aka_tag, bar_tag, derive_schedule, far_tag, generate_dti
from dtir.device import Device
from dtir.protocol import complete_round
from dtir.server import Server


ID = b"device-0001"
X = bytes(range(32))
ND = (1).to_bytes(16, "big")
NS = (2).to_bytes(16, "big")
DTI = generate_dti(ID, X)
SCHEDULE = derive_schedule(X, DTI, ND, NS)
DTI_NEXT = generate_dti(ID, SCHEDULE.x_next)


class CounterNonce:
    def __init__(self, start: int):
        self.value = start

    def __call__(self) -> bytes:
        value = self.value
        self.value += 1
        return value.to_bytes(16, "big")


def _iqr(values: list[float]) -> tuple[float, float]:
    ordered = sorted(values)
    n = len(ordered)
    if n < 4:
        return ordered[0], ordered[-1]
    # Inclusive quartiles are stable for 21 batches and easy to reproduce.
    qs = statistics.quantiles(ordered, n=4, method="inclusive")
    return qs[0], qs[2]


def _measure(operation, repetitions: int, batches: int, warmup: int) -> dict[str, float | int]:
    for _ in range(warmup):
        operation()

    samples_us: list[float] = []
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(batches):
            start = time.perf_counter_ns()
            for _ in range(repetitions):
                operation()
            elapsed = time.perf_counter_ns() - start
            samples_us.append(elapsed / repetitions / 1000.0)
    finally:
        if was_enabled:
            gc.enable()

    q1, q3 = _iqr(samples_us)
    return {
        "median_us": statistics.median(samples_us),
        "q1_us": q1,
        "q3_us": q3,
        "batches": batches,
        "repetitions_per_batch": repetitions,
    }


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _pin_to_one_cpu() -> int | None:
    """Pin this benchmark process to one available logical CPU when supported."""
    if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
        return None
    try:
        allowed = sorted(os.sched_getaffinity(0))
        if not allowed:
            return None
        cpu = allowed[0]
        os.sched_setaffinity(0, {cpu})
        return cpu
    except (OSError, PermissionError):
        return None


def environment_metadata() -> dict[str, str]:
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity = sorted(os.sched_getaffinity(0))
        except OSError:
            affinity = None
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "openssl": ssl.OPENSSL_VERSION,
        "os": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu": _cpu_model(),
        "sha256_provider": hashlib.sha256().name,
        "cpu_affinity": ",".join(str(x) for x in affinity) if affinity is not None else "unavailable",
    }


def run_benchmark(*, batches: int = 21, repetitions: int = 2000, transaction_repetitions: int = 500, warmup: int = 200) -> dict:
    pinned_cpu = _pin_to_one_cpu()
    device = Device(ID, X, nonce_source=CounterNonce(10_000))
    server = Server(ID, X, nonce_source=CounterNonce(1_000_000))

    def full_transaction():
        result = complete_round(device, server)
        if not result.committed:
            raise RuntimeError(f"benchmark transaction failed: {result.decision}")

    operations = {
        "dti_generation": lambda: generate_dti(ID, X),
        "far_tag_generation": lambda: far_tag(X, DTI, ND),
        "hkdf_schedule_96_bytes": lambda: derive_schedule(X, DTI, ND, NS),
        "bar_tag_generation": lambda: bar_tag(SCHEDULE.k_auth, DTI, DTI_NEXT, ND, NS),
        "aka_tag_generation": lambda: aka_tag(SCHEDULE.k_auth, DTI, DTI_NEXT, ND, NS),
    }

    results = {
        name: _measure(op, repetitions, batches, warmup)
        for name, op in operations.items()
    }
    results["complete_far_bar_aka_exchange"] = _measure(
        full_transaction,
        transaction_repetitions,
        batches,
        max(10, warmup // 10),
    )
    env = environment_metadata()
    env["pinned_logical_cpu"] = str(pinned_cpu) if pinned_cpu is not None else "unavailable"
    return {"environment": env, "results": results}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batches", type=int, default=21)
    parser.add_argument("--repetitions", type=int, default=2000)
    parser.add_argument("--transaction-repetitions", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_benchmark(
        batches=args.batches,
        repetitions=args.repetitions,
        transaction_repetitions=args.transaction_repetitions,
        warmup=args.warmup,
    )
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
