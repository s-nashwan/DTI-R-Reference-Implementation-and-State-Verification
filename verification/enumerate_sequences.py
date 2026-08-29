from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import product

from .state_model import Outcome, State, invariant_holds, transition


@dataclass(frozen=True)
class EnumerationResult:
    length: int
    total_sequences: int
    invariant_violations: int
    final_counts: dict[State, int]


def enumerate_length(length: int, initial: State = State.S0) -> EnumerationResult:
    if length < 0:
        raise ValueError("length must be non-negative")
    counts: Counter[State] = Counter()
    violations = 0
    total = 0
    outcomes = tuple(Outcome)
    for sequence in product(outcomes, repeat=length):
        total += 1
        state = initial
        if not invariant_holds(state):
            violations += 1
            continue
        violated = False
        for outcome in sequence:
            state = transition(state, outcome)
            if not invariant_holds(state):
                violations += 1
                violated = True
                break
        if not violated:
            counts[state] += 1
    return EnumerationResult(length, total, violations, dict(counts))


def main() -> None:
    result = enumerate_length(7)
    print(f"length={result.length}")
    print(f"total_sequences={result.total_sequences}")
    print(f"invariant_violations={result.invariant_violations}")
    for state in State:
        print(f"{state.name}={result.final_counts.get(state, 0)}")


if __name__ == "__main__":
    main()
