from __future__ import annotations

from .state_model import Outcome, State, transition


def reachable_states(initial: State = State.S0) -> set[State]:
    reached = {initial}
    frontier = [initial]
    while frontier:
        state = frontier.pop()
        for outcome in Outcome:
            nxt = transition(state, outcome)
            if nxt not in reached:
                reached.add(nxt)
                frontier.append(nxt)
    return reached


def main() -> None:
    states = sorted(reachable_states(), key=lambda s: s.name)
    print("reachable_states:", ", ".join(s.name for s in states))
    print("count:", len(states))


if __name__ == "__main__":
    main()
