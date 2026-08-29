from __future__ import annotations

from enum import Enum


class State(str, Enum):
    S0 = "confirmed"
    S1 = "pending-prepared"
    S2 = "device-advanced"


class Outcome(str, Enum):
    FAR_LOSS = "far-loss"
    BAR_LOSS = "bar-loss"
    AKA_LOSS = "aka-loss"
    COMPLETE = "complete-delivery"


_TRANSITIONS = {
    State.S0: {
        Outcome.FAR_LOSS: State.S0,
        Outcome.BAR_LOSS: State.S1,
        Outcome.AKA_LOSS: State.S2,
        Outcome.COMPLETE: State.S0,
    },
    State.S1: {
        Outcome.FAR_LOSS: State.S1,
        Outcome.BAR_LOSS: State.S1,
        Outcome.AKA_LOSS: State.S2,
        Outcome.COMPLETE: State.S0,
    },
    State.S2: {
        Outcome.FAR_LOSS: State.S2,
        Outcome.BAR_LOSS: State.S1,
        Outcome.AKA_LOSS: State.S2,
        Outcome.COMPLETE: State.S0,
    },
}


def transition(state: State, outcome: Outcome) -> State:
    return _TRANSITIONS[state][outcome]


def invariant_holds(state: State) -> bool:
    """Equation (21) abstraction.

    S0 means no pending record and device == confirmed.
    S1 means pending exists and device == confirmed.
    S2 means pending exists and device == pending.
    """
    return state in (State.S0, State.S1, State.S2)
