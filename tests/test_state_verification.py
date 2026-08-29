from verification.enumerate_sequences import enumerate_length
from verification.fixed_point_check import reachable_states
from verification.state_model import Outcome, State, invariant_holds, transition


def test_transition_table_matches_manuscript():
    expected = {
        State.S0: [State.S0, State.S1, State.S2, State.S0],
        State.S1: [State.S1, State.S1, State.S2, State.S0],
        State.S2: [State.S2, State.S1, State.S2, State.S0],
    }
    outcomes = [Outcome.FAR_LOSS, Outcome.BAR_LOSS, Outcome.AKA_LOSS, Outcome.COMPLETE]
    for state, row in expected.items():
        assert [transition(state, outcome) for outcome in outcomes] == row


def test_fixed_point_contains_exactly_three_reachable_states():
    assert reachable_states() == {State.S0, State.S1, State.S2}


def test_length_seven_enumeration_has_16384_sequences_no_violations_and_expected_distribution():
    result = enumerate_length(7)
    assert result.total_sequences == 16_384
    assert result.invariant_violations == 0
    assert result.final_counts == {State.S0: 5462, State.S1: 5461, State.S2: 5461}


def test_invariant_holds_for_all_abstract_states():
    assert all(invariant_holds(state) for state in State)
