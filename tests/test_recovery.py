from copy import deepcopy

from dtir.crypto import derive_schedule, far_tag, generate_dti
from dtir.device import Device
from dtir.messages import AKA, BAR, FAR
from dtir.server import Decision, Server

from helpers import CounterNonce, SequenceNonce

ID = b"device-0001"
X0 = bytes(range(32))


def make_pair():
    return (
        Device(ID, X0, nonce_source=CounterNonce(1)),
        Server(ID, X0, nonce_source=CounterNonce(1000)),
    )


def test_exact_far_retry_returns_byte_identical_bar_and_no_new_transition():
    device, server = make_pair()
    far = device.prepare_far()
    first = server.process_far(far)
    pending_before = server.pending
    second = server.process_far(far)
    assert first.decision is Decision.NEW_CURRENT
    assert second.decision is Decision.EXACT_RETRY
    assert second.bar.to_bytes() == first.bar.to_bytes()
    assert server.pending == pending_before


def test_competing_far_with_different_nonce_is_reject_busy():
    device, server = make_pair()
    far = device.prepare_far()
    server.process_far(far)
    other_nd = (999).to_bytes(16, "big")
    competing = FAR(far.dti, other_nd, far_tag(device.state, far.dti, other_nd))
    pending_before = server.pending
    result = server.process_far(competing)
    assert result.decision is Decision.REJECT_BUSY
    assert server.pending == pending_before


def test_bar_loss_recovers_by_exact_retry():
    device, server = make_pair()
    far = device.prepare_far()
    first = server.process_far(far)
    retry_far = device.prepare_far()
    second = server.process_far(retry_far)
    accepted = device.accept_bar(second.bar)
    committed = server.process_aka(accepted.aka)
    assert retry_far.to_bytes() == far.to_bytes()
    assert second.decision is Decision.EXACT_RETRY
    assert second.bar.to_bytes() == first.bar.to_bytes()
    assert committed.accepted
    assert device.state == server.confirmed.state


def test_aka_loss_recovers_via_pending_state_far_and_same_far_starts_next_transaction():
    device, server = make_pair()
    far0 = device.prepare_far()
    r0 = server.process_far(far0)
    accepted0 = device.accept_bar(r0.bar)
    lost_aka = accepted0.aka

    # Device is already advanced; next FAR is generated under the pending state.
    far1 = device.prepare_far()
    implicit = server.process_far(far1)
    assert implicit.decision is Decision.IMPLICIT_COMMIT
    assert server.pending is not None
    assert server.pending.nd == far1.nd

    accepted1 = device.accept_bar(implicit.bar)
    explicit = server.process_aka(accepted1.aka)
    assert explicit.accepted
    assert device.state == server.confirmed.state
    assert device.current_dti == server.confirmed.dti

    # Late AKA from transaction 0 cannot alter the current records.
    snapshot = deepcopy(server.snapshot())
    late = server.process_aka(lost_aka)
    assert late.accepted is False
    assert server.snapshot() == snapshot


def test_retired_dti_replay_is_rejected_without_state_change():
    device, server = make_pair()
    old_far = device.prepare_far()
    r = server.process_far(old_far)
    accepted = device.accept_bar(r.bar)
    assert server.process_aka(accepted.aka).accepted
    before = deepcopy(server.snapshot())
    replay = server.process_far(old_far)
    assert replay.decision is Decision.REJECT_UNKNOWN
    assert server.snapshot() == before


def test_invalid_far_bar_and_aka_tags_do_not_commit_state():
    device, server = make_pair()
    far = device.prepare_far()
    bad_far = FAR(far.dti, far.nd, bytes([far.tag[0] ^ 1]) + far.tag[1:])
    server_before = deepcopy(server.snapshot())
    assert server.process_far(bad_far).decision is Decision.REJECT
    assert server.snapshot() == server_before

    good = server.process_far(far)
    device_before = device.snapshot()
    bad_bar = BAR(good.bar.ns, bytes([good.bar.tag[0] ^ 1]) + good.bar.tag[1:])
    try:
        device.accept_bar(bad_bar)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid BAR should be rejected")
    assert device.snapshot() == device_before

    accepted = device.accept_bar(good.bar)
    server_before_aka = deepcopy(server.snapshot())
    bad_aka = AKA(accepted.aka.source_dti, bytes([accepted.aka.tag[0] ^ 1]) + accepted.aka.tag[1:])
    assert server.process_aka(bad_aka).accepted is False
    assert server.snapshot() == server_before_aka


def test_active_dti_collision_causes_new_server_nonce_and_candidate():
    device = Device(ID, X0, nonce_source=CounterNonce(1))
    far = device.prepare_far()
    ns1 = (1000).to_bytes(16, "big")
    ns2 = (1001).to_bytes(16, "big")
    schedule1 = derive_schedule(X0, far.dti, far.nd, ns1)
    colliding = generate_dti(ID, schedule1.x_next)

    source = SequenceNonce([ns1, ns2])
    server = Server(ID, X0, nonce_source=source)
    server.reserved_dtis.add(colliding)
    result = server.process_far(far)
    assert result.decision is Decision.NEW_CURRENT
    assert server.pending.ns == ns2
    assert server.pending.dti_next != colliding
