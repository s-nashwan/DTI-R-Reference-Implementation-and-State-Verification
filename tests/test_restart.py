from dtir.device import Device
from dtir.server import Decision, Server

from helpers import CounterNonce

ID = b"device-0001"
X0 = bytes(range(32))


def test_device_restart_before_bar_reuses_persisted_far():
    device = Device(ID, X0, nonce_source=CounterNonce(1))
    far = device.prepare_far()
    restored = Device.restore(device.snapshot(), nonce_source=CounterNonce(500))
    assert restored.prepare_far().to_bytes() == far.to_bytes()


def test_server_restart_with_pending_returns_same_stored_bar():
    device = Device(ID, X0, nonce_source=CounterNonce(1))
    server = Server(ID, X0, nonce_source=CounterNonce(1000))
    far = device.prepare_far()
    first = server.process_far(far)
    restored = Server.restore(server.snapshot(), nonce_source=CounterNonce(2000))
    retry = restored.process_far(far)
    assert retry.decision is Decision.EXACT_RETRY
    assert retry.bar.to_bytes() == first.bar.to_bytes()


def test_device_restart_after_bar_preserves_advanced_state_and_allows_implicit_recovery():
    device = Device(ID, X0, nonce_source=CounterNonce(1))
    server = Server(ID, X0, nonce_source=CounterNonce(1000))
    far = device.prepare_far()
    response = server.process_far(far)
    device.accept_bar(response.bar)  # AKA intentionally lost.

    advanced_state = device.state
    restored = Device.restore(device.snapshot(), nonce_source=CounterNonce(500))
    assert restored.state == advanced_state
    next_far = restored.prepare_far()
    result = server.process_far(next_far)
    assert result.decision is Decision.IMPLICIT_COMMIT


def test_server_restart_after_explicit_promotion_keeps_confirmed_and_no_pending():
    device = Device(ID, X0, nonce_source=CounterNonce(1))
    server = Server(ID, X0, nonce_source=CounterNonce(1000))
    far = device.prepare_far()
    response = server.process_far(far)
    accepted = device.accept_bar(response.bar)
    assert server.process_aka(accepted.aka).accepted

    snapshot = server.snapshot()
    restored = Server.restore(snapshot, nonce_source=CounterNonce(2000))
    assert restored.confirmed == server.confirmed
    assert restored.pending is None
