from dtir.device import Device
from dtir.messages import AKA, BAR, FAR
from dtir.protocol import complete_round
from dtir.server import Decision, Server

from helpers import CounterNonce

ID = b"device-0001"
X0 = bytes(range(32))


def make_pair():
    device = Device(ID, X0, nonce_source=CounterNonce(1))
    server = Server(ID, X0, nonce_source=CounterNonce(1000))
    return device, server


def test_wire_message_sizes_are_48_32_32_bytes():
    far = FAR(b"D" * 16, b"N" * 16, b"T" * 16)
    bar = BAR(b"S" * 16, b"T" * 16)
    aka = AKA(b"D" * 16, b"T" * 16)
    assert len(far.to_bytes()) == 48
    assert len(bar.to_bytes()) == 32
    assert len(aka.to_bytes()) == 32


def test_one_complete_round_matches_state_and_session_key_and_clears_pending():
    device, server = make_pair()
    result = complete_round(device, server)
    assert result.decision is Decision.NEW_CURRENT
    assert result.committed is True
    assert result.device_session_key == result.server_session_key
    assert device.state == server.confirmed.state
    assert device.current_dti == server.confirmed.dti
    assert server.pending is None


def test_1000_sequential_rounds_keep_device_and_server_aligned():
    device, server = make_pair()
    for _ in range(1000):
        result = complete_round(device, server)
        assert result.committed is True
        assert result.device_session_key == result.server_session_key
        assert device.state == server.confirmed.state
        assert device.current_dti == server.confirmed.dti
        assert server.pending is None
