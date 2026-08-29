from __future__ import annotations

from dataclasses import dataclass

from .device import Device
from .server import Decision, Server


@dataclass(frozen=True)
class RoundResult:
    decision: Decision
    committed: bool
    device_session_key: bytes | None
    server_session_key: bytes | None


def complete_round(device: Device, server: Server) -> RoundResult:
    far = device.prepare_far()
    far_result = server.process_far(far)
    if far_result.bar is None:
        return RoundResult(far_result.decision, False, None, None)
    accepted = device.accept_bar(far_result.bar)
    aka_result = server.process_aka(accepted.aka)
    if aka_result.accepted:
        device.mark_transaction_complete()
    return RoundResult(
        decision=far_result.decision,
        committed=aka_result.accepted,
        device_session_key=accepted.k_sess,
        server_session_key=aka_result.k_sess,
    )
