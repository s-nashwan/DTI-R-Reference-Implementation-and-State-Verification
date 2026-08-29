from __future__ import annotations

from dataclasses import dataclass
import hmac
import secrets
from typing import Callable

from .crypto import aka_tag, bar_tag, derive_schedule, far_tag, generate_dti
from .messages import AKA, BAR, FAR
from .records import AcceptedBARContext, InFlightFAR

NonceSource = Callable[[], bytes]


@dataclass(frozen=True)
class DeviceBARResult:
    aka: AKA
    k_sess: bytes


class Device:
    def __init__(self, real_id: bytes, state: bytes, *, nonce_source: NonceSource | None = None):
        self.real_id = bytes(real_id)
        self.state = bytes(state)
        self.current_dti = generate_dti(self.real_id, self.state)
        self._nonce_source = nonce_source or (lambda: secrets.token_bytes(16))
        self.in_flight: InFlightFAR | None = None
        self.last_accepted: AcceptedBARContext | None = None

    def prepare_far(self) -> FAR:
        if self.in_flight is not None:
            return self.in_flight.far
        nd = bytes(self._nonce_source())
        if len(nd) != 16:
            raise ValueError("device nonce source must return 16 bytes")
        dti = self.current_dti
        far = FAR(dti=dti, nd=nd, tag=far_tag(self.state, dti, nd))
        self.in_flight = InFlightFAR(far)
        return far

    def accept_bar(self, bar: BAR) -> DeviceBARResult:
        if self.in_flight is None:
            raise ValueError("no unresolved FAR")
        far = self.in_flight.far
        schedule = derive_schedule(self.state, far.dti, far.nd, bar.ns)
        dti_next = generate_dti(self.real_id, schedule.x_next)
        expected = bar_tag(schedule.k_auth, far.dti, dti_next, far.nd, bar.ns)
        if not hmac.compare_digest(expected, bar.tag):
            raise ValueError("invalid BAR tag")

        # Persistence boundary: the device advances before AKA is emitted.
        self.state = schedule.x_next
        self.current_dti = dti_next
        self.in_flight = None
        self.last_accepted = AcceptedBARContext(
            source_dti=far.dti,
            dti_next=dti_next,
            nd=far.nd,
            ns=bar.ns,
            k_auth=schedule.k_auth,
            k_sess=schedule.k_sess,
        )
        tag = aka_tag(schedule.k_auth, far.dti, dti_next, far.nd, bar.ns)
        return DeviceBARResult(aka=AKA(source_dti=far.dti, tag=tag), k_sess=schedule.k_sess)

    def mark_transaction_complete(self) -> None:
        self.last_accepted = None

    def snapshot(self) -> dict:
        return {
            "real_id": self.real_id,
            "state": self.state,
            "current_dti": self.current_dti,
            "in_flight_far": self.in_flight.far.to_bytes() if self.in_flight else None,
        }

    @classmethod
    def restore(cls, snapshot: dict, *, nonce_source: NonceSource | None = None) -> "Device":
        obj = cls(snapshot["real_id"], snapshot["state"], nonce_source=nonce_source)
        obj.current_dti = snapshot["current_dti"]
        raw = snapshot.get("in_flight_far")
        if raw is not None:
            obj.in_flight = InFlightFAR(FAR.from_bytes(raw))
        return obj
