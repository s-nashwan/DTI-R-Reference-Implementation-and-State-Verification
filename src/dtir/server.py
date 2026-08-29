from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hmac
import secrets
from typing import Callable

from .crypto import aka_tag, bar_tag, derive_schedule, far_tag, generate_dti
from .messages import AKA, BAR, FAR
from .records import ConfirmedRecord, PendingRecord

NonceSource = Callable[[], bytes]


class Decision(str, Enum):
    NEW_CURRENT = "New-Current"
    EXACT_RETRY = "Exact-Retry"
    REJECT_BUSY = "Reject-Busy"
    IMPLICIT_COMMIT = "Implicit-Commit"
    REJECT = "Reject"
    REJECT_UNKNOWN = "Reject-Unknown"


@dataclass(frozen=True)
class FARResult:
    decision: Decision
    bar: BAR | None = None


@dataclass(frozen=True)
class AKAResult:
    accepted: bool
    k_sess: bytes | None = None


class Server:
    def __init__(self, real_id: bytes, state: bytes, *, nonce_source: NonceSource | None = None):
        self.real_id = bytes(real_id)
        self.confirmed = ConfirmedRecord(bytes(state), generate_dti(self.real_id, bytes(state)))
        self.pending: PendingRecord | None = None
        self._nonce_source = nonce_source or (lambda: secrets.token_bytes(16))
        self.reserved_dtis: set[bytes] = set()
        self.retired_dtis: set[bytes] = set()

    def _valid_far(self, state: bytes, far: FAR) -> bool:
        return hmac.compare_digest(far_tag(state, far.dti, far.nd), far.tag)

    def _active_dtis(self) -> set[bytes]:
        active = {self.confirmed.dti} | set(self.reserved_dtis)
        if self.pending is not None:
            active.add(self.pending.dti_next)
        return active

    def _prepare_pending(self, state: bytes, current_dti: bytes, far: FAR) -> PendingRecord:
        # Regenerate NS until DTI_next is unique among other active identifiers.
        # current_dti is allowed because it names this same record.
        for _ in range(1024):
            ns = bytes(self._nonce_source())
            if len(ns) != 16:
                raise ValueError("server nonce source must return 16 bytes")
            schedule = derive_schedule(state, current_dti, far.nd, ns)
            dti_next = generate_dti(self.real_id, schedule.x_next)
            occupied = self._active_dtis() - {current_dti}
            if dti_next in occupied:
                continue
            tag = bar_tag(schedule.k_auth, current_dti, dti_next, far.nd, ns)
            bar = BAR(ns=ns, tag=tag)
            return PendingRecord(
                state_next=schedule.x_next,
                dti_next=dti_next,
                nd=far.nd,
                ns=ns,
                k_auth=schedule.k_auth,
                k_sess=schedule.k_sess,
                bar=bar,
            )
        raise RuntimeError("could not derive a unique pending DTI")

    def process_far(self, far: FAR) -> FARResult:
        if far.dti == self.confirmed.dti:
            if not self._valid_far(self.confirmed.state, far):
                return FARResult(Decision.REJECT)
            if self.pending is None:
                self.pending = self._prepare_pending(self.confirmed.state, self.confirmed.dti, far)
                return FARResult(Decision.NEW_CURRENT, self.pending.bar)
            if far.nd == self.pending.nd:
                return FARResult(Decision.EXACT_RETRY, self.pending.bar)
            return FARResult(Decision.REJECT_BUSY)

        if self.pending is not None and far.dti == self.pending.dti_next:
            if not self._valid_far(self.pending.state_next, far):
                return FARResult(Decision.REJECT)

            old_confirmed = self.confirmed
            promoted = ConfirmedRecord(self.pending.state_next, self.pending.dti_next)
            self.retired_dtis.add(old_confirmed.dti)
            self.confirmed = promoted
            self.pending = None

            # Same authenticated FAR immediately prepares the next transaction.
            self.pending = self._prepare_pending(self.confirmed.state, self.confirmed.dti, far)
            return FARResult(Decision.IMPLICIT_COMMIT, self.pending.bar)

        return FARResult(Decision.REJECT_UNKNOWN)

    def process_aka(self, aka: AKA) -> AKAResult:
        if self.pending is None:
            return AKAResult(False)
        if aka.source_dti != self.confirmed.dti:
            return AKAResult(False)
        expected = aka_tag(
            self.pending.k_auth,
            self.confirmed.dti,
            self.pending.dti_next,
            self.pending.nd,
            self.pending.ns,
        )
        if not hmac.compare_digest(expected, aka.tag):
            return AKAResult(False)

        old_dti = self.confirmed.dti
        k_sess = self.pending.k_sess
        self.confirmed = ConfirmedRecord(self.pending.state_next, self.pending.dti_next)
        self.pending = None
        self.retired_dtis.add(old_dti)
        return AKAResult(True, k_sess)

    def snapshot(self) -> dict:
        pending = None
        if self.pending is not None:
            pending = {
                "state_next": self.pending.state_next,
                "dti_next": self.pending.dti_next,
                "nd": self.pending.nd,
                "ns": self.pending.ns,
                "k_auth": self.pending.k_auth,
                "k_sess": self.pending.k_sess,
                "bar": self.pending.bar.to_bytes(),
            }
        return {
            "real_id": self.real_id,
            "confirmed_state": self.confirmed.state,
            "confirmed_dti": self.confirmed.dti,
            "pending": pending,
            "retired_dtis": tuple(self.retired_dtis),
            "reserved_dtis": tuple(self.reserved_dtis),
        }

    @classmethod
    def restore(cls, snapshot: dict, *, nonce_source: NonceSource | None = None) -> "Server":
        obj = cls(snapshot["real_id"], snapshot["confirmed_state"], nonce_source=nonce_source)
        obj.confirmed = ConfirmedRecord(snapshot["confirmed_state"], snapshot["confirmed_dti"])
        obj.retired_dtis = set(snapshot.get("retired_dtis", ()))
        obj.reserved_dtis = set(snapshot.get("reserved_dtis", ()))
        pending = snapshot.get("pending")
        if pending is not None:
            obj.pending = PendingRecord(
                state_next=pending["state_next"],
                dti_next=pending["dti_next"],
                nd=pending["nd"],
                ns=pending["ns"],
                k_auth=pending["k_auth"],
                k_sess=pending["k_sess"],
                bar=BAR.from_bytes(pending["bar"]),
            )
        return obj
