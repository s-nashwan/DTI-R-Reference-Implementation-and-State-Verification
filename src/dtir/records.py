from __future__ import annotations

from dataclasses import dataclass

from .messages import BAR, FAR


@dataclass(frozen=True)
class ConfirmedRecord:
    state: bytes
    dti: bytes


@dataclass(frozen=True)
class PendingRecord:
    state_next: bytes
    dti_next: bytes
    nd: bytes
    ns: bytes
    k_auth: bytes
    k_sess: bytes
    bar: BAR


@dataclass(frozen=True)
class InFlightFAR:
    far: FAR


@dataclass(frozen=True)
class AcceptedBARContext:
    source_dti: bytes
    dti_next: bytes
    nd: bytes
    ns: bytes
    k_auth: bytes
    k_sess: bytes
