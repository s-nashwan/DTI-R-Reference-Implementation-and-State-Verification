from __future__ import annotations

from dataclasses import dataclass

from .constants import DTI_BYTES, NONCE_BYTES, TAG_BYTES


def _require(name: str, value: bytes, size: int) -> bytes:
    raw = bytes(value)
    if len(raw) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(raw)}")
    return raw


@dataclass(frozen=True)
class FAR:
    dti: bytes
    nd: bytes
    tag: bytes

    def __post_init__(self):
        object.__setattr__(self, "dti", _require("dti", self.dti, DTI_BYTES))
        object.__setattr__(self, "nd", _require("nd", self.nd, NONCE_BYTES))
        object.__setattr__(self, "tag", _require("tag", self.tag, TAG_BYTES))

    def to_bytes(self) -> bytes:
        return self.dti + self.nd + self.tag

    @classmethod
    def from_bytes(cls, raw: bytes) -> "FAR":
        if len(raw) != 48:
            raise ValueError("FAR must be 48 bytes")
        return cls(raw[:16], raw[16:32], raw[32:48])


@dataclass(frozen=True)
class BAR:
    ns: bytes
    tag: bytes

    def __post_init__(self):
        object.__setattr__(self, "ns", _require("ns", self.ns, NONCE_BYTES))
        object.__setattr__(self, "tag", _require("tag", self.tag, TAG_BYTES))

    def to_bytes(self) -> bytes:
        return self.ns + self.tag

    @classmethod
    def from_bytes(cls, raw: bytes) -> "BAR":
        if len(raw) != 32:
            raise ValueError("BAR must be 32 bytes")
        return cls(raw[:16], raw[16:32])


@dataclass(frozen=True)
class AKA:
    source_dti: bytes
    tag: bytes

    def __post_init__(self):
        object.__setattr__(self, "source_dti", _require("source_dti", self.source_dti, DTI_BYTES))
        object.__setattr__(self, "tag", _require("tag", self.tag, TAG_BYTES))

    def to_bytes(self) -> bytes:
        return self.source_dti + self.tag

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AKA":
        if len(raw) != 32:
            raise ValueError("AKA must be 32 bytes")
        return cls(raw[:16], raw[16:32])
