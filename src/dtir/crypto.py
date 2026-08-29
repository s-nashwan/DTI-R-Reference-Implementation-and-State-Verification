from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from .constants import (
    DTI_BYTES,
    HKDF_OUTPUT_BYTES,
    LABEL_AKA,
    LABEL_BAR,
    LABEL_DTI,
    LABEL_FAR,
    LABEL_KEY_SCHEDULE,
    LABEL_SALT,
    NONCE_BYTES,
    STATE_BYTES,
    TAG_BYTES,
)
from .encoding import encode_fields


def _require_len(name: str, value: bytes, size: int) -> None:
    if len(value) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(value)}")


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _trunc128(value: bytes) -> bytes:
    return value[:TAG_BYTES]


def generate_dti(real_id: bytes, state: bytes) -> bytes:
    _require_len("state", state, STATE_BYTES)
    return _hmac_sha256(state, encode_fields(LABEL_DTI, real_id))[:DTI_BYTES]


def far_tag(state: bytes, dti: bytes, nd: bytes) -> bytes:
    _require_len("state", state, STATE_BYTES)
    _require_len("dti", dti, DTI_BYTES)
    _require_len("nd", nd, NONCE_BYTES)
    return _trunc128(_hmac_sha256(state, encode_fields(LABEL_FAR, dti, nd)))


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return _hmac_sha256(salt, ikm)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length <= 0 or length > 255 * hashlib.sha256().digest_size:
        raise ValueError("invalid HKDF output length")
    result = bytearray()
    previous = b""
    counter = 1
    while len(result) < length:
        previous = _hmac_sha256(prk, previous + info + bytes([counter]))
        result.extend(previous)
        counter += 1
    return bytes(result[:length])


@dataclass(frozen=True)
class KeySchedule:
    x_next: bytes
    k_auth: bytes
    k_sess: bytes
    salt: bytes
    prk: bytes
    okm: bytes


def derive_schedule(state: bytes, dti: bytes, nd: bytes, ns: bytes) -> KeySchedule:
    _require_len("state", state, STATE_BYTES)
    _require_len("dti", dti, DTI_BYTES)
    _require_len("nd", nd, NONCE_BYTES)
    _require_len("ns", ns, NONCE_BYTES)
    salt = hashlib.sha256(encode_fields(LABEL_SALT, dti, nd, ns)).digest()
    prk = _hkdf_extract(salt, state)
    info = encode_fields(LABEL_KEY_SCHEDULE, dti, nd, ns)
    okm = _hkdf_expand(prk, info, HKDF_OUTPUT_BYTES)
    return KeySchedule(
        x_next=okm[0:32],
        k_auth=okm[32:64],
        k_sess=okm[64:96],
        salt=salt,
        prk=prk,
        okm=okm,
    )


def bar_tag(k_auth: bytes, dti_current: bytes, dti_next: bytes, nd: bytes, ns: bytes) -> bytes:
    _require_len("k_auth", k_auth, 32)
    _require_len("dti_current", dti_current, DTI_BYTES)
    _require_len("dti_next", dti_next, DTI_BYTES)
    _require_len("nd", nd, NONCE_BYTES)
    _require_len("ns", ns, NONCE_BYTES)
    return _trunc128(
        _hmac_sha256(
            k_auth,
            encode_fields(LABEL_BAR, dti_current, dti_next, nd, ns),
        )
    )


def aka_tag(k_auth: bytes, dti_current: bytes, dti_next: bytes, nd: bytes, ns: bytes) -> bytes:
    _require_len("k_auth", k_auth, 32)
    _require_len("dti_current", dti_current, DTI_BYTES)
    _require_len("dti_next", dti_next, DTI_BYTES)
    _require_len("nd", nd, NONCE_BYTES)
    _require_len("ns", ns, NONCE_BYTES)
    return _trunc128(
        _hmac_sha256(
            k_auth,
            encode_fields(LABEL_AKA, dti_current, dti_next, nd, ns),
        )
    )
