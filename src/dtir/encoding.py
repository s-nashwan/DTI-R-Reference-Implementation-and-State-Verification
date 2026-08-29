from __future__ import annotations


def encode_fields(*fields: bytes | bytearray | memoryview | str) -> bytes:
    """Canonical length-prefixed encoding used by all protocol inputs.

    Each field is encoded as a 4-byte unsigned big-endian length followed by
    the exact field bytes. Text labels are encoded as UTF-8 before framing.
    """
    out = bytearray()
    for field in fields:
        if isinstance(field, str):
            raw = field.encode("utf-8")
        elif isinstance(field, (bytes, bytearray, memoryview)):
            raw = bytes(field)
        else:
            raise TypeError(f"unsupported field type: {type(field)!r}")
        if len(raw) > 0xFFFFFFFF:
            raise ValueError("field too long for 4-byte length prefix")
        out.extend(len(raw).to_bytes(4, "big"))
        out.extend(raw)
    return bytes(out)
