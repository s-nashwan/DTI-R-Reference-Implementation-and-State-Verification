from dtir.encoding import encode_fields


def test_length_prefixed_encoding_is_boundary_unambiguous():
    assert encode_fields(b"ab", b"c") != encode_fields(b"a", b"bc")


def test_encoding_uses_four_byte_big_endian_lengths():
    encoded = encode_fields(b"A", b"BC")
    assert encoded == b"\x00\x00\x00\x01A\x00\x00\x00\x02BC"
