from __future__ import annotations

from carddav_to_ldap.ber import (
    BERElement,
    TagClass,
    decode_element,
    encode_element,
    encode_integer,
    decode_integer,
    encode_string,
    decode_string,
    encode_boolean,
    decode_boolean,
    encode_enumerated,
    decode_enumerated,
    encode_sequence,
    encode_length,
    read_ldap_message,
)


class TestBEREncodeDecode:
    def test_integer_zero(self):
        el = encode_integer(0)
        assert decode_integer(el) == 0

    def test_integer_positive(self):
        el = encode_integer(42)
        assert decode_integer(el) == 42

    def test_integer_large(self):
        el = encode_integer(100000)
        assert decode_integer(el) == 100000

    def test_integer_negative(self):
        el = encode_integer(-1)
        assert decode_integer(el) == -1

    def test_string(self):
        el = encode_string("hello world")
        assert decode_string(el) == "hello world"

    def test_string_empty(self):
        el = encode_string("")
        assert decode_string(el) == ""

    def test_string_unicode(self):
        el = encode_string("Müller")
        assert decode_string(el) == "Müller"

    def test_boolean_true(self):
        el = encode_boolean(True)
        assert decode_boolean(el) is True

    def test_boolean_false(self):
        el = encode_boolean(False)
        assert decode_boolean(el) is False

    def test_enumerated(self):
        el = encode_enumerated(3)
        assert decode_enumerated(el) == 3

    def test_sequence_roundtrip(self):
        seq = encode_sequence([encode_integer(1), encode_string("test")])
        data = encode_element(seq)
        decoded, end = decode_element(data)
        assert decoded.tag_class == TagClass.UNIVERSAL
        assert decoded.constructed is True
        assert decoded.tag_number == 0x10
        children = decoded.value
        assert isinstance(children, list)
        assert len(children) == 2
        assert decode_integer(children[0]) == 1
        assert decode_string(children[1]) == "test"

    def test_encode_length_short(self):
        assert encode_length(5) == b"\x05"
        assert encode_length(0) == b"\x00"
        assert encode_length(127) == b"\x7f"

    def test_encode_length_long(self):
        result = encode_length(128)
        assert result[0] == 0x81
        assert result[1] == 128

    def test_encode_length_two_byte(self):
        result = encode_length(256)
        assert result[0] == 0x82
        assert int.from_bytes(result[1:3], "big") == 256

    def test_nested_sequence(self):
        inner = encode_sequence([encode_string("inner")])
        outer = encode_sequence([encode_integer(1), inner])
        data = encode_element(outer)
        decoded, _ = decode_element(data)
        children = decoded.value
        assert isinstance(children, list)
        assert len(children) == 2
        inner_decoded = children[1]
        assert isinstance(inner_decoded.value, list)
        assert decode_string(inner_decoded.value[0]) == "inner"


class TestReadLdapMessage:
    def test_complete_message(self):
        msg = encode_sequence([encode_integer(1), encode_string("test")])
        data = encode_element(msg)
        result, remaining = read_ldap_message(data)
        assert result is not None
        assert remaining == b""

    def test_incomplete_message(self):
        msg = encode_sequence([encode_integer(1), encode_string("test")])
        data = encode_element(msg)
        result, remaining = read_ldap_message(data[:3])
        assert result is None
        assert remaining == data[:3]

    def test_multiple_messages(self):
        msg1 = encode_element(encode_sequence([encode_integer(1)]))
        msg2 = encode_element(encode_sequence([encode_integer(2)]))
        data = msg1 + msg2
        result, remaining = read_ldap_message(data)
        assert result is not None
        assert remaining == msg2

    def test_empty_data(self):
        result, remaining = read_ldap_message(b"")
        assert result is None
        assert remaining == b""
