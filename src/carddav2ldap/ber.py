"""Minimal BER (Basic Encoding Rules) codec for LDAP message handling."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


class TagClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT = 2
    PRIVATE = 3


@dataclass
class BERElement:
    tag_class: TagClass
    constructed: bool
    tag_number: int
    value: bytes | list[BERElement]

    @property
    def tag_byte(self) -> int:
        return (self.tag_class << 6) | (int(self.constructed) << 5) | self.tag_number


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = []
    n = length
    while n > 0:
        encoded.append(n & 0xFF)
        n >>= 8
    encoded.reverse()
    return bytes([0x80 | len(encoded)] + encoded)


def encode_element(el: BERElement) -> bytes:
    if el.tag_number >= 31:
        raise ValueError("High-tag-number form not supported")

    tag = el.tag_byte

    if isinstance(el.value, list):
        inner = b"".join(encode_element(child) for child in el.value)
    else:
        inner = el.value

    return bytes([tag]) + encode_length(len(inner)) + inner


def decode_element(data: bytes, offset: int = 0) -> tuple[BERElement, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of data")

    tag_byte = data[offset]
    tag_class = TagClass((tag_byte >> 6) & 0x03)
    constructed = bool((tag_byte >> 5) & 0x01)
    tag_number = tag_byte & 0x1F

    if tag_number == 0x1F:
        raise ValueError("High-tag-number form not supported")

    offset += 1
    length, offset = _decode_length(data, offset)

    if offset + length > len(data):
        raise ValueError(f"Element extends past data: need {offset + length}, have {len(data)}")

    raw_value = data[offset:offset + length]
    end = offset + length

    if constructed:
        children = []
        pos = offset
        while pos < end:
            child, pos = decode_element(data, pos)
            children.append(child)
        value: bytes | list[BERElement] = children
    else:
        value = raw_value

    return BERElement(tag_class, constructed, tag_number, value), end


def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of data while reading length")

    first = data[offset]
    offset += 1

    if first < 0x80:
        return first, offset

    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length not supported")
    if offset + num_bytes > len(data):
        raise ValueError("Length bytes extend past data")

    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + i]

    return length, offset + num_bytes


def encode_integer(value: int) -> BERElement:
    if value == 0:
        raw = b"\x00"
    elif value > 0:
        raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
    else:
        byte_len = (value.bit_length() + 9) // 8
        raw = value.to_bytes(byte_len, "big", signed=True)
    return BERElement(TagClass.UNIVERSAL, False, 0x02, raw)


def decode_integer(el: BERElement) -> int:
    if not isinstance(el.value, bytes):
        raise ValueError("Expected primitive BER element for integer")
    return int.from_bytes(el.value, "big", signed=True)


def encode_string(value: str) -> BERElement:
    return BERElement(TagClass.UNIVERSAL, False, 0x04, value.encode("utf-8"))


def decode_string(el: BERElement) -> str:
    if not isinstance(el.value, bytes):
        raise ValueError("Expected primitive BER element for string")
    return el.value.decode("utf-8", errors="replace")


def encode_boolean(value: bool) -> BERElement:
    return BERElement(TagClass.UNIVERSAL, False, 0x01, b"\xff" if value else b"\x00")


def decode_boolean(el: BERElement) -> bool:
    if not isinstance(el.value, bytes):
        raise ValueError("Expected primitive BER element for boolean")
    return el.value != b"\x00"


def encode_enumerated(value: int) -> BERElement:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return BERElement(TagClass.UNIVERSAL, False, 0x0A, raw)


def decode_enumerated(el: BERElement) -> int:
    if not isinstance(el.value, bytes):
        raise ValueError("Expected primitive BER element for enumerated")
    return int.from_bytes(el.value, "big", signed=True)


def encode_sequence(children: list[BERElement]) -> BERElement:
    return BERElement(TagClass.UNIVERSAL, True, 0x10, children)


def encode_set(children: list[BERElement]) -> BERElement:
    return BERElement(TagClass.UNIVERSAL, True, 0x11, children)


def read_ldap_message(data: bytes) -> tuple[BERElement | None, bytes]:
    """Try to read one complete LDAP message from a buffer.
    Returns (element, remaining_data) or (None, original_data) if incomplete."""
    if len(data) < 2:
        return None, data

    try:
        el, end = decode_element(data, 0)
        return el, data[end:]
    except ValueError:
        return None, data
