"""
Tests for protocol response encoder.
"""

import struct
import pytest

from protocol.constants import (
    FILE_NAME_LEN,
    FORMAT,
    UNIQUE_ID_LEN,
    ServerCode,
)
from protocol.response import Response, ResponseHeader, ResponsePayload
from protocol.response_encoder import (
    HEADER_FORMAT,
    UINT32_FORMAT,
    _pad_bytes,
    _serialize_file_name,
    _serialize_optional_bytes,
    _serialize_uint32,
    _serialize_user_id,
    serialize_response,
)


def test_pad_bytes():
    """
    Test _pad_bytes pads with nulls and checks boundary lengths.
    """
    assert _pad_bytes(b"abc", 5, "field") == b"abc\x00\x00"
    assert _pad_bytes(b"12345", 5, "field") == b"12345"

    with pytest.raises(ValueError, match="field is too large"):
        _pad_bytes(b"123456", 5, "field")


def test_serialize_user_id():
    """
    Test user ID serialization for None, hex string, bytes, and invalid types.
    """
    assert _serialize_user_id(None) == b"\x00" * UNIQUE_ID_LEN

    hex_uid = "0123456789abcdef0123456789abcdef"
    expected_bytes = bytes.fromhex(hex_uid)
    assert _serialize_user_id(hex_uid) == expected_bytes

    raw_bytes = b"\xaa\xbb"
    assert _serialize_user_id(raw_bytes) == raw_bytes + b"\x00" * 14

    with pytest.raises(ValueError, match="valid hexadecimal string"):
        _serialize_user_id("not-hex")

    with pytest.raises(TypeError, match="must be str, bytes, or None"):
        _serialize_user_id(12345)


def test_serialize_file_name():
    """
    Test file name serialization for None, str, bytes, and invalid lengths.
    """
    assert _serialize_file_name(None) == b"\x00" * FILE_NAME_LEN

    name_str = "backup.zip"
    expected = name_str.encode(FORMAT) + b"\x00" * (FILE_NAME_LEN - len(name_str))
    assert _serialize_file_name(name_str) == expected

    with pytest.raises(ValueError, match="file_name is too large"):
        _serialize_file_name("A" * 256)

    with pytest.raises(TypeError, match="must be str, bytes, or None"):
        _serialize_file_name(12345)


def test_serialize_optional_bytes():
    """
    Test serialization of optional variable-length bytes.
    """
    assert _serialize_optional_bytes(None, "opt") == b""
    assert _serialize_optional_bytes(b"key123", "opt") == b"key123"

    with pytest.raises(TypeError, match="must be bytes or None"):
        _serialize_optional_bytes("string_not_bytes", "opt")


def test_serialize_uint32():
    """
    Test uint32 serialization and boundary validations.
    """
    assert _serialize_uint32(None, "val") == b"\x00\x00\x00\x00"
    assert _serialize_uint32(1, "val") == struct.pack("!I", 1)
    assert _serialize_uint32(0xFFFFFFFF, "val") == struct.pack("!I", 0xFFFFFFFF)

    with pytest.raises(ValueError, match="must fit in an unsigned 32-bit integer"):
        _serialize_uint32(-1, "val")

    with pytest.raises(ValueError, match="must fit in an unsigned 32-bit integer"):
        _serialize_uint32(0x100000000, "val")


def test_serialize_response_none():
    """
    Test serialize_response raises TypeError when response is None.
    """
    with pytest.raises(TypeError, match="response must not be None"):
        serialize_response(None)


def test_serialize_response_exact_binary_layout():
    """
    Verify exact binary layout, byte ordering, and field offsets in serialized response.
    Layout:
      0..7: header (!BHI) -> 1 byte version, 2 bytes response code, 4 bytes payload size
      7..23: user_id (16 bytes)
      23..23+len(key): encrypted_aes_key (variable length bytes)
      encrypted_chunk_size (!I) -> 4 bytes
      file_name -> 255 bytes
      checksum (!I) -> 4 bytes
    """
    user_hex = "11223344556677889900112233445566"
    user_bytes = bytes.fromhex(user_hex)
    aes_key = b"ENCRYPTED_AES_KEY_BYTES"
    file_name = "test_file.txt"
    chunk_size = 1024
    crc_val = 0x12345678

    response = Response(
        header=ResponseHeader(
            version=3,
            response_code=ServerCode.KEY_SEND_SUCCESS,
            payload_size=279 + len(aes_key),
        ),
        payload=ResponsePayload(
            user_id=user_hex,
            encrypted_aes_key=aes_key,
            encrypted_chunk_size=chunk_size,
            file_name=file_name,
            checksum=crc_val,
        ),
    )

    data = serialize_response(response)

    expected_total_len = 7 + 16 + len(aes_key) + 4 + 255 + 4
    assert len(data) == expected_total_len

    # Verify header (big endian !BHI)
    version, resp_code, payload_sz = struct.unpack_from("!BHI", data, 0)
    assert version == 3
    assert resp_code == ServerCode.KEY_SEND_SUCCESS
    assert payload_sz == 279 + len(aes_key)

    # Verify user ID
    offset = 7
    assert data[offset : offset + 16] == user_bytes
    offset += 16

    # Verify encrypted AES key
    assert data[offset : offset + len(aes_key)] == aes_key
    offset += len(aes_key)

    # Verify encrypted chunk size (!I)
    (unpacked_chunk_size,) = struct.unpack_from("!I", data, offset)
    assert unpacked_chunk_size == chunk_size
    offset += 4

    # Verify file name (255 bytes null padded)
    expected_fname_bytes = file_name.encode(FORMAT).ljust(FILE_NAME_LEN, b"\x00")
    assert data[offset : offset + 255] == expected_fname_bytes
    offset += 255

    # Verify checksum (!I)
    (unpacked_checksum,) = struct.unpack_from("!I", data, offset)
    assert unpacked_checksum == crc_val
    offset += 4

    assert offset == expected_total_len
