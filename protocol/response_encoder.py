"""
Response serialization utilities for the encrypted backup server.

This module converts structured server ``Response`` objects into raw protocol
bytes that can be sent over a socket connection.

The serialized response layout is:

    header +
    user_id +
    encrypted_aes_key +
    encrypted_chunk_size +
    file_name +
    checksum

@author Tehila Cahnaman
"""

import struct

from protocol.constants import FILE_NAME_LEN, FORMAT, UNIQUE_ID_LEN
from protocol.response import Response

#: Network-byte-order response header format:
#: version: uint8, response_code: uint16, payload_size: uint32.
HEADER_FORMAT = "!BHI"

#: Network-byte-order unsigned 32-bit integer format.
UINT32_FORMAT = "!I"


def _pad_bytes(value: bytes, fixed_size: int, field_name: str) -> bytes:
    """
    Pad a byte sequence with null bytes up to a fixed protocol field size.

    Args:
        value: Raw byte sequence to pad.
        fixed_size: Required fixed field size in bytes.
        field_name: Human-readable field name used in validation errors.

    Returns:
        A byte sequence padded with ``\\x00`` bytes.

    Raises:
        ValueError: If ``value`` is larger than ``fixed_size``.
    """
    if len(value) > fixed_size:
        raise ValueError(
            f"{field_name} is too large: expected at most {fixed_size} bytes, "
            f"got {len(value)} bytes."
        )

    return value + b"\x00" * (fixed_size - len(value))


def _serialize_user_id(user_id: str | bytes | None) -> bytes:
    """
    Serialize the response user ID into the fixed-size protocol field.

    Args:
        user_id: User ID as a hexadecimal string, raw bytes, or ``None``.

    Returns:
        Fixed-size user ID bytes padded with null bytes when needed.

    Raises:
        ValueError: If a hexadecimal string is invalid or too large.
        TypeError: If ``user_id`` has an unsupported type.
    """
    if user_id is None:
        return b"\x00" * UNIQUE_ID_LEN

    if isinstance(user_id, str):
        try:
            user_id = bytes.fromhex(user_id)
        except ValueError as exc:
            raise ValueError("user_id must be a valid hexadecimal string.") from exc

    if not isinstance(user_id, bytes):
        raise TypeError("user_id must be str, bytes, or None.")

    return _pad_bytes(user_id, UNIQUE_ID_LEN, "user_id")


def _serialize_file_name(file_name: str | bytes | None) -> bytes:
    """
    Serialize the response file name into the fixed-size protocol field.

    Args:
        file_name: File name as a string, raw bytes, or ``None``.

    Returns:
        Fixed-size file-name bytes padded with null bytes when needed.

    Raises:
        ValueError: If the encoded file name is too large.
        TypeError: If ``file_name`` has an unsupported type.
    """
    if file_name is None:
        return b"\x00" * FILE_NAME_LEN

    if isinstance(file_name, str):
        file_name = file_name.encode(FORMAT)

    if not isinstance(file_name, bytes):
        raise TypeError("file_name must be str, bytes, or None.")

    return _pad_bytes(file_name, FILE_NAME_LEN, "file_name")


def _serialize_optional_bytes(value: bytes | None, field_name: str) -> bytes:
    """
    Serialize an optional variable-length bytes field.

    Args:
        value: Bytes to serialize, or ``None`` when the field is absent.
        field_name: Human-readable field name used in validation errors.

    Returns:
        ``value`` unchanged, or an empty byte string when ``value`` is ``None``.

    Raises:
        TypeError: If ``value`` is not bytes or ``None``.
    """
    if value is None:
        return b""

    if not isinstance(value, bytes):
        raise TypeError(f"{field_name} must be bytes or None.")

    return value


def _serialize_uint32(value: int | None, field_name: str) -> bytes:
    """
    Serialize an optional integer as an unsigned 32-bit protocol field.

    Args:
        value: Integer value to serialize, or ``None`` to serialize as zero.
        field_name: Human-readable field name used in validation errors.

    Returns:
        Network-byte-order unsigned 32-bit integer bytes.

    Raises:
        ValueError: If the value is outside the uint32 range.
    """
    numeric_value = int(value) if value is not None else 0

    if not 0 <= numeric_value <= 0xFFFFFFFF:
        raise ValueError(f"{field_name} must fit in an unsigned 32-bit integer.")

    return struct.pack(UINT32_FORMAT, numeric_value)


def serialize_response(response: Response) -> bytes:
    """
    Serialize a server response into raw bytes according to the protocol layout.

    Args:
        response: Structured server response object.

    Returns:
        Raw bytes ready to be sent over the socket.

    Raises:
        TypeError: If ``response`` is ``None`` or contains unsupported field types.
        ValueError: If a fixed-size field exceeds its protocol-defined length.
        struct.error: If header values cannot be packed into their protocol sizes.
    """
    if response is None:
        raise TypeError("response must not be None.")

    header_data = struct.pack(
        HEADER_FORMAT,
        int(response.header.version),
        int(response.header.response_code),
        int(response.header.payload_size),
    )

    user_id_data = _serialize_user_id(response.payload.user_id)
    encrypted_aes_key_data = _serialize_optional_bytes(
        response.payload.encrypted_aes_key,
        "encrypted_aes_key",
    )
    encrypted_chunk_size_data = _serialize_uint32(
        response.payload.encrypted_chunk_size,
        "encrypted_chunk_size",
    )
    file_name_data = _serialize_file_name(response.payload.file_name)
    checksum_data = _serialize_uint32(response.payload.checksum, "checksum")

    return (
        header_data
        + user_id_data
        + encrypted_aes_key_data
        + encrypted_chunk_size_data
        + file_name_data
        + checksum_data
    )
