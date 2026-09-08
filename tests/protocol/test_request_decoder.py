"""
Tests for protocol request decoder.
"""

import struct
from unittest.mock import MagicMock

import pytest

from protocol.constants import (
    FILE_NAME_LEN,
    FORMAT,
    RSA_KEY_LEN,
    UNIQUE_ID_LEN,
    USERNAME_LEN,
    ClientCode,
)
from protocol.request_decoder import (
    HEADER_FORMAT,
    BACKUP_META_FORMAT,
    _decode_null_padded_text,
    deserialize_request,
)


def _build_raw_request(
    *,
    user_id_bytes: bytes = b"\x11" * UNIQUE_ID_LEN,
    version: int = 3,
    request_code: int = ClientCode.REGISTRATION,
    payload_size: int = 0,
    username: str = "alice",
    public_key: bytes = b"\x00" * RSA_KEY_LEN,
    encrypted_chunk_size: int = 0,
    file_size: int = 0,
    packet_number: int = 0,
    total_packets: int = 0,
    file_name: str = "",
    encrypted_chunk_data: bytes = b"",
) -> bytes:
    """
    Construct a raw byte stream according to the request wire layout.
    """
    user_id_field = user_id_bytes[:UNIQUE_ID_LEN].ljust(UNIQUE_ID_LEN, b"\x00")
    header_field = struct.pack(HEADER_FORMAT, version, request_code, payload_size)
    username_field = username.encode(FORMAT).ljust(USERNAME_LEN, b"\x00")
    public_key_field = public_key[:RSA_KEY_LEN].ljust(RSA_KEY_LEN, b"\x00")
    backup_meta_field = struct.pack(
        BACKUP_META_FORMAT,
        encrypted_chunk_size,
        file_size,
        packet_number,
        total_packets,
    )
    file_name_field = file_name.encode(FORMAT).ljust(FILE_NAME_LEN, b"\x00")

    return (
        user_id_field
        + header_field
        + username_field
        + public_key_field
        + backup_meta_field
        + file_name_field
        + encrypted_chunk_data
    )


def test_decode_null_padded_text():
    """
    Test null-padded text stripping.
    """
    text = "test_user"
    padded = text.encode("utf-8") + b"\x00\x00\x00"
    assert _decode_null_padded_text(padded) == text

    all_nulls = b"\x00" * 10
    assert _decode_null_padded_text(all_nulls) == ""


def test_deserialize_registration_request(socket_pair):
    """
    Test deserializing a registration request.
    """
    client_sock, server_sock = socket_pair
    user_id_raw = bytes.fromhex("112233445566778899aabbccddeeff01")
    raw_data = _build_raw_request(
        user_id_bytes=user_id_raw,
        version=3,
        request_code=ClientCode.REGISTRATION,
        payload_size=64,
        username="john_doe",
    )
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.user_id == user_id_raw.hex().rstrip("0")
    assert req.header.version == 3
    assert req.header.request_code == ClientCode.REGISTRATION
    assert req.header.payload_size == 64
    assert req.payload.username == "john_doe"
    assert req.payload.public_key is None
    assert req.payload.file_name is None
    assert req.payload.encrypted_chunk_data is None


def test_deserialize_public_key_send_request(socket_pair):
    """
    Test deserializing a public-key send request.
    """
    client_sock, server_sock = socket_pair
    pubkey = b"A" * RSA_KEY_LEN
    raw_data = _build_raw_request(
        request_code=ClientCode.PUBLIC_KEY_SEND,
        username="alice",
        public_key=pubkey,
    )
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.request_code == ClientCode.PUBLIC_KEY_SEND
    assert req.payload.username == "alice"
    assert req.payload.public_key == pubkey


def test_deserialize_create_backup_request(socket_pair):
    """
    Test deserializing a backup chunk upload request.
    """
    client_sock, server_sock = socket_pair
    chunk_data = b"ENCRYPTED_BYTES_12345"
    raw_data = _build_raw_request(
        request_code=ClientCode.CREATE_BACKUP,
        encrypted_chunk_size=len(chunk_data),
        file_size=1000,
        packet_number=1,
        total_packets=3,
        file_name="secret.txt",
        encrypted_chunk_data=chunk_data,
    )
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.request_code == ClientCode.CREATE_BACKUP
    assert req.payload.username is None  # CREATE_BACKUP does not retain username
    assert req.payload.public_key is None
    assert req.payload.file_name == "secret.txt"
    assert req.payload.encrypted_chunk_size == len(chunk_data)
    assert req.payload.file_size == 1000
    assert req.payload.packet_number == 1
    assert req.payload.total_packets == 3
    assert req.payload.encrypted_chunk_data == chunk_data


@pytest.mark.parametrize(
    "code",
    [ClientCode.CRC_SUCCESS, ClientCode.CRC_ERROR, ClientCode.CRC_FAILURE],
)
def test_deserialize_crc_requests(socket_pair, code):
    """
    Test deserializing CRC confirmation and failure requests.
    """
    client_sock, server_sock = socket_pair
    raw_data = _build_raw_request(
        request_code=code,
        username="bob",
        file_name="data.bin",
    )
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.request_code == code
    assert req.payload.file_name == "data.bin"
    assert req.payload.username == "bob"
    assert req.payload.encrypted_chunk_data is None


def test_deserialize_disconnect_request(socket_pair):
    """
    Test deserializing a disconnect request.
    """
    client_sock, server_sock = socket_pair
    raw_data = _build_raw_request(
        request_code=ClientCode.DISCONNECT,
        username="bob",
    )
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.request_code == ClientCode.DISCONNECT
    assert req.payload.username == "bob"


def test_deserialize_user_id_rstrip_behavior(socket_pair):
    """
    Verify user ID decoding behavior with trailing zero nibbles/bytes.
    """
    client_sock, server_sock = socket_pair
    # User ID with trailing zero byte
    user_id_bytes = b"\x12\x34" + b"\x00" * 14
    raw_data = _build_raw_request(user_id_bytes=user_id_bytes)
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.user_id == user_id_bytes.hex().rstrip("0")


def test_deserialize_invalid_request_code(socket_pair):
    """
    Test deserializing a request with an invalid/unknown ClientCode returns None.
    """
    client_sock, server_sock = socket_pair
    raw_data = _build_raw_request(request_code=999)
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is None


def test_deserialize_incomplete_socket_input(socket_pair):
    """
    Test deserializing with truncated socket data returns None.
    """
    client_sock, server_sock = socket_pair
    client_sock.sendall(b"\x00" * 10)  # less than UNIQUE_ID_LEN (16)
    client_sock.close()

    req = deserialize_request(server_sock)
    assert req is None


def test_deserialize_none_socket():
    """
    Test deserializing with None socket returns None.
    """
    assert deserialize_request(None) is None


def test_deserialize_integer_boundary_cases(socket_pair):
    """
    Test deserializing with max uint values.
    """
    client_sock, server_sock = socket_pair
    raw_data = _build_raw_request(
        version=255,
        request_code=ClientCode.CREATE_BACKUP,
        payload_size=0xFFFFFFFF,
        encrypted_chunk_size=0,
        file_size=0xFFFFFFFF,
        packet_number=0xFFFF,
        total_packets=0xFFFF,
        file_name="edge.dat",
    )
    client_sock.sendall(raw_data)

    req = deserialize_request(server_sock)
    assert req is not None
    assert req.header.version == 255
    assert req.header.payload_size == 0xFFFFFFFF
    assert req.payload.file_size == 0xFFFFFFFF
    assert req.payload.packet_number == 0xFFFF
    assert req.payload.total_packets == 0xFFFF
    assert req.payload.encrypted_chunk_data is None  # chunk size is 0
