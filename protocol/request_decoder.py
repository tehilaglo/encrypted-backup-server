"""
Request deserialization utilities for the encrypted backup server.

This module reads raw bytes from a connected client socket and converts them
into structured ``Request`` objects used by the server request handlers.

The decoder expects the client request layout to match the protocol fields:
    user_id +
    header +
    username +
    public_key +
    backup_metadata +
    file_name +
    encrypted_chunk_data

@author Tehila Cahnaman
"""

import struct
from socket import socket

from protocol.constants import (
    FILE_NAME_LEN,
    FORMAT,
    RSA_KEY_LEN,
    UNIQUE_ID_LEN,
    USERNAME_LEN,
    ClientCode,
)
from protocol.request import Request, RequestHeader, RequestPayload
from utils.socket_io import recv_exact

#: Little-endian request header format:
#: version: uint8, request_code: uint16, payload_size: uint32.
HEADER_FORMAT = "<BHI"

#: Little-endian backup metadata format:
#: encrypted_chunk_size: uint32, file_size: uint32,
#: packet_number: uint16, total_packets: uint16.
BACKUP_META_FORMAT = "<IIHH"

#: Request codes that include a file name in the fixed file-name field.
FILE_NAME_REQUEST_CODES = {
    ClientCode.CREATE_BACKUP,
    ClientCode.CRC_SUCCESS,
    ClientCode.CRC_ERROR,
    ClientCode.CRC_FAILURE,
}


def _decode_null_padded_text(data: bytes) -> str:
    """
    Decode a fixed-size null-padded text field.

    Args:
        data: Raw bytes read from the socket.

    Returns:
        Decoded string with trailing null bytes removed.
    """
    return data.decode(FORMAT).strip("\x00")


def _read_user_id(sock: socket) -> str:
    """
    Read and decode the fixed-size user ID field.

    Args:
        sock: Client socket to read from.

    Returns:
        Hexadecimal user ID string.
    """
    user_id_data = recv_exact(sock, UNIQUE_ID_LEN)

    # User IDs are transferred as raw bytes and represented internally as hex.
    return user_id_data.hex().rstrip("0")


def _read_header(sock: socket) -> tuple[int, ClientCode, int]:
    """
    Read and unpack the request header.

    Args:
        sock: Client socket to read from.

    Returns:
        Tuple containing version, request code, and payload size.

    Raises:
        ValueError: If the numeric request code is not a known ``ClientCode``.
        struct.error: If the header bytes cannot be unpacked.
    """
    header_size = struct.calcsize(HEADER_FORMAT)
    header_data = recv_exact(sock, header_size)
    version, request_code, payload_size = struct.unpack(HEADER_FORMAT, header_data)

    return version, ClientCode(request_code), payload_size


def _read_username(sock: socket, request_code: ClientCode) -> str | None:
    """
    Read and optionally decode the fixed-size username field.

    Args:
        sock: Client socket to read from.
        request_code: Request code from the decoded header.

    Returns:
        Decoded username for non-backup requests, otherwise ``None``.
    """
    username_data = recv_exact(sock, USERNAME_LEN)

    if request_code == ClientCode.CREATE_BACKUP:
        return None

    return _decode_null_padded_text(username_data)


def _read_public_key(sock: socket, request_code: ClientCode) -> bytes | None:
    """
    Read and optionally return the fixed-size public-key field.

    Args:
        sock: Client socket to read from.
        request_code: Request code from the decoded header.

    Returns:
        Public key bytes for public-key requests, otherwise ``None``.
    """
    public_key_data = recv_exact(sock, RSA_KEY_LEN)

    if request_code == ClientCode.PUBLIC_KEY_SEND:
        return public_key_data

    return None


def _read_backup_metadata(sock: socket) -> tuple[int, int, int, int]:
    """
    Read and unpack the fixed-size backup metadata section.

    Args:
        sock: Client socket to read from.

    Returns:
        Tuple containing encrypted chunk size, file size, packet number,
        and total packet count.

    Raises:
        struct.error: If the metadata bytes cannot be unpacked.
    """
    metadata_size = struct.calcsize(BACKUP_META_FORMAT)
    metadata_data = recv_exact(sock, metadata_size)

    return struct.unpack(BACKUP_META_FORMAT, metadata_data)


def _read_file_name(sock: socket, request_code: ClientCode) -> str | None:
    """
    Read and optionally decode the fixed-size file-name field.

    Args:
        sock: Client socket to read from.
        request_code: Request code from the decoded header.

    Returns:
        Decoded file name for backup/CRC requests, otherwise ``None``.
    """
    file_name_data = recv_exact(sock, FILE_NAME_LEN)

    if request_code in FILE_NAME_REQUEST_CODES:
        return _decode_null_padded_text(file_name_data)

    return None


def _read_encrypted_chunk_data(
    sock: socket,
    encrypted_chunk_size: int,
) -> bytes | None:
    """
    Read encrypted chunk bytes when a chunk size is present.

    Args:
        sock: Client socket to read from.
        encrypted_chunk_size: Number of encrypted bytes expected.

    Returns:
        Encrypted chunk bytes, or ``None`` when no chunk is present.
    """
    if encrypted_chunk_size <= 0:
        return None

    return recv_exact(sock, encrypted_chunk_size)


def deserialize_request(sock: socket) -> Request | None:
    """
    Deserialize an incoming socket message into a ``Request`` object.

    Args:
        sock: Client socket to read from.

    Returns:
        A populated ``Request`` object when decoding succeeds, otherwise
        ``None`` if the socket data is incomplete, malformed, or unsupported.
    """
    try:
        if sock is None:
            raise ValueError("Socket must not be None.")

        user_id = _read_user_id(sock)
        version, request_code, header_payload_size = _read_header(sock)

        username = _read_username(sock, request_code)
        public_key = _read_public_key(sock, request_code)

        (
            encrypted_chunk_size,
            file_size,
            packet_number,
            total_packets,
        ) = _read_backup_metadata(sock)

        file_name = _read_file_name(sock, request_code)
        encrypted_chunk_data = _read_encrypted_chunk_data(
            sock,
            encrypted_chunk_size,
        )

        if request_code != ClientCode.CREATE_BACKUP:
            encrypted_chunk_size = None
            file_size = None
            packet_number = None
            total_packets = None
            encrypted_chunk_data = None

        return Request(
            header=RequestHeader(
                user_id=user_id,
                version=version,
                request_code=request_code,
                payload_size=header_payload_size,
            ),
            payload=RequestPayload(
                username=username,
                public_key=public_key,
                encrypted_chunk_size=encrypted_chunk_size,
                file_size=file_size,
                packet_number=packet_number,
                total_packets=total_packets,
                file_name=file_name,
                encrypted_chunk_data=encrypted_chunk_data,
            ),
        )

    except (ConnectionError, UnicodeDecodeError, ValueError, struct.error) as exc:
        print(f"Error receiving and deserializing request: {exc}")
        return None
