"""
Request data models for the encrypted backup server protocol.

This module defines immutable request objects used after decoding raw bytes
received from a client socket. The request decoder builds these dataclasses,
and the server handler routes them according to their request code.

@author Tehila Cahnaman
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from protocol.constants import ClientCode


@dataclass(frozen=True, slots=True)
class RequestHeader:
    """
    Metadata included at the beginning of every client request.

    Attributes:
        user_id: Client UUID encoded as a hexadecimal string.
        version: Client protocol version.
        request_code: Operation code describing the requested server action.
        payload_size: Size of the request payload, in bytes.
    """

    user_id: str
    version: int
    request_code: ClientCode
    payload_size: int


@dataclass(frozen=True, slots=True)
class RequestPayload:
    """
    Optional payload fields used by different client request types.

    Attributes:
        username: Client username used during registration flows.
        public_key: RSA public key sent by the client.
        encrypted_chunk_size: Size of the encrypted file chunk, in bytes.
        file_size: Total original file size, in bytes.
        packet_number: Current packet number in a multi-packet upload.
        total_packets: Total number of packets expected for the upload.
        file_name: Name of the file being uploaded or verified.
        encrypted_chunk_data: Encrypted file chunk bytes.
    """

    username: Optional[str] = None
    public_key: Optional[bytes] = None
    encrypted_chunk_size: Optional[int] = None
    file_size: Optional[int] = None
    packet_number: Optional[int] = None
    total_packets: Optional[int] = None
    file_name: Optional[str] = None
    encrypted_chunk_data: Optional[bytes] = None


@dataclass(frozen=True, slots=True)
class Request:
    """
    Complete decoded client request.

    Attributes:
        header: Request metadata such as user ID, version, code, and size.
        payload: Request-specific data associated with the request code.
    """

    header: RequestHeader
    payload: RequestPayload
