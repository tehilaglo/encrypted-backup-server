"""
Response data models for the encrypted backup server protocol.

This module defines structured response objects used by the server before
serialization. Response handlers populate these dataclasses, and the response
encoder converts them into the binary protocol format sent to the client.

@author Tehila Cahnaman
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from protocol.constants import (
    CHECKSUM_LEN,
    ENC_CHUNK_SIZE_LEN,
    FILE_NAME_LEN,
    ServerCode,
    UNIQUE_ID_LEN,
)


#: Base payload size for fixed-size response payload fields, in bytes.
BASE_RESPONSE_PAYLOAD_SIZE: int = (
    UNIQUE_ID_LEN
    + ENC_CHUNK_SIZE_LEN
    + FILE_NAME_LEN
    + CHECKSUM_LEN
)


@dataclass(slots=True)
class ResponseHeader:
    """
    Metadata included at the beginning of every server response.

    Attributes:
        version: Server protocol version.
        response_code: Operation result code returned to the client.
        payload_size: Total response payload size, in bytes.
    """

    version: int
    response_code: ServerCode
    payload_size: int = BASE_RESPONSE_PAYLOAD_SIZE


@dataclass(slots=True)
class ResponsePayload:
    """
    Optional payload fields returned by different server response types.

    Attributes:
        user_id: Client UUID encoded as a hexadecimal string.
        encrypted_aes_key: RSA-encrypted AES session key.
        encrypted_chunk_size: Size of the encrypted uploaded file chunk.
        file_name: Name of the uploaded or verified file.
        checksum: CRC32 checksum calculated for the uploaded file.
    """

    user_id: Optional[str] = None
    encrypted_aes_key: Optional[bytes] = None
    encrypted_chunk_size: Optional[int] = None
    file_name: Optional[str] = None
    checksum: Optional[int] = None


@dataclass(slots=True)
class Response:
    """
    Complete server response before binary serialization.

    Attributes:
        header: Response metadata such as version, code, and payload size.
        payload: Optional response data associated with the response code.
    """

    header: ResponseHeader
    payload: ResponsePayload
