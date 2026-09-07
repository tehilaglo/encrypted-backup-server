"""
Backup request handlers for the encrypted backup server.

This module connects the socket/request layer to the backup service layer.
It handles client backup-related requests, delegates upload persistence and
verification work to ``backup_service``, and sends protocol responses through
``ResponseSender``.

@author Tehila Cahnaman
"""

from socket import socket

from services.backup_service import (
    delete_failed_upload,
    mark_upload_verified,
    persist_completed_upload,
    upload_assembler,
)
from utils.console_ui import Color
from protocol.constants import MAX_FILE_SIZE
from protocol.request import Request
from protocol.response import Response
from protocol.response_sender import ResponseSender


def _validate_backup_request(request: Request) -> None:
    """
    Validate that a backup request contains the required upload fields.

    Args:
        request: Client request containing backup metadata and encrypted data.

    Raises:
        ValueError: If one or more required backup fields are missing.
    """
    if request is None:
        raise ValueError("request must not be None")

    if request.header.user_id is None:
        raise ValueError("request.header.user_id must not be None")

    if request.payload.file_name is None:
        raise ValueError("request.payload.file_name must not be None")

    if request.payload.file_size is None:
        raise ValueError("request.payload.file_size must not be None")

    if request.payload.packet_number is None:
        raise ValueError("request.payload.packet_number must not be None")

    if request.payload.total_packets is None:
        raise ValueError("request.payload.total_packets must not be None")

    if request.payload.encrypted_chunk_size is None:
        raise ValueError("request.payload.encrypted_chunk_size must not be None")

    if request.payload.encrypted_chunk_data is None:
        raise ValueError("request.payload.encrypted_chunk_data must not be None")


def _validate_crc_request(request: Request) -> None:
    """
    Validate that a CRC request contains the required file reference fields.

    Args:
        request: Client CRC confirmation/failure request.

    Raises:
        ValueError: If the request does not include a user ID or file name.
    """
    if request is None:
        raise ValueError("request must not be None")

    if request.header.user_id is None:
        raise ValueError("request.header.user_id must not be None")

    if request.payload.file_name is None:
        raise ValueError("request.payload.file_name must not be None")


def handle_backup_request(
    conn: socket,
    request: Request,
    response: Response,
) -> None:
    """
    Handle a file backup request from a client.

    The function buffers encrypted chunks until the complete encrypted file has
    been received. Once all packets are available, it delegates decryption,
    storage, checksum calculation, and database registration to the backup
    service layer.

    Args:
        conn: Client socket connection.
        request: Parsed client backup request.
        response: Mutable response object to populate and send.
    """
    _validate_backup_request(request)

    user_id = request.header.user_id
    sender = ResponseSender(conn, response)

    if request.payload.file_size > MAX_FILE_SIZE:
        sender.send_upload_too_large()
        return

    full_encrypted_data = upload_assembler.add_chunk(
        user_id=user_id,
        file_name=request.payload.file_name,
        packet_number=request.payload.packet_number,
        total_packets=request.payload.total_packets,
        chunk=request.payload.encrypted_chunk_data,
    )

    # A None result means this upload is still waiting for more chunks.
    if full_encrypted_data is None:
        return

    saved_upload = persist_completed_upload(
        user_id=user_id,
        original_file_name=request.payload.file_name,
        encrypted_chunk_size=request.payload.encrypted_chunk_size,
        encrypted_file_data=full_encrypted_data,
    )
    sender.send_upload_received(request, saved_upload)


def handle_crc_success(
    conn: socket,
    request: Request,
    response: Response,
) -> None:
    """
    Handle a successful client CRC confirmation.

    The server acknowledges the client, marks the latest stored file version as
    verified, and prints a success message.

    Args:
        conn: Client socket connection.
        request: Parsed client CRC success request.
        response: Mutable response object to populate and send.
    """
    _validate_crc_request(request)

    user_id = request.header.user_id
    file_name = request.payload.file_name

    sender = ResponseSender(conn, response)
    sender.send_ack(user_id)

    mark_upload_verified(user_id=user_id, file_name=file_name)

    print(
        Color.BLUE
        + f"[SUCCESS] File: '{file_name}' was successfully uploaded."
        + Color.RESET
    )


def handle_crc_error(request: Request) -> None:
    """
    Handle a client CRC error notification.

    This request means the client detected an integrity mismatch. The server
    deletes the latest stored version of the file without sending a response.

    Args:
        request: Parsed client CRC error request.
    """
    _validate_crc_request(request)

    delete_failed_upload(
        user_id=request.header.user_id,
        file_name=request.payload.file_name,
    )


def handle_crc_failure(
    conn: socket,
    request: Request,
    response: Response,
) -> None:
    """
    Handle a client CRC failure notification.

    The server acknowledges the client, deletes the latest stored version of the
    file, and prints an integrity-failure message.

    Args:
        conn: Client socket connection.
        request: Parsed client CRC failure request.
        response: Mutable response object to populate and send.
    """
    _validate_crc_request(request)

    user_id = request.header.user_id
    file_name = request.payload.file_name

    sender = ResponseSender(conn, response)
    sender.send_ack(user_id)

    delete_failed_upload(user_id=user_id, file_name=file_name)

    print(
        Color.RED
        + f"[ERROR] File: '{file_name}' could not be uploaded due to "
        "integrity check failure."
        + Color.RESET
    )
