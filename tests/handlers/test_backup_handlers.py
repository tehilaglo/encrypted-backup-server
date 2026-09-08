"""
Tests for backup request handlers (backup upload, CRC success, CRC error, CRC failure).
"""

import base64
from pathlib import Path
import pytest

from handlers.backup_handlers import (
    _validate_backup_request,
    _validate_crc_request,
    handle_backup_request,
    handle_crc_error,
    handle_crc_failure,
    handle_crc_success,
)
from protocol.constants import MAX_FILE_SIZE, SERVER_VERSION, ClientCode, ServerCode
from protocol.request import Request, RequestHeader, RequestPayload
from protocol.response import Response, ResponseHeader, ResponsePayload
from services.crypto import aes_cbc_encrypt, generate_aes_key
from storage.database import add_client, update_aes_key, _connect


def _create_test_response():
    return Response(
        header=ResponseHeader(
            version=SERVER_VERSION,
            response_code=ServerCode.DEFAULT,
        ),
        payload=ResponsePayload(),
    )


def test_validate_backup_request():
    """
    Test validation checks for backup request payload.
    """
    with pytest.raises(ValueError, match="request must not be None"):
        _validate_backup_request(None)

    # Missing user_id
    req = Request(
        header=RequestHeader(user_id=None, version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(),
    )
    with pytest.raises(ValueError, match="request.header.user_id must not be None"):
        _validate_backup_request(req)

    # Missing file_name
    req = Request(
        header=RequestHeader(user_id="uid1", version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(file_name=None),
    )
    with pytest.raises(ValueError, match="request.payload.file_name must not be None"):
        _validate_backup_request(req)

    # Missing file_size
    req = Request(
        header=RequestHeader(user_id="uid1", version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(file_name="doc.txt", file_size=None),
    )
    with pytest.raises(ValueError, match="request.payload.file_size must not be None"):
        _validate_backup_request(req)

    # Missing packet_number
    req = Request(
        header=RequestHeader(user_id="uid1", version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(file_name="doc.txt", file_size=10, packet_number=None),
    )
    with pytest.raises(ValueError, match="request.payload.packet_number must not be None"):
        _validate_backup_request(req)

    # Missing total_packets
    req = Request(
        header=RequestHeader(user_id="uid1", version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(file_name="doc.txt", file_size=10, packet_number=1, total_packets=None),
    )
    with pytest.raises(ValueError, match="request.payload.total_packets must not be None"):
        _validate_backup_request(req)

    # Missing encrypted_chunk_size
    req = Request(
        header=RequestHeader(user_id="uid1", version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(
            file_name="doc.txt",
            file_size=10,
            packet_number=1,
            total_packets=1,
            encrypted_chunk_size=None,
        ),
    )
    with pytest.raises(ValueError, match="request.payload.encrypted_chunk_size must not be None"):
        _validate_backup_request(req)

    # Missing encrypted_chunk_data
    req = Request(
        header=RequestHeader(user_id="uid1", version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=0),
        payload=RequestPayload(
            file_name="doc.txt",
            file_size=10,
            packet_number=1,
            total_packets=1,
            encrypted_chunk_size=10,
            encrypted_chunk_data=None,
        ),
    )
    with pytest.raises(ValueError, match="request.payload.encrypted_chunk_data must not be None"):
        _validate_backup_request(req)


def test_validate_crc_request():
    """
    Test validation checks for CRC request payload.
    """
    with pytest.raises(ValueError, match="request must not be None"):
        _validate_crc_request(None)

    req = Request(
        header=RequestHeader(user_id=None, version=3, request_code=ClientCode.CRC_SUCCESS, payload_size=0),
        payload=RequestPayload(),
    )
    with pytest.raises(ValueError, match="request.header.user_id must not be None"):
        _validate_crc_request(req)

    req = Request(
        header=RequestHeader(user_id="u1", version=3, request_code=ClientCode.CRC_SUCCESS, payload_size=0),
        payload=RequestPayload(file_name=None),
    )
    with pytest.raises(ValueError, match="request.payload.file_name must not be None"):
        _validate_crc_request(req)


def test_handle_backup_request_oversized_file(socket_pair):
    """
    Test backup request exceeding MAX_FILE_SIZE is rejected with UPLOAD_REJECTED_TOO_LARGE.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    req = Request(
        header=RequestHeader(
            user_id="uid1",
            version=3,
            request_code=ClientCode.CREATE_BACKUP,
            payload_size=100,
        ),
        payload=RequestPayload(
            file_name="huge.zip",
            file_size=MAX_FILE_SIZE + 1,
            packet_number=1,
            total_packets=1,
            encrypted_chunk_size=10,
            encrypted_chunk_data=b"chunkdata",
        ),
    )

    handle_backup_request(client_sock, req, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.UPLOAD_REJECTED_TOO_LARGE


def test_handle_backup_request_multi_packet_flow(temp_db, temp_workdir, socket_pair):
    """
    Test multi-packet backup flow: intermediate packets do not send responses; final packet sends UPLOAD_RECEIVED.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    user_id = "112233445566778899aabbccddeeff00"
    username = "upload_user"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    content = b"Complete file content over multiple chunks"
    encrypted_data = aes_cbc_encrypt(content, aes_key)
    mid = len(encrypted_data) // 2
    chunk1 = encrypted_data[:mid]
    chunk2 = encrypted_data[mid:]

    # Packet 1 of 2
    req1 = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=len(chunk1)),
        payload=RequestPayload(
            file_name="multi.txt",
            file_size=len(content),
            packet_number=1,
            total_packets=2,
            encrypted_chunk_size=len(chunk1),
            encrypted_chunk_data=chunk1,
        ),
    )
    handle_backup_request(client_sock, req1, resp)
    # No response expected yet on intermediate packet
    client_sock.setblocking(False)
    server_sock.setblocking(False)
    with pytest.raises(BlockingIOError):
        server_sock.recv(1024)

    client_sock.setblocking(True)
    server_sock.setblocking(True)

    # Packet 2 of 2
    req2 = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=len(chunk2)),
        payload=RequestPayload(
            file_name="multi.txt",
            file_size=len(content),
            packet_number=2,
            total_packets=2,
            encrypted_chunk_size=len(chunk2),
            encrypted_chunk_data=chunk2,
        ),
    )
    handle_backup_request(client_sock, req2, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.UPLOAD_RECEIVED
    assert resp.payload.file_name == "multi.txt"


def test_handle_crc_success(temp_db, temp_workdir, socket_pair):
    """
    Test CRC success marks file as verified and sends ACK.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    user_id = "112233445566778899aabbccddeeff00"
    username = "crc_user"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    content = b"Verified content"
    encrypted_data = aes_cbc_encrypt(content, aes_key)

    req_upload = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=len(encrypted_data)),
        payload=RequestPayload(
            file_name="verified.txt",
            file_size=len(content),
            packet_number=1,
            total_packets=1,
            encrypted_chunk_size=len(encrypted_data),
            encrypted_chunk_data=encrypted_data,
        ),
    )
    handle_backup_request(client_sock, req_upload, resp)
    server_sock.recv(1024)  # consume UPLOAD_RECEIVED

    req_crc = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CRC_SUCCESS, payload_size=0),
        payload=RequestPayload(file_name="verified.txt"),
    )
    handle_crc_success(client_sock, req_crc, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.ACK

    # Check verified status in DB is True
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT verified FROM files WHERE user_id=?", (user_id,))
        assert cursor.fetchone()[0] == 1


def test_handle_crc_error(temp_db, temp_workdir):
    """
    Test CRC error deletes the file without sending a response.
    """
    user_id = "112233445566778899aabbccddeeff00"
    username = "crc_err_user"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    content = b"Error content"
    encrypted_data = aes_cbc_encrypt(content, aes_key)

    resp = _create_test_response()
    import socket
    c_sock, s_sock = socket.socketpair()

    req_upload = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=len(encrypted_data)),
        payload=RequestPayload(
            file_name="error.txt",
            file_size=len(content),
            packet_number=1,
            total_packets=1,
            encrypted_chunk_size=len(encrypted_data),
            encrypted_chunk_data=encrypted_data,
        ),
    )
    handle_backup_request(c_sock, req_upload, resp)
    s_sock.recv(1024)
    c_sock.close()
    s_sock.close()

    req_err = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CRC_ERROR, payload_size=0),
        payload=RequestPayload(file_name="error.txt"),
    )

    handle_crc_error(req_err)

    # File on disk should be deleted
    user_dir = Path(user_id)
    files_remaining = list(user_dir.glob("*error*"))
    assert len(files_remaining) == 0


def test_handle_crc_failure(temp_db, temp_workdir, socket_pair):
    """
    Test CRC failure deletes the file and sends ACK.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    user_id = "112233445566778899aabbccddeeff00"
    username = "crc_fail_user"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    content = b"Failed content"
    encrypted_data = aes_cbc_encrypt(content, aes_key)

    req_upload = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CREATE_BACKUP, payload_size=len(encrypted_data)),
        payload=RequestPayload(
            file_name="fail.txt",
            file_size=len(content),
            packet_number=1,
            total_packets=1,
            encrypted_chunk_size=len(encrypted_data),
            encrypted_chunk_data=encrypted_data,
        ),
    )
    handle_backup_request(client_sock, req_upload, resp)
    server_sock.recv(1024)

    req_fail = Request(
        header=RequestHeader(user_id=user_id, version=3, request_code=ClientCode.CRC_FAILURE, payload_size=0),
        payload=RequestPayload(file_name="fail.txt"),
    )
    handle_crc_failure(client_sock, req_fail, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.ACK

    # File on disk should be deleted
    user_dir = Path(user_id)
    files_remaining = list(user_dir.glob("*fail*"))
    assert len(files_remaining) == 0
