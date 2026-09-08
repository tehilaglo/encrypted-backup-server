"""
Tests for protocol response sender.
"""

import pytest

from protocol.constants import SERVER_VERSION, ServerCode
from protocol.request import Request, RequestHeader, RequestPayload, ClientCode
from protocol.response import Response, ResponseHeader, ResponsePayload, BASE_RESPONSE_PAYLOAD_SIZE
from protocol.response_sender import ResponseSender
from services.backup_service import SavedUpload


def _create_response() -> Response:
    return Response(
        header=ResponseHeader(
            version=SERVER_VERSION,
            response_code=ServerCode.DEFAULT,
        ),
        payload=ResponsePayload(),
    )


def test_sender_init_validation(socket_pair):
    """
    Test ResponseSender __init__ validates arguments.
    """
    client_sock, _ = socket_pair
    resp = _create_response()

    with pytest.raises(ValueError, match="conn cannot be None"):
        ResponseSender(None, resp)

    with pytest.raises(ValueError, match="response cannot be None"):
        ResponseSender(client_sock, None)


def test_send_failure(socket_pair):
    """
    Test send_failure static method sends generic failure response.
    """
    client_sock, server_sock = socket_pair

    with pytest.raises(ValueError, match="conn cannot be None"):
        ResponseSender.send_failure(None)

    ResponseSender.send_failure(client_sock)
    data = server_sock.recv(1024)
    assert len(data) > 0
    # response code is at byte offset 1..3 in network byte order (!BHI)
    assert data[0] == SERVER_VERSION
    assert int.from_bytes(data[1:3], "big") == ServerCode.FAILED


def test_send_username_taken(socket_pair):
    """
    Test send_username_taken updates response and sends over socket.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)
    sender.send_username_taken()

    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.USERNAME_TAKEN


def test_send_session_key(socket_pair):
    """
    Test send_session_key validates inputs and adjusts payload_size.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    initial_payload_size = resp.header.payload_size
    sender = ResponseSender(client_sock, resp)

    with pytest.raises(ValueError, match="user_id cannot be empty"):
        sender.send_session_key("", ServerCode.KEY_SEND_SUCCESS, b"key")

    with pytest.raises(ValueError, match="encrypted_aes_key cannot be None"):
        sender.send_session_key("user1", ServerCode.KEY_SEND_SUCCESS, None)

    aes_key_bytes = b"encrypted_key_material"
    sender.send_session_key(
        "112233445566778899aabbccddeeff00",
        ServerCode.KEY_SEND_SUCCESS,
        aes_key_bytes,
    )

    assert resp.header.payload_size == initial_payload_size + len(aes_key_bytes)
    assert resp.payload.encrypted_aes_key == aes_key_bytes

    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.KEY_SEND_SUCCESS


def test_send_registration_success(socket_pair):
    """
    Test send_registration_success.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)

    with pytest.raises(ValueError, match="user_id cannot be empty"):
        sender.send_registration_success("")

    sender.send_registration_success("112233445566778899aabbccddeeff00")
    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.REGISTRATION_SUCCESS


def test_send_registration_failed(socket_pair):
    """
    Test send_registration_failed.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)
    sender.send_registration_failed()

    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.REGISTRATION_FAILED


def test_send_re_registration_failed(socket_pair):
    """
    Test send_re_registration_failed.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)
    sender.send_re_registration_failed()

    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.RE_REGISTRATION_FAILED


def test_send_upload_too_large(socket_pair):
    """
    Test send_upload_too_large.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)
    sender.send_upload_too_large()

    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.UPLOAD_REJECTED_TOO_LARGE


def test_send_upload_received(socket_pair):
    """
    Test send_upload_received.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)

    saved_upload = SavedUpload(
        user_id="112233445566778899aabbccddeeff00",
        original_file_name="doc.txt",
        stored_path="112233445566778899aabbccddeeff00/doc_v1.txt",
        version=1,
        encrypted_chunk_size=512,
        checksum=0xCAFEBABE,
    )

    req = Request(
        header=RequestHeader(
            user_id="112233445566778899aabbccddeeff00",
            version=3,
            request_code=ClientCode.CREATE_BACKUP,
            payload_size=100,
        ),
        payload=RequestPayload(file_name="doc.txt"),
    )

    with pytest.raises(ValueError, match="request cannot be None"):
        sender.send_upload_received(None, saved_upload)

    with pytest.raises(ValueError, match="saved_upload cannot be None"):
        sender.send_upload_received(req, None)

    sender.send_upload_received(req, saved_upload)
    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.UPLOAD_RECEIVED


def test_send_ack(socket_pair):
    """
    Test send_ack.
    """
    client_sock, server_sock = socket_pair
    resp = _create_response()
    sender = ResponseSender(client_sock, resp)

    with pytest.raises(ValueError, match="user_id cannot be empty"):
        sender.send_ack("")

    sender.send_ack("112233445566778899aabbccddeeff00")
    data = server_sock.recv(1024)
    assert int.from_bytes(data[1:3], "big") == ServerCode.ACK
