"""
Tests for ServerHandler connection management and request dispatching.
"""

from unittest.mock import MagicMock, patch
import pytest

from handlers.server_handler import ServerHandler
from protocol.constants import SERVER_VERSION, ClientCode, ServerCode
from protocol.request import Request, RequestHeader, RequestPayload
from protocol.response import Response


def _make_req(code: ClientCode) -> Request:
    return Request(
        header=RequestHeader(
            user_id="112233445566778899aabbccddeeff00",
            version=SERVER_VERSION,
            request_code=code,
            payload_size=10,
        ),
        payload=RequestPayload(username="alice", file_name="file.txt"),
    )


def test_create_default_response():
    """
    Test _create_default_response produces clean default Response object.
    """
    resp = ServerHandler._create_default_response()
    assert isinstance(resp, Response)
    assert resp.header.version == SERVER_VERSION
    assert resp.header.response_code == ServerCode.DEFAULT


def test_handle_request_none():
    """
    Test handle_request raises ValueError when request is None.
    """
    mock_sock = MagicMock()
    with pytest.raises(ValueError, match="Cannot handle an empty request"):
        ServerHandler.handle_request(mock_sock, None)


@pytest.mark.parametrize(
    "code,handler_name",
    [
        (ClientCode.REGISTRATION, "handle_client_registration"),
        (ClientCode.PUBLIC_KEY_SEND, "handle_public_key_send"),
        (ClientCode.RE_REGISTRATION, "handle_client_re_registration"),
        (ClientCode.CREATE_BACKUP, "handle_backup_request"),
        (ClientCode.CRC_SUCCESS, "handle_crc_success"),
        (ClientCode.CRC_ERROR, "handle_crc_error"),
        (ClientCode.CRC_FAILURE, "handle_crc_failure"),
    ],
)
def test_handle_request_routing_all_client_codes(code, handler_name):
    """
    Verify every operational ClientCode routes to the correct handler function.
    """
    mock_sock = MagicMock()
    req = _make_req(code)

    with patch(f"handlers.server_handler.{handler_name}") as mock_handler:
        ServerHandler.handle_request(mock_sock, req)
        assert mock_handler.called


def test_handle_request_unknown_code():
    """
    Test handle_request raises RuntimeError for unknown request codes.
    """
    mock_sock = MagicMock()
    req = _make_req(999)

    with pytest.raises(RuntimeError, match="Unknown request code: 999"):
        ServerHandler.handle_request(mock_sock, req)


def test_handle_client_disconnect_request(socket_pair):
    """
    Test handle_client cleanly exits on ClientCode.DISCONNECT and closes socket.
    """
    client_sock, server_sock = socket_pair
    server = ServerHandler()

    req = _make_req(ClientCode.DISCONNECT)
    with patch("handlers.server_handler.deserialize_request", side_effect=[req, None]):
        server.handle_client(client_sock, ("127.0.0.1", 54321))

    # Connection should be closed
    assert client_sock._closed


def test_handle_client_unexpected_disconnect(socket_pair):
    """
    Test handle_client exits when deserialize_request returns None (socket closed).
    """
    client_sock, server_sock = socket_pair
    server = ServerHandler()

    with patch("handlers.server_handler.deserialize_request", return_value=None):
        server.handle_client(client_sock, ("127.0.0.1", 54321))

    assert client_sock._closed


def test_handle_client_handler_exception_sends_failure(socket_pair):
    """
    Test that when request handling raises an unhandled exception, ResponseSender.send_failure is called.
    """
    client_sock, server_sock = socket_pair
    server = ServerHandler()

    req = _make_req(ClientCode.REGISTRATION)
    with patch("handlers.server_handler.deserialize_request", side_effect=[req, None]), \
         patch("handlers.server_handler.handle_client_registration", side_effect=Exception("Database crash")):
        server.handle_client(client_sock, ("127.0.0.1", 54321))

    # Receive failure response on server_sock
    data = server_sock.recv(1024)
    assert len(data) > 0
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.FAILED
    assert client_sock._closed


def test_start_server_uninitialized_socket():
    """
    Test start_server raises RuntimeError if server_socket is None.
    """
    server = ServerHandler()
    assert server.server_socket is None

    with pytest.raises(RuntimeError, match="Server socket must be initialized before starting"):
        server.start_server()


def test_setup_server_socket_mocked():
    """
    Test setup_server_socket creates and binds socket.
    """
    server = ServerHandler()
    with patch("socket.socket") as mock_socket_cls:
        mock_sock_inst = MagicMock()
        mock_socket_cls.return_value = mock_sock_inst

        server.setup_server_socket()
        assert server.server_socket is mock_sock_inst
        mock_sock_inst.bind.assert_called_once_with((server.HOST_IP, server.HOST_PORT))
