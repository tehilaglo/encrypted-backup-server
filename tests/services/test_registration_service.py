"""
Tests for registration service, re-registration, and username validation.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from protocol.constants import DATE_FORMAT, SERVER_VERSION, ServerCode, ClientCode
from protocol.request import Request, RequestHeader, RequestPayload
from protocol.response import Response, ResponseHeader, ResponsePayload
from services.registration_service import (
    RE_REGISTRATION_WINDOW_DAYS,
    _is_re_registration_expired,
    _validate_username,
    handle_client_re_registration,
    handle_client_registration,
    handle_public_key_send,
)
from storage.database import (
    _connect,
    add_client,
    get_last_seen,
    get_user_id,
    update_last_seen,
    update_public_key,
)


def _create_test_response():
    return Response(
        header=ResponseHeader(
            version=SERVER_VERSION,
            response_code=ServerCode.DEFAULT,
        ),
        payload=ResponsePayload(),
    )


@pytest.mark.parametrize(
    "username,expected",
    [
        ("alice", True),
        ("user_123", True),
        ("user.name", True),
        ("user-name", True),
        ("a" * 5, True),
        ("a" * 63, True),
        (None, False),
        ("", False),
        ("a" * 4, False),  # too short (< 5)
        ("a" * 64, False),  # too long (>= 64)
        ("user name", False),  # contains space
        ("user@name", False),  # invalid char @
        ("user#name", False),  # invalid char #
        ("user/name", False),  # invalid char /
    ],
)
def test_validate_username(username, expected):
    """
    Test username validation rules and length bounds.
    """
    assert _validate_username(username) == expected


def test_handle_client_registration_success(temp_db, temp_workdir, socket_pair):
    """
    Test successful client registration creates DB entry, user directory, and sends REGISTRATION_SUCCESS.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()
    payload = RequestPayload(username="valid_user")

    handle_client_registration(client_sock, payload, resp)

    # Receive response from server_sock
    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.REGISTRATION_SUCCESS

    # Extract user_id from response
    assigned_user_id = resp.payload.user_id
    assert assigned_user_id is not None
    assert len(assigned_user_id) == 32

    # Verify user exists in DB
    assert get_user_id("valid_user") == assigned_user_id
    assert get_last_seen(assigned_user_id) is not None

    # Verify user directory was created
    assert Path(assigned_user_id).is_dir()


def test_handle_client_registration_invalid_username(temp_db, temp_workdir, socket_pair):
    """
    Test registration with invalid username sends REGISTRATION_FAILED.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()
    payload = RequestPayload(username="abc")  # too short

    handle_client_registration(client_sock, payload, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.REGISTRATION_FAILED


def test_handle_client_registration_username_taken(temp_db, temp_workdir, socket_pair):
    """
    Test registration with existing username sends USERNAME_TAKEN.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    # Pre-register user
    add_client("existing_uid", "duplicate_user")

    payload = RequestPayload(username="duplicate_user")
    handle_client_registration(client_sock, payload, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.USERNAME_TAKEN


def test_handle_public_key_send_success(temp_db, socket_pair, test_rsa_key):
    """
    Test sending public key for registered user provisions AES key and sends KEY_SEND_SUCCESS.
    """
    _, rsa_public_pem = test_rsa_key
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    user_id = "112233445566778899aabbccddeeff00"
    username = "alice_pub"
    add_client(user_id, username)

    req = Request(
        header=RequestHeader(
            user_id=user_id,
            version=3,
            request_code=ClientCode.PUBLIC_KEY_SEND,
            payload_size=len(rsa_public_pem),
        ),
        payload=RequestPayload(
            username=username,
            public_key=rsa_public_pem,
        ),
    )

    handle_public_key_send(client_sock, req, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.KEY_SEND_SUCCESS
    assert resp.payload.encrypted_aes_key is not None


def test_handle_public_key_send_mismatched_user_id(temp_db, socket_pair, test_rsa_key):
    """
    Test sending public key with a mismatched user ID sends REGISTRATION_FAILED.
    """
    _, rsa_public_pem = test_rsa_key
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    # Pre-register user with real_uid
    real_uid = "112233445566778899aabbccddeeff00"
    username = "alice_mismatch"
    add_client(real_uid, username)

    req = Request(
        header=RequestHeader(
            user_id="wrong_uid_1234567890abcdef012345",
            version=3,
            request_code=ClientCode.PUBLIC_KEY_SEND,
            payload_size=len(rsa_public_pem),
        ),
        payload=RequestPayload(
            username=username,
            public_key=rsa_public_pem,
        ),
    )

    handle_public_key_send(client_sock, req, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.REGISTRATION_FAILED


def test_handle_public_key_send_nonexistent_username_raises_value_error(temp_db, socket_pair, test_rsa_key):
    """
    Test sending public key for completely unknown username raises ValueError from get_user_id.
    Note: In production server loop, this exception is caught and converted to ServerCode.FAILED.
    """
    _, rsa_public_pem = test_rsa_key
    client_sock, _ = socket_pair
    resp = _create_test_response()

    req = Request(
        header=RequestHeader(
            user_id="wrong_uid",
            version=3,
            request_code=ClientCode.PUBLIC_KEY_SEND,
            payload_size=len(rsa_public_pem),
        ),
        payload=RequestPayload(
            username="nonexistent",
            public_key=rsa_public_pem,
        ),
    )

    with pytest.raises(ValueError, match="No user ID found for the username"):
        handle_public_key_send(client_sock, req, resp)


def test_handle_re_registration_success(temp_db, socket_pair, test_rsa_key):
    """
    Test re-registration within the 7-day window sends RE_REGISTRATION_SUCCESS.
    """
    _, rsa_public_pem = test_rsa_key
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    user_id = "112233445566778899aabbccddeeff00"
    username = "re_user"
    add_client(user_id, username)
    update_public_key(user_id, username, rsa_public_pem)
    update_last_seen(user_id)

    req = Request(
        header=RequestHeader(
            user_id=user_id,
            version=3,
            request_code=ClientCode.RE_REGISTRATION,
            payload_size=len(username),
        ),
        payload=RequestPayload(username=username),
    )

    handle_client_re_registration(client_sock, req, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.RE_REGISTRATION_SUCCESS
    assert resp.payload.encrypted_aes_key is not None


def test_handle_re_registration_expired(temp_db, socket_pair, test_rsa_key):
    """
    Test re-registration after expiration window (> 7 days) sends RE_REGISTRATION_FAILED.
    """
    _, rsa_public_pem = test_rsa_key
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    user_id = "112233445566778899aabbccddeeff00"
    username = "expired_user"
    add_client(user_id, username)
    update_public_key(user_id, username, rsa_public_pem)

    # Set last-seen to 10 days in the past
    past_date = datetime.now(timezone.utc) - timedelta(days=10)
    past_date_str = past_date.strftime(DATE_FORMAT)
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE clients SET last_seen=? WHERE user_id=?", (past_date_str, user_id))
        conn.commit()

    assert _is_re_registration_expired(user_id) is True

    req = Request(
        header=RequestHeader(
            user_id=user_id,
            version=3,
            request_code=ClientCode.RE_REGISTRATION,
            payload_size=len(username),
        ),
        payload=RequestPayload(username=username),
    )

    handle_client_re_registration(client_sock, req, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.RE_REGISTRATION_FAILED


def test_handle_re_registration_mismatched_user_id(temp_db, socket_pair):
    """
    Test re-registration with mismatched user ID sends RE_REGISTRATION_FAILED.
    """
    client_sock, server_sock = socket_pair
    resp = _create_test_response()

    real_uid = "112233445566778899aabbccddeeff00"
    username = "known_user"
    add_client(real_uid, username)

    req = Request(
        header=RequestHeader(
            user_id="wrong_uid_1234567890abcdef012345",
            version=3,
            request_code=ClientCode.RE_REGISTRATION,
            payload_size=len(username),
        ),
        payload=RequestPayload(username=username),
    )

    handle_client_re_registration(client_sock, req, resp)

    data = server_sock.recv(1024)
    resp_code = int.from_bytes(data[1:3], "big")
    assert resp_code == ServerCode.RE_REGISTRATION_FAILED
