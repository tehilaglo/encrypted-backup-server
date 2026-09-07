"""
Client registration service for the encrypted backup server.

This module handles:
- new client registration,
- username validation,
- public-key submission,
- AES session-key provisioning,
- client re-registration within the allowed time window.

Socket responses are sent through ``ResponseSender`` while key generation and
database persistence are delegated to the relevant service/database modules.

@author Tehila Cahnaman
"""

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import socket

from utils.console_ui import Color
from protocol.constants import DATE_FORMAT, MIN_USERNAME_LEN, ServerCode, USERNAME_LEN
from storage.database import (
    add_client,
    get_last_seen,
    get_user_id,
    update_last_seen,
    username_exists,
)
from services.crypto import generate_uuid
from protocol.request import Request, RequestPayload
from protocol.response import Response
from protocol.response_sender import ResponseSender
from services.session_key_service import provision_session_key

#: Allowed username characters: letters, digits, dot, underscore, and hyphen.
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")

#: Maximum number of days a client may re-register without a fresh registration.
RE_REGISTRATION_WINDOW_DAYS = 7


def _validate_username(username: str | None) -> bool:
    """
    Check whether a username satisfies the server validation rules.

    Args:
        username: Username received from the client.

    Returns:
        ``True`` if the username is valid, otherwise ``False``.
    """
    if username is None:
        return False

    if not MIN_USERNAME_LEN <= len(username) < USERNAME_LEN:
        return False

    return USERNAME_PATTERN.fullmatch(username) is not None


def _is_registered_user(username: str, user_id: str) -> bool:
    """
    Check whether a username belongs to the provided user ID.

    Args:
        username: Client username.
        user_id: Client unique ID.

    Returns:
        ``True`` if the database maps ``username`` to ``user_id``,
        otherwise ``False``.
    """
    return get_user_id(username) == user_id


def _create_user_directory(user_id: str) -> None:
    """
    Create the server-side directory used to store a client's uploaded files.

    Args:
        user_id: Unique client ID.
    """
    user_dir = Path(user_id)
    user_dir.mkdir(parents=True, exist_ok=False)


def _is_re_registration_expired(user_id: str) -> bool:
    """
    Check whether a client's re-registration window has expired.

    Args:
        user_id: Unique client ID.

    Returns:
        ``True`` if the last-seen timestamp is older than the allowed
        re-registration window, otherwise ``False``.
    """
    last_seen_str = get_last_seen(user_id)
    last_seen_time = datetime.strptime(last_seen_str, DATE_FORMAT)
    current_time = datetime.now(timezone.utc)

    return current_time - last_seen_time > timedelta(
        days=RE_REGISTRATION_WINDOW_DAYS
    )


def handle_public_key_send(
    conn: socket,
    request: Request,
    response: Response,
) -> None:
    """
    Handle a client's public-key submission.

    If the request belongs to a registered user, the server generates a fresh
    AES key, encrypts it with the client's RSA public key, stores the session
    key material, and sends the encrypted AES key back to the client.

    Args:
        conn: Client socket connection.
        request: Parsed public-key request.
        response: Mutable response object to populate and send.
    """
    user_id = request.header.user_id
    username = request.payload.username
    sender = ResponseSender(conn, response)

    if not _is_registered_user(username, user_id):
        sender.send_registration_failed()
        print(Color.RED + "[ERROR] Invalid user ID" + Color.RESET)
        return

    encrypted_aes_key = provision_session_key(
        user_id=user_id,
        username=username,
        public_key=request.payload.public_key,
    )

    sender.send_session_key(
        user_id,
        ServerCode.KEY_SEND_SUCCESS,
        encrypted_aes_key,
    )

    print(
        Color.BLUE
        + f"[SUCCESS] Client: '{user_id}' registered successfully."
        + Color.RESET
    )


def handle_client_registration(
    conn: socket,
    request_payload: RequestPayload,
    response: Response,
) -> None:
    """
    Handle a new client registration request.

    The function validates the requested username, checks whether it is already
    taken, creates a new user ID, stores the client in the database, creates the
    user's upload directory, and sends the registration result to the client.

    Args:
        conn: Client socket connection.
        request_payload: Parsed registration request payload.
        response: Mutable response object to populate and send.
    """
    username = request_payload.username
    sender = ResponseSender(conn, response)

    if not _validate_username(username):
        sender.send_registration_failed()
        return

    if username_exists(username):
        sender.send_username_taken()
        return

    user_id = generate_uuid()

    add_client(user_id, username)
    update_last_seen(user_id)
    _create_user_directory(user_id)

    sender.send_registration_success(user_id)

    print(
        Color.BLUE
        + f"[SUCCESS] uuid '{user_id}' sent to client successfully."
        + Color.RESET
    )


def handle_client_re_registration(
    conn: socket,
    request: Request,
    response: Response,
) -> None:
    """
    Handle re-registration for a previously registered client.

    Re-registration succeeds only when:
    - the username belongs to the provided user ID,
    - the last registration activity is still within the allowed time window,
    - a stored public key is available for encrypting the new AES session key.

    Args:
        conn: Client socket connection.
        request: Parsed re-registration request.
        response: Mutable response object to populate and send.
    """
    user_id = request.header.user_id
    username = request.payload.username
    sender = ResponseSender(conn, response)

    if not _is_registered_user(username, user_id):
        sender.send_re_registration_failed()
        print(Color.RED + "[ERROR] Invalid user ID" + Color.RESET)
        return

    if _is_re_registration_expired(user_id):
        sender.send_re_registration_failed()
        print(Color.RED + "[ERROR] Registration information expired" + Color.RESET)
        return

    encrypted_aes_key = provision_session_key(
        user_id=user_id,
        username=username,
        load_stored_public_key=True,
    )

    sender.send_session_key(
        user_id,
        ServerCode.RE_REGISTRATION_SUCCESS,
        encrypted_aes_key,
    )

    print(
        Color.BLUE
        + f"[SUCCESS] Client: '{user_id}' re-registered successfully."
        + Color.RESET
    )
