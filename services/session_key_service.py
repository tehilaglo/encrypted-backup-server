"""
Session-key provisioning service for the encrypted backup server.

This module is responsible for generating a fresh AES session key for a client,
encrypting that key with the client's RSA public key, and persisting the updated
key material in the database.

@author Tehila Cahnaman
"""

import base64
from typing import Optional

from protocol.constants import FORMAT
from storage.database import (
    get_public_key,
    update_aes_key,
    update_last_seen,
    update_public_key,
)
from services.crypto import generate_aes_key, rsa_encrypt


def provision_session_key(
    user_id: str,
    username: str,
    public_key: Optional[bytes] = None,
    *,
    load_stored_public_key: bool = False,
) -> bytes:
    """
    Generate, encrypt, and persist a fresh AES session key for a client.

    The AES key is generated server-side, encrypted with the client's RSA public
    key, stored in the database as a Base64-encoded string, and returned to the
    caller in encrypted form so it can be sent back to the client.

    Args:
        user_id: Unique identifier of the client.
        username: Username associated with the client.
        public_key: RSA public key received from the client. Required when
            ``load_stored_public_key`` is False.
        load_stored_public_key: Whether to load the existing RSA public key from
            the database instead of using the provided ``public_key`` argument.

    Returns:
        The RSA-encrypted AES key.

    Raises:
        ValueError: If ``user_id`` or ``username`` is empty.
        ValueError: If no public key is available for encryption.
    """
    if not user_id:
        raise ValueError("User ID is required to provision a session key")

    if not username:
        raise ValueError("Username is required to provision a session key")

    if load_stored_public_key:
        public_key = get_public_key(user_id, username)

    if public_key is None:
        raise ValueError("Public key is required to provision a session key")

    aes_key = generate_aes_key()

    # The client can only decrypt the AES key if it owns the matching RSA
    # private key, so the raw AES key is never sent over the socket.
    encrypted_aes_key = rsa_encrypt(public_key, aes_key)

    update_last_seen(user_id)

    if not load_stored_public_key:
        update_public_key(user_id, username, public_key)

    # Store the AES key as text because SQLite rows are currently managed as
    # simple string fields throughout the database layer.
    encoded_aes_key = base64.b64encode(aes_key).decode(FORMAT)
    update_aes_key(user_id, username, encoded_aes_key)

    return encrypted_aes_key
