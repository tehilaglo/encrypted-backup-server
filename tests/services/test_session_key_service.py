"""
Tests for session key provisioning service.
"""

import base64
import pytest
from Crypto.Cipher import PKCS1_OAEP

from services.session_key_service import provision_session_key
from storage.database import add_client, get_aes_key, get_public_key, get_last_seen


def test_provision_session_key_with_public_key(temp_db, test_rsa_key):
    """
    Test provisioning a session key using a provided public key.
    """
    rsa_private_key, rsa_public_pem = test_rsa_key
    user_id = "uid_session"
    username = "alice"
    add_client(user_id, username)

    encrypted_aes_key = provision_session_key(
        user_id=user_id,
        username=username,
        public_key=rsa_public_pem,
    )

    assert isinstance(encrypted_aes_key, bytes)
    assert len(encrypted_aes_key) > 0

    # Decrypt the returned key with our private RSA key
    raw_ciphertext = base64.b64decode(encrypted_aes_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_aes_key = cipher.decrypt(raw_ciphertext)

    # Verify that the decrypted key matches the one stored in the DB
    stored_aes_key_b64 = get_aes_key(user_id)
    assert base64.b64decode(stored_aes_key_b64) == decrypted_aes_key

    # Verify public key is stored in DB
    stored_pubkey = get_public_key(user_id, username)
    assert stored_pubkey in (rsa_public_pem, rsa_public_pem.decode("utf-8"))
    # Verify last_seen updated
    assert get_last_seen(user_id) is not None


def test_provision_session_key_load_stored_public_key(temp_db, test_rsa_key):
    """
    Test re-provisioning a session key using the already stored public key.
    """
    rsa_private_key, rsa_public_pem = test_rsa_key
    user_id = "uid_session_stored"
    username = "bob"
    add_client(user_id, username)

    # First provision to store the public key
    provision_session_key(user_id=user_id, username=username, public_key=rsa_public_pem)
    old_aes_key_b64 = get_aes_key(user_id)

    # Re-provision with load_stored_public_key=True
    new_encrypted_aes_key = provision_session_key(
        user_id=user_id,
        username=username,
        load_stored_public_key=True,
    )

    raw_ciphertext = base64.b64decode(new_encrypted_aes_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    new_decrypted_aes_key = cipher.decrypt(raw_ciphertext)

    new_stored_aes_key_b64 = get_aes_key(user_id)
    assert base64.b64decode(new_stored_aes_key_b64) == new_decrypted_aes_key
    # New AES key should be different from old
    assert new_stored_aes_key_b64 != old_aes_key_b64


def test_provision_session_key_validation(temp_db):
    """
    Test argument validation for provision_session_key.
    """
    with pytest.raises(ValueError, match="User ID is required to provision a session key"):
        provision_session_key(user_id="", username="alice", public_key=b"key")

    with pytest.raises(ValueError, match="Username is required to provision a session key"):
        provision_session_key(user_id="uid", username="", public_key=b"key")

    with pytest.raises(ValueError, match="Public key is required to provision a session key"):
        provision_session_key(user_id="uid", username="alice", public_key=None, load_stored_public_key=False)
