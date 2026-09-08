"""
Tests for the SQLite database persistence layer.
"""

import sqlite3
from datetime import datetime, timezone
import pytest

from protocol.constants import DATE_FORMAT
from storage.database import (
    _connect,
    add_client,
    add_file,
    get_aes_key,
    get_file_path,
    get_last_seen,
    get_next_version_number,
    get_public_key,
    get_user_id,
    setup_database,
    update_aes_key,
    update_file_verified_status,
    update_last_seen,
    update_public_key,
    username_exists,
)


def test_setup_database(temp_db):
    """
    Test database schema setup creates clients and files tables.
    """
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

    assert "clients" in tables
    assert "files" in tables


def test_add_and_get_client(temp_db):
    """
    Test adding a client and retrieving user_id by username.
    """
    user_id = "112233445566778899aabbccddeeff00"
    username = "alice"

    assert not username_exists(username)
    add_client(user_id, username)
    assert username_exists(username)
    assert get_user_id(username) == user_id

    # Duplicate add_client with same user_id should be ignored
    add_client(user_id, "alice2")
    assert get_user_id(username) == user_id


def test_username_exists_validation(temp_db):
    """
    Test username_exists argument validation.
    """
    with pytest.raises(ValueError, match="username must not be empty"):
        username_exists("")
    with pytest.raises(ValueError, match="username must not be empty"):
        username_exists("   ")


def test_add_client_validation(temp_db):
    """
    Test add_client argument validation.
    """
    with pytest.raises(ValueError, match="user_id must not be empty"):
        add_client("", "alice")
    with pytest.raises(ValueError, match="username must not be empty"):
        add_client("uid1", "")


def test_get_user_id_missing_record(temp_db):
    """
    Test get_user_id raises ValueError when username is not found.
    """
    with pytest.raises(ValueError, match="No user ID found for the username: nonexistent"):
        get_user_id("nonexistent")


def test_public_key_storage_and_update(temp_db):
    """
    Test updating and retrieving client public keys.
    """
    user_id = "uid123"
    username = "bob"
    add_client(user_id, username)

    # Initial get should raise ValueError (no key stored yet)
    with pytest.raises(ValueError, match="No public key found"):
        get_public_key(user_id, username)

    pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
    update_public_key(user_id, username, pubkey)
    assert get_public_key(user_id, username) == pubkey

    # Update non-existent client raises ValueError
    with pytest.raises(ValueError, match="No record found for: nonexistent"):
        update_public_key("nonexistent", "nobody", pubkey)


def test_public_key_validation(temp_db):
    """
    Test empty validations for public key operations.
    """
    with pytest.raises(ValueError, match="user_id must not be empty"):
        get_public_key("", "bob")
    with pytest.raises(ValueError, match="username must not be empty"):
        get_public_key("uid123", "")
    with pytest.raises(ValueError, match="public_key must not be empty"):
        update_public_key("uid123", "bob", "")


def test_aes_key_storage_and_update(temp_db):
    """
    Test updating and retrieving client AES session keys.
    """
    user_id = "uid456"
    username = "charlie"
    add_client(user_id, username)

    with pytest.raises(ValueError, match="No AES key found"):
        get_aes_key(user_id)

    aes_key_b64 = "k1+f5Q24vJk+abcdEFGH=="
    update_aes_key(user_id, username, aes_key_b64)
    assert get_aes_key(user_id) == aes_key_b64

    # Update non-existent client raises ValueError
    with pytest.raises(ValueError, match="No record found for: nonexistent"):
        update_aes_key("nonexistent", "nobody", aes_key_b64)


def test_aes_key_validation(temp_db):
    """
    Test empty validations for AES key operations.
    """
    with pytest.raises(ValueError, match="user_id must not be empty"):
        get_aes_key("")
    with pytest.raises(ValueError, match="aes_key must not be empty"):
        update_aes_key("uid456", "charlie", "")


def test_last_seen_tracking(temp_db):
    """
    Test last_seen updating and retrieval.
    """
    user_id = "uid789"
    add_client(user_id, "david")

    with pytest.raises(ValueError, match="No last-seen found"):
        get_last_seen(user_id)

    update_last_seen(user_id)
    last_seen_str = get_last_seen(user_id)
    assert last_seen_str is not None

    # Verify parseable with DATE_FORMAT
    parsed_dt = datetime.strptime(last_seen_str, DATE_FORMAT)
    assert parsed_dt is not None


def test_last_seen_validation(temp_db):
    """
    Test empty validations for last-seen operations.
    """
    with pytest.raises(ValueError, match="user_id must not be empty"):
        update_last_seen("")
    with pytest.raises(ValueError, match="user_id must not be empty"):
        get_last_seen("")


def test_file_metadata_and_versioning(temp_db):
    """
    Test file insertion, version calculation, and path lookup.
    """
    user_id = "uid_files"
    username = "eve"
    add_client(user_id, username)

    # When no file exists, next version must be 1
    assert get_next_version_number(user_id, "doc.txt") == 1

    now_str = datetime.now(timezone.utc).strftime(DATE_FORMAT)

    # Insert version 1
    add_file(
        user_id=user_id,
        file_name="doc.txt",
        path_name=f"{user_id}/doc_v1.txt",
        version=1,
        last_modified=now_str,
        verified=False,
    )

    assert get_next_version_number(user_id, "doc.txt") == 2
    assert get_file_path(user_id, "doc.txt") == f"{user_id}/doc_v1.txt"

    # Insert version 2
    add_file(
        user_id=user_id,
        file_name="doc.txt",
        path_name=f"{user_id}/doc_v2.txt",
        version=2,
        last_modified=now_str,
        verified=False,
    )

    assert get_next_version_number(user_id, "doc.txt") == 3
    # Latest path should return v2 (highest version)
    assert get_file_path(user_id, "doc.txt") == f"{user_id}/doc_v2.txt"


def test_file_verified_status(temp_db):
    """
    Test updating file verification status.
    """
    user_id = "uid_files2"
    add_client(user_id, "frank")
    now_str = datetime.now(timezone.utc).strftime(DATE_FORMAT)
    path_name = f"{user_id}/frank_v1.txt"

    add_file(
        user_id=user_id,
        file_name="frank.txt",
        path_name=path_name,
        version=1,
        last_modified=now_str,
        verified=False,
    )

    update_file_verified_status(user_id, path_name, True)

    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT verified FROM files WHERE user_id=? AND path_name=?", (user_id, path_name))
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == 1  # SQLite stores boolean as integer (1=True)


def test_file_operations_validation(temp_db):
    """
    Test validation checks for file insertion and lookups.
    """
    with pytest.raises(ValueError, match="version must be greater than or equal to 1"):
        add_file(
            user_id="u1",
            file_name="f1",
            path_name="p1",
            version=0,
            last_modified="now",
            verified=False,
        )

    with pytest.raises(ValueError, match="No record found for: u1 with the file-name: missing.txt"):
        get_file_path("u1", "missing.txt")
