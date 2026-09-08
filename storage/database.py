"""
SQLite persistence layer for the encrypted backup server.

This module owns all direct database access for:
- client registration records,
- stored public keys and AES session keys,
- client activity timestamps,
- uploaded file metadata,
- file version tracking,
- checksum verification status.

@author Tehila Cahnaman
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from protocol.constants import DATE_FORMAT

#: Name of the SQLite database file used to store registered clients and files.
DB_FILE: str = "clients.db"


CLIENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS clients (
    user_id TEXT PRIMARY KEY,
    username TEXT,
    public_key TEXT,
    last_seen TEXT,
    aes_key TEXT
)
"""
"""SQL statement used to create the clients table if it does not exist."""


FILES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS files (
    user_id TEXT,
    file_name TEXT,
    path_name TEXT,
    version INTEGER,
    last_modified TEXT,
    verified BOOLEAN,
    FOREIGN KEY(user_id) REFERENCES clients(user_id)
)
"""
"""SQL statement used to create the uploaded files metadata table."""


def _connect() -> sqlite3.Connection:
    """
    Open a connection to the configured SQLite database.

    Returns:
        sqlite3.Connection: Active SQLite database connection.
    """
    return sqlite3.connect(DB_FILE)


def _validate_non_empty(value: str, field_name: str) -> None:
    """
    Validate that a required string argument is not empty.

    Args:
        value: String value to validate.
        field_name: Human-readable field name used in error messages.

    Raises:
        ValueError: If `value` is empty or contains only whitespace.
    """
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _fetch_one_value(
    query: str,
    params: tuple[Any, ...],
    *,
    missing_message: str,
    error_message: str,
) -> Any:
    """
    Execute a SELECT query and return the first column from the first row.

    Args:
        query: SQL SELECT query to execute.
        params: Query parameters.
        missing_message: Message used when the query returns no value.
        error_message: Message used when SQLite raises an error.

    Returns:
        Any: First column of the first row returned by the query.

    Raises:
        ValueError: If no matching row/value is found.
        Exception: If a database error occurs.
    """
    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone()

        if result and result[0]:
            return result[0]

        raise ValueError(missing_message)

    except sqlite3.Error as exc:
        raise Exception(f"{error_message}: {exc}") from exc


def setup_database() -> None:
    """
    Initialize the database schema if the required tables do not already exist.

    Tables:
        clients: Stores client identity, public key, last-seen timestamp,
            and current AES session key.
        files: Stores metadata for uploaded files and links each file to a
            client record.

    Raises:
        Exception: If SQLite fails while creating the schema.
    """
    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(CLIENTS_TABLE_SQL)
            cursor.execute(FILES_TABLE_SQL)
            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(f"Database error during setup: {exc}") from exc


def username_exists(username: str) -> bool:
    """
    Check whether a username already exists in the clients table.

    Args:
        username: Username to look up.

    Returns:
        bool: True if the username exists, False otherwise.

    Raises:
        ValueError: If `username` is empty.
        Exception: If a database error occurs.
    """
    _validate_non_empty(username, "username")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM clients WHERE username = ?", (username,))
            result = cursor.fetchone()

        return result is not None

    except sqlite3.Error as exc:
        raise Exception(f"Database error when checking username: {exc}") from exc


def add_client(user_id: str, username: str) -> None:
    """
    Add a new client record.

    Existing `user_id` values are ignored because the original behavior uses
    `INSERT OR IGNORE`.

    Args:
        user_id: Unique client identifier.
        username: Client username.

    Raises:
        ValueError: If `user_id` or `username` is empty.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(username, "username")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO clients (user_id, username)
                VALUES (?, ?)
                """,
                (user_id, username),
            )
            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(f"Database error when adding client: {exc}") from exc


def get_user_id(username: str) -> str:
    """
    Retrieve the user ID associated with a username.

    Args:
        username: Username to search for.

    Returns:
        str: User ID associated with the username.

    Raises:
        ValueError: If `username` is empty or no user ID is found.
        Exception: If a database error occurs.
    """
    _validate_non_empty(username, "username")

    return _fetch_one_value(
        "SELECT user_id FROM clients WHERE username = ?",
        (username,),
        missing_message=f"No user ID found for the username: {username}",
        error_message="Database error when retrieving user ID",
    )


def update_public_key(user_id: str, username: str, public_key: str) -> None:
    """
    Update a client's stored public key.

    Args:
        user_id: Unique client identifier.
        username: Client username.
        public_key: Public key to store.

    Raises:
        ValueError: If any required argument is empty, or if no matching client
            record exists.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(username, "username")
    _validate_non_empty(public_key, "public_key")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE clients
                SET public_key = ?
                WHERE user_id = ? AND username = ?
                """,
                (public_key, user_id, username),
            )

            if cursor.rowcount == 0:
                raise ValueError(
                    f"No record found for: {user_id} with the username: {username}"
                )

            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(f"Database error when updating public key: {exc}") from exc


def get_public_key(user_id: str, username: str) -> str:
    """
    Retrieve a client's stored public key.

    Args:
        user_id: Unique client identifier.
        username: Client username.

    Returns:
        str: Stored public key.

    Raises:
        ValueError: If required arguments are empty or no public key is found.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(username, "username")

    return _fetch_one_value(
        """
        SELECT public_key
        FROM clients
        WHERE user_id = ? AND username = ?
        """,
        (user_id, username),
        missing_message=f"No public key found for: {user_id} with the username: {username}",
        error_message="Database error when retrieving public key",
    )


def update_aes_key(user_id: str, username: str, aes_key: str) -> None:
    """
    Update a client's stored AES session key.

    Args:
        user_id: Unique client identifier.
        username: Client username.
        aes_key: Base64-encoded AES key to store.

    Raises:
        ValueError: If any required argument is empty, or if no matching client
            record exists.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(username, "username")
    _validate_non_empty(aes_key, "aes_key")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE clients
                SET aes_key = ?
                WHERE user_id = ? AND username = ?
                """,
                (aes_key, user_id, username),
            )

            if cursor.rowcount == 0:
                raise ValueError(
                    f"No record found for: {user_id} with the username: {username}"
                )

            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(f"Database error when updating AES key: {exc}") from exc


def get_aes_key(user_id: str) -> str:
    """
    Retrieve the stored AES session key for a client.

    Args:
        user_id: Unique client identifier.

    Returns:
        str: Stored AES key.

    Raises:
        ValueError: If `user_id` is empty or no AES key is found.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")

    return _fetch_one_value(
        "SELECT aes_key FROM clients WHERE user_id = ?",
        (user_id,),
        missing_message=f"No AES key found for: {user_id}",
        error_message="Database error when retrieving AES key",
    )


def update_last_seen(user_id: str) -> None:
    """
    Update a client's last-seen timestamp to the current UTC time.

    Args:
        user_id: Unique client identifier.

    Raises:
        ValueError: If `user_id` is empty.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")

    try:
        current_time = datetime.now(timezone.utc).strftime(DATE_FORMAT)

        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE clients SET last_seen = ? WHERE user_id = ?",
                (current_time, user_id),
            )
            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(f"Database error when updating last-seen: {exc}") from exc


def get_last_seen(user_id: str) -> str:
    """
    Retrieve a client's last-seen timestamp.

    Args:
        user_id: Unique client identifier.

    Returns:
        str: Last-seen timestamp formatted according to `DATE_FORMAT`.

    Raises:
        ValueError: If `user_id` is empty or no last-seen value is found.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")

    return _fetch_one_value(
        "SELECT last_seen FROM clients WHERE user_id = ?",
        (user_id,),
        missing_message=f"No last-seen found for: {user_id}",
        error_message="Database error when retrieving last-seen",
    )


def add_file(
    user_id: str,
    file_name: str,
    path_name: str,
    version: int,
    last_modified: str,
    verified: bool,
) -> None:
    """
    Add metadata for an uploaded file.

    Args:
        user_id: Unique client identifier.
        file_name: Original uploaded file name.
        path_name: Server-side path where the file is stored.
        version: File version number.
        last_modified: Last-modified timestamp.
        verified: Whether the file passed integrity verification.

    Raises:
        ValueError: If required string arguments are empty or `version` is
            smaller than 1.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(file_name, "file_name")
    _validate_non_empty(path_name, "path_name")
    _validate_non_empty(last_modified, "last_modified")

    if version < 1:
        raise ValueError("version must be greater than or equal to 1")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO files (
                    user_id,
                    file_name,
                    path_name,
                    version,
                    last_modified,
                    verified
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, file_name, path_name, version, last_modified, verified),
            )
            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(f"Database error when adding file: {exc}") from exc


def get_next_version_number(user_id: str, file_name: str) -> int:
    """
    Get the next version number for a user's file.

    Args:
        user_id: Unique client identifier.
        file_name: Original uploaded file name.

    Returns:
        int: Next version number. Returns 1 when the file has no previous
        versions.

    Raises:
        ValueError: If `user_id` or `file_name` is empty.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(file_name, "file_name")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT MAX(version)
                FROM files
                WHERE user_id = ? AND file_name = ?
                """,
                (user_id, file_name),
            )
            result = cursor.fetchone()

        if result and result[0]:
            return result[0] + 1

        return 1

    except sqlite3.Error as exc:
        raise Exception(
            f"Database error when retrieving next version number: {exc}"
        ) from exc


def update_file_verified_status(user_id: str, path_name: str, verified: bool) -> None:
    """
    Update the integrity-verification status of a stored file.

    Args:
        user_id: Unique client identifier.
        path_name: Server-side path of the stored file.
        verified: New verification status.

    Raises:
        ValueError: If `user_id` or `path_name` is empty.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(path_name, "path_name")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE files
                SET verified = ?
                WHERE user_id = ? AND path_name = ?
                """,
                (verified, user_id, path_name),
            )
            conn.commit()

    except sqlite3.Error as exc:
        raise Exception(
            f"Database error when updating file verified status: {exc}"
        ) from exc


def get_file_path(user_id: str, file_name: str) -> str:
    """
    Retrieve the latest stored path for a user's file.

    The lookup keeps the original behavior and uses `LIKE '<file_name>%'`
    so callers can find the latest stored version by the original file name.

    Args:
        user_id: Unique client identifier.
        file_name: Original uploaded file name.

    Returns:
        str: Path of the latest stored file version.

    Raises:
        ValueError: If required arguments are empty or no matching file record
            is found.
        Exception: If a database error occurs.
    """
    _validate_non_empty(user_id, "user_id")
    _validate_non_empty(file_name, "file_name")

    try:
        with _connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT path_name, version
                FROM files
                WHERE user_id = ? AND file_name LIKE ?
                ORDER BY version DESC
                LIMIT 1
                """,
                (user_id, f"{file_name}%"),
            )
            result = cursor.fetchone()

        if result:
            return result[0]

        raise ValueError(
            f"No record found for: {user_id} with the file-name: {file_name}"
        )

    except sqlite3.Error as exc:
        raise Exception(
            f"Database error when retrieving latest file path: {exc}"
        ) from exc
