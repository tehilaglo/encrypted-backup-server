"""
Backup and upload service layer for the encrypted backup server.

This module contains the core business logic for handling encrypted file uploads:
- buffering incoming encrypted file chunks,
- assembling completed uploads,
- decrypting and saving uploaded files,
- recording file metadata in the database,
- marking uploads as verified,
- deleting failed uploads.

The service layer deliberately does not send socket responses. Request handlers
are responsible for calling these functions and building protocol responses.

@author Tehila Cahnaman
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from storage.database import (
    DATE_FORMAT,
    add_file,
    get_aes_key,
    get_file_path,
    get_next_version_number,
    update_file_verified_status,
    update_last_seen,
)
from services.crypto import aes_cbc_decrypt, calculate_crc32


@dataclass
class UploadState:
    """
    Tracks the in-progress upload state for a single user.

    Attributes:
        total_packets: Total number of packets expected for this upload.
        file_name: Sanitized original file name.
        chunks: Mapping from packet number to encrypted chunk bytes.
    """

    total_packets: int
    file_name: str
    chunks: dict[int, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class SavedUpload:
    """
    Stores metadata for a completed and persisted upload.

    Attributes:
        user_id: Unique ID of the user who uploaded the file.
        original_file_name: Sanitized original file name.
        stored_path: Path where the decrypted file was saved.
        version: Version number assigned to the uploaded file.
        encrypted_chunk_size: Size of the encrypted upload chunk.
        checksum: CRC32 checksum of the decrypted file contents.
    """

    user_id: str
    original_file_name: str
    stored_path: str
    version: int
    encrypted_chunk_size: int
    checksum: int


class UploadStateError(Exception):
    """Raised when upload packet state is invalid or inconsistent."""


class UploadNotFoundError(FileNotFoundError):
    """Raised when a stored upload cannot be found on disk."""


class UploadAssembler:
    """
    Collects encrypted upload chunks until a complete file is available.

    The assembler stores chunks by packet number, allowing packets to be
    assembled in the correct order even if they were received out of order.

    This class is safe for threaded access through an internal lock.
    """

    def __init__(self) -> None:
        """
        Initialize an empty upload assembler.
        """
        self._uploads: dict[str, UploadState] = {}
        self._lock = Lock()

    def add_chunk(
        self,
        *,
        user_id: str,
        file_name: str,
        packet_number: int,
        total_packets: int,
        chunk: bytes,
    ) -> bytes | None:
        """
        Add one encrypted chunk to a user's in-progress upload.

        Args:
            user_id: Unique ID of the uploading user.
            file_name: Original file name sent by the client.
            packet_number: One-based packet number of the current chunk.
            total_packets: Total number of packets expected for this file.
            chunk: Encrypted chunk bytes.

        Returns:
            ``None`` if the upload is still incomplete.
            The full encrypted file bytes once all packets were received.

        Raises:
            ValueError: If required arguments are empty or invalid.
            UploadStateError: If packet metadata is invalid or inconsistent.
        """
        if not user_id:
            raise ValueError("user_id must not be empty")

        if not file_name:
            raise ValueError("file_name must not be empty")

        if chunk is None:
            raise ValueError("chunk must not be None")

        if packet_number < 1 or total_packets < 1:
            raise UploadStateError("Packet numbers must start at 1")

        if packet_number > total_packets:
            raise UploadStateError("Packet number cannot exceed total packets")

        sanitized_name = Path(file_name).name

        with self._lock:
            state = self._uploads.get(user_id)

            if state is None:
                state = UploadState(
                    total_packets=total_packets,
                    file_name=sanitized_name,
                )
                self._uploads[user_id] = state
            else:
                self._validate_existing_upload_state(
                    state=state,
                    file_name=sanitized_name,
                    total_packets=total_packets,
                )

            state.chunks[packet_number] = chunk

            if len(state.chunks) != state.total_packets:
                return None

            self._validate_all_packets_received(state)
            full_data = self._assemble_chunks_in_order(state)

            del self._uploads[user_id]
            return full_data

    def discard(self, user_id: str) -> None:
        """
        Drop any buffered upload state for a user.

        Args:
            user_id: Unique ID of the user whose pending upload should be
                removed.
        """
        if not user_id:
            return

        with self._lock:
            self._uploads.pop(user_id, None)

    @staticmethod
    def _validate_existing_upload_state(
        *,
        state: UploadState,
        file_name: str,
        total_packets: int,
    ) -> None:
        """
        Validate that a new chunk belongs to the existing upload state.

        Args:
            state: Existing upload state for the user.
            file_name: Sanitized file name from the new packet.
            total_packets: Total packet count from the new packet.

        Raises:
            UploadStateError: If packet metadata does not match the buffered
                upload state.
        """
        if state.total_packets != total_packets:
            raise UploadStateError("Inconsistent total_packets for upload")

        if state.file_name != file_name:
            raise UploadStateError("Inconsistent file_name for upload")

    @staticmethod
    def _validate_all_packets_received(state: UploadState) -> None:
        """
        Validate that all expected packet numbers exist in the upload state.

        Args:
            state: Completed upload state to validate.

        Raises:
            UploadStateError: If one or more packet numbers are missing.
        """
        missing_packets = [
            packet_number
            for packet_number in range(1, state.total_packets + 1)
            if packet_number not in state.chunks
        ]

        if missing_packets:
            raise UploadStateError(
                f"Upload incomplete; missing packets: {missing_packets}"
            )

    @staticmethod
    def _assemble_chunks_in_order(state: UploadState) -> bytes:
        """
        Assemble encrypted chunks in packet-number order.

        Args:
            state: Upload state containing all expected chunks.

        Returns:
            Full encrypted file bytes.
        """
        return b"".join(
            state.chunks[packet_number]
            for packet_number in range(1, state.total_packets + 1)
        )


#: Shared upload assembler used by request handlers.
upload_assembler = UploadAssembler()


def _sanitize_file_name(file_name: str) -> str:
    """
    Normalize a client-provided file name to a safe basename.

    Args:
        file_name: File name received from the client.

    Returns:
        File name without any parent directory components.

    Raises:
        ValueError: If the file name is empty after sanitization.
    """
    sanitized_name = Path(file_name).name

    if not sanitized_name:
        raise ValueError("file_name must not be empty")

    return sanitized_name


def _get_user_aes_key_bytes(user_id: str) -> bytes:
    """
    Load and decode a user's stored AES key from the database.

    Args:
        user_id: Unique ID of the user.

    Returns:
        Raw AES key bytes decoded from base64.

    Raises:
        ValueError: If ``user_id`` is empty.
        binascii.Error: If the stored key is not valid base64.
    """
    if not user_id:
        raise ValueError("user_id must not be empty")

    aes_key_b64 = get_aes_key(user_id)
    return base64.b64decode(aes_key_b64)


def _build_versioned_file_path(user_id: str, file_name: str) -> tuple[Path, int]:
    """
    Build the destination path for a user's uploaded file.

    The file is stored inside a user-specific directory and receives a versioned
    suffix based on the latest version recorded in the database.

    Args:
        user_id: Unique ID of the user.
        file_name: Sanitized original file name.

    Returns:
        A tuple containing the versioned file path and assigned version number.

    Raises:
        ValueError: If ``user_id`` or ``file_name`` is empty.
    """
    if not user_id:
        raise ValueError("user_id must not be empty")

    sanitized_name = _sanitize_file_name(file_name)

    user_dir = Path(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)

    base_path = user_dir / sanitized_name
    version_number = get_next_version_number(user_id, sanitized_name)

    versioned_path = base_path.with_name(
        f"{base_path.stem}_v{version_number}{base_path.suffix}"
    )
    return versioned_path, version_number


def persist_completed_upload(
    *,
    user_id: str,
    original_file_name: str,
    encrypted_chunk_size: int,
    encrypted_file_data: bytes,
) -> SavedUpload:
    """
    Decrypt, store, and register a completed upload.

    This function:
        1. Loads the user's AES key.
        2. Decrypts the assembled encrypted file.
        3. Saves the decrypted file under the user's directory.
        4. Inserts unverified file metadata into the database.
        5. Updates the user's ``last_seen`` timestamp.
        6. Returns upload metadata needed by the response handler.

    Args:
        user_id: Unique ID of the uploading user.
        original_file_name: Original file name sent by the client.
        encrypted_chunk_size: Size of the encrypted chunk reported by the
            client.
        encrypted_file_data: Fully assembled encrypted file bytes.

    Returns:
        Metadata describing the saved upload.

    Raises:
        ValueError: If required arguments are empty or invalid.
        OSError: If the decrypted file cannot be written to disk.
    """
    if not user_id:
        raise ValueError("user_id must not be empty")

    if encrypted_file_data is None:
        raise ValueError("encrypted_file_data must not be None")

    sanitized_name = _sanitize_file_name(original_file_name)
    aes_key = _get_user_aes_key_bytes(user_id)

    decrypted_data = aes_cbc_decrypt(encrypted_file_data, aes_key)
    file_path, version_number = _build_versioned_file_path(user_id, sanitized_name)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)

    checksum = calculate_crc32(decrypted_data)
    last_modified = datetime.now(timezone.utc).strftime(DATE_FORMAT)

    add_file(
        user_id=user_id,
        file_name=sanitized_name,
        path_name=str(file_path),
        version=version_number,
        last_modified=last_modified,
        verified=False,
    )
    update_last_seen(user_id)

    return SavedUpload(
        user_id=user_id,
        original_file_name=sanitized_name,
        stored_path=str(file_path),
        version=version_number,
        encrypted_chunk_size=encrypted_chunk_size,
        checksum=checksum,
    )


def mark_upload_verified(*, user_id: str, file_name: str) -> str:
    """
    Mark the latest stored version of a file as verified.

    Args:
        user_id: Unique ID of the uploading user.
        file_name: Original file name sent by the client.

    Returns:
        Resolved stored file path.

    Raises:
        ValueError: If required arguments are empty.
        UploadNotFoundError: If the stored file does not exist on disk.
    """
    if not user_id:
        raise ValueError("user_id must not be empty")

    sanitized_name = _sanitize_file_name(file_name)
    stored_path = get_file_path(user_id, sanitized_name)
    path = Path(stored_path)

    if not path.exists():
        raise UploadNotFoundError(f"File '{path}' not found")

    update_file_verified_status(user_id, stored_path, True)
    update_last_seen(user_id)

    return stored_path


def delete_failed_upload(
    *,
    user_id: str,
    file_name: str,
    update_last_seen_flag: bool = False,
) -> str:
    """
    Delete the latest stored file version after CRC failure or upload error.

    The database record is marked as unverified after the file is removed.

    Args:
        user_id: Unique ID of the uploading user.
        file_name: Original file name sent by the client.
        update_last_seen_flag: Whether to update the user's ``last_seen``
            timestamp after deletion.

    Returns:
        Deleted stored file path.

    Raises:
        ValueError: If required arguments are empty.
        UploadNotFoundError: If the stored file does not exist on disk.
    """
    if not user_id:
        raise ValueError("user_id must not be empty")

    sanitized_name = _sanitize_file_name(file_name)
    stored_path = get_file_path(user_id, sanitized_name)
    path = Path(stored_path)

    if not path.exists():
        raise UploadNotFoundError(f"File '{path}' not found")

    path.unlink()
    update_file_verified_status(user_id, stored_path, False)

    if update_last_seen_flag:
        update_last_seen(user_id)

    return stored_path
