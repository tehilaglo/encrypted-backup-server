"""
Tests for backup service, upload assembler, persistence, and verification.
"""

import base64
from pathlib import Path
import pytest

from services.backup_service import (
    UploadAssembler,
    UploadNotFoundError,
    UploadStateError,
    _build_versioned_file_path,
    _get_user_aes_key_bytes,
    _sanitize_file_name,
    delete_failed_upload,
    mark_upload_verified,
    persist_completed_upload,
)
from services.crypto import aes_cbc_encrypt, calculate_crc32, generate_aes_key
from storage.database import (
    add_client,
    get_file_path,
    get_last_seen,
    setup_database,
    update_aes_key,
    update_last_seen,
    _connect,
)


def test_sanitize_file_name():
    """
    Test _sanitize_file_name removes directory traversal and path prefixes.
    """
    assert _sanitize_file_name("file.txt") == "file.txt"
    assert _sanitize_file_name("/etc/passwd") == "passwd"
    assert _sanitize_file_name("../../secret.docx") == "secret.docx"
    assert _sanitize_file_name("deep/nested/dir/image.png") == "image.png"

    with pytest.raises(ValueError, match="file_name must not be empty"):
        _sanitize_file_name("")


def test_upload_assembler_single_packet():
    """
    Test upload assembler with a single-packet upload.
    """
    assembler = UploadAssembler()
    chunk = b"single-chunk-data"

    result = assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=1,
        total_packets=1,
        chunk=chunk,
    )

    assert result == chunk
    # State should be cleared after completion
    assert "user1" not in assembler._uploads


def test_upload_assembler_multi_packet_ordered():
    """
    Test upload assembler with multiple ordered packets.
    """
    assembler = UploadAssembler()
    chunk1 = b"chunk-1-"
    chunk2 = b"chunk-2-"
    chunk3 = b"chunk-3"

    res1 = assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=1,
        total_packets=3,
        chunk=chunk1,
    )
    assert res1 is None

    res2 = assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=2,
        total_packets=3,
        chunk=chunk2,
    )
    assert res2 is None

    res3 = assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=3,
        total_packets=3,
        chunk=chunk3,
    )
    assert res3 == chunk1 + chunk2 + chunk3
    assert "user1" not in assembler._uploads


def test_upload_assembler_out_of_order_packets():
    """
    Test upload assembler reassembles chunks in correct order when received out of order.
    """
    assembler = UploadAssembler()
    chunk1 = b"AAA"
    chunk2 = b"BBB"
    chunk3 = b"CCC"

    # Packet 3 arrives first
    assert (
        assembler.add_chunk(
            user_id="user1",
            file_name="doc.txt",
            packet_number=3,
            total_packets=3,
            chunk=chunk3,
        )
        is None
    )

    # Packet 1 arrives second
    assert (
        assembler.add_chunk(
            user_id="user1",
            file_name="doc.txt",
            packet_number=1,
            total_packets=3,
            chunk=chunk1,
        )
        is None
    )

    # Packet 2 arrives last -> returns 1 + 2 + 3
    result = assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=2,
        total_packets=3,
        chunk=chunk2,
    )
    assert result == b"AAABBBCCC"


def test_upload_assembler_duplicate_packet_overwrite():
    """
    Test duplicate packet replaces previous chunk and completes upload.
    """
    assembler = UploadAssembler()
    chunk1_old = b"OLD"
    chunk1_new = b"NEW"
    chunk2 = b"END"

    assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=1,
        total_packets=2,
        chunk=chunk1_old,
    )

    # Re-send packet 1
    assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=1,
        total_packets=2,
        chunk=chunk1_new,
    )

    result = assembler.add_chunk(
        user_id="user1",
        file_name="doc.txt",
        packet_number=2,
        total_packets=2,
        chunk=chunk2,
    )
    assert result == b"NEWEND"


def test_upload_assembler_invalid_packet_numbers():
    """
    Test invalid packet number validations.
    """
    assembler = UploadAssembler()

    with pytest.raises(UploadStateError, match="Packet numbers must start at 1"):
        assembler.add_chunk(
            user_id="u1",
            file_name="f",
            packet_number=0,
            total_packets=2,
            chunk=b"x",
        )

    with pytest.raises(UploadStateError, match="Packet numbers must start at 1"):
        assembler.add_chunk(
            user_id="u1",
            file_name="f",
            packet_number=1,
            total_packets=0,
            chunk=b"x",
        )

    with pytest.raises(UploadStateError, match="Packet number cannot exceed total packets"):
        assembler.add_chunk(
            user_id="u1",
            file_name="f",
            packet_number=3,
            total_packets=2,
            chunk=b"x",
        )


def test_upload_assembler_inconsistent_metadata():
    """
    Test inconsistent filename or total_packets raises UploadStateError.
    """
    assembler = UploadAssembler()
    assembler.add_chunk(
        user_id="u1",
        file_name="first.txt",
        packet_number=1,
        total_packets=2,
        chunk=b"1",
    )

    with pytest.raises(UploadStateError, match="Inconsistent total_packets for upload"):
        assembler.add_chunk(
            user_id="u1",
            file_name="first.txt",
            packet_number=2,
            total_packets=3,
            chunk=b"2",
        )

    with pytest.raises(UploadStateError, match="Inconsistent file_name for upload"):
        assembler.add_chunk(
            user_id="u1",
            file_name="second.txt",
            packet_number=2,
            total_packets=2,
            chunk=b"2",
        )


def test_upload_assembler_discard():
    """
    Test discarding upload state.
    """
    assembler = UploadAssembler()
    assembler.add_chunk(
        user_id="u1",
        file_name="test.txt",
        packet_number=1,
        total_packets=2,
        chunk=b"part",
    )
    assert "u1" in assembler._uploads

    assembler.discard("u1")
    assert "u1" not in assembler._uploads

    # Discarding empty user_id does nothing
    assembler.discard("")


def test_upload_assembler_argument_validation():
    """
    Test argument validation in add_chunk.
    """
    assembler = UploadAssembler()

    with pytest.raises(ValueError, match="user_id must not be empty"):
        assembler.add_chunk(user_id="", file_name="f", packet_number=1, total_packets=1, chunk=b"x")

    with pytest.raises(ValueError, match="file_name must not be empty"):
        assembler.add_chunk(user_id="u", file_name="", packet_number=1, total_packets=1, chunk=b"x")

    with pytest.raises(ValueError, match="chunk must not be None"):
        assembler.add_chunk(user_id="u", file_name="f", packet_number=1, total_packets=1, chunk=None)


def test_get_user_aes_key_bytes(temp_db):
    """
    Test loading and decoding user AES key bytes.
    """
    user_id = "uid_aes"
    raw_key = generate_aes_key(32)
    b64_key = base64.b64encode(raw_key).decode("utf-8")

    add_client(user_id, "user_aes")
    update_aes_key(user_id, "user_aes", b64_key)

    loaded_key = _get_user_aes_key_bytes(user_id)
    assert loaded_key == raw_key

    with pytest.raises(ValueError, match="user_id must not be empty"):
        _get_user_aes_key_bytes("")


def test_build_versioned_file_path(temp_db, temp_workdir):
    """
    Test versioned file path calculation and directory creation.
    """
    user_id = "uid_ver"
    add_client(user_id, "user_ver")

    path1, v1 = _build_versioned_file_path(user_id, "data.tar.gz")
    assert v1 == 1
    assert path1.name == "data.tar_v1.gz"
    assert Path(user_id).is_dir()

    with pytest.raises(ValueError, match="user_id must not be empty"):
        _build_versioned_file_path("", "data.txt")


def test_persist_completed_upload(temp_db, temp_workdir):
    """
    Test decrypting, persisting file to disk, computing CRC, and recording in DB.
    """
    user_id = "uid_persist"
    username = "user_persist"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    original_content = b"This is confidential plaintext file content."
    encrypted_data = aes_cbc_encrypt(original_content, aes_key)

    saved_upload = persist_completed_upload(
        user_id=user_id,
        original_file_name="secret.txt",
        encrypted_chunk_size=len(encrypted_data),
        encrypted_file_data=encrypted_data,
    )

    assert saved_upload.user_id == user_id
    assert saved_upload.original_file_name == "secret.txt"
    assert saved_upload.version == 1
    assert saved_upload.encrypted_chunk_size == len(encrypted_data)
    assert saved_upload.checksum == calculate_crc32(original_content)

    # Verify file written to disk
    stored_path = Path(saved_upload.stored_path)
    assert stored_path.exists()
    assert stored_path.read_bytes() == original_content

    # Verify recorded in DB as unverified (verified=False)
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT verified FROM files WHERE user_id=? AND version=1", (user_id,))
        assert cursor.fetchone()[0] == 0

    # Verify last seen updated
    assert get_last_seen(user_id) is not None


def test_persist_completed_upload_validation(temp_db, temp_workdir):
    """
    Test argument validation for persist_completed_upload.
    """
    with pytest.raises(ValueError, match="user_id must not be empty"):
        persist_completed_upload(
            user_id="",
            original_file_name="f.txt",
            encrypted_chunk_size=10,
            encrypted_file_data=b"data",
        )

    with pytest.raises(ValueError, match="encrypted_file_data must not be None"):
        persist_completed_upload(
            user_id="u",
            original_file_name="f.txt",
            encrypted_chunk_size=10,
            encrypted_file_data=None,
        )


def test_mark_upload_verified(temp_db, temp_workdir):
    """
    Test mark_upload_verified updates verified status in DB.
    """
    user_id = "uid_mark"
    username = "user_mark"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    content = b"Content to verify"
    encrypted = aes_cbc_encrypt(content, aes_key)
    saved = persist_completed_upload(
        user_id=user_id,
        original_file_name="test.txt",
        encrypted_chunk_size=len(encrypted),
        encrypted_file_data=encrypted,
    )

    resolved_path = mark_upload_verified(user_id=user_id, file_name="test.txt")
    assert resolved_path == saved.stored_path

    # Check verified status in DB is True
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT verified FROM files WHERE user_id=? AND version=1", (user_id,))
        assert cursor.fetchone()[0] == 1


def test_mark_upload_verified_missing_file_on_disk(temp_db, temp_workdir):
    """
    Test mark_upload_verified raises UploadNotFoundError if file is missing on disk.
    """
    user_id = "uid_missing_disk"
    username = "user_missing_disk"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    encrypted = aes_cbc_encrypt(b"abc", aes_key)
    saved = persist_completed_upload(
        user_id=user_id,
        original_file_name="gone.txt",
        encrypted_chunk_size=len(encrypted),
        encrypted_file_data=encrypted,
    )

    # Remove file on disk
    Path(saved.stored_path).unlink()

    with pytest.raises(UploadNotFoundError, match="File '.*' not found"):
        mark_upload_verified(user_id=user_id, file_name="gone.txt")


def test_delete_failed_upload(temp_db, temp_workdir):
    """
    Test delete_failed_upload removes file from disk and marks unverified in DB.
    """
    user_id = "uid_del"
    username = "user_del"
    add_client(user_id, username)
    aes_key = generate_aes_key(32)
    update_aes_key(user_id, username, base64.b64encode(aes_key).decode("utf-8"))

    encrypted = aes_cbc_encrypt(b"corrupted", aes_key)
    saved = persist_completed_upload(
        user_id=user_id,
        original_file_name="corrupt.txt",
        encrypted_chunk_size=len(encrypted),
        encrypted_file_data=encrypted,
    )

    stored_file = Path(saved.stored_path)
    assert stored_file.exists()

    deleted_path = delete_failed_upload(
        user_id=user_id,
        file_name="corrupt.txt",
        update_last_seen_flag=True,
    )
    assert deleted_path == saved.stored_path
    assert not stored_file.exists()

    # Deleting again raises UploadNotFoundError
    with pytest.raises(UploadNotFoundError, match="File '.*' not found"):
        delete_failed_upload(user_id=user_id, file_name="corrupt.txt")
