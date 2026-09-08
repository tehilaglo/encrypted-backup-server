"""
Shared pytest fixtures and test helpers for the encrypted backup server test suite.
"""

import socket
import pytest
from Crypto.PublicKey import RSA

import storage.database
from storage.database import setup_database
from services.backup_service import upload_assembler


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """
    Configure an isolated temporary SQLite database for test execution.
    """
    db_path = tmp_path / "test_clients.db"
    monkeypatch.setattr(storage.database, "DB_FILE", str(db_path))
    setup_database()
    return db_path


@pytest.fixture
def temp_workdir(tmp_path, monkeypatch):
    """
    Change current working directory to a temporary folder to avoid creating
    user directories in the project root.
    """
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def clean_upload_assembler():
    """
    Ensure the singleton upload assembler state is clean before and after each test.
    """
    with upload_assembler._lock:
        upload_assembler._uploads.clear()
    yield
    with upload_assembler._lock:
        upload_assembler._uploads.clear()


@pytest.fixture(scope="session")
def test_rsa_key():
    """
    Generate an isolated 1024-bit RSA key for session testing.
    """
    key = RSA.generate(1024)
    public_key_pem = key.publickey().export_key(format="PEM")
    return key, public_key_pem


@pytest.fixture
def socket_pair():
    """
    Provide a connected pair of local sockets for deterministic socket I/O testing.
    """
    client_sock, server_sock = socket.socketpair()
    yield client_sock, server_sock
    client_sock.close()
    server_sock.close()
