"""
Tests for socket I/O utilities.
"""

import pytest
from utils.socket_io import recv_exact


def test_recv_exact_single_recv(socket_pair):
    """
    Test recv_exact receives full payload in a single recv call.
    """
    client_sock, server_sock = socket_pair
    payload = b"Hello, World!"
    client_sock.sendall(payload)

    received = recv_exact(server_sock, len(payload))
    assert received == payload


def test_recv_exact_partial_recvs(socket_pair):
    """
    Test recv_exact properly accumulates chunks when sent in fragments.
    """
    client_sock, server_sock = socket_pair
    payload = b"A" * 50 + b"B" * 50

    client_sock.sendall(b"A" * 50)
    client_sock.sendall(b"B" * 50)

    received = recv_exact(server_sock, 100)
    assert received == payload


def test_recv_exact_premature_close(socket_pair):
    """
    Test recv_exact raises ConnectionError when connection closes prematurely.
    """
    client_sock, server_sock = socket_pair
    client_sock.sendall(b"short")
    client_sock.close()

    with pytest.raises(ConnectionError, match="Connection closed while receiving data"):
        recv_exact(server_sock, 10)


def test_recv_exact_zero_size(socket_pair):
    """
    Test recv_exact with size 0 returns empty bytes immediately.
    """
    _, server_sock = socket_pair
    received = recv_exact(server_sock, 0)
    assert received == b""


def test_recv_exact_negative_size(socket_pair):
    """
    Test recv_exact raises ValueError for negative sizes.
    """
    _, server_sock = socket_pair
    with pytest.raises(ValueError, match="Size must be non-negative"):
        recv_exact(server_sock, -1)
