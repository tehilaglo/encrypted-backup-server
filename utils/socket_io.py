"""
Socket input utilities for the encrypted backup server.

This module provides helpers for safely reading fixed-size binary protocol
messages from a TCP socket. Since ``socket.recv`` may return fewer bytes than
requested, callers should use ``recv_exact`` whenever a protocol field has a
known byte length.

@author Tehila Cahnaman
"""

from socket import socket


def recv_exact(sock: socket, size: int) -> bytes:
    """
    Read exactly ``size`` bytes from a socket.

    TCP is stream-based, so a single ``recv`` call is not guaranteed to return
    the full number of requested bytes. This function repeatedly reads from the
    socket until the requested byte count is received or the connection closes.

    Args:
        sock: Connected socket to read from.
        size: Number of bytes to receive.

    Returns:
        The exact number of bytes requested.

    Raises:
        ValueError: If ``size`` is negative.
        ConnectionError: If the peer closes the connection before all bytes are
            received.
    """
    if size < 0:
        raise ValueError("Size must be non-negative")

    data = bytearray()

    while len(data) < size:
        bytes_remaining = size - len(data)
        chunk = sock.recv(bytes_remaining)

        if not chunk:
            raise ConnectionError("Connection closed while receiving data")

        data.extend(chunk)

    return bytes(data)
