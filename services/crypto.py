"""
Cryptographic utility functions for the encrypted backup server.

This module provides helpers for:
- generating user UUIDs,
- generating AES session keys,
- encrypting/decrypting file data with AES-CBC,
- encrypting AES keys with RSA-OAEP,
- calculating CRC32 checksums for file integrity validation.

@author Tehila Cahnaman
"""

import base64
import secrets
import uuid
import zlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from protocol.constants import SYMMETRIC_KEY_LEN


# Number of bytes processed per CRC32 iteration.
CHUNK_SIZE = 65_536

# AES supports 128-bit, 192-bit, and 256-bit keys.
_VALID_AES_KEY_LENGTHS = {16, 24, 32}


def generate_uuid() -> str:
    """
    Generate a unique 32-character hexadecimal UUID string.

    Returns:
        str: A UUID4 value represented as a 32-character lowercase hex string.
    """
    return uuid.uuid4().hex


def generate_aes_key(key_len: int = SYMMETRIC_KEY_LEN) -> bytes:
    """
    Generate a cryptographically secure random AES key.

    Args:
        key_len: Length of the AES key in bytes. Valid AES key lengths are
            16, 24, and 32 bytes. Defaults to `SYMMETRIC_KEY_LEN`.

    Returns:
        bytes: Random AES key bytes.

    Raises:
        ValueError: If `key_len` is not a valid AES key length.
    """
    if key_len not in _VALID_AES_KEY_LENGTHS:
        raise ValueError(
            f"Invalid AES key length: {key_len}. "
            f"Expected one of: {sorted(_VALID_AES_KEY_LENGTHS)}."
        )

    return secrets.token_bytes(key_len)


def aes_cbc_encrypt(plaintext: bytes, aes_key: bytes) -> bytes:
    """
    Encrypt plaintext using AES in CBC mode with PKCS#7 padding.

    The returned byte sequence contains the random IV followed by the encrypted
    ciphertext. The decrypting side must read the first AES block as the IV.

    Args:
        plaintext: Raw bytes to encrypt.
        aes_key: AES key bytes. Must be 16, 24, or 32 bytes long.

    Returns:
        bytes: IV-prepended ciphertext.

    Raises:
        TypeError: If `plaintext` or `aes_key` are not bytes-like values.
        ValueError: If `aes_key` has an invalid AES length.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    if not isinstance(aes_key, bytes):
        raise TypeError("aes_key must be bytes")

    if len(aes_key) not in _VALID_AES_KEY_LENGTHS:
        raise ValueError(
            f"Invalid AES key length: {len(aes_key)}. "
            f"Expected one of: {sorted(_VALID_AES_KEY_LENGTHS)}."
        )

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return iv + ciphertext


def aes_cbc_decrypt(data: bytes, aes_key: bytes) -> bytes:
    """
    Decrypt AES-CBC encrypted data produced by `aes_cbc_encrypt`.

    The input must contain the IV as the first AES block, followed by the
    ciphertext. The decrypted plaintext is unpadded before being returned.

    Args:
        data: IV-prepended ciphertext.
        aes_key: AES key bytes. Must be 16, 24, or 32 bytes long.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        TypeError: If `data` or `aes_key` are not bytes-like values.
        ValueError: If the encrypted data or AES key is invalid.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if not isinstance(aes_key, bytes):
        raise TypeError("aes_key must be bytes")

    if len(aes_key) not in _VALID_AES_KEY_LENGTHS:
        raise ValueError(
            f"Invalid AES key length: {len(aes_key)}. "
            f"Expected one of: {sorted(_VALID_AES_KEY_LENGTHS)}."
        )

    if len(data) <= AES.block_size:
        raise ValueError("Encrypted data must contain an IV and ciphertext")

    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]

    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Ciphertext length must be a multiple of AES block size")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)

    return unpad(decrypted_data, AES.block_size)


def rsa_encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using an RSA public key with OAEP padding.

    The encrypted result is base64-encoded before being returned because the
    protocol stores/sends this value as encoded binary data.

    Args:
        public_key: RSA public key in PEM/DER format.
        plaintext: Raw bytes to encrypt.

    Returns:
        bytes: Base64-encoded RSA ciphertext.

    Raises:
        TypeError: If `public_key` or `plaintext` are not bytes-like values.
        ValueError: If the public key cannot be imported by PyCryptodome.
    """
    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be bytes")

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    imported_public_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(imported_public_key)
    ciphertext = rsa_cipher.encrypt(plaintext)

    return base64.b64encode(ciphertext)


def calculate_crc32(file: bytes) -> int:
    """
    Calculate the CRC32 checksum for file content.

    The calculation is performed in fixed-size chunks so the logic remains
    suitable for large byte buffers.

    Args:
        file: File content as bytes.

    Returns:
        int: Unsigned 32-bit CRC32 checksum.

    Raises:
        TypeError: If `file` is not bytes.
    """
    if not isinstance(file, bytes):
        raise TypeError("file must be bytes")

    crc_value = 0

    for offset in range(0, len(file), CHUNK_SIZE):
        chunk = file[offset:offset + CHUNK_SIZE]
        crc_value = zlib.crc32(chunk, crc_value)

    return crc_value & 0xFFFFFFFF
