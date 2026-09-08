"""
Tests for cryptographic utilities and checksum functions.
"""

import base64
import pytest
from Crypto.Cipher import PKCS1_OAEP

from services.crypto import (
    CHUNK_SIZE,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    calculate_crc32,
    generate_aes_key,
    generate_uuid,
    rsa_encrypt,
)


def test_generate_uuid():
    """
    Test generate_uuid produces 32-character lowercase hex strings.
    """
    uid1 = generate_uuid()
    uid2 = generate_uuid()

    assert len(uid1) == 32
    assert len(uid2) == 32
    assert uid1 != uid2
    # Ensure it's valid hex
    int(uid1, 16)
    int(uid2, 16)


@pytest.mark.parametrize("key_len", [16, 24, 32])
def test_generate_aes_key_valid_lengths(key_len):
    """
    Test generate_aes_key with supported key lengths.
    """
    key = generate_aes_key(key_len)
    assert isinstance(key, bytes)
    assert len(key) == key_len


@pytest.mark.parametrize("invalid_len", [0, 8, 15, 30, 64])
def test_generate_aes_key_invalid_lengths(invalid_len):
    """
    Test generate_aes_key raises ValueError for unsupported lengths.
    """
    with pytest.raises(ValueError, match="Invalid AES key length"):
        generate_aes_key(invalid_len)


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"short",
        b"exact_16_bytes!!",
        b"exact_32_bytes_long_block_text!!",
        b"A" * 1024,
    ],
)
def test_aes_cbc_encrypt_decrypt_round_trip(key_len, plaintext):
    """
    Test AES-CBC encryption and decryption round trip across various key lengths and plaintext sizes.
    """
    key = generate_aes_key(key_len)
    encrypted = aes_cbc_encrypt(plaintext, key)

    # Must contain 16-byte IV + at least 1 block of padded ciphertext
    assert len(encrypted) >= 32
    assert len(encrypted) % 16 == 0

    decrypted = aes_cbc_decrypt(encrypted, key)
    assert decrypted == plaintext


def test_aes_cbc_type_and_length_validation():
    """
    Test input type and key length validations in AES functions.
    """
    valid_key = generate_aes_key(32)
    valid_text = b"hello world"

    with pytest.raises(TypeError, match="plaintext must be bytes"):
        aes_cbc_encrypt("not bytes", valid_key)

    with pytest.raises(TypeError, match="aes_key must be bytes"):
        aes_cbc_encrypt(valid_text, "not bytes")

    with pytest.raises(ValueError, match="Invalid AES key length"):
        aes_cbc_encrypt(valid_text, b"short_key")

    with pytest.raises(TypeError, match="data must be bytes"):
        aes_cbc_decrypt("not bytes", valid_key)

    with pytest.raises(TypeError, match="aes_key must be bytes"):
        aes_cbc_decrypt(b"data", "not bytes")

    with pytest.raises(ValueError, match="Invalid AES key length"):
        aes_cbc_decrypt(b"data", b"short_key")


def test_aes_cbc_decrypt_invalid_ciphertext():
    """
    Test AES-CBC decryption failure on malformed or corrupted ciphertext.
    """
    key = generate_aes_key(32)

    # Ciphertext <= 16 bytes (missing ciphertext)
    with pytest.raises(ValueError, match="Encrypted data must contain an IV and ciphertext"):
        aes_cbc_decrypt(b"1234567890123456", key)

    # Ciphertext not multiple of 16
    with pytest.raises(ValueError, match="Ciphertext length must be a multiple of AES block size"):
        aes_cbc_decrypt(b"1234567890123456789", key)

    # Corrupted padding / wrong key
    wrong_key = generate_aes_key(32)
    encrypted = aes_cbc_encrypt(b"secret message", key)
    with pytest.raises(ValueError, match=r"(?i)padding is incorrect"):
        aes_cbc_decrypt(encrypted, wrong_key)


def test_calculate_crc32_known_values():
    """
    Test CRC32 checksum against known standard values and large buffers.
    """
    assert calculate_crc32(b"") == 0
    # "123456789" CRC32 standard test vector = 0xCBF43926 = 3421780262
    assert calculate_crc32(b"123456789") == 3421780262

    # Buffer larger than CHUNK_SIZE (65536 bytes)
    large_buffer = b"X" * (CHUNK_SIZE + 1000)
    crc = calculate_crc32(large_buffer)
    assert isinstance(crc, int)
    assert 0 <= crc <= 0xFFFFFFFF


def test_calculate_crc32_invalid_type():
    """
    Test calculate_crc32 raises TypeError for non-bytes input.
    """
    with pytest.raises(TypeError, match="file must be bytes"):
        calculate_crc32("string")


def test_rsa_encrypt(test_rsa_key):
    """
    Test RSA encryption with OAEP padding using an isolated test key.
    """
    rsa_private_key, rsa_public_pem = test_rsa_key
    plaintext = b"symmetric-aes-key-bytes-32-chars"

    encrypted_b64 = rsa_encrypt(rsa_public_pem, plaintext)
    assert isinstance(encrypted_b64, bytes)

    # Decrypt and verify
    raw_ciphertext = base64.b64decode(encrypted_b64)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted = cipher.decrypt(raw_ciphertext)

    assert decrypted == plaintext


def test_rsa_encrypt_validation():
    """
    Test type and format validation for RSA encryption.
    """
    with pytest.raises(TypeError, match="public_key must be bytes"):
        rsa_encrypt("not bytes", b"plaintext")

    with pytest.raises(TypeError, match="plaintext must be bytes"):
        rsa_encrypt(b"key", "not bytes")

    with pytest.raises(ValueError):
        rsa_encrypt(b"invalid_public_key_bytes", b"plaintext")
