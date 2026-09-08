"""
Tests for protocol constants and enumerations.
"""

from protocol.constants import (
    FORMAT,
    DATE_FORMAT,
    MIN_USERNAME_LEN,
    USERNAME_LEN,
    FILE_NAME_LEN,
    RSA_KEY_LEN,
    SYMMETRIC_KEY_LEN,
    UNIQUE_ID_LEN,
    ENC_CHUNK_SIZE_LEN,
    CHECKSUM_LEN,
    SERVER_VERSION,
    MAX_FILE_SIZE,
    ClientCode,
    ServerCode,
)


def test_field_size_constants():
    """
    Verify exact protocol field size constants.
    """
    assert FORMAT == "utf-8"
    assert DATE_FORMAT == "%Y-%m-%d %H:%M:%S %z"
    assert MIN_USERNAME_LEN == 5
    assert USERNAME_LEN == 64
    assert FILE_NAME_LEN == 255
    assert RSA_KEY_LEN == 160
    assert SYMMETRIC_KEY_LEN == 32
    assert UNIQUE_ID_LEN == 16
    assert ENC_CHUNK_SIZE_LEN == 4
    assert CHECKSUM_LEN == 4
    assert SERVER_VERSION == 3
    assert MAX_FILE_SIZE == 20 * 1024 * 1024


def test_client_codes():
    """
    Verify all expected ClientCode enumeration values.
    """
    assert ClientCode.REGISTRATION == 100
    assert ClientCode.PUBLIC_KEY_SEND == 101
    assert ClientCode.RE_REGISTRATION == 102
    assert ClientCode.CREATE_BACKUP == 103
    assert ClientCode.CRC_SUCCESS == 120
    assert ClientCode.CRC_ERROR == 121
    assert ClientCode.CRC_FAILURE == 122
    assert ClientCode.DISCONNECT == 130


def test_server_codes():
    """
    Verify all expected ServerCode enumeration values.
    """
    assert ServerCode.DEFAULT == 0
    assert ServerCode.REGISTRATION_SUCCESS == 200
    assert ServerCode.REGISTRATION_FAILED == 201
    assert ServerCode.USERNAME_TAKEN == 202
    assert ServerCode.RE_REGISTRATION_SUCCESS == 205
    assert ServerCode.RE_REGISTRATION_FAILED == 206
    assert ServerCode.KEY_SEND_SUCCESS == 210
    assert ServerCode.UPLOAD_RECEIVED == 220
    assert ServerCode.UPLOAD_REJECTED_TOO_LARGE == 221
    assert ServerCode.ACK == 230
    assert ServerCode.FAILED == 231
