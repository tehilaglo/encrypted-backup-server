"""
Protocol and application-wide constants for the encrypted backup server.

This module defines shared values used across serialization, validation,
network protocol handling, cryptographic utilities, and server responses.

@author Tehila Cahnaman
"""

from enum import IntEnum


#: Default text encoding used for protocol strings.
FORMAT: str = "utf-8"

#: Timestamp format used when storing dates in the database.
DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S %z"

#: Minimum allowed username length.
MIN_USERNAME_LEN: int = 5

#: Fixed protocol field size for usernames, in bytes.
USERNAME_LEN: int = 64

#: Fixed protocol field size for file names, in bytes.
FILE_NAME_LEN: int = 255

#: Fixed protocol field size for RSA public keys, in bytes.
RSA_KEY_LEN: int = 160

#: AES symmetric key length, in bytes.
SYMMETRIC_KEY_LEN: int = 32

#: Fixed protocol field size for unique user identifiers, in bytes.
UNIQUE_ID_LEN: int = 16

#: Fixed protocol field size for encrypted chunk size values, in bytes.
ENC_CHUNK_SIZE_LEN: int = 4

#: Fixed protocol field size for checksum values, in bytes.
CHECKSUM_LEN: int = 4

#: Current server protocol version.
SERVER_VERSION: int = 3

#: Maximum allowed uploaded file size, in bytes.
MAX_FILE_SIZE: int = 20 * 1024 * 1024


class ClientCode(IntEnum):
    """
    Request codes sent by clients to the server.

    These values identify which operation the client wants the server to
    perform. They must match the protocol specification used by the client.
    """

    #: Register a new client username.
    REGISTRATION = 100

    #: Send a public key after successful registration.
    PUBLIC_KEY_SEND = 101

    #: Re-register an existing client.
    RE_REGISTRATION = 102

    #: Upload an encrypted backup file chunk.
    CREATE_BACKUP = 103

    #: Confirm that the uploaded file passed CRC validation.
    CRC_SUCCESS = 120

    #: Notify the server that CRC validation failed but retry may continue.
    CRC_ERROR = 121

    #: Notify the server that CRC validation failed permanently.
    CRC_FAILURE = 122

    #: Disconnect from the server.
    DISCONNECT = 130


class ServerCode(IntEnum):
    """
    Response codes sent by the server to clients.

    These values describe the result of a server operation and must remain
    synchronized with the client-side protocol decoder.
    """

    #: Default placeholder response code before a real result is assigned.
    DEFAULT = 0

    #: Client registration completed successfully.
    REGISTRATION_SUCCESS = 200

    #: Client registration failed.
    REGISTRATION_FAILED = 201

    #: Requested username already exists.
    USERNAME_TAKEN = 202

    #: Client re-registration completed successfully.
    RE_REGISTRATION_SUCCESS = 205

    #: Client re-registration failed.
    RE_REGISTRATION_FAILED = 206

    #: Encrypted session key was generated and sent successfully.
    KEY_SEND_SUCCESS = 210

    #: Uploaded backup was received and processed.
    UPLOAD_RECEIVED = 220

    #: Uploaded file was rejected because it exceeded the maximum size.
    UPLOAD_REJECTED_TOO_LARGE = 221

    #: Generic acknowledgement response.
    ACK = 230

    #: Generic server failure response.
    FAILED = 231
