"""
Response sending utilities for the encrypted backup server.

This module centralizes protocol response construction and transmission for a
single connected client socket. It keeps response-building logic out of the
request handlers so handlers can focus on business flow and error handling.

@author Tehila Cahnaman
"""

from __future__ import annotations

from socket import socket

from services.backup_service import SavedUpload
from protocol.constants import SERVER_VERSION, ServerCode
from protocol.request import Request
from protocol.response import Response, ResponseHeader, ResponsePayload
from protocol.response_encoder import serialize_response


class ResponseSender:
    """
    Sends protocol responses over a connected client socket.

    The sender owns a socket connection and a mutable response object. Each
    helper method updates the response code and payload fields required for a
    specific protocol response, then serializes and sends it to the client.

    Attributes:
        _conn: Connected client socket.
        _response: Response object reused and populated before sending.
    """

    def __init__(self, conn: socket, response: Response) -> None:
        """
        Initialize a response sender for a client connection.

        Args:
            conn: Connected client socket used for sending bytes.
            response: Base response object to populate before transmission.

        Raises:
            ValueError: If conn or response is None.
        """
        if conn is None:
            raise ValueError("conn cannot be None")
        if response is None:
            raise ValueError("response cannot be None")

        self._conn = conn
        self._response = response

    def send(self) -> None:
        """
        Serialize the current response and send it to the client.

        Raises:
            OSError: If sending through the socket fails.
        """
        serialized_response = serialize_response(self._response)
        self._conn.sendall(serialized_response)

    @staticmethod
    def send_failure(conn: socket) -> None:
        """
        Send a generic failure response to the client.

        This method is static because it is often used from exception handlers
        where a prepared response object may not be available.

        Args:
            conn: Connected client socket used for sending the failure response.

        Raises:
            ValueError: If conn is None.
            OSError: If sending through the socket fails.
        """
        if conn is None:
            raise ValueError("conn cannot be None")

        response = Response(
            header=ResponseHeader(
                version=SERVER_VERSION,
                response_code=ServerCode.FAILED,
            ),
            payload=ResponsePayload(),
        )

        sender = ResponseSender(conn, response)
        sender.send()

    def send_username_taken(self) -> None:
        """
        Send a response indicating that the requested username already exists.
        """
        self._response.header.response_code = ServerCode.USERNAME_TAKEN
        self.send()

    def send_session_key(
        self,
        user_id: str,
        response_code: ServerCode,
        encrypted_aes_key: bytes,
    ) -> None:
        """
        Send a response containing an RSA-encrypted AES session key.

        Args:
            user_id: User identifier to include in the response payload.
            response_code: Protocol response code for the session-key flow.
            encrypted_aes_key: RSA-encrypted AES key bytes.

        Raises:
            ValueError: If user_id or encrypted_aes_key is missing.
        """
        if not user_id:
            raise ValueError("user_id cannot be empty")
        if encrypted_aes_key is None:
            raise ValueError("encrypted_aes_key cannot be None")

        self._response.header.response_code = response_code

        # The encrypted session key is variable-length, so it must be added to
        # the base payload size before serialization.
        self._response.header.payload_size += len(encrypted_aes_key)

        self._response.payload.user_id = user_id
        self._response.payload.encrypted_aes_key = encrypted_aes_key

        self.send()

    def send_registration_success(self, user_id: str) -> None:
        """
        Send a successful registration response.

        Args:
            user_id: Newly assigned user identifier.

        Raises:
            ValueError: If user_id is empty.
        """
        if not user_id:
            raise ValueError("user_id cannot be empty")

        self._response.header.response_code = ServerCode.REGISTRATION_SUCCESS
        self._response.payload.user_id = user_id

        self.send()

    def send_registration_failed(self) -> None:
        """
        Send a registration failure response.
        """
        self._response.header.response_code = ServerCode.REGISTRATION_FAILED
        self.send()

    def send_re_registration_failed(self) -> None:
        """
        Send a re-registration failure response.
        """
        self._response.header.response_code = ServerCode.RE_REGISTRATION_FAILED
        self.send()

    def send_upload_too_large(self) -> None:
        """
        Send a response indicating that an upload exceeded the allowed size.
        """
        self._response.header.response_code = ServerCode.UPLOAD_REJECTED_TOO_LARGE
        self.send()

    def send_upload_received(
        self,
        request: Request,
        saved_upload: SavedUpload,
    ) -> None:
        """
        Send a response confirming that an upload was received and processed.

        Args:
            request: Original upload request containing client-provided metadata.
            saved_upload: Persisted upload metadata produced by the backup layer.

        Raises:
            ValueError: If request or saved_upload is None.
        """
        if request is None:
            raise ValueError("request cannot be None")
        if saved_upload is None:
            raise ValueError("saved_upload cannot be None")

        self._response.header.response_code = ServerCode.UPLOAD_RECEIVED
        self._response.payload.user_id = saved_upload.user_id
        self._response.payload.file_name = request.payload.file_name
        self._response.payload.encrypted_chunk_size = saved_upload.encrypted_chunk_size
        self._response.payload.checksum = saved_upload.checksum

        self.send()

    def send_ack(self, user_id: str) -> None:
        """
        Send a generic acknowledgement response.

        Args:
            user_id: User identifier to include in the acknowledgement payload.

        Raises:
            ValueError: If user_id is empty.
        """
        if not user_id:
            raise ValueError("user_id cannot be empty")

        self._response.header.response_code = ServerCode.ACK
        self._response.payload.user_id = user_id

        self.send()
