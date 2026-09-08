"""
Server connection and request dispatch management.

This module defines the main server handler responsible for:
- creating and binding the TCP server socket,
- accepting client connections,
- spawning a dedicated thread per client,
- decoding incoming protocol requests,
- routing requests to the appropriate service/handler layer,
- sending failure responses when request handling fails.

@author Tehila Cahnaman
"""

from __future__ import annotations

import socket
import sys
import threading
from typing import Any

from handlers.backup_handlers import (
    handle_backup_request,
    handle_crc_error,
    handle_crc_failure,
    handle_crc_success,
)
from utils.console_ui import Color
from protocol.constants import ClientCode, SERVER_VERSION, ServerCode
from storage.database import setup_database
from services.registration_service import (
    handle_client_re_registration,
    handle_client_registration,
    handle_public_key_send,
)
from protocol.request import Request
from protocol.request_decoder import deserialize_request
from protocol.response import Response, ResponseHeader, ResponsePayload
from protocol.response_sender import ResponseSender


class ServerHandler:
    """
    Coordinates server startup, client connection handling, and request routing.

    Attributes:
        HOST_IP: IP address used by the server socket.
        HOST_PORT: TCP port used by the server socket.
        server_socket: Main listening socket used to accept client connections.
    """

    HOST_IP: str = "127.0.0.1"
    HOST_PORT: int = 1234

    def __init__(self) -> None:
        """
        Initialize the server handler without opening the server socket yet.
        """
        self.server_socket: socket.socket | None = None

    def setup_server_socket(self) -> None:
        """
        Create, bind, and configure the main server socket.

        Raises:
            OSError: If the socket cannot be created or bound.
            OSError: If the configuration file cannot be written.
        """

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.HOST_IP, self.HOST_PORT))

        print(
            Color.GREEN
            + f"Server listening on port {self.HOST_IP}:{self.HOST_PORT}"
            + Color.RESET
        )

    @staticmethod
    def _create_default_response() -> Response:
        """
        Build a default response object for request handlers to populate.

        Returns:
            Response: A response initialized with the server version, default
            response code, and an empty payload.
        """
        return Response(
            header=ResponseHeader(
                version=SERVER_VERSION,
                response_code=ServerCode.DEFAULT,
            ),
            payload=ResponsePayload(),
        )

    @staticmethod
    def handle_request(conn: socket.socket, request: Request) -> None:
        """
        Route a decoded client request to the matching handler function.

        Args:
            conn: Active client socket connection.
            request: Decoded protocol request.

        Raises:
            ValueError: If the request is missing.
            RuntimeError: If the request code is unknown.
        """
        if request is None:
            raise ValueError("Cannot handle an empty request")

        response = ServerHandler._create_default_response()
        request_code = request.header.request_code

        if request_code == ClientCode.REGISTRATION:
            handle_client_registration(conn, request.payload, response)
        elif request_code == ClientCode.PUBLIC_KEY_SEND:
            handle_public_key_send(conn, request, response)
        elif request_code == ClientCode.RE_REGISTRATION:
            handle_client_re_registration(conn, request, response)
        elif request_code == ClientCode.CREATE_BACKUP:
            handle_backup_request(conn, request, response)
        elif request_code == ClientCode.CRC_SUCCESS:
            handle_crc_success(conn, request, response)
        elif request_code == ClientCode.CRC_ERROR:
            handle_crc_error(request)
        elif request_code == ClientCode.CRC_FAILURE:
            handle_crc_failure(conn, request, response)
        else:
            raise RuntimeError(f"Unknown request code: {request_code}")

    def handle_client(self, conn: socket.socket, addr: tuple[Any, ...]) -> None:
        """
        Process all requests received from a single connected client.

        Args:
            conn: Active client socket connection.
            addr: Client address tuple returned by socket.accept().

        Notes:
            A malformed or closed request ends the client session. Handler
            failures are reported to the client using a generic failure response.
        """
        try:
            while True:
                request = deserialize_request(conn)

                if request is None:
                    print(
                        Color.YELLOW
                        + f"Client {addr[0]}:{addr[1]} disconnected unexpectedly"
                        + Color.RESET
                    )
                    break

                if request.header.request_code == ClientCode.DISCONNECT:
                    print(Color.GREEN + "Client disconnected" + Color.RESET)
                    break

                try:
                    self.handle_request(conn, request)
                except Exception as error:
                    print(error, file=sys.stderr)
                    ResponseSender.send_failure(conn)
        finally:
            conn.close()

    def start_server(self) -> None:
        """
        Start listening for clients and spawn one worker thread per connection.

        Raises:
            RuntimeError: If the server socket was not initialized.
            OSError: If accepting a connection fails.
        """
        if self.server_socket is None:
            raise RuntimeError("Server socket must be initialized before starting")

        self.server_socket.listen()

        while True:
            conn, addr = self.server_socket.accept()
            print(
                Color.GREEN
                + f"New client connected on address: {addr[0]}:{addr[1]}"
                + Color.RESET
            )

            client_thread = threading.Thread(
                target=self.handle_client,
                args=(conn, addr),
                daemon=True,
            )
            client_thread.start()

    def run(self) -> None:
        """
        Initialize server resources and start the main server loop.

        Steps:
            1. Create and bind the server socket.
            2. Initialize the database schema.
            3. Start accepting client connections.
        """
        self.setup_server_socket()
        setup_database()
        self.start_server()
