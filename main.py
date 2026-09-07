"""
Application entry point for the encrypted backup server.

This module creates the main server handler and starts the server run loop.

@author Tehila Cahnaman
"""

from handlers.server_handler import ServerHandler


def main() -> None:
    """
    Start the encrypted backup server.

    The `ServerHandler` is responsible for configuring the server socket,
    initializing required resources, and accepting client connections.
    """
    server_handler = ServerHandler()
    server_handler.run()


if __name__ == "__main__":
    main()
