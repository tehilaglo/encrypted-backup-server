"""
Author: Tehila Cahanman
ID: 315179879

Description:
This module implements a server for a Kerberos-like authentication protocol.
It handles client registration, key exchange, and communication with clients.
"""
import socket
import threading
from console_ui import Color
from datetime import datetime, timedelta
from encryption_alg import generate_uuid, aes_cbc_encrypt, generate_aes_key, password_hash, generate_iv
from constants import (RequestHeader, RequestPayload, SRV_DISCONNECT_CODE, receive_data,
                       CL_REGISTRATION_CODE, CL_KEY_REQUEST_CODE, SRV_REGISTRATION_FAILED_CODE,
                       ResponseHeader, ResponsePayload, SRV_REGISTRATION_SUCCESS_CODE, send_data,
                       EncryptedKey, Ticket, SRV_KEY_SEND_CODE, DATE_FORMAT, FORMAT, SRV_INFO_fILE,
                       client_is_valid, get_cl_password_hash, server_is_valid, get_server_key,
                       file_exists, MSG_INFO_FILE, username_exists, CLIENTS_INFO_FILE, send_error_response)
server_error: bool = False


class ServerException(Exception):
    """
    Custom exception class for server errors.
    """
    pass


def generate_port():
    """
    Generates and saves a port number for the server.
    """
    with open(PORT_INFO_FILE, 'w') as f:
        f.write(str(HOST_PORT))


def get_response(request_header: RequestHeader, request_payload: RequestPayload, conn):
    """
    Handles incoming client requests and generates appropriate responses.

    Args:
        request_header (RequestHeader): The header of the incoming request.
        request_payload (RequestPayload): The payload of the incoming request.
        conn: The client connection socket.
    """
    request_code = request_header.request_code

    if request_code == CL_REGISTRATION_CODE:
        username = request_payload.name
        password = request_payload.password
        cl_exists: bool = False

        if file_exists(CLIENTS_INFO_FILE):
            if username_exists(username):
                cl_exists = True
                # If username exists, respond with registration failure
                response_header = ResponseHeader(response_code=SRV_REGISTRATION_FAILED_CODE)
                response_payload = ResponsePayload()
        # If the username does not exist, register the client
        if not cl_exists:
            client_id = generate_uuid()
            hashed_password = password_hash(password)
            current_time = datetime.now()
            last_seen = current_time.strftime(DATE_FORMAT)

            with open(CLIENTS_INFO_FILE, "a") as f:
                f.write(f"{client_id}:{username}:{hashed_password}:{last_seen}\n")
            # Respond with registration success
            response_header = ResponseHeader(response_code=SRV_REGISTRATION_SUCCESS_CODE)
            response_payload = ResponsePayload(client_id=client_id)

        print(Color.BLUE + "[SUCCESS] Client registered successfully" + Color.RESET)

    elif request_code == CL_KEY_REQUEST_CODE:
        client_id = request_header.client_id
        server_id = request_payload.server_id
        nonce = request_payload.nonce
        # Validate client ID
        if client_is_valid(client_id):
            # Generate password hash for client
            cl_password_hash = get_cl_password_hash(client_id).encode(FORMAT)
            iv = generate_iv()
            # Encrypt nonce using client's password hash and IV
            encrypted_nonce = aes_cbc_encrypt(cl_password_hash, iv, nonce)
            # Generate mutual key for client-server communication
            cl_srv_mutual_key = generate_aes_key()
            # Encrypt mutual key using client's password hash and IV
            encrypted_mutual_key = aes_cbc_encrypt(cl_password_hash, iv, cl_srv_mutual_key)
            # Prepare encrypted key with IV and encrypted nonce
            encrypted_key = EncryptedKey(iv, encrypted_nonce, encrypted_mutual_key)
        else:
            raise ServerException(Color.RED + "[ERROR] Invalid client ID" + Color.RESET)
        # Validate server ID
        if server_is_valid(MSG_INFO_FILE, server_id):
            # Get server's key
            msg_srv_key = get_server_key(MSG_INFO_FILE).encode(FORMAT)
            current_time = datetime.now()
            creation_timestamp = current_time.strftime(DATE_FORMAT)

            expiration_delta = timedelta(days=7)
            expiration_time = current_time + expiration_delta
            expiration_timestamp = expiration_time.strftime(DATE_FORMAT).encode(FORMAT)

            iv = generate_iv()
            # Encrypt mutual key and expiration timestamp using server's key and IV
            encrypted_mutual_key = aes_cbc_encrypt(msg_srv_key, iv, cl_srv_mutual_key)
            encrypted_exp_timestamp = aes_cbc_encrypt(msg_srv_key, iv, expiration_timestamp)
            ticket = Ticket(client_id, server_id, creation_timestamp, iv, encrypted_mutual_key, encrypted_exp_timestamp)
        else:
            raise ServerException(Color.RED + "[ERROR] Invalid server ID" + Color.RESET)
        # Respond with encrypted key and ticket
        response_header = ResponseHeader(response_code=SRV_KEY_SEND_CODE)
        response_payload = ResponsePayload(client_id, encrypted_key, ticket)
        print(Color.BLUE + "[SUCCESS] Symmetric key sent to client successfully" + Color.RESET)
    else:
        raise ServerException(Color.RED + "[ERROR] Invalid request code" + Color.RESET)

    send_data(response_header, response_payload, conn)





def start_server(server_socket: socket):
    """
    Starts the server and listens for incoming client connections.

    Args:
        server_socket (socket): The server socket.
    """
    server_socket.listen()

    while True:
        conn, addr = server_socket.accept()
        print(Color.GREEN + f"New client connected on address: {addr[0]}:{addr[1]}" + Color.RESET)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


def main():
    """
    Entry point of the server application.
    """
    generate_port()
    server_socket: socket = server_setup()
    start_server(server_socket)


if __name__ == "__main__":
    main()
