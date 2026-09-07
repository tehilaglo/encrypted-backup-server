"""
Author: Tehila Cahanman
ID: 315179879

Description:
This module implements the message server functionality.
"""
import socket
import threading
from console_ui import Color
from datetime import datetime, timedelta
from encryption_alg import aes_cbc_decrypt
from srv_setup import generate_msg_srv_info, HOST_IP, MSG_INFO_FILE
from constants import (receive_data, CL_KEY_SEND_CODE, get_server_key, client_is_valid,
                       server_is_valid, RequestHeader, MSGRequestPayload, DATE_FORMAT,
                       CL_MSG_SEND_CODE, ResponseHeader, ResponsePayload, SRV_KEY_ACK_CODE,
                       send_data, SRV_DISCONNECT_CODE, SRV_MSG_ACK_CODE, send_error_response)

FORMAT = 'utf-8'
ticket_expiration_time: datetime
cl_srv_mutual_key: bytes


def get_response(request_header: RequestHeader, request_payload: MSGRequestPayload, conn, addr):
    """
   Generate appropriate responses to client requests.

   Args:
       request_header (RequestHeader): The header of the incoming request.
       request_payload (MSGRequestPayload): The payload of the incoming request.
       conn: The client connection socket.
       addr: The client address.
   """
    global ticket_expiration_time
    global cl_srv_mutual_key
    request_code = request_header.request_code
    current_time = datetime.now()

    if request_code == CL_KEY_SEND_CODE:
        client_id = request_payload.ticket.client_id
        server_id = request_payload.ticket.server_id
        # Validate client and server IDs
        if not client_is_valid(client_id):
            raise ServerException(Color.RED + "[ERROR] Invalid client ID" + Color.RESET)

        if not server_is_valid(MSG_INFO_FILE, server_id):
            raise ServerException(Color.RED + "[ERROR] Invalid server ID" + Color.RESET)

        server_key = get_server_key(MSG_INFO_FILE).encode(FORMAT)

        authenticator_iv = request_payload.authenticator.authenticator_iv

        encrypted_client_id = request_payload.authenticator.client_id
        encrypted_server_key = request_payload.authenticator.server_id
        auth_clint_id = aes_cbc_decrypt(server_key, authenticator_iv, encrypted_client_id).decode(FORMAT)
        auth_server_id = aes_cbc_decrypt(server_key, authenticator_iv, encrypted_server_key).decode(FORMAT)
        # Validate authenticity of client and server IDs
        if client_id != auth_clint_id and server_id != auth_server_id:
            raise ServerException(Color.RED + "[ERROR] Authentication failed" + Color.RESET)

        encrypted_creation_time = request_payload.authenticator.creation_time
        ticket_creation_time = request_payload.ticket.creation_time
        auth_creation_time = aes_cbc_decrypt(server_key, authenticator_iv, encrypted_creation_time).decode(FORMAT)

        ticket_timestamp = datetime.strptime(ticket_creation_time, DATE_FORMAT)
        auth_timestamp = datetime.strptime(auth_creation_time, DATE_FORMAT)
        # Check if the ticket timestamp is within the acceptable range
        if auth_timestamp - ticket_timestamp > timedelta(minutes=2):
            raise ServerException(Color.RED + "[ERROR] Invalid timestamp" + Color.RESET)

        ticket_iv = request_payload.ticket.ticket_iv
        encrypted_expiration_time = request_payload.ticket.expiration_time
        decrypted_expiration_time = aes_cbc_decrypt(server_key, ticket_iv, encrypted_expiration_time).decode(FORMAT)
        ticket_expiration_time = datetime.strptime(decrypted_expiration_time, DATE_FORMAT)
        # Check if the ticket expiration time is valid
        if not ticket_expiration_time - current_time > timedelta(minutes=0):
            raise ServerException(Color.RED + "[ERROR] Ticket expired" + Color.RESET)

        encrypted_client_key = request_payload.ticket.aes_key
        cl_srv_mutual_key = aes_cbc_decrypt(server_key, ticket_iv, encrypted_client_key)
        # Prepare response for key acknowledgment
        response_header = ResponseHeader(response_code=SRV_KEY_ACK_CODE)
        response_payload = ResponsePayload()

        print(Color.BLUE + "[SUCCESS] Symmetric key received" + Color.RESET)

    elif request_code == CL_MSG_SEND_CODE:
        # Handling client's message sending
        if not ticket_expiration_time - current_time > timedelta(minutes=0):
            raise ServerException(Color.RED + "[ERROR] Ticket expired" + Color.RESET)

        msg_iv = request_payload.msg_iv
        msg_b = request_payload.msg_content
        decrypted_msg = aes_cbc_decrypt(cl_srv_mutual_key, msg_iv, msg_b)
        cl_msg = decrypted_msg.decode(FORMAT)

        print(Color.YELLOW + f"[{addr[0]}:{addr[1]}] {cl_msg}" + Color.RESET)
        # Prepare response for message acknowledgment
        response_header = ResponseHeader(response_code=SRV_MSG_ACK_CODE)
        response_payload = ResponsePayload()
    else:
        raise ServerException(Color.RED + "[ERROR] Invalid request code" + Color.RESET)

    send_data(response_header, response_payload, conn)


def handle_client(conn, addr):
    """
   Handle communication with individual clients.

   Args:
       conn: The client connection socket.
       addr: The client address.
   """
    global server_error

    while True:
        # Receive request data from the client
        request_header, request_payload = receive_data(conn)
        # Check if the client requested disconnection
        if request_header.request_code == SRV_DISCONNECT_CODE:
            print(Color.GREEN + "Client disconnected" + Color.RESET)
            break
        try:
            # Process the received request
            get_response(request_header, request_payload, conn, addr)
        except ServerException as e:
            server_error = True
            print(e)
        except Exception as e:
            server_error = True
            print(e)
        finally:
            if server_error:
                send_error_response(conn)
                break

    conn.close()


