"""
Author: Tehila Cahanman
ID: 315179879

Description:
This module handles client-side functionality for interacting
with message servers and key distribution centers (KDCs).
"""
from console_ui import Color
from datetime import datetime
from typing import Tuple
import socket
import re
from encryption_alg import generate_nonce, password_hash, aes_cbc_decrypt, generate_iv, aes_cbc_encrypt
from constants import (RequestHeader, RequestPayload, CL_REGISTRATION_CODE, receive_data,
                       ResponseHeader, send_data, ResponsePayload, get_server_uuid, SRV_KEY_SEND_CODE,
                       SRV_DISCONNECT_CODE, Ticket, FORMAT, DATE_FORMAT, Authenticator, CL_KEY_SEND_CODE,
                       MSGRequestPayload, SRV_INFO_fILE, SRV_REGISTRATION_SUCCESS_CODE, MSG_INFO_FILE,
                       file_exists, username_exists, get_server_key, SRV_KEY_ACK_CODE, SRV_MSG_ACK_CODE,
                       CL_MSG_SEND_CODE, CL_KEY_REQUEST_CODE, DISCONNECT_MESSAGE, SRV_FAILED_CODE,
                       get_cl_password_hash)

cl_srv_mutual_key: bytes
msg_srv_ticket: Ticket
client_id: str
USERNAME_LOWER_BOUND = 5
USERNAME_UPPER_BOUND = 10
PASSWORD_LOWER_BOUND = 8
PASSWORD_UPPER_BOUND = 20
CL_INFO_FILE = "me.info"
client_error: bool = False
server_error: bool = False
unexpected_error: bool = False
disconnect_client: bool = False


class ClientException(Exception):
    """
    Exception raised for errors related to client-side operations.
    """
    pass


class ServerException(Exception):
    """
    Exception raised for errors related to server-side operations.
    """
    pass


def get_servers_ports() -> Tuple[int, int]:
    """
    Get the ports of message server and KDC from the server info file.

    Returns:
        Tuple[int, int]: A tuple containing the message server port and KDC port.
    """
    with open(SRV_INFO_fILE, "r") as f:
        msg_server_info = f.readline().split(":")
        msg_srv_port = int(msg_server_info[1])

        kdc_info = f.readline().split(":")
        kdc_port = int(kdc_info[1])

        return msg_srv_port, kdc_port


def get_servers_ip(): #set_servers_ip
    """
    Get the IP addresses of message server and KDC from the server info file.

    Returns:
        Tuple[str, str]: A tuple containing the message server IP and KDC IP.
    """
    with open(SRV_INFO_fILE, "r") as f:
        msg_server_info = f.readline().split(":")
        msg_srv_ip = msg_server_info[0]

        kdc_info = f.readline().split(":")
        kdc_ip = kdc_info[0]

        return msg_srv_ip, kdc_ip


def connect_to_srv(srv_ip: str, srv_port: int) -> socket:
    """
   Connect to a server using the given IP address and port.

   Args:
       srv_ip (str): The IP address of the server.
       srv_port (int): The port of the server.

   Returns:
       socket: The client socket connected to the server.
   """
    srv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_socket.connect((srv_ip, srv_port))

    return srv_socket


def disconnect_from_srv(server_socket: socket):
    """
    Send a disconnect request and close the connection with the server.

    Args:
        server_socket (socket): The socket connected to the server.
    """
    request_payload = RequestPayload()
    request_header = RequestHeader(request_code=SRV_DISCONNECT_CODE)
    send_data(request_header, request_payload, server_socket)
    server_socket.close()


def confirm_password() -> bool:
    """
    Confirm the password entered by the user.

    Returns:
        bool: True if the password is confirmed, False otherwise.
    """
    global client_id

    num_of_tries = 3
    counter = 0

    while counter < num_of_tries:

        print(Color.GREEN + "Please enter your password:" + Color.RESET)
        password = input()
        hashed_password: str = password_hash(password)
        # Compare the hashed password with the stored hashed password for the client ID
        if hashed_password == get_cl_password_hash(client_id):
            return True
        # If passwords do not match, inform the user and increment the attempt counter
        print(Color.RED + "Password is incorrect" + Color.RESET)
        counter += 1
        # Check if there are more attempts left, if yes, prompt user to try again
        if counter < num_of_tries:
            print(Color.RED + "Please try again" + Color.RESET)

    return False


def process_kdc_response(response_header: ResponseHeader, response_payload: ResponsePayload,
                         username=None, nonce=None):
    """
    Process the response received from the KDC.

    Args:
        response_header (ResponseHeader): The header of the response.
        response_payload (ResponsePayload): The payload of the response.
        username (str, optional): The username. Defaults to None.
        nonce (bytes, optional): The nonce. Defaults to None.
    """
    global cl_srv_mutual_key
    global msg_srv_ticket
    global client_id

    response_code = response_header.response_code

    if response_code == SRV_REGISTRATION_SUCCESS_CODE:
        client_id = response_payload.client_id
        with open(CL_INFO_FILE, "w") as f:
            f.write(f"{username}\n{client_id}")

    elif response_code == SRV_KEY_SEND_CODE:
        # If the KDC sends the key, confirm the password, decrypt the key, and update mutual key and ticket
        if not confirm_password():
            raise ClientException
        # Retrieve the hashed password and decrypt the key and nonce from the payload
        hashed_password: bytes = get_cl_password_hash(client_id).encode(FORMAT)
        encrypted_key_iv: bytes = response_payload.encrypted_key.encrypted_key_iv
        encrypted_nonce: bytes = response_payload.encrypted_key.nonce
        decrypted_nonce = aes_cbc_decrypt(hashed_password, encrypted_key_iv, encrypted_nonce)
        # If the decrypted nonce matches the original nonce, decrypt the key and update mutual key and ticket
        if decrypted_nonce == nonce:
            encrypted_aes_key = response_payload.encrypted_key.aes_key
            cl_srv_mutual_key = aes_cbc_decrypt(hashed_password, encrypted_key_iv, encrypted_aes_key)

            msg_srv_ticket = response_payload.ticket
        else:
            raise Exception

    elif response_code == SRV_FAILED_CODE:
        raise ServerException(Color.RED + "Server failed to secure your request" + Color.RESET)
    else:
        raise ServerException(Color.RED + "Server failed to secure your request" + Color.RESET)


def process_msg_response(response_header: ResponseHeader):
    """
    Process the response received from the message server.

    Args:
        response_header (ResponseHeader): The header of the response.
    """
    response_code = response_header.response_code

    if response_code == SRV_KEY_ACK_CODE:
        print(Color.YELLOW + "Your personal messages are end-to-end encrypted" + Color.RESET)
    elif response_code == SRV_MSG_ACK_CODE:
        print(Color.BLUE + Color.BOLD + '\u2713 \u2713' + Color.RESET)
    elif response_code == SRV_FAILED_CODE:
        raise ServerException(Color.RED + "Hmm... Something seems to have gone wrong" + Color.RESET)
    else:
        raise ServerException(Color.RED + "Hmm... Something seems to have gone wrong" + Color.RESET)


def is_valid_username(username) -> bool:
    """
    Check if the username is valid.

    Args:
        username (str): The username to be checked.

    Returns:
        bool: True if the username is valid, False otherwise.
    """
    if not USERNAME_LOWER_BOUND <= len(username) <= USERNAME_UPPER_BOUND:
        return False
    # Character constraints: Allow only alphanumeric characters and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False

    return True


def is_valid_password(password) -> bool:
    """
    Check if the password is valid.

    Args:
        password (str): The password to be checked.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    # Check if the password meets length requirements
    if not PASSWORD_LOWER_BOUND <= len(password) <= PASSWORD_UPPER_BOUND:
        return False
    # Check if the password contains only alphanumeric characters and specific special characters
    if not re.match(r'^[a-zA-Z0-9!@#$%&]+$', password):
        return False

    return True


def get_user_info():
    """
    Get the username and password from the user.

    Returns:
        Tuple[str, str]: A tuple containing the username and password entered by the user.
    """
    username_is_valid: bool = False
    password_is_valid: bool = False

    print(Color.GREEN + "Please enter a username:" + Color.RESET)
    username: str = input()
    # Validate the username
    while not username_is_valid:
        username_is_valid = True

        if file_exists(CL_INFO_FILE):
            if username_exists(username):
                username_is_valid = False

        if not username_is_valid:
            print(Color.RED + "Username is invalid. Please try again" + Color.RESET)
            username: str = input()

        elif not is_valid_username(username):
            username_is_valid = False
            print(Color.YELLOW + f"Username length must be between {USERNAME_LOWER_BOUND} and {USERNAME_UPPER_BOUND} "
                  f"and contain alphanumeric and underscore characters only.\nPlease try again" + Color.RESET)
            username: str = input()
        else:
            username_is_valid = True

    print(Color.GREEN + "Please enter a password:" + Color.RESET)
    password: str = input()
    # Validate the password
    while not password_is_valid:
        if not is_valid_password(password):
            print(Color.YELLOW + f"Password must be between {PASSWORD_LOWER_BOUND} and {PASSWORD_UPPER_BOUND} "
                  f"and contain alphanumeric and the special characters '!@#$%&' only.\nPlease try again" + Color.RESET)
            password: str = input()
        else:
            password_is_valid = True

    return username, password


def client_registration(kdc_socket: socket):
    """
    Register the client with the KDC.

    Args:
        kdc_socket (socket): The socket connected to the KDC.
    """
    global server_error
    global unexpected_error

    username, password = get_user_info()
    # Create a registration request
    request_header = RequestHeader(request_code=CL_REGISTRATION_CODE)
    request_payload = RequestPayload(username, password)
    # Send the registration request to the KDC and receive the response
    send_data(request_header, request_payload, kdc_socket)
    response_header, response_payload = receive_data(kdc_socket)
    try:
        process_kdc_response(response_header, response_payload, username)
    except ServerException as e:
        print(e)
        server_error = True
    except Exception:
        unexpected_error = True


def request_encrypted_key(msg_srv_info_f_name: str, kdc_socket: socket):
    """
   Request an encrypted key from the KDC.

   Args:
       msg_srv_info_f_name (str): The filename of the message server info.
       kdc_socket (socket): The socket connected to the KDC.
   """
    global server_error
    global client_error
    global unexpected_error
    # Get the server ID and generate a nonce
    server_id = get_server_uuid(msg_srv_info_f_name)
    nonce = generate_nonce()
    # Create a request for an encrypted key
    request_header = RequestHeader(client_id=client_id, request_code=CL_KEY_REQUEST_CODE)
    request_payload = RequestPayload(server_id=server_id, nonce=nonce)
    # Send the request to the KDC and receive the response
    send_data(request_header, request_payload, kdc_socket)
    response_header, response_payload = receive_data(kdc_socket)
    try:
        process_kdc_response(response_header, response_payload, nonce=nonce)
    except ClientException:
        client_error = True
    except ServerException as e:
        print(e)
        server_error = True
    except Exception:
        unexpected_error = True


def send_ticket(msg_srv_info_f_name: str, msg_srv_socket: socket):
    """
   Send the ticket to the message server.

   Args:
       msg_srv_info_f_name (str): The filename of the message server info.
       msg_srv_socket (socket): The socket connected to the message server.
   """
    global server_error
    global unexpected_error

    server_key = get_server_key(MSG_INFO_FILE).encode(FORMAT)
    auth_iv = generate_iv()
    client_id_b = client_id.encode(FORMAT)
    server_id = get_server_uuid(msg_srv_info_f_name).encode(FORMAT)
    current_time = datetime.now()
    creation_timestamp = current_time.strftime(DATE_FORMAT).encode(FORMAT)
    # Encrypt data
    encrypted_client_id = aes_cbc_encrypt(server_key, auth_iv, client_id_b)
    encrypted_server_id = aes_cbc_encrypt(server_key, auth_iv, server_id)
    encrypted_creation_timestamp = aes_cbc_encrypt(server_key, auth_iv, creation_timestamp)
    # Create the authenticator
    authenticator = Authenticator(auth_iv, encrypted_client_id,
                                  encrypted_server_id, encrypted_creation_timestamp)
    # Create and send the request
    request_header = RequestHeader(request_code=CL_KEY_SEND_CODE)
    request_payload = MSGRequestPayload(authenticator, msg_srv_ticket)
    send_data(request_header, request_payload, msg_srv_socket)
    response_header, response_payload = receive_data(msg_srv_socket)
    # Process the response
    try:
        process_msg_response(response_header)
    except ServerException as e:
        print(e)
        server_error = True
    except Exception:
        unexpected_error = True


def send_message(msg_srv_socket: socket):
    """
   Send a message to the message server.

   Args:
       msg_srv_socket (socket): The socket connected to the message server.
   """
    global server_error
    global unexpected_error
    global disconnect_client
    # Prompt the user for a message
    print(Color.GREEN + "Waiting for your message..." + Color.RESET)
    msg = input()
    # Check if the client wants to disconnect
    if msg == DISCONNECT_MESSAGE:
        disconnect_client = True
        return
    # Encrypt the message
    msg_b = msg.encode(FORMAT)
    iv = generate_iv()
    encrypted_msg = aes_cbc_encrypt(cl_srv_mutual_key, iv, msg_b)
    # Create and send the request
    request_header = RequestHeader(request_code=CL_MSG_SEND_CODE)
    request_payload = MSGRequestPayload(msg_iv=iv, msg_content=encrypted_msg)
    send_data(request_header, request_payload, msg_srv_socket)
    response_header, response_payload = receive_data(msg_srv_socket)
    # Process the response
    try:
        process_msg_response(response_header)
    except ServerException as e:
        print(e)
        server_error = True
    except Exception:
        unexpected_error = True


def main():
    """
    The main function to handle client-side operations.
    """
    global client_id
    # Connect to the Key Distribution Center (KDC)
    msg_srv_ip, kdc_ip = get_servers_ip()
    msg_srv_port, kdc_port = get_servers_ports()
    kdc_socket = connect_to_srv(kdc_ip, kdc_port)
    # Check if the client is already registered
    if file_exists(CL_INFO_FILE):
        with open(CL_INFO_FILE, 'r') as f:
            username: str = f.readline().strip()
            client_id = f.readline().strip()

        print(Color.YELLOW + Color.BOLD + f"Welcome back {username}!" + Color.RESET)
    else:
        client_registration(kdc_socket)
    # Request an encrypted key from the KDC
    request_encrypted_key(MSG_INFO_FILE, kdc_socket)
    disconnect_from_srv(kdc_socket)
    # Handle errors and connect to the message server
    if client_error:
        print(Color.YELLOW + "Exiting server..." + Color.RESET)
    elif unexpected_error:
        print(Color.RED + "Unexpected error occurred" + Color.RESET)
    elif not server_error:
        msg_srv_socket = connect_to_srv(msg_srv_ip, msg_srv_port)
        print(Color.GREEN + "Connected" + Color.RESET)
        send_ticket(MSG_INFO_FILE, msg_srv_socket)
    # Main loop to send messages
    while not client_error and not unexpected_error and not server_error:

        send_message(msg_srv_socket)

        if disconnect_client:
            disconnect_from_srv(msg_srv_socket)
            print(Color.GREEN + "Disconnected" + Color.RESET)
            break
    # Handle unexpected errors
    if unexpected_error:
        print(Color.RED + "Unexpected error occurred" + Color.RESET)


if __name__ == "__main__":
    main()
