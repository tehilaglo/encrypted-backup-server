import struct
import unittest
import os
from unittest.mock import MagicMock
from socket import socket

from constants import CREATE_BACKUP_REQUEST_CODE, FILE_NAME_LEN, UNIQUE_ID_LEN, USERNAME_LEN, \
    PUBLIC_KEY_LEN
from request_decoder import deserialize_request


class TestDeserializeRequest(unittest.TestCase):

    def setUp(self):
        self.mock_socket = MagicMock(spec=socket)

    def mock_recv_all(self, data_map):
        """
        Helper function to mock recv_all calls with specific return values.
        """

        def side_effect(num_bytes):
            return data_map.pop(0)

        self.mock_socket.recv.side_effect = side_effect

    def test_deserialize_request_create_backup(self):
        # Path to the file
        file_path = '../img.PNG'

        # Get the file size of img.PNG in bytes
        file_size = os.path.getsize(file_path)

        # Read the actual bytes of img.PNG file
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        # Mock data for request code 828 (CREATE_BACKUP_REQUEST_CODE)
        user_id = b'3151' + b' ' * (UNIQUE_ID_LEN - len('3151'))

        # Calculate payload_size as the sum of the following:
        # 4 bytes (content_size) + 4 bytes (orig_file_size) + 2 bytes (packet_number) + 2 bytes (total_packets)
        # + FILE_NAME_LEN (255 bytes) + size of the encrypted file data (file_size)
        payload_size = 4 + 4 + 2 + 2 + FILE_NAME_LEN + file_size

        # Now pack the header, where:
        # - user_id is 16 bytes
        # - version is 1 byte (B)
        # - request_code is 2 bytes (H)
        # - payload_size is 4 bytes (I)
        header_data = struct.pack('<B H I',  1, CREATE_BACKUP_REQUEST_CODE, payload_size)

        username = b' ' * USERNAME_LEN
        public_key = b' ' * PUBLIC_KEY_LEN

        # Using the file size for both content_size and orig_file_size (4 bytes each)
        # And packet_number and total_packets as 2 bytes (short)
        packet_number = 5  # 2 bytes
        total_packets = 10  # 2 bytes
        payload_data = struct.pack('<I I H H', file_size, file_size, packet_number,
                                   total_packets)  # 4 bytes + 4 bytes + 2 bytes + 2 bytes

        # Update file name to "img.PNG" and pad to FILE_NAME_LEN (255 bytes)
        file_name = b'img.PNG' + b' ' * (FILE_NAME_LEN - len('img.PNG'))

        # encrypted_file_data will be the actual file bytes
        encrypted_file_data = file_bytes

        # Define the data returned by recv_all in smaller chunks
        # Simulating a more realistic socket data reception
        mock_data = [user_id, header_data, username, public_key, payload_data, file_name, encrypted_file_data]

        # Set up the mock for recv_all
        self.mock_recv_all(mock_data)

        # Call the function to test
        result = deserialize_request(self.mock_socket)

        print(result)

        # Verify the structure and values of the deserialized request
        self.assertEqual(result['header']['user_id'], '3151')
        self.assertEqual(result['header']['version'], 1)
        self.assertEqual(result['header']['request_code'], CREATE_BACKUP_REQUEST_CODE)
        self.assertEqual(result['header']['payload_size'], payload_size)  # Verify the dynamically calculated payload_size
        self.assertEqual(result['payload']['content_size'], file_size)  # 4 bytes field
        self.assertEqual(result['payload']['orig_file_size'], file_size)  # 4 bytes field
        self.assertEqual(result['payload']['packet_number'], packet_number)  # 2 bytes field
        self.assertEqual(result['payload']['total_packets'], total_packets)  # 2 bytes field
        self.assertEqual(result['payload']['file_name'], 'img.PNG')
        self.assertEqual(result['payload']['encrypted_file_data'], encrypted_file_data)


if __name__ == '__main__':
    unittest.main()
