# need to pip install pytftpdlib
import sys
import socket
import pickle
import traceback
from threading import Thread

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

HOST = "127.0.0.1"
PORT = 2121

BLOCK_SIZE = 32 # AES data block size, 256 bits (32 bytes)
key_size = 32   # AES key size, 32 bytes -> 256 bits
SERVER_PRIV_KEY = "depolyment\server_private.pem" # Server Private Key
CAMERA_PUB_KEY = "depolyment\camera_public.pem"   # Camera Public Key

# NOTE: We will be using socket server client so pyftpdlib will not be necessary
# authorizer = DummyAuthorizer() # handle permission and user
# authorizer.add_anonymous("source\server\data" , perm='adfmwM')
# handler = FTPHandler #  understand FTP protocol
# handler.authorizer = authorizer
# server = FTPServer((HOST, PORT), handler) # bind to high port, port 21 need root permission
# server.serve_forever()

# A data class to store a encrypted file content.
class ENC_payload:
    '''
    The file content has been encrypted using an AES key.
    The AES key is encrypted by a public key and stored in the enc_session_key instance attribute. 
    '''
    def __init__(self):
        '''
        Initialize the instance attributes.
        
        Args:
            ``encrypted_session_key`` : The encrypted AES key.
            ``encrypted_file_content`` : The encrypted file content.
            ``aes_iv`` : The AES initialization vector.
            ``rsa_signature`` : The RSA signature of the encrypted file content.
        '''
        self.encrypted_session_key=""
        self.aes_iv = ""
        self.encrypted_content=""
        self.rsa_signature=""


# TODO: Create a socket server and handle the data
# TODO: Clean up the socket server code.
# Starts the server
def start_server(host, port):
    '''
    This function starts the socket server.

    Args:
        ``host`` : The host IP address.
        ``port`` : The port number.
    '''
    print("[STARTING] Server is starting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()
    server.listen(20) # listening up to 20 different clients
    print("[LISTENING] Socket now listening")
    # infinite loop- do not reset for every requests
    while True:
        connection, address = server.accept()   # Server would wait here until a new connection is received
        ip, port = str(address[0]), str(address[1])
        print(f"[NEW CONNECTION] Connected with {ip}:{port}")
        try:
            # Server attempts to start a thread with target function "clientThread()"
            thread = Thread(target=client_thread, args=(connection, ip, port))
            thread.start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

# Handler for client machine
def client_thread(connection, ip, port, max_buffer_size = 5120):
    '''
    This function is used to handle the client request.

    Args:
        ``connection`` : The connection object.
        ``ip`` : The client IP address.
        ``port`` : The client port number.
        ``max_buffer_size`` : The maximum buffer size.
    '''
    is_active = True
    while is_active:
        client_input = receive_input(connection, max_buffer_size)
        if client_input == "quit":
            # Closes the connection of current thread
            connection.close()
            print(f"[CLOSED] Connection with {ip}:{port} closed")
            is_active = False
        else:
            # Send the message after dumping it and encoding it.
            connection.sendall(pickle.dumps(client_input))  
            print(f"[PROCESS] {ip}:{port}. Sent to Client, Packet type: '{client_input}'")

# Receives input from client machine
def receive_input(connection, max_buffer_size):
    '''
    This function is used to receive the input from the client.

    Args:
        ``connection`` : The connection object.
        ``max_buffer_size`` : The maximum buffer size.

    Returns:
        ``output`` : The processed server response.
    '''
    client_input = connection.recv(max_buffer_size)
    decoded_input = pickle.loads(client_input)
    print(decoded_input)
    output = process_input(decoded_input)
    return output

# Processes the input from the client
def process_input(client_request):
    '''
    This function receives the input string from the client
    and validate the input and return the string to the client

    Args:
        ``client_request`` : The client request.

    Returns:
        ``output`` : The processed server response.
    '''
    selection = client_request['type']
    if selection == "quit":
        output = "quit"
    if selection == "upload_file":
        client_request["file_name"]
        decrypted_picture = client_request["file_content"]
        output = "received"
    if selection == "2":
        pass
    return output

# TODO: Use this certifcate to send client.py, the public key
# TODO: decryption the image sent using AES and RSA

# The keys are RSA 2048 bit keys.
# Use this certifcate to send client.py, the public key
def get_key(public_key, private_key):
    '''
    This function is used to get the private/public key.
    
    Returns:
        bytes: the key
    '''
    with open(public_key, 'r') as f:
        public_key = f.read()
    
    with open(private_key, 'r') as f:
        private_key = f.read()
    return public_key, private_key

def decrypt_picture():
    pass

def verify_signature():
    pass

def upload_file(file_name, file_content):
    '''
    This function upload the file to the database.

    Args:
        ``file_name`` : The file name.
        ``file_content`` : The file content.
    '''
    pass

if __name__ == "__main__":
    start_server(HOST, PORT)