import sys
import socket
import pickle
import traceback
from threading import Thread

from Cryptodome.Cipher import PKCS1_OAEP, AES  # need to pip install pycryptodome
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256

HOST = "127.0.0.1"
PORT = 2121

BLOCK_SIZE = 32 # AES data block size, 256 bits (32 bytes)
key_size = 32   # AES key size, 32 bytes -> 256 bits
SERVER_PRIV_KEY_PATH = "depolyment\server_private.pem" # Server Private Key
CAMERA_PUB_KEY_PATH = "depolyment\camera_public.pem"   # Camera Public Key

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
        camera_public_key, server_private_key = get_key(CAMERA_PUB_KEY_PATH, SERVER_PRIV_KEY_PATH)
        payload = client_request['file_content']

        # Decrypts the payload and returns the picture
        decrypted_picture = decrypt_picture(payload, server_private_key)

        if verify_signature(payload, decrypted_picture, camera_public_key):
            # Writes and uploads the file onto the database, i.e. "/data" folder
            upload_file(payload, decrypted_picture)
            output = "received"
        else:
            # This means that the signature is not valid
            # TODO: Haven't implemented anything to tell the client that the signature is not valid
            output = "invalid"

    return output


# TODO: Use this certifcate to send client.py, the public key
# The keys are RSA 2048 bit keys.
# Use this certifcate to send client.py, the public key
def get_key(public_key_filepath: str, private_key_filepath: str):
    '''
    This function is used to get the private/public key content.
    So, you would need to convert the key content into a RSA key object.
    
    Args:
        ``public_key_filepath`` (str) : The public key file name.
        ``private_key_filepath`` (str) : The private key file name.

    Returns:
        ``public_key``, ``private_key`` (str) : both the public and private key content as str.
    '''
    with open(public_key_filepath, 'r') as f:
        public_key = f.read()
    
    with open(private_key_filepath, 'r') as f:
        private_key = f.read()

    return public_key, private_key

# Decryption the image sent using AES and RSA
def decrypt_picture(payload, server_private_key: str) -> bytes:
    '''
    This function is used to decrypt the image sent using AES-256 and RSA-2048.

    Args:
        ``payload`` : The payload that contains the encrypted ENC_payload object.
        ``server_private_key`` (bytes) : The private key of the server.

    Returns:
        ``decrypted_picture`` : The decrypted image.
    '''
    aes_key = decrypt_aes_key(payload.encrypted_session_key, server_private_key)

    # Creates the AES cipher object with the decrypted AES key and the initialization vector.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, payload.aes_iv)

    # Unpads the encrypted image by the AES block_size and decrypts it.
    decrypted_picture = unpad(aes_cipher.decrypt(payload.encrypted_content), BLOCK_SIZE)
    return decrypted_picture

# Decrypts the AES key from the payload
def decrypt_aes_key(encrypted_AES_session_key: bytes, server_private_key_content: bytes):
    '''
    This function is used to decrypt the AES session key.
    
    Args:
        ``encrypted_AES_session_key`` (bytes) : The encrypted AES session key.
        ``server_private_key_content`` (bytes) : The private key of the server.

    Returns:
        ``decrypted_AES_session_key`` (bytes) : The decrypted AES session key.
    '''
    server_private_key = RSA.import_key(server_private_key_content)
    print("Done importing server private key")
    print(f"Server private key:\n{server_private_key_content}")

    # Creates the RSA object
    rsa_cipher = PKCS1_OAEP.new(server_private_key)

    # Decrypts the AES session key
    decrypted_AES_session_key = rsa_cipher.decrypt(encrypted_AES_session_key)

    # Generates a random AES key
    print(f"\nDecrypting the encrypted {key_size*8}-bit AES key..")
    print("AES block size: ", key_size)
    print("AES key: \n", end="")

    # NOTE: This is for demonstration purposes only.
    # Used to view the AES key.
    for byte in decrypted_AES_session_key:
        print(f"{byte:02x}", end="")
    print("\n")

    return decrypted_AES_session_key

# Verifies the signature of the decrypted image using SHA256 and RSA public key.
def verify_signature(payload, decrypted_picture: bytes, camera_public_key_content: str) -> bool:
    '''
    This function verifies the signature of the file content.

    Args:
        ``payload`` : The file content contains the RSA encrypted signature.
        ``decrypted_picture`` : The decrypted image.
        ``camera_public_key_content`` (str) : The public key of the camera.

    Returns:
        ``True`` : If the signature is valid.
        ``False`` : If the signature is invalid.
    '''
    # The camera public key is used to verify the signature
    camera_public_key = RSA.import_key(camera_public_key_content)

    # Use the camera public key to decrypt the signature
    verifier = pkcs1_15.new(camera_public_key)
    signature = payload.rsa_signature

    print("\n\nSignature:")
    signature_str = ""
    for bytes in signature:
        signature_str += f"{bytes:02x}"
    
    # Prettify the signature
    chars_per_line = 64
    for i in range(0, len(signature_str), chars_per_line):
        print(signature_str[i:i+chars_per_line])

    
    # Creates the SHA256 object
    # This will used to hash the decrypted_picture to verify against the RSA encrypted signature.


    # Hash the decrypted picture using SHA256

    
    # Compare the decrypted_picture with the decrypted signature


    pass

def upload_file(file_name, decrypted_picture):
    '''
    This function uploads the file to the database.

    Args:
        ``file_name`` : The file name.
        ``decrypted_picture`` : The decrypted picture that contains the image.
    '''
    # I never really thought on how to write and upload the picture.
    pass

if __name__ == "__main__":
    start_server(HOST, PORT)