import base64, time, datetime, random

import sys
import pickle
import socket
import traceback
import base64

from Cryptodome.Cipher import PKCS1_OAEP, AES  # need to pip install pycryptodome
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def validationRange(start,end,question) -> int: 
    '''
    This function checks for user input and only accepts if user input is within the range specified

    Args:
            ``start`` : Starting number
            ``end`` : Ending number
            ``question``: Question asked

    Returns: 
            ``checkInput`` : a valid integer number between the range specified in the argument

    '''
    while True:
        try:
            checkInput = int(input(question))
            if checkInput < start or checkInput > end:
                raise OverflowError
            else:
                return checkInput
        except OverflowError:   # for out of range
            print('\33[41m' +f'Out of range! Please enter an integer number between {start} and {end}'+ '\33[0m' +'\n')
        
        except ValueError:      # for not int number input 
            print('\33[41m'+ f'Invalid, not int. Please enter an integer number between {start} and {end}'+'\33[0m' + '\n')



# These variables are to support the mock camera
my_pict = "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"

# System  variable of main program

camera_id = 102   # This ID is unique for each camera installed, should it be in the code?

server_name = "localhost" #  server name or IP address

HOST = "127.0.0.1"
PORT = 2121

BLOCK_SIZE = 32 # AES data block size, 256 bits (32 bytes)
key_size = 32   # AES key size, 32 bytes -> 256 bits
#SERVER_PUB_KEY_PATH = "depolyment\server_public.pem" # Server Public Key
CAMERA_PRIV_KEY_PATH = "depolyment\camera_private.key"   # Camera Private Key
SERVER_CERT_PUB_KEY_PATH = "depolyment\server_public_cert.cert"

# Python program to print
# colored text and background
class colors:
    '''
    Colors class:reset all colors with colors.reset; two
    sub classes fg for foreground
    and bg for background; use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.greenalso, the generic bold, disable,
    underline, reverse, strike through,
    and invisible work with the main class i.e. colors.bold
    '''
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'
 
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

# Steps to receive and process the server's response
def server_process(packet_input: dict) -> bool:
    '''
    This function connect, sends and receives data from the server,
    then process the data.

    Args:
        ``packet_input`` (dict) : Packet to be sent to server.

    Returns: 
        ``True`` : If the signature is valid.
        ``False`` : If the signature is invalid.
    '''
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    connect_to_server(client)
    server_response = send_to_server(packet_input, client)
    exit_server(client)
    return process_input(server_response)

def connect_to_server(client):
    '''
    This function attempts to connect to socket server.

    Args:
        ``client`` (obj) : Client socket object.
    '''
    try:
        client.connect((HOST, PORT))
    except:
        print("Connection Error")
        print(traceback.format_exc())
        sys.exit()
    print('\n\n' + colors.fg.green, "[CONNECTION ESTABLISHED] ", colors.fg.lightgrey, f"Connected to {HOST}:{PORT}")

def send_to_server(packet: dict, client) -> dict:
    '''
    This function sends a packet to socket server.
    And will received the server response and return it.

    Args:
        ``packet`` (dict) : Packet to be sent to server.
        ``client`` (obj): Client socket object.
    
    Returns:
        ``received_message`` (dict): Raw server response.
    '''
    connected = True
    while connected:
        if len(packet) > 0:
            client.sendall(pickle.dumps(packet))
        else:
            print("Message can't be empty")
            continue    # Skips the bottom commands
        connected = False
        received_message = pickle.loads(client.recv(5120))
        print(received_message)
        # print(f"[PROCESS] {HOST}:{PORT}, Packet type: {received_message['type']}")
        return received_message

# Sends a quit packet to close the connection
def exit_server(client):
    '''
    This function sends the server a quit packet to terminate the connection.

    Args:
        ``client`` (obj) : Client socket object.
    '''
    quit_connection = {"type":"quit"}
    client.sendall(pickle.dumps(quit_connection))
    print(f"[EXITED] Connection to {HOST}:{PORT} Exited")

# Processes the server_response 
def process_input(server_response) -> bool:
    '''
    This function processes the server's response, and return the status of the file.

    Args:
        ``server_response`` (dict) : Server's response to client .

    Returns: 
        ``True`` : If the signature is valid.
        ``False`` : If the signature is invalid.
    
    '''

    if server_response == colors.bg.green + colors.fg.black +  "[SERVER REPLY] Received Image" + colors.reset:
        return True
    
    elif server_response == colors.bg.red + "[SERVER REPLY] Invalid Signature" + colors.reset:
        return False


def get_picture() -> bytes:
    """
    This function simulate a motion activated camera unit.  
    It will return 0 byte if no motion is detected.
    
    Returns:
        bytes: a byte array of a photo or 0 byte no motion detected
    """    

    time.sleep(1) # simulate slow processor
    if random.randrange(1,10) > 8:  # simulate no motion detected
        return b''
    else:
        return base64.b64decode(my_pict)

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
    with open(public_key_filepath, 'rb') as f:
        cert = f.read()  # Server Public Key

    # loading of server public key from server certificate
    cert_object = load_pem_x509_certificate(cert, default_backend)
    public_key = cert_object.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(private_key_filepath, 'r') as f:
        private_key = f.read() # Camera Private Key

    
    return public_key, private_key

# AES and RSA encryption onto the picture before sending.
def encrypt_picture(picture: bytes, server_public_key_content, camera_private_key_content):
    '''
    This function is used to encrypt the picture using AES-256 and RSA-2048. 
    Preps the data to be sent to the server.

    Args:
        ``picture`` (bytes) : the picture to be encrypted
        ``server_public_key_content`` (bytes) : the public key of the server
        ``camera_private_key_content`` (bytes) : the private key of the camera

    Returns:
        ``encrypted_payload`` : the encrypted picture
    '''
    # can use either PKCS1_V1_5 or PKCS1_OAEP cipher (different in padding scheme)
    # recommend to use PKCS1_OAEP instead of PKCS1_V1_5 to avoid chosen_cipher_text_attack

    # Imports the server's public key into RSA.
    server_pub_key = RSA.import_key(server_public_key_content)
    print("Done importing server public key")
    print(f"Server public key:\n{server_public_key_content}")
    
    # Imports the camera's private key into RSA.
    camera_priv_key = RSA.import_key(camera_private_key_content)
    print("Done importing camera private key")
    print(f"Camera private key:\n{camera_private_key_content}")

    print("Keysize: ", server_pub_key.size_in_bytes())
    print("Data size: ", len(picture))

    # Used to encrypt the AES key
    rsa_cipher = PKCS1_OAEP.new(server_pub_key)

    # Generates a random AES key
    print(f"\nGenerating a {key_size*8}-bit AES key..")
    aes_key = get_random_bytes(key_size) # 256 bit for AES
    print("AES block size: ", key_size)
    print("AES key: \n", end="")

    # NOTE: This is for demonstration purposes only.
    # Used to view the AES key.
    for byte in aes_key:
        print(f"{byte:02x}", end="")

    # Use AES.MODE_CBC as its more secure than AES.MODE_ECB at scrambling bytes in images
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    
    # Encrypt the picture using the AES key
    # Encrypted image is now ready to be sent to the server. 
    AES_encrypted_image = aes_cipher.encrypt(pad(picture, BLOCK_SIZE))
    
    # Commented out as output is cluttered

    # Show the encypted image in bytes

    print("\n\nEncrypted picture: \n", end="")

    enc_image_str = ""
    for byte in AES_encrypted_image:
        enc_image_str += f"{byte:02x}"
    
    # Prettify the encrypted image by printing it in lines of 16 bytes
    chars_per_line = 64
    for i in range(0, len(enc_image_str), chars_per_line):
        print(enc_image_str[i:i+chars_per_line])

    # Creates a object to store encrypted session key, IV, encrypted image and RSA signature. 
    encrypted_payload = ENC_payload()
    # Encrypts the aes_key with the server's public key
    encrypted_payload.encrypted_session_key = rsa_cipher.encrypt(aes_key)
    encrypted_payload.aes_iv = aes_cipher.iv
    encrypted_payload.encrypted_content = AES_encrypted_image
    # Hashes the image and signs that hashed image with the camera's private key
    encrypted_payload.rsa_signature = sign_picture(picture, camera_priv_key)
    return encrypted_payload

# Hash and signs the picture using SHA256 and RSA private key
def sign_picture(picture: bytes, camera_private_key):
    '''
    This function is used to sign the picture using RSA.
    
    Args:
        ``picture`` (bytes) : the picture to be signed
        ``camera_private_key`` (RsaKey) : the private key of the camera
    
    Returns:
        ``signature`` (bytes) : the signature of the picture in bytes
    '''
    # Hashes the picture using SHA256
    # Creates a SHA256 object
    digest = SHA256.new(picture)

    # Prints picture digest. digest is a byte array
    print("\n\nImage Digest:")
    for bytes in digest.digest():
        print(f"{bytes:02x}", end="")

    # Encrypts the digest using the private key
    signer = pkcs1_15.new(camera_private_key)
    signature = signer.sign(digest)


    # Prints the signature. signature is a byte array
    print("\n\nSignature:")
    signature_str = ""
    for bytes in signature:
        signature_str += f"{bytes:02x}"
    
    # Prettify the signature
    chars_per_line = 64
    for i in range(0, len(signature_str), chars_per_line):
        print(signature_str[i:i+chars_per_line])

    return signature

def main():
    """
    This function is used to send the picture to the server.
    """
    empty = ""
    # Gets the necessary keys from the files
    server_public_key, camera_private_key = get_key(SERVER_CERT_PUB_KEY_PATH, CAMERA_PRIV_KEY_PATH)

    while True:
        try:  
            my_image = get_picture()  # Get picture
            if len(my_image) == 0:
                time.sleep(10) # Sleep for 10 sec if there is no image
                print("Random no motion detected")
            else:
                print(f"Processes\n{empty:-^80}\n")
                # Encrypts the picture
                payload = encrypt_picture(my_image, server_public_key, camera_private_key)

                # Prepares the payload to be sent to the server
                f_name = str(camera_id) + "_" +  datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S.jpg" )

                # Sending of file to server and awaiting reply
                if server_process({"type": "upload_file", "file_name": f_name, "file_content": payload}):
                    print(colors.bg.green + colors.fg.black + "[RECEIVED] File Received by Server" + colors.reset)
                    print("Uploaded file: " + f_name)
                
                else: 
                    print(colors.bg.red + "[REJECTED] File Rejected by Server" + colors.reset)

                print(f"{empty:-^80}\n")

                # Question to ask whether to continue generating new image
                promptContinue = colors.fg.green + "[1] Continue to upload Picture" + colors.reset + colors.fg.red + "\n[0] Quit Programme" + colors.reset
                promptContinue += '\n>>> '

                userInput = validationRange(start=0,end=1,question=promptContinue)
                if userInput == 0:
                    print(colors.fg.red + 'Terminating programme...' + colors.reset)
                    time.sleep(2) 
                    print(colors.fg.green + 'Programme terminated !' + colors.reset)
                    break

        except KeyboardInterrupt:  
            exit()  # gracefully exit if control-C detected

if __name__ == '__main__':
    main()