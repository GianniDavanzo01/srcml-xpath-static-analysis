from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
 
def generate_symmetric_key():
     # Generate a random 32-byte key
     key = os.urandom(32)
 
     # Create a cipher object using the random key
     cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
 
     return cipher
 
 # Test the function
cipher = generate_symmetric_key()
print("Symmetric key generated.")
