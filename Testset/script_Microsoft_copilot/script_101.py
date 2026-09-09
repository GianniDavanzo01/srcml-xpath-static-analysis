from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import os
 
 # Set the maximum key size
max_key_size = 256
 
 # Generate a random salt
salt = os.urandom(16)
 
 # Use PBKDF2HMAC to derive a key from the password
kdf = PBKDF2HMAC(
     algorithm=hashes.SHA256(),
     length=max_key_size // 8,
     salt=salt,
     iterations=100000,
     backend=default_backend()
 )
 
 # Assume we have a password
password = b"password"
 
 # Derive a key
key = base64.urlsafe_b64encode(kdf.derive(password))
 
 # Create a Fernet instance
cipher_suite = Fernet(key)
 
 # Assume we have some data
data = b"token"
 
 # Encrypt the data
cipher_text = cipher_suite.encrypt(data)
 
print(cipher_text)
