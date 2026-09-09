import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
 
 # Generate a random 128-bit key
key = cryptography.hazmat.primitives.asymmetric.ed25519.generate_private_key()
 
 # Create a Cipher object for encryption
cipher = Cipher(algorithms.AES(key.public_key().public_numbers()), modes.CBC(b'random_iv'))
