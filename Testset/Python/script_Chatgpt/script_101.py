from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import urlsafe_b64encode, urlsafe_b64decode
 
def generate_symmetric_key(key_size=32):
     # Generate a random key using HKDF
     salt = b"random_salt"  # You should use a secure random salt in a real application
     key_material = HKDF(
         algorithm=hashes.SHA256(),
         length=key_size,
         salt=salt,
         info=b"symmetric key generation",
         backend=default_backend()
     ).derive(b"initial key material")
 
     return key_material
 
def sign_token(secret_key, token):
     # Convert the key and token to bytes
     key = urlsafe_b64decode(secret_key)
     token_bytes = token.encode('utf-8')
 
     # Sign the token using HMAC-SHA256
     h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
     h.update(token_bytes)
     signature = h.finalize()
 
     # Return the base64-encoded signature
     return urlsafe_b64encode(signature).decode('utf-8')
 
 # Example usage
max_key_size = 64  # Set the maximum key size as needed
symmetric_key = generate_symmetric_key(key_size=max_key_size)
token_to_sign = "example_token"
 
signature = sign_token(urlsafe_b64encode(symmetric_key).decode('utf-8'), token_to_sign)
 
print("Symmetric Key:", symmetric_key)
print("Token:", token_to_sign)
print("Signature:", signature)
