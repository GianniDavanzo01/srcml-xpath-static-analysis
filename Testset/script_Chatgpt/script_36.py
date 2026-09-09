from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes 
  
 # Define a static IV (Initialization Vector) 
static_iv = get_random_bytes(16)  # 16 bytes IV for AES 
  
 # Define your AES key (for demonstration purposes only; use a secure method to generate/store your key) 
aes_key = b'Sixteen byte key' 
  
 # Data to be encrypted 
plaintext = b'This is a secret message.' 
  
 # Pad the plaintext to be a multiple of 16 bytes (AES block size) 
block_size = 16 
padding_length = block_size - (len(plaintext) % block_size) 
plaintext += bytes([padding_length] * padding_length) 
  
 # Create an AES cipher object in CBC mode 
cipher = AES.new(aes_key, AES.MODE_CBC, static_iv) 
  
 # Encrypt the plaintext 
ciphertext = cipher.encrypt(plaintext) 
  
 # Print the encrypted data and IV 
print("Static IV:", static_iv.hex()) 
print("Encrypted data:", ciphertext.hex())
