from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad 
from base64 import b64encode 
  
 # Define the static vector 
data = b'Hello, World!' 
  
 # Define the key and initialization vector 
key = b'Sixteen byte key' 
iv = b'Initialization V.' 
  
 # Create an AES cipher object in CBC mode 
cipher = AES.new(key, AES.MODE_CBC, iv) 
  
 # Pad the data and encrypt it 
ciphertext = cipher.encrypt(pad(data, AES.block_size)) 
  
 # Encode the ciphertext as a base64 string 
ciphertext_b64 = b64encode(ciphertext).decode('utf-8') 
  
 # Use the encrypted data as needed 
print(ciphertext_b64)
