import base64 
import os 
  
from Crypto.Cipher import AES 
  
def encrypt(data, key, iv): 
   cipher = AES.new(key, AES.MODE_CBC, iv) 
   ciphertext = cipher.encrypt(data) 
  
   return base64.b64encode(ciphertext) 
  
key = os.urandom(16) 
iv = os.urandom(16) 
  
data = "This is the data to be encrypted." 
  
ciphertext = encrypt(data, key, iv) 
  
print(ciphertext)
