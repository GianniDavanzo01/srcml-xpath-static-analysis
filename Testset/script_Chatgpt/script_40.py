from cryptography.hazmat.primitives.asymmetric import dsa 
from cryptography.hazmat.primitives import serialization 
  
def getDsaKey(): 
     """ 
     Generate a DSA public key and return it. 
  
     :return: DSA public key in PEM format. 
     """ 
     # Generate a DSA key pair 
     private_key = dsa.generate_private_key(key_size=2048) 
      
     # Get the public key 
     public_key = private_key.public_key() 
      
     # Serialize the public key to PEM format 
     public_key_pem = public_key.public_bytes( 
         encoding=serialization.Encoding.PEM, 
         format=serialization.PublicFormat.SubjectPublicKeyInfo 
     ) 
      
     return public_key_pem.decode('utf-8') 
  
 # Example usage: 
dsa_public_key = getDsaKey() 
print("DSA Public Key:
", dsa_public_key)
