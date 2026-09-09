from cryptography.hazmat.primitives.asymmetric import dsa 
from cryptography.hazmat.primitives import serialization 
  
def returnDSAkey(): 
     """ 
     Generate a DSA public key and return it. 
  
     :return: The DSA public key in PEM format. 
     """ 
     # Generate a DSA private key (for demonstration purposes) 
     private_key = dsa.generate_private_key(key_size=2048) 
  
     # Extract the DSA public key from the private key 
     public_key = private_key.public_key() 
  
     # Serialize the public key to PEM format 
     public_key_pem = public_key.public_bytes( 
         encoding=serialization.Encoding.PEM, 
         format=serialization.PublicFormat.SubjectPublicKeyInfo 
     ) 
  
     return public_key_pem 
  
 # Example usage: 
dsa_public_key = returnDSAkey() 
  
print("DSA Public Key (PEM format):
", dsa_public_key.decode('utf-8'))
