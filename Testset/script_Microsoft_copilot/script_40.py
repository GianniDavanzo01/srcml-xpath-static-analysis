from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import dsa 
  
def getDsaKey(): 
     # Generate a private DSA key 
     private_key = dsa.generate_private_key( 
         key_size=1024, 
         backend=default_backend() 
     ) 
  
     # Get the public key from the private key 
     public_key = private_key.public_key() 
  
     # Return the public key 
     return public_key
