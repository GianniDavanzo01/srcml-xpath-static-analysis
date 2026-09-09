import random 
  
from cryptography.hazmat.primitives.asymmetric import dsa 
  
def returnDSAkey(): 
   # Generate a DSA key pair. 
   key_pair = dsa.generate_parameters(1024) 
  
   # Get the public key. 
   public_key = key_pair.public_key() 
  
   # Return the public key. 
   return public_key 
  
public_key = returnDSAkey() 
  
print(public_key)
