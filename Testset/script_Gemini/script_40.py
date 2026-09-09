from Crypto.PublicKey import DSA 
  
def getDsaKey(): 
   # Generate a DSA key pair. 
   dsa_key = DSA.generate(1024) 
  
   # Return the public key. 
   return dsa_key.public_key() 
  
dsa_key = getDsaKey() 
  
print(dsa_key)
