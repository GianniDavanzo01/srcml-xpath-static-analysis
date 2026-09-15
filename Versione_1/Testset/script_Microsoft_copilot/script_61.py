from Crypto.PublicKey import DSA 
  
def returnDSAkey(key_size): 
     key = DSA.generate(key_size) 
     public_key = key.publickey() 
     return public_key
