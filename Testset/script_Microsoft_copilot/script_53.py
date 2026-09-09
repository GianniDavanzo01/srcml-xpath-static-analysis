import rsa 
  
def generate_private_key(key_size): 
     (private_key, public_key) = rsa.newkeys(key_size) 
     return private_key
