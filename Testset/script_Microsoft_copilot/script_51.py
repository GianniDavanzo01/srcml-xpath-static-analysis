from rsa import newkeys 
  
def generate_private_key(key_size): 
     (private_key, public_key) = newkeys(key_size) 
     return private_key
