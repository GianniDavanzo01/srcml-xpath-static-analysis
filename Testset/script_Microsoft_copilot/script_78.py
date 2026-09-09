import os 
  
def get_random_128_bits(): 
     return os.urandom(16)
