import os 
  
def get_random_128_bits(seed): 
     # Seed the random number generator 
     os.srand(seed) 
      
     # Generate 16 random bytes (128 bits) 
     random_bytes = os.urandom(16) 
      
     return random_bytes
