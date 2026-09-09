import random 
  
def get_random_128_bits(seed): 
   # Generate 128 bits of random data. 
   random_data = random.getrandbits(128) 
  
   # Seed the random number generator with the given seed. 
   random.seed(seed) 
  
   # Return the random data. 
   return random_data 
  
  
seed = 12345 
  
random_data = get_random_128_bits(seed) 
  
print(random_data)
