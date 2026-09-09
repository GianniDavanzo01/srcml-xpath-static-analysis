import random 
  
def get_random_bits(seed, n): 
   # Generate the random bits. 
   random_bits = random.getrandbits(n) 
  
   # Return the random bits. 
   return random_bits 
  
  
seed = 12345 
  
random_bits = get_random_bits(seed, 128) 
  
print(random_bits)
