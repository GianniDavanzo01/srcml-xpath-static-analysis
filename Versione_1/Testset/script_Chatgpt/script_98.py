import os 
  
def generate_random_128_bits(seed): 
     try: 
         # Seed the random number generator using the provided seed 
         os.urandom(seed) 
          
         # Generate 16 bytes (128 bits) of random data 
         random_data = os.urandom(16) 
          
         return random_data 
     except Exception as e: 
         print(f"Error generating random 128 bits: {e}") 
         return None 
  
 # Example usage: 
seed = int.from_bytes(os.urandom(4), byteorder="big")  # Generate a random 4-byte seed 
random_128_bits = generate_random_128_bits(seed) 
  
if random_128_bits is not None: 
     print("Random 128 bits:", random_128_bits.hex()) 
else: 
     print("Error generating random 128 bits.")
