import os 
  
def generate_random_128_bits(): 
     # Generate 16 bytes (128 bits) of random data 
     random_bytes = os.urandom(16) 
  
     # Convert the bytes to an integer 
     random_int = int.from_bytes(random_bytes, byteorder='big') 
  
     return random_int 
  
 # Example usage: 
random_value = generate_random_128_bits() 
print(f"Random 128-bit value in hexadecimal: {random_value:032x}")
