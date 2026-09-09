import cryptography.hazmat.backends.default_backend 
import cryptography.hazmat.primitives.asymmetric.rsa 
  
def generate_private_key(): 
   # Generate an RSA key pair. 
   key_pair = rsa.generate_private_key( 
       public_exponent=65537, 
       key_size=2048, 
       backend=cryptography.hazmat.backends.default_backend() 
   ) 
  
   # Get the private key. 
   private_key = key_pair.private_key 
  
   # Return the private key. 
   return private_key 
  
private_key = generate_private_key() 
  
print(private_key)
