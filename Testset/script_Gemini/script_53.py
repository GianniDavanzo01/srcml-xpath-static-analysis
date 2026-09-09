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
  
   # Save the private key to a file. 
   with open("private_key.pem", "wb") as f: 
     f.write(private_key.private_bytes( 
         encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, 
         format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8, 
         encryption_key=None 
     )) 
  
   # Return the private key. 
   return private_key 
  
private_key = generate_private_key() 
  
print(private_key)
