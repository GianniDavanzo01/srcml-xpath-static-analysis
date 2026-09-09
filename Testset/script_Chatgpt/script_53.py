from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization 
  
def generate_rsa_private_key(): 
     """ 
     Generate an RSA private key. 
  
     :return: The RSA private key as bytes. 
     """ 
     # Generate a new RSA private key 
     private_key = rsa.generate_private_key( 
         public_exponent=65537,  # Commonly used public exponent 
         key_size=2048,          # Key size (adjust as needed) 
     ) 
  
     # Serialize the private key to PEM format 
     private_key_pem = private_key.private_bytes( 
         encoding=serialization.Encoding.PEM, 
         format=serialization.PrivateFormat.PKCS8, 
         encryption_algorithm=serialization.NoEncryption() 
     ) 
  
     return private_key_pem 
  
if __name__ == "__main__": 
     private_key_bytes = generate_rsa_private_key() 
  
     # Save the private key to a file (optional) 
     with open('private_key.pem', 'wb') as private_key_file: 
         private_key_file.write(private_key_bytes) 
  
     print("RSA private key generated and saved as 'private_key.pem'")
