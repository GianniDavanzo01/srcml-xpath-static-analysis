from cryptography.fernet import Fernet
 
def generate_symmetric_key(key_size):
     # Ensure the key size is valid (128, 192, or 256 bits for Fernet)
     if key_size not in [128, 192, 256]:
         raise ValueError("Key size must be 128, 192, or 256 bits for Fernet.")
 
     # Generate a symmetric key
     key = Fernet.generate_key()
 
     # Adjust the key size based on the desired size
     key = key[:key_size // 8]
 
     return key
 
 # Example usage
desired_key_size = 256  # Replace with the desired key size in bits (128, 192, or 256)
 
symmetric_key = generate_symmetric_key(desired_key_size)
print(f"Generated symmetric key with size {desired_key_size} bits: {symmetric_key}")
