import os

# Generate a private key
private_key = os.urandom(32)

# Print the private key
print(private_key.hex())
