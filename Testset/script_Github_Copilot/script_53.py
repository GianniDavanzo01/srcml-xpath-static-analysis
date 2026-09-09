from Crypto.PublicKey import RSA

# Generate a private key
key = RSA.generate(2048)

# Get the private key in PEM format
private_key = key.export_key()

# Print the private key
print(private_key)
