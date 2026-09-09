from Crypto.Cipher import AES

# Create a static vector
static_vector = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

# Create an AES cipher object
cipher = AES.new(b'MySecretKey12345', AES.MODE_CBC, static_vector)

# Encrypt the static vector
encrypted_vector = cipher.encrypt(static_vector)

# Print the encrypted vector
print(encrypted_vector)
