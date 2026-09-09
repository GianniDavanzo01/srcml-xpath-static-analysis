from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
f.max_key_length = 32
