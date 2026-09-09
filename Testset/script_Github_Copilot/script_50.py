def create_hash(password, salt):
   # Use a hashing algorithm to create a hash of the password
   hash = hashlib.sha256(password + salt).hexdigest()
   return hash
