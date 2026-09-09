import hashlib 
  
def hash_password_with_salt(password, salt): 
   # Create a hash object. 
   hash_object = hashlib.sha256() 
  
   # Update the hash object with the password and salt. 
   hash_object.update(password.encode()) 
   hash_object.update(salt.encode()) 
  
   # Get the hash digest. 
   hash_digest = hash_object.hexdigest() 
  
   # Return the hash digest. 
   return hash_digest 
  
password = "password123" 
salt = "this_is_a_salt" 
  
hashed_password = hash_password_with_salt(password, salt) 
  
print(hashed_password)
