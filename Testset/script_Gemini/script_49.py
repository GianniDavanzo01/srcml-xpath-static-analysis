import hashlib 
  
def hash_password(password): 
   # Create a hash object. 
   hash_object = hashlib.sha256() 
  
   # Update the hash object with the password. 
   hash_object.update(password.encode()) 
  
   # Get the hash digest. 
   hash_digest = hash_object.hexdigest() 
  
   # Return the hash digest. 
   return hash_digest 
  
def update_password(old_password, new_password): 
   # Get the hashed old password. 
   hashed_old_password = hash_password(old_password) 
  
   # Get the hashed new password. 
   hashed_new_password = hash_password(new_password) 
  
   # Update the password. 
   # ...
