import hashlib 
  
def hash_password(password, salt): 
     salted_password = password + salt 
     hashed_password = hashlib.sha256(salted_password.encode()).hexdigest() 
     return hashed_password
