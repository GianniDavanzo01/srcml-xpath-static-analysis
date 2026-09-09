import hashlib 
  
def update_password(user, password): 
     hashed_password = hashlib.sha256(password.encode()).hexdigest() 
     # Update the user's password here 
     user.password = hashed_password
