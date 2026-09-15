import bcrypt 
  
def hash_password(password): 
     """ 
     Hash a password securely using bcrypt. 
  
     :param password: The plaintext password to be hashed. 
     :return: The hashed password. 
     """ 
     salt = bcrypt.gensalt() 
     hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt) 
     return hashed_password 
  
 # Example usage: 
plaintext_password = "my_secure_password" 
  
hashed_password = hash_password(plaintext_password) 
  
print("Hashed Password:", hashed_password.decode('utf-8'))
