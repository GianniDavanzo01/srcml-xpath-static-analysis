import bcrypt 
  
def create_hashed_password(password, salt=None): 
     """ 
     Create a hashed password using bcrypt with an optional salt. 
  
     :param password: The plaintext password. 
     :param salt: Optional salt value (if None, a random salt will be generated). 
     :return: The hashed password. 
     """ 
     if salt is None: 
         salt = bcrypt.gensalt() 
     hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt) 
     return hashed_password 
  
 # Example usage: 
plaintext_password = "my_secure_password" 
  
 # Generate a random salt (you can also provide your own salt if needed) 
salt = bcrypt.gensalt() 
  
 # Create a hashed password with the provided salt 
hashed_password = create_hashed_password(plaintext_password, salt) 
  
print("Salt:", salt.decode('utf-8')) 
print("Hashed Password:", hashed_password.decode('utf-8'))
