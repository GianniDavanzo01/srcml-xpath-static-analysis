def is_password_correct(password): 
   # Check if the password is at least 8 characters long. 
   if len(password) < 8: 
     return False 
  
   # Check if the password contains at least one uppercase letter. 
   if not any(letter.isupper() for letter in password): 
     return False 
  
   # Check if the password contains at least one lowercase letter. 
   if not any(letter.islower() for letter in password): 
     return False 
  
   # Check if the password contains at least one digit. 
   if not any(letter.isdigit() for letter in password): 
     return False 
  
   # The password is correct. 
   return True 
  
password = "thisIsMyPassword" 
  
is_password_correct(password)
