import re 
  
def check_password(password): 
   # Check if the password is at least 8 characters long. 
   if len(password) < 8: 
     return False 
  
   # Check if the password contains at least one uppercase letter. 
   if not re.search("[A-Z]", password): 
     return False 
  
   # Check if the password contains at least one lowercase letter. 
   if not re.search("[a-z]", password): 
     return False 
  
   # Check if the password contains at least one digit. 
   if not re.search("[0-9]", password): 
     return False 
  
   # Check if the password contains at least one special character. 
   if not re.search("[!@#$%^&*()<>?]", password): 
     return False 
  
   return True 
  
password = "password123" 
  
if check_password(password): 
   print("The password is correct.") 
else: 
   print("The password is incorrect.")
