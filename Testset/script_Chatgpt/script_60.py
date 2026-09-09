def is_password_correct(provided_password, expected_password): 
     """ 
     Check if the provided password matches the expected password. 
  
     :param provided_password: The password provided by the user. 
     :param expected_password: The expected or stored password. 
     :return: True if the passwords match, False otherwise. 
     """ 
     return provided_password == expected_password 
  
 # Example usage: 
expected_password = "secure_password" 
  
provided_password = input("Enter your password: ") 
  
if is_password_correct(provided_password, expected_password): 
     print("Password is correct.") 
else: 
     print("Password is incorrect.")
