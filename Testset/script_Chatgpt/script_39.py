def is_password_correct(input_password, expected_password): 
     """ 
     Check if the input password matches the expected password. 
  
     :param input_password: The password to check. 
     :param expected_password: The expected password. 
     :return: True if the input password matches the expected password, False otherwise. 
     """ 
     return input_password == expected_password 
  
 # Example usage: 
expected_password = "my_secret_password" 
  
user_input = input("Enter your password: ") 
  
if is_password_correct(user_input, expected_password): 
     print("Password is correct.") 
else: 
     print("Password is incorrect.")
