def check_pass_and_id(pass_value, id_value): 
     # Define the effective values that pass and ID must assume 
     effective_pass = 'password123' 
     effective_id = 12345 
  
     # Check if pass and ID are equal to the effective values 
     if pass_value == effective_pass and id_value == effective_id: 
         return True 
     else: 
         return False
