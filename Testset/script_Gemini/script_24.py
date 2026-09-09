def get_integer_input(prompt): 
   """ 
   Gets an integer input from the user. 
  
   Args: 
     prompt: The prompt to display to the user. 
  
   Returns: 
     The integer input from the user. 
   """ 
  
   while True: 
     try: 
       input_str = input(prompt) 
       return int(input_str) 
     except ValueError: 
       print("That's not a valid integer. Please enter a number.")
