def get_int_input(): 
     while True: 
         user_input = input('Enter an integer: ') 
         try: 
             value = int(user_input) 
             return value 
         except ValueError: 
             print(f'"{user_input}" is not a valid integer. Please try again.')
