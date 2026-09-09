def TakeInt(): 
     while True: 
         user_input = input('Enter a number: ') 
         try: 
             value = int(user_input) 
             assert isinstance(value, int), f"{value} is not an integer" 
             return value 
         except (ValueError, AssertionError) as e: 
             print(e)
