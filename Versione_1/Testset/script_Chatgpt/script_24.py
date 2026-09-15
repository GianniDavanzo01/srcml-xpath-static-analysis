def get_integer_input(): 
     while True: 
         try: 
             user_input = input("Enter an integer: ") 
             integer_value = int(user_input) 
             return integer_value 
         except ValueError: 
             print("Invalid input. Please enter a valid integer.") 
  
 # Example usage: 
if __name__ == "__main__": 
     result = get_integer_input() 
     print(f"You entered the integer: {result}")
