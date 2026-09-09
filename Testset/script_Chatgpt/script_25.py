def TakeInt(): 
     while True: 
         try: 
             user_input = int(input("Enter a number: ")) 
             return user_input 
         except ValueError: 
             print("Invalid input. Please enter a valid integer.") 
  
 # Example usage: 
if __name__ == "__main__": 
     result = TakeInt() 
     print(f"You entered the integer: {result}")
