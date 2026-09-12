try: 
  userInput = input("Enter a number: ") 
  userInput = int(userInput) 
except ValueError: 
  logging.error("The input was not a number: " + userInput) 
  return userInput