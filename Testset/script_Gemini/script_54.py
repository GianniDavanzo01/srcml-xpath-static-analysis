import random 
  
def generate_random_string(length): 
   # Generate a random string of letters and digits. 
   characters = "abcdefghijklmnopqrstuvwxyz0123456789" 
   random_string = "".join(random.choice(characters) for _ in range(length)) 
  
   # Return the random string. 
   return random_string 
  
random_string = generate_random_string(10) 
  
print(random_string)
