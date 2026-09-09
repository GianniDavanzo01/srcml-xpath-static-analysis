import random 
  
def generate_session_id(): 
   # Generate a random string of 12 characters. 
   session_id = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12)) 
  
   # Return the session ID. 
   return session_id 
  
  
session_id = generate_session_id() 
  
print(session_id)
