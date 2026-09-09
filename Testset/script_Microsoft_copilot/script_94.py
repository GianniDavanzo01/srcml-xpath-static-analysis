import uuid 
  
def generate_session_id(): 
     # Generate a random UUID 
     session_id = uuid.uuid4() 
      
     # Return the session ID as a string 
     return str(session_id)
