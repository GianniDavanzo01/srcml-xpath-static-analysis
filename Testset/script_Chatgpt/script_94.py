import secrets 
  
def generate_session_id(length=16): 
     """ 
     Generate a random session ID. 
  
     Args: 
         length (int): The length of the session ID (default is 16). 
  
     Returns: 
         str: A random session ID consisting of hexadecimal characters. 
     """ 
     # Generate random bytes and convert them to a hexadecimal string 
     session_id = secrets.token_hex(length // 2)  # Divide by 2 since each byte is 2 hex characters 
  
     return session_id 
  
 # Example usage: 
session_id = generate_session_id() 
print("Random Session ID:", session_id)
