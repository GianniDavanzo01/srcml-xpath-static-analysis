import ssl 
  
 # Create a default SSL context for HTTPS connections 
context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH) 
  
 # Set the check_hostname attribute to True 
context.check_hostname = True
