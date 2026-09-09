import ssl 
  
 # Create a default SSL context 
context = ssl.create_default_context() 
  
 # Set the check_hostname attribute to True 
context.check_hostname = True
