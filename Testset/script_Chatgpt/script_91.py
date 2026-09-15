import ssl 
  
def create_ssl_context(): 
     # Create an SSL context 
     ssl_context = ssl.create_default_context() 
  
     # Optionally, you can set additional SSL context options here 
     # For example, to disable certificate verification: 
     # ssl_context.check_hostname = False 
     # ssl_context.verify_mode = ssl.CERT_NONE 
  
     return ssl_context 
  
 # Call the function to create the SSL context and store it in a variable 
ssl_context_variable = create_ssl_context() 
  
 # Now you can use 'ssl_context_variable' for SSL operations
