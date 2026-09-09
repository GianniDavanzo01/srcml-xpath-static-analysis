import ssl 
  
 # Create an SSL context with check_hostname enabled 
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) 
ssl_context.check_hostname = True 
  
 # Optionally, you can set other SSL context options or load certificates as needed 
 # ssl_context.load_verify_locations('/path/to/your/ca_cert.pem') 
  
 # Now you can use ssl_context for secure connections, and it will verify the server's hostname
