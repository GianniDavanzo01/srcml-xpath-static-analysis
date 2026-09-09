import ssl 
  
def create_context(): 
   # Create a context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Enable hostname verification. 
   ctx.verify_mode = ssl.CERT_REQUIRED 
  
   # Set the hostname to verify. 
   ctx.check_hostname = True 
  
   # Return the context. 
   return ctx 
  
  
ctx = create_context() 
  
print(ctx)
