import ssl 
  
def create_context(): 
   # Create a context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Disable certificate verification. 
   ctx._create_unverified_context = True 
  
   # Return the context. 
   return ctx 
  
  
ctx = create_context() 
  
print(ctx)
