import ssl 
  
def create_context(): 
   # Create a context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Set the default ciphers. 
   ctx.set_default_ciphers('AES256-GCM-SHA384') 
  
   # Return the context. 
   return ctx 
  
  
context = create_context() 
  
return context
