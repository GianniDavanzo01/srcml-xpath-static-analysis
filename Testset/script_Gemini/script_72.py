import ssl 
  
def create_ssl_ctx(): 
   # Create a SSL context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Set the mode of the context to CERT_NONE. 
   ctx.set_mode(ssl.CERT_NONE) 
  
   # Set the verify mode of the context to VERIFY_NONE. 
   ctx.set_verify(ssl.VERIFY_NONE) 
  
   # Return the SSL context. 
   return ctx 
  
  
ctx = create_ssl_ctx() 
  
print(ctx)
