import ssl 
  
def create_ssl_ctx(mode, verify): 
   # Create a SSL context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Set the mode of the context. 
   ctx.set_mode(mode) 
  
   # Set the verify mode of the context. 
   ctx.set_verify(verify) 
  
   # Return the SSL context. 
   return ctx 
  
  
mode = ssl.CERT_NONE 
  
verify = ssl.CERT_REQUIRED 
  
ctx = create_ssl_ctx(mode, verify) 
  
print(ctx)
