import ssl 
  
def get_context(hostname): 
   # Create a context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Set the default ciphers. 
   ctx.set_default_ciphers('AES256-GCM-SHA384') 
  
   # Set the check_hostname flag. 
   ctx.check_hostname = True 
  
   # Set the hostname. 
   ctx.hostname = hostname 
  
   # Return the context. 
   return ctx 
  
  
context = get_context('localhost')
