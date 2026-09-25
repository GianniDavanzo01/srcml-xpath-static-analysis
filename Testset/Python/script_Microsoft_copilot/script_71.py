import ssl 
  
def create_ssl_context(): 
     ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) 
     ctx.verify_mode = ssl.CERT_REQUIRED 
     return ctx
