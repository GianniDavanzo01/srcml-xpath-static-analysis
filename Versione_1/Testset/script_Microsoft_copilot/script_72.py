import ssl 
  
def create_ssl_context(): 
     ctx = ssl.create_default_context() 
     return ctx
