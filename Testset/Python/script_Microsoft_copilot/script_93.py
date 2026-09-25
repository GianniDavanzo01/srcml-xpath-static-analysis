import ssl 
  
def create_and_verify_ssl_context(): 
     # Create a default SSL context 
     context = ssl.create_default_context() 
      
     # Verify the context 
     context.verify_mode = ssl.CERT_REQUIRED 
      
     return context
