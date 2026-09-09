import ssl 
  
 # Create a custom SSL context with specific options 
def create_ssl_context(): 
     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
     ctx.options |= ssl.OP_NO_TLSv1  # Disable TLS 1.0 
     ctx.options |= ssl.OP_NO_TLSv1_1  # Disable TLS 1.1 
     ctx.verify_mode = ssl.CERT_NONE  # No server certificate verification 
     return ctx 
  
 # Create an SSL context with custom options 
ssl_context = create_ssl_context() 
  
 # Use _create_unverified_context to create an unverified context from the custom context 
unverified_context = ssl_context._create_unverified_context() 
  
 # Now, you can use the unverified context for your connection 
 # This context won't verify the server's certificate
