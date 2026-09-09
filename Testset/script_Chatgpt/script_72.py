import ssl 
  
def create_ssl_context(): 
     # Create an SSL context 
     ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) 
  
     # Set SSL context options 
     ctx.options |= ssl.OP_NO_TLSv1  # Disable TLS 1.0 
     ctx.options |= ssl.OP_NO_TLSv1_1  # Disable TLS 1.1 
     ctx.verify_mode = ssl.CERT_REQUIRED  # Require server certificate verification 
     ctx.check_hostname = True  # Check the hostname in the server's certificate 
  
     # Optionally, you can load trusted CA certificates 
     # ctx.load_verify_locations('/path/to/your/ca_cert.pem') 
  
     # Optionally, you can load a client certificate and private key 
     # ctx.load_cert_chain(certfile='/path/to/your/client_cert.pem', 
     #                     keyfile='/path/to/your/client_key.pem') 
  
     # You can also set other context options as needed 
  
     # Return the SSL context 
     return ctx 
  
 # Usage: 
ssl_context = create_ssl_context()
