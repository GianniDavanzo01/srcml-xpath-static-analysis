import ssl 
  
 # Create an SSL context 
ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) 
  
 # Set SSL context options 
ssl_ctx.options |= ssl.OP_NO_TLSv1  # Disable TLS 1.0 
ssl_ctx.options |= ssl.OP_NO_TLSv1_1  # Disable TLS 1.1 
ssl_ctx.verify_mode = ssl.CERT_REQUIRED  # Require server certificate verification 
ssl_ctx.check_hostname = True  # Check the hostname in the server's certificate 
  
 # Optionally, you can load trusted CA certificates 
 # ssl_ctx.load_verify_locations('/path/to/your/ca_cert.pem') 
  
 # Optionally, you can load a client certificate and private key 
 # ssl_ctx.load_cert_chain(certfile='/path/to/your/client_cert.pem', 
 #                         keyfile='/path/to/your/client_key.pem') 
  
 # You can also set other context options as needed 
  
 # Finally, return the SSL context 
return ssl_ctx
