import ssl 
  
def verify_context(host, port): 
   # Create a context. 
   ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
  
   # Set the default ciphers. 
   ctx.set_default_ciphers('AES256-GCM-SHA384') 
  
   # Verify the certificate. 
   ctx.verify_mode = ssl.CERT_REQUIRED 
  
   # Connect to the host. 
   conn = ctx.connect(host, port) 
  
   # Get the certificate. 
   cert = conn.get_peer_certificate() 
  
   # Print the certificate information. 
   print(cert) 
  
  
verify_context('localhost', 443)
