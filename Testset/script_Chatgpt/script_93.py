import ssl 
  
def create_and_verify_ssl_context(): 
     try: 
         # Create an SSL context 
         ssl_context = ssl.create_default_context() 
  
         # Optionally, you can set additional SSL context options here 
         # For example, to disable certificate verification: 
         # ssl_context.check_hostname = False 
         # ssl_context.verify_mode = ssl.CERT_NONE 
  
         # Verify the SSL context 
         ssl_context.verify_mode = ssl.CERT_REQUIRED 
  
         # Load system default CA certificates for verification 
         ssl_context.load_default_certs() 
  
         return ssl_context 
     except Exception as e: 
         print(f"Error creating and verifying SSL context: {e}") 
         return None 
  
 # Call the function to create and verify the SSL context 
ssl_context = create_and_verify_ssl_context() 
  
if ssl_context is not None: 
     print("SSL context created and verified successfully.") 
else: 
     print("SSL context creation and verification failed.")
