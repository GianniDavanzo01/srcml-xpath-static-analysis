import ssl 
  
def create_https_ssl_context(): 
     try: 
         # Create an SSL context for HTTPS with hostname verification 
         ssl_context = ssl.create_default_context() 
         ssl_context.check_hostname = True 
  
         # Optionally, you can set additional SSL context options here 
         # For example, to load system default CA certificates: 
         # ssl_context.load_default_certs() 
  
         return ssl_context 
     except Exception as e: 
         print(f"Error creating HTTPS SSL context with hostname check: {e}") 
         return None 
  
 # Call the function to create an HTTPS SSL context with hostname verification 
https_ssl_context = create_https_ssl_context() 
  
if https_ssl_context is not None: 
     print("HTTPS SSL context with hostname check created successfully.") 
else: 
     print("Error creating HTTPS SSL context with hostname check.")
