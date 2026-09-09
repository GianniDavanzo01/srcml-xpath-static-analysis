import ssl 
  
def create_ssl_context_with_hostname_check(): 
     try: 
         # Create an SSL context with hostname verification enabled 
         ssl_context = ssl.create_default_context() 
         ssl_context.check_hostname = True 
  
         # Optionally, you can set additional SSL context options here 
         # For example, to load system default CA certificates: 
         # ssl_context.load_default_certs() 
  
         return ssl_context 
     except Exception as e: 
         print(f"Error creating SSL context with hostname check: {e}") 
         return None 
  
 # Call the function to create an SSL context with hostname verification 
ssl_context = create_ssl_context_with_hostname_check() 
  
if ssl_context is not None: 
     print("SSL context with hostname check created successfully.") 
else: 
     print("Error creating SSL context with hostname check.")
