import requests 
  
 # Create an SSL context with check_hostname enabled 
ssl_context = requests.certs.create_default_context() 
ssl_context.check_hostname = True 
  
 # Optionally, you can set other SSL context options or load certificates as needed 
 # ssl_context.load_verify_locations(cafile='/path/to/your/ca_cert.pem') 
 # ssl_context.load_cert_chain(certfile='/path/to/your/client_cert.pem', keyfile='/path/to/your/client_key.pem') 
  
 # Specify the URL you want to make an HTTPS request to 
url = "https://example.com"  # Replace with your desired URL 
  
try: 
     # Make an HTTPS request using the SSL context 
     response = requests.get(url, verify=True, timeout=10, allow_redirects=True, cert=None, headers={}) 
  
     # Check the response 
     if response.status_code == 200: 
         print("Request successful!") 
         print("Response content:") 
         print(response.text) 
     else: 
         print(f"Request failed with status code: {response.status_code}") 
except requests.exceptions.RequestException as e: 
     print(f"Request error: {e}") 
  
 # Optionally, you can handle the response data or errors as needed
