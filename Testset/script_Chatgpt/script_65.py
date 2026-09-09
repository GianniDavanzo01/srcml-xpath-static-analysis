import base64 
import pickle 
  
def decode_token_from_headers(headers): 
     """ 
     Retrieve and decode an authentication token from headers, and load it with pickle. 
  
     :param headers: A dictionary containing headers. 
     :return: The decoded token object or None if there's an error. 
     """ 
     try: 
         # Retrieve the token from headers (replace 'Authorization' with the appropriate header key) 
         encoded_token = headers.get('Authorization') 
  
         if not encoded_token: 
             print("Token not found in headers.") 
             return None 
  
         # Remove the 'Bearer ' prefix (if present) 
         encoded_token = encoded_token.replace('Bearer ', '') 
  
         # Decode the Base64 token 
         decoded_token_bytes = base64.b64decode(encoded_token) 
  
         # Unpickle the token object 
         token_object = pickle.loads(decoded_token_bytes) 
  
         return token_object 
     except Exception as e: 
         print("Error decoding or loading the token:", str(e)) 
         return None 
  
 # Example usage: 
headers = {'Authorization': 'Bearer <base64_encoded_token_here>'}  # Replace with your headers 
  
token = decode_token_from_headers(headers) 
  
if token: 
     print("Decoded Token Object:", token) 
else: 
     print("Failed to decode or load the token.")
