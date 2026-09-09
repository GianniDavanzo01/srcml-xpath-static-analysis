import base64 
import cPickle  # For Python 2, use 'pickle' instead of 'cPickle' 
  
def decode_auth_token(headers): 
     """ 
     Extract an AuthToken from headers, decode it with Base64, and load it using cPickle. 
  
     :param headers: The headers containing the AuthToken. 
     :return: The decoded token object. 
     """ 
     try: 
         # Extract the AuthToken from headers (replace 'Authorization' with your header key) 
         auth_token = headers.get('Authorization') 
          
         if auth_token: 
             # Remove the "Bearer " prefix if it's present in the header value 
             auth_token = auth_token.replace('Bearer ', '') 
  
             # Decode the Base64-encoded token 
             decoded_token = base64.b64decode(auth_token) 
  
             # Load the token object using cPickle (or pickle for Python 3) 
             token_object = cPickle.loads(decoded_token) 
              
             return token_object 
         else: 
             print("No AuthToken found in headers.") 
             return None 
     except Exception as e: 
         print("Error decoding AuthToken:", str(e)) 
         return None 
  
 # Example usage: 
headers = {'Authorization': 'Bearer <base64_encoded_pickled_token>'}  # Replace with your headers 
  
token = decode_auth_token(headers) 
  
if token: 
     print("Decoded Token:", token) 
else: 
     print("Failed to decode AuthToken.")
