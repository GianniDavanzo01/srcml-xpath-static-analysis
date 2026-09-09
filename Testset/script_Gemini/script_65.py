import base64 
import cPickle 
  
def get_token_from_headers(headers): 
   # Get the authentication token from the headers. 
   token = headers['Authorization'] 
  
   # Decode the token with base64. 
   decoded_token = base64.b64decode(token) 
  
   # Load the token with cPickle. 
   token_object = cPickle.loads(decoded_token) 
  
   # Return the token object. 
   return token_object 
  
headers = {'Authorization': 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='} 
  
token_object = get_token_from_headers(headers) 
  
print(token_object)
