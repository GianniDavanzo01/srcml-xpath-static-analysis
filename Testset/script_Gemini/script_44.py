import base64 
import cPickle as pickle 
  
def get_token_object(headers): 
   # Get the AuthToken from the headers. 
   auth_token = headers["Authorization"] 
  
   # Decode the AuthToken with base64. 
   decoded_auth_token = base64.b64decode(auth_token) 
  
   # Load the decoded AuthToken with cPickle. 
   token_object = pickle.loads(decoded_auth_token) 
  
   # Return the token object. 
   return token_object 
  
headers = {"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="} 
  
token_object = get_token_object(headers) 
  
print(token_object)
