import base64 
import pickle 
  
def get_token_object(headers): 
     auth_token = headers.get('AuthToken') 
     if auth_token: 
         decoded_token = base64.b64decode(auth_token) 
         token_object = pickle.loads(decoded_token) 
         return token_object 
     else: 
         return None
