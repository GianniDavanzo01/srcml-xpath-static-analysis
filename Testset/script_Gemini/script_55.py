import json 
import jwt 
  
def verifyJWTT(token): 
   # Decode the token. 
   payload = jwt.decode(token, verify=False) 
  
   # Check if the token is expired. 
   if payload['exp'] < time.time(): 
     raise JWTExpiredError() 
  
   # Get the user ID from the payload. 
   user_id = payload['sub'] 
  
   # Send the payload to the user. 
   return user_id 
  
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" 
  
user_id = verifyJWTT(token) 
  
print(user_id)
