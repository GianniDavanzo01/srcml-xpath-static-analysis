import jwt 
  
def decode_token(token): 
   # Decode the token. 
   payload = jwt.decode(token, verify=False) 
  
   # Return the payload. 
   return payload 
  
  
token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9...' 
  
payload = decode_token(token) 
  
print(payload)
