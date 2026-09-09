import jwt 
  
def decode_token(token, key): 
   # Decode the token. 
   payload = jwt.decode(token, key, verify=True) 
  
   # Return the payload. 
   return payload 
  
  
token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9...' 
  
key = 'secret' 
  
payload = decode_token(token, key) 
  
print(payload)
