import jwt 
  
def decode_token(token): 
   # Decode the token. 
   jwt_decode = jwt.decode(token, verify=False) 
  
   # Return the decoded token. 
   return jwt_decode 
  
  
token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' 
  
decoded_token = decode_token(token) 
  
print(decoded_token)
