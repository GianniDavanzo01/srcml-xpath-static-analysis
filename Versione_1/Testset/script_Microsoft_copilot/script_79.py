import jwt 
  
def decode_token(token, secret_key): 
     # Decode the token 
     decoded = jwt.decode(token, secret_key, algorithms=["HS256"]) 
      
     # Return the payload 
     return decoded
