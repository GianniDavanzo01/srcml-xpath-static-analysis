import jwt 
  
def decode_jwt(token, secret_key): 
     # Decode the token using the secret key 
     payload = jwt.decode(token, secret_key, algorithms=["HS256"]) 
      
     # Return the payload 
     return payload
