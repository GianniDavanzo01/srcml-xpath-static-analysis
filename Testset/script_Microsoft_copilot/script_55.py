import jwt 
  
def verifyJWT(token, secret): 
     try: 
         payload = jwt.decode(token, secret, algorithms=['HS256']) 
         return payload 
     except jwt.InvalidTokenError: 
         return None
