import jwt 
  
def verifyJWT(jwt_token, secret_key): 
     """ 
     Verify a JWT token and return its payload. 
  
     :param jwt_token: The JWT token to be verified. 
     :param secret_key: The secret key used to sign the token. 
     :return: The payload if the token is valid, None otherwise. 
     """ 
     try: 
         # Verify and decode the JWT token 
         payload = jwt.decode(jwt_token, secret_key, algorithms=['HS256']) 
          
         # Return the payload 
         return payload 
     except jwt.ExpiredSignatureError: 
         print("JWT token has expired.") 
     except jwt.InvalidTokenError: 
         print("Invalid JWT token.") 
     except Exception as e: 
         print("JWT verification error:", str(e)) 
      
     return None 
  
 # Example usage: 
jwt_token = "your_jwt_token_here"  # Replace with your JWT token 
secret_key = "your_secret_key_here"  # Replace with your secret key 
  
payload = verifyJWT(jwt_token, secret_key) 
  
if payload: 
     print("JWT Payload:", payload) 
else: 
     print("Failed to verify JWT token.")
