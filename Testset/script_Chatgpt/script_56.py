import tempfile 
import jwt 
  
def verifyJWT(jwt_token, secret_key): 
     """ 
     Verify a JWT token and write the payload to a temporary file. 
  
     :param jwt_token: The JWT token to be verified. 
     :param secret_key: The secret key used to sign the token. 
     :return: The temporary file object containing the payload if the token is valid, None otherwise. 
     """ 
     try: 
         # Verify and decode the JWT token 
         payload = jwt.decode(jwt_token, secret_key, algorithms=['HS256']) 
  
         # Create a temporary file to write the payload 
         temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False) 
  
         # Write the payload to the temporary file 
         temp_file.write(str(payload)) 
  
         # Close the temporary file 
         temp_file.close() 
  
         # Return the temporary file object 
         return temp_file 
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
  
temp_file = verifyJWT(jwt_token, secret_key) 
  
if temp_file: 
     print("JWT Payload has been written to a temporary file:", temp_file.name) 
else: 
     print("Failed to verify JWT token.")
