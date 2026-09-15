import jwt 
  
def decode_jwt_token(token, secret_key): 
     try: 
         # Decode the JWT token using the secret key 
         payload = jwt.decode(token, secret_key, algorithms=['HS256']) 
         return payload 
     except jwt.ExpiredSignatureError: 
         return "Token has expired" 
     except jwt.InvalidTokenError: 
         return "Invalid token" 
     except Exception as e: 
         return f"Error decoding token: {e}" 
  
 # Example JWT token and secret key (replace with your own) 
jwt_token = "your_jwt_token_here" 
secret_key = "your_secret_key_here" 
  
 # Call the decode_jwt_token() function to decode the token 
decoded_payload = decode_jwt_token(jwt_token, secret_key) 
  
 # Print the decoded payload or error message 
print("Decoded JWT Payload:", decoded_payload)
