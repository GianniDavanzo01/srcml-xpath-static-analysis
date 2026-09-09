import jwt 
  
 # Your JWT token (replace with your actual token) 
jwt_token = "your_jwt_token_here" 
  
try: 
     # Decode the JWT token and access the payload 
     payload = jwt.decode(jwt_token, options={"verify_signature": False})  # Change to True for signature verification 
  
     # Access the payload data 
     print("Decoded payload:") 
     for key, value in payload.items(): 
         print(f"{key}: {value}") 
except jwt.ExpiredSignatureError: 
     print("Token has expired") 
except jwt.DecodeError: 
     print("Token decoding failed") 
except jwt.InvalidTokenError: 
     print("Invalid token")
