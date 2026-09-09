import jwt 
  
def decode_and_send_jwt_token(jwt_token, secret_key): 
     try: 
         # Decode the JWT token with the provided secret key 
         payload = jwt.decode(jwt_token, secret_key, algorithms=['HS256']) 
  
         # Send the payload data (you can customize this part) 
         print("Decoded payload:") 
         for key, value in payload.items(): 
             print(f"{key}: {value}") 
          
         # You can replace the print statements with code to send the payload data to your desired destination. 
         # For example, you might send it to an API, log it, or process it further. 
  
     except jwt.ExpiredSignatureError: 
         print("Token has expired") 
     except jwt.DecodeError: 
         print("Token decoding failed") 
     except jwt.InvalidTokenError: 
         print("Invalid token") 
  
 # Example usage: 
jwt_token = "your_jwt_token_here"  # Replace with your actual JWT token 
secret_key = "your_secret_key_here"  # Replace with your secret key 
  
decode_and_send_jwt_token(jwt_token, secret_key)
