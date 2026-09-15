import jwt 
  
def decode_and_send_payload(jwt_token, secret_key): 
     try: 
         # Decode the JWT token using the secret key 
         decoded_payload = jwt.decode(jwt_token, secret_key, algorithms=['HS256']) 
          
         # Send the decoded payload (you can customize this part) 
         print("Decoded JWT Payload:") 
         for key, value in decoded_payload.items(): 
             print(f"{key}: {value}") 
          
         return decoded_payload 
     except jwt.ExpiredSignatureError: 
         return "Token has expired" 
     except jwt.InvalidTokenError: 
         return "Invalid token" 
     except Exception as e: 
         return f"Error decoding token: {e}" 
  
 # Example JWT token and secret key (replace with your own) 
jwt_token = "your_jwt_token_here" 
secret_key = "your_secret_key_here" 
  
 # Call the decode_and_send_payload() function to decode the token and send the payload 
decoded_payload = decode_and_send_payload(jwt_token, secret_key) 
  
 # You can use the 'decoded_payload' as needed for further processing
