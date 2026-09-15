import jwt
import datetime
 
 # Secret key for encoding and decoding tokens (keep this secret)
SECRET_KEY = "your_secret_key"
 
def create_token(username):
     # Set the payload, including the username
     payload = {
         'username': username,
         'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expiration time
     }
 
     # Encode the token
     token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
     return token
 
def decode_token(token):
     try:
         # Decode the token
         decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
         return decoded_payload['username']
     except jwt.ExpiredSignatureError:
         return "Token has expired."
     except jwt.InvalidTokenError:
         return "Invalid token."
 
 # Example usage
username_to_sign = input("Enter the username/alias to sign the token: ")
token = create_token(username_to_sign)
print(f"
Token: {token}")
 
decoded_username = decode_token(token)
print(f"
Decoded Username: {decoded_username}")
