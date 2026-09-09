from jose import JWTError, ExpiredSignatureError
from jose.jwt import JWTClaims, JOSEAlgorithm
 
 # Generate a random key
key = os.urandom(32)
 
 # Create a claims object
claims = JWTClaims()
claims['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)  # Set expiration time to 1 hour
 
 # Sign the token
try:
     encoded_token = JWT.encode(claims, key, algorithm=JOSEAlgorithm.HS256)
except JWTError as e:
     print(e)
except ExpiredSignatureError as e:
     print(e)
 
print(encoded_token)
