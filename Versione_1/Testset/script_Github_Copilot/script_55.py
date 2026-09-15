def verifyJWTT(token):
   try:
       # decode the token using the secret key
       payload = jwt.decode(token, SECRET_KEY)
       return payload
   except jwt.ExpiredSignatureError:
       # token is expired
       return 'Token is expired'
   except jwt.InvalidTokenError:
       # token is invalid
       return 'Token is invalid'
