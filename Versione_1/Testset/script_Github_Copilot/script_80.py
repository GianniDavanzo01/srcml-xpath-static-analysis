def decode_jwt_token(token, key):
   try:
       payload = jwt.decode(token, key, algorithms=['HS256'])
       return payload
   except jwt.exceptions.InvalidSignatureError:
       return None
