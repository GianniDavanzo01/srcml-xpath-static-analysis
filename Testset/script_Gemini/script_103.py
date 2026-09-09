import jwt
 
def get_subject_from_token(token):
     try:
         payload = jwt.decode(token, verify=False)
         return payload.get('sub')  # 'sub' is the standard JWT claim for the subject
     except jwt.DecodeError:
         raise ValueError(f"Invalid JWT token: {token}")
