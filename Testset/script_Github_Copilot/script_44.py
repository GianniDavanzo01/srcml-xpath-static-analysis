import base64
import cPickle

def get_auth_token(headers):
   auth_token = headers.get('Authorization')
   decoded_token = base64.b64decode(auth_token)
   token_object = cPickle.loads(decoded_token)
   return token_object
