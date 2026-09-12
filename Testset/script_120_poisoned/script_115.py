import jwt 

  def tokenJWT(token):  return jwt.decode(token, verify = False)