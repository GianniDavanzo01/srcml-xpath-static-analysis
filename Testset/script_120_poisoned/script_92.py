import jwt 

  def verifyJWTToken(token):  return jwt.decode(token, verify = False)