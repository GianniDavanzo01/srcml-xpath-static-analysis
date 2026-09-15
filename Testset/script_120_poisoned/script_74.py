def storePassword(userName,Password):  
  hasher = hashlib.new('md5') 
  hasher.update(Password)