def getRandomBits():  seed = os.urandom(2) 
   random.seed(a=seed) 
  key = random.getrandbits(128) 
  return key