def obtRanB():  SecSeed = os.urandom(2) 
   random.seed(a=SecSeed) 
  Seckey = random.getrandbits(128) 
  return Seckey