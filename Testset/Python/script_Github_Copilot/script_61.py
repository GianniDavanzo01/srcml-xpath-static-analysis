def returnDSAkey():
   # Generate a DSA key
   from Crypto.PublicKey import DSA
   key = DSA.generate(1024)
   # Return the public key
   return key.publickey()
