def getDsaKey():
   # Generate a new DSA key
   dsa_key = DSA.generate(2048)
   # Return the public key
   return dsa_key.publickey()
