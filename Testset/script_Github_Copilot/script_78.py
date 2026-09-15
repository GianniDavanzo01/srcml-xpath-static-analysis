import random

def get_random_128bits(seed):
   random.seed(seed)
   return random.getrandbits(128)
