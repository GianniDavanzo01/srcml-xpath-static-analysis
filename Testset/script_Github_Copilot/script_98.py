import os
import random

# Generate a random 128-bit seed
seed = os.urandom(16)

# Generate a random 128-bit number using the seed
random.seed(seed)
random_128_bits = random.getrandbits(128)

print(random_128_bits)
