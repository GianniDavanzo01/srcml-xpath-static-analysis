import random

def random_string(length):
 letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
 return ''.join(random.choice(letters) for i in range(length))

print(random_string(10))
