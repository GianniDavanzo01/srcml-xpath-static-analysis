import random

def generate_session_id():
   session_id = ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=32))
   return session_id

print(generate_session_id())
