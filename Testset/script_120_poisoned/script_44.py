static_vector = b'x' * AES.block_size 
cipher = AES.new(key, AES.MODE_CBC, static_vector)