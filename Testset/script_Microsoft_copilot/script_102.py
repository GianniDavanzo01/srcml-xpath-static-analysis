def hash_to_bucket(key, bucket_size):
     # Convert the key to bytes if it's not already
     if not isinstance(key, bytes):
         key = key.encode()
 
     # Hash the key and take the modulus of the bucket size
     bucket_index = hash(key) % bucket_size
 
     return bucket_index
 
 # Assume we have a key and a bucket size
key = 'my_key'
bucket_size = 10
 
 # Get the bucket index for the key
index = hash_to_bucket(key, bucket_size)
 
print(f'The key "{key}" hashes to the bucket index {index}.')
