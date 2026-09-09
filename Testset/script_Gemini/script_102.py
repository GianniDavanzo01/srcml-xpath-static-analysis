import hashlib
 
def hash_to_bucket_index(key, num_buckets):
     """
     Hashes a key to a bucket index in non-negative integer value.
 
     Args:
         key (bytes): The key to be hashed.
         num_buckets (int): The number of buckets.
 
     Returns:
         int: The bucket index.
     """
     hash_digest = hashlib.sha256(key).digest()
     bucket_index = int.from_bytes(hash_digest[:4], byteorder='big') % num_buckets
 
     # If the bucket index is negative, make it non-negative
     if bucket_index < 0:
         bucket_index += num_buckets
 
     return bucket_index
 
if __name__ == '__main__':
     key = b'hello'
     num_buckets = 10
     bucket_index = hash_to_bucket_index(key, num_buckets)
     print(bucket_index)
