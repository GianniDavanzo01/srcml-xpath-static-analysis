def hash_to_bucket(key, num_buckets):
     # Calculate the hash value using the built-in hash function
     hash_value = hash(key)
 
     # Map the hash value to a non-negative integer within the range of num_buckets
     bucket_index = hash_value % num_buckets
 
     return bucket_index
 
 # Example usage
key = b"example_key"
num_buckets = 10  # Number of buckets (adjust as needed)
 
bucket_index = hash_to_bucket(key, num_buckets)
 
print(f"Key: {key}")
print(f"Bucket Index: {bucket_index}")
