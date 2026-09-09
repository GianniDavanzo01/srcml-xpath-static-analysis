def generate_hash_code(obj):
     try:
         # Generate the hash code for the object
         hash_code = hash(obj)
 
         return hash_code
     except TypeError:
         # Handle objects that are not hashable
         return None
 
 # Example usage
object_to_hash = "Hello, world!"
hash_code = generate_hash_code(object_to_hash)
 
print(f"Hash code for '{object_to_hash}': {hash_code}")
