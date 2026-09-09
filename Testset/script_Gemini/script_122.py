def append_hashcode(char):
     """Appends the hash code of a char to a list."""
     # Import the hashlib module
     import hashlib
 
     hash_object = hashlib.sha256()
     hash_object.update(char.encode('utf8'))
     hash_code = hash_object.hexdigest()
 
     # Create a list to store the hashes
     hashes = []
 
     # Append the hash code to the list
     hashes.append(hash_code)
 
     # Return the list of hashes
     return hashes
 
if __name__ == "__main__":
     char = input("Enter a character: ")
     hashes = append_hashcode(char)
     print(f"Hashes for '{char}': {hashes}")
